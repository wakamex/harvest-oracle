"""Differential check of one Harvest function across versions of its machine code.

A version is a relocatable object that defines the function: a build of Harvest's source, the target object
delinked from the original executable, or an object compiled from a decompiler's C. Each is linked at
0x20000000 with data bound to the original executable (symbols.tsv). Direct callees visible to the compiler
execute in the version or the image; other callees
without a known address become named stubs. The harness runs every version on the same generated cases,
and the cases are compared: outcome, return value, the ordered calls out of the function with their
arguments, and every word written to generated memory or the executable's globals.
"""

import bisect
import functools
import hashlib
import json
import os
import re
import subprocess
import tempfile
from importlib import resources
from pathlib import Path

BASE = 0x20000000
# A version given as this path runs the original executable's own code of the function in place.
IMAGE = "image"
ALLOCATORS = frozenset(("_Znwm", "_Znam", "malloc", "calloc", "realloc"))
# Undefined symbols without an address in symbols.tsv that are data, not functions.
DATA_PREFIXES = ("_ZTV", "_ZTI", "_ZTS", "__dso_handle")
# The harness fills the argument registers a call may clobber with this after every recorded call, and the
# unused ones at entry: a register still holding it at a call was not set for that call.
POISON = "0xbadc0de0badc0de"
# Registers that can carry arguments of a call without a known signature, such as a virtual call: rdi and rsi,
# and xmm0 to xmm3. Code uses the other argument registers as scratch between calls often enough that comparing
# them reports leftovers as differences.
UNKNOWN_GP, UNKNOWN_XMM = 2, 4

# Bytes to compare behind a pointer or reference argument that points into the stack or a version's own
# data, by pointee type; other pointees compare their first 8 bytes.
POINTEE_SIZES = {
    "ox::core::CVector3d<float>": 12, "ox::core::CRect<float>": 16, "ox::core::CRect<int>": 16,
    "ox::core::CString<char>": 16, "ox::core::CString<wchar_t>": 16, "ox::core::CVector2d<float>": 8,
    "ox::core::CVector2d<int>": 8, "ox::video::SColor": 4, "float": 4, "int": 4, "unsigned int": 4,
    "double": 8, "bool": 1, "char": 1, "wchar_t": 4, "unsigned char": 1,
}

# Integer argument counts of C callees, which have no mangled signature.
C_ARGUMENTS = {
    "wcscmp": 2, "wcslen": 1, "wcsncmp": 3, "strcmp": 2, "strncmp": 3, "strcoll": 2,
    "strcspn": 2, "strspn": 2, "strlen": 1, "strnlen": 2, "strchr": 2, "strrchr": 2,
    "strpbrk": 2, "strstr": 2, "strtok": 2, "strcpy": 2, "strncpy": 3, "strcat": 2,
    "strncat": 3, "strdup": 1, "strndup": 2, "strtol": 3, "strtoul": 3, "strtoll": 3,
    "strtoull": 3, "strtod": 2, "strtof": 2, "lua_pushstring": 2, "lua_pushlstring": 3,
    "lua_pushvfstring": 3, "lua_pushfstring": 2, "lua_getfield": 3, "lua_setfield": 3,
    "lua_getglobal": 2, "lua_setglobal": 2, "luaL_getmetafield": 3, "luaL_callmeta": 3,
    "luaL_typerror": 3, "luaL_argerror": 3, "luaL_checkstack": 3, "luaL_newmetatable": 2,
    "luaL_checkudata": 3, "luaL_error": 2, "luaL_loadfile": 2, "luaL_loadstring": 2,
    "luaL_loadbuffer": 4, "luaL_loadbufferx": 4, "luaL_register": 3, "luaL_gsub": 4,
    "luaL_optlstring": 4,
    "memcpy": 3, "memmove": 3, "memset": 3, "malloc": 1, "free": 1, "calloc": 2, "realloc": 2,
    "_Unwind_Resume": 1, "__cxa_begin_catch": 1, "__cxa_end_catch": 0, "__cxa_rethrow": 0,
    "__cxa_atexit": 3, "__cxa_pure_virtual": 0,
}

# Readable string parameters by general-purpose argument register. A cstring descriptor includes its NUL
# terminator; a counted descriptor names the register holding its length and the bytes per element.
C_STRING_ARGUMENTS = {
    "wcscmp": {0: ("cstring", 4), 1: ("cstring", 4)},
    "wcslen": {0: ("cstring", 4)},
    "wcsncmp": {0: ("bounded", 2, 4), 1: ("bounded", 2, 4)},
    "strcmp": {0: ("cstring", 1), 1: ("cstring", 1)},
    "strncmp": {0: ("bounded", 2, 1), 1: ("bounded", 2, 1)},
    "strcoll": {0: ("cstring", 1), 1: ("cstring", 1)},
    "strcspn": {0: ("cstring", 1), 1: ("cstring", 1)},
    "strspn": {0: ("cstring", 1), 1: ("cstring", 1)},
    "strlen": {0: ("cstring", 1)},
    "strnlen": {0: ("bounded", 1, 1)},
    "strchr": {0: ("cstring", 1)},
    "strrchr": {0: ("cstring", 1)},
    "strpbrk": {0: ("cstring", 1), 1: ("cstring", 1)},
    "strstr": {0: ("cstring", 1), 1: ("cstring", 1)},
    "strtok": {0: ("cstring", 1), 1: ("cstring", 1)},
    "strcpy": {1: ("cstring", 1)},
    "strncpy": {1: ("bounded", 2, 1)},
    "strcat": {0: ("cstring", 1), 1: ("cstring", 1)},
    "strncat": {0: ("cstring", 1), 1: ("bounded", 2, 1)},
    "strdup": {0: ("cstring", 1)},
    "strndup": {0: ("bounded", 1, 1)},
    "strtol": {0: ("cstring", 1)}, "strtoul": {0: ("cstring", 1)},
    "strtoll": {0: ("cstring", 1)}, "strtoull": {0: ("cstring", 1)},
    "strtod": {0: ("cstring", 1)}, "strtof": {0: ("cstring", 1)},
    "lua_pushstring": {1: ("cstring", 1)},
    "lua_pushlstring": {1: ("counted", 2, 1)},
    "lua_pushvfstring": {1: ("cstring", 1)}, "lua_pushfstring": {1: ("cstring", 1)},
    "lua_getfield": {2: ("cstring", 1)}, "lua_setfield": {2: ("cstring", 1)},
    "lua_getglobal": {1: ("cstring", 1)}, "lua_setglobal": {1: ("cstring", 1)},
    "luaL_getmetafield": {2: ("cstring", 1)}, "luaL_callmeta": {2: ("cstring", 1)},
    "luaL_typerror": {2: ("cstring", 1)}, "luaL_argerror": {2: ("cstring", 1)},
    "luaL_checkstack": {2: ("cstring", 1)}, "luaL_newmetatable": {1: ("cstring", 1)},
    "luaL_checkudata": {2: ("cstring", 1)}, "luaL_error": {1: ("cstring", 1)},
    "luaL_loadfile": {1: ("cstring", 1)}, "luaL_loadstring": {1: ("cstring", 1)},
    "luaL_loadbuffer": {1: ("counted", 2, 1), 3: ("cstring", 1)},
    "luaL_loadbufferx": {1: ("counted", 2, 1), 3: ("cstring", 1)},
    "luaL_register": {1: ("cstring", 1)},
    "luaL_gsub": {1: ("cstring", 1), 2: ("cstring", 1), 3: ("cstring", 1)},
    "luaL_optlstring": {2: ("cstring", 1)},
}


def run(command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, text=True, **kwargs).stdout


class Harvest:
    """A Harvest checkout: the original executable and its symbol table."""

    def __init__(self, root, build="1.18-linux-amd64"):
        self.root = Path(root)
        self.build = build
        self.image = self.root / "orig" / build / "Harvest"
        self.symbols = self.root / "config" / build / "symbols.tsv"
        for path in (self.image, self.symbols):
            if not path.exists():
                raise SystemExit(f"{path} not found: pass the Harvest checkout with --harvest")
        self.known, self.sizes = {}, {}
        for line in self.symbols.read_text().splitlines()[1:]:
            address, size, name = line.split("\t")[:3]
            self.known[name] = int(address, 16)
            self.sizes[name] = int(size)
        self.names = {address: name for name, address in self.known.items()}
        self._plt = None
        # Start addresses of the executable's loadable segments, in order: rev.ng's segment_N.
        self.segments = [int(m.group(1), 16) for m in re.finditer(r"LOAD\s+0x\w+\s+(0x\w+)",
                                                                   run(["readelf", "-lW", str(self.image)]))]

    @property
    def plt(self):
        """The executable's PLT entries as ADDRESS=NAME pairs, from the disassembler's name@plt labels."""
        if self._plt is None:
            entries = []
            listing = subprocess.run(["objdump", "-d", "--no-show-raw-insn", "-j", ".plt", str(self.image)],
                                     capture_output=True, text=True).stdout
            for line in listing.splitlines():
                m = re.match(r"([0-9a-f]+) <(.+)@plt>:", line)
                if m:
                    entries.append(f"0x{int(m.group(1), 16):x}={m.group(2)}")
            self._plt = ",".join(entries)
        return self._plt

    def return_kind(self, signature):
        """The return type of a member function from its declarations in src/, when they agree."""
        head = signature.split("(")[0]
        method = head.rsplit("::", 1)[-1]
        kinds = set()
        pattern = re.compile(rf"^\s*(?:static\s+|virtual\s+|inline\s+)*([\w:<>]+\s*\**)\s+{re.escape(method)}\s*\(")
        for header in (self.root / "src").rglob("*.h"):
            for line in header.read_text(errors="replace").splitlines():
                m = pattern.match(line)
                if m:
                    kinds.add(kind_of(m.group(1).replace(" ", "")))
        return kinds.pop() if len(kinds) == 1 else "none"

    @property
    def vague_functions(self):
        """Weak text definitions across this build, cached by object path, size and nanosecond mtime."""
        objects = sorted((self.root / "build" / "match" / self.build).rglob("*.o"))
        stamps = [(str(p.resolve()), p.stat().st_size, p.stat().st_mtime_ns) for p in objects]
        key = hashlib.sha256(json.dumps(stamps).encode()).hexdigest()
        cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "harvest-oracle" / "weak-functions"
        path = cache / f"{key}.json"
        if path.exists():
            return set(json.loads(path.read_text()))
        names = set()
        # One binutils invocation for the whole build. W denotes a weak function; V denotes weak data.
        if objects:
            for line in run(["nm", "--defined-only", *map(str, objects)]).splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[1] == "W":
                    names.add(parts[2])
        cache.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f".{os.getpid()}.tmp")
        temporary.write_text(json.dumps(sorted(names)))
        temporary.replace(path)
        return names


def functions(path):
    """Sized text symbols, including local definitions and aliases."""
    return {p[3]: (int(p[0], 16), int(p[1], 16))
            for line in run(["nm", "-S", str(path)]).splitlines()
            if len(p := line.split()) == 4 and p[2] in "tTwW" and int(p[1], 16)}


@functools.lru_cache(maxsize=8)
def instructions(path, size, mtime):
    """Disassemble an immutable file once; stat values invalidate reused paths."""
    result = []
    for line in run(["objdump", "-d", "-w", str(path)]).splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*([\w.]+)\s*(.*)", line)
        if m:
            result.append((int(m[1], 16), len(m[2].split()), m[3], m[4].split("#")[0].strip()))
    return result


def listing(path):
    stat = Path(path).stat()
    return instructions(str(path), stat.st_size, stat.st_mtime_ns)


def execution_plan(harvest, elf, entry, function, follow, out):
    """Reachable direct-call closure over a fixed follow set; indirect calls remain boundaries.

    A small file tells the harness which image ranges to restore and which transfer instructions to trap.
    Transfers are trapped at their source so an indirect call stays recorded even when its target is runnable.
    """
    own = functions(elf) if elf != "-" else {}
    original = {name: (address, harvest.sizes[name]) for name, address in harvest.known.items()
                if name in follow and harvest.sizes.get(name)}
    # Prefer the version's definition, including for calls made by an image fallback body.
    redirects = {harvest.known[n]: a for n, (a, _) in own.items() if n in harvest.known}
    extents = {a: n for a, n in original.values()}
    extents.update({a: size for name, (a, size) in own.items() if name not in ALLOCATORS})
    allocator_addresses = {a: name for name, (a, _) in own.items() if name in ALLOCATORS}
    image_code = listing(harvest.image)
    object_code = listing(elf) if elf != "-" else []
    image_addresses = [r[0] for r in image_code]
    object_addresses = [r[0] for r in object_code]
    pending, visited = [entry], set()
    rows = [f"N {address:x} {name}" for address, name in allocator_addresses.items()]
    while pending:
        start = pending.pop()
        if start in visited or start not in extents:
            continue
        visited.add(start)
        end = start + extents[start]
        if elf == "-" or start < BASE:
            rows.append(f"R {start:x} {end - start:x}")
        code, addresses = (image_code, image_addresses) if start < BASE else (object_code, object_addresses)
        for address, length, op, arg in code[bisect.bisect_left(addresses, start):bisect.bisect_left(addresses, end)]:
            if not start <= address < end or op not in ("call", "callq", "jmp", "jmpq"):
                continue
            indirect = arg.startswith("*")
            if not indirect:
                m = re.match(r"([0-9a-f]+)", arg)
                if not m:
                    raise ValueError(f"{function}: unsupported transfer at {address:x}: {arg}")
                target = int(m[1], 16)
                if start <= target < end and not op.startswith("call"):
                    continue
                target = redirects.get(target, target) if elf != "-" else target
                if target in extents:
                    pending.append(target)
                    # Original direct calls execute in place when they already have the right target.
                    if target == int(m[1], 16):
                        continue
                elif target >= BASE and elf != "-" and target not in allocator_addresses:
                    # Named stubs and decompiler adapters keep their existing mechanism.
                    continue
                rows.append(f"B {address:x} {address + length:x} {target:x} -1 -1 1 0 {2 if target in extents else 0} {int(op.startswith('call'))} 0 0")
            else:
                operand = arg[1:]
                base = index = -1
                scale, displacement, memory, target = 1, 0, 0, 0
                if operand.startswith("%"):
                    base = UCONTEXT_REGISTERS[operand[1:]]
                else:
                    memory = 1
                    m = re.fullmatch(r"(-?(?:0x)?[0-9a-f]+)?\((?:%(\w+))?(?:,%(\w+)(?:,([1248]))?)?\)", operand)
                    if m:
                        displacement = int(m[1] or "0", 16)
                        if m[2] == "rip":
                            displacement += address + length
                        elif m[2]:
                            base = UCONTEXT_REGISTERS[m[2]]
                        if m[3]:
                            index = UCONTEXT_REGISTERS[m[3]]
                        scale = int(m[4] or 1)
                    elif re.fullmatch(r"(?:0x)?[0-9a-f]+", operand):
                        displacement = int(operand, 16)
                    else:
                        raise ValueError(f"{function}: unsupported indirect transfer at {address:x}: {arg}")
                rows.append(f"B {address:x} {address + length:x} {target:x} {base} {index} {scale} {displacement & ((1 << 64) - 1):x} {memory} {int(op.startswith('call'))} {start:x} {end:x}")
    path = out / (Path(elf).stem + ".plan" if elf != "-" else "image.plan")
    path.write_text("\n".join(rows) + "\n")
    return path


def kind_of(type_name):
    if type_name == "bool":
        return "bool"
    if type_name in ("float", "f32"):
        return "float"
    if type_name in ("int", "s32", "u32", "unsignedint", "long", "u64", "s64") or type_name.endswith("*"):
        return "int"
    return "none"


def harness_binary():
    """The compiled harness, built on first use into the user cache directory."""
    source = resources.files("harvest_oracle").joinpath("harness.c").read_bytes()
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "harvest-oracle"
    binary = cache / f"harness-{hashlib.sha256(source).hexdigest()[:16]}"
    if not binary.exists():
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as scratch:
            c = Path(scratch) / "harness.c"
            c.write_bytes(source)
            run(["gcc", "-O2", "-fPIE", "-pie", "-o", str(binary), str(c), "-lm"])
    return binary


def demangle(names):
    return run(["c++filt"], input="\n".join(names)).splitlines() if names else []


def parameters(signature):
    """Split the parameter list of a demangled signature at top-level commas."""
    inner = signature[signature.index("(") + 1 : signature.rindex(")")]
    depth, items, current = 0, [], ""
    for ch in inner:
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        if ch == "," and depth == 0:
            items.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        items.append(current.strip())
    return [] if items == ["void"] else items


def argument_spec(signature, member=True):
    spec = "p" if member else ""
    for p in parameters(signature):
        if "*" in p or p.endswith("&"):
            spec += "p"
        elif p == "float":
            spec += "f"
        elif p == "double":
            spec += "d"
        elif p == "bool":
            spec += "b"
        else:
            spec += "i"
    return spec


def is_member(qualified):
    """Whether a demangled function name names a member function: its scope is not a lowercase namespace path."""
    if "::" not in qualified or qualified.startswith("operator"):
        return False
    scope = qualified.rsplit("::", 1)[0]
    return not all(part.isidentifier() and part.islower() for part in scope.split("::"))


def pointee_size(parameter):
    base = parameter.replace("const", "").replace("&", "").replace("*", "").strip()
    return POINTEE_SIZES.get(base, 8)


def describe_callees(callees, signatures, pointee, string_arguments=None):
    """Argument register counts (integer, float) and pointee sizes of callees, from their mangled names."""
    for name, demangled in zip(callees, demangle(callees)):
        if name in C_ARGUMENTS:
            signatures[name] = (C_ARGUMENTS[name], 0)
            if string_arguments is not None and name in C_STRING_ARGUMENTS:
                string_arguments[name] = C_STRING_ARGUMENTS[name]
            continue
        if "(" not in demangled or ")" not in demangled:
            continue
        head = demangled[: demangled.index("(")]
        try:
            spec = argument_spec(demangled[: demangled.rindex(")") + 1], member=is_member(head))
        except ValueError:
            continue
        signatures[name] = (sum(c in "pib" for c in spec), sum(c in "fd" for c in spec))
        params = [p for p in parameters(demangled[: demangled.rindex(")") + 1]) if p not in ("float", "double")]
        pointee[name] = ([8] if is_member(head) else []) + [pointee_size(p) for p in params]


def link(harvest, name, obj, function, out, pad=False):
    """Link OBJ with its own text definitions available to direct calls.

    Returns the linked executable, the function's address in it, the address of the named stubs' thunk slot,
    the named stubs and the ranges of the version's own copies of executable data."""
    known = harvest.known
    defined, undefined, data = set(), set(), set()
    text_definitions = set(functions(obj))
    for line in run(["nm", str(obj)]).splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "U":
            undefined.add(parts[1])
        elif len(parts) == 3 and parts[1] in "TWVDBRGSC" and parts[1].isupper():
            defined.add(parts[2])
            if parts[1] in "DBRGSC":
                data.add(parts[2])
    if function not in defined:
        raise SystemExit(f"{obj} does not define {function}")
    # An object built from a decompiler's C (revng.py) defines adapters under its callees' names, which must stay
    # its own; what it leaves undefined, and its data (rev.ng's header defines segment_N and globals tentatively),
    # is bound to the executable.
    decompiled = "oracle_native_slot" in defined
    segments = harvest.segments

    def inside(address):
        return function in known and known[function] <= address < known[function] + harvest.sizes.get(function, 0)

    defsyms, stubs, blobs = [], [], []
    for symbol in sorted(((undefined | data if decompiled else defined | undefined)) - {function}):
        segment = re.fullmatch(r"segment_(\d+)", symbol)
        if segment and int(segment.group(1)) < len(segments):
            defsyms.append(f"--defsym={symbol}=0x{segments[int(segment.group(1))]:x}")
        elif re.fullmatch(r"function_0x[0-9a-f]+_Code_x86_64", symbol):
            defsyms.append(f"--defsym={symbol}=0x{symbol[11:-12]}")
        elif symbol in text_definitions:
            continue
        elif symbol in known:
            defsyms.append(f"--defsym={symbol}=0x{known[symbol]:x}")
        elif re.fullmatch(r"sub_[0-9a-f]+", symbol) and inside(int(symbol[4:], 16)):
            # A delinker label inside the function under test, such as a jump table entry: the same offset
            # in the linked copy, which holds the executable's code byte for byte.
            defsyms.append(f"--defsym={symbol}={function}+0x{int(symbol[4:], 16) - known[function]:x}")
        elif re.fullmatch(r"lbl_[0-9a-f]+", symbol):
            # A delinker label names its own address in the executable; the object's copy of the bytes behind
            # it is not always the executable's.
            defsyms.append(f"--defsym={symbol}=0x{symbol[4:]}")
        elif symbol in undefined:
            (blobs if symbol.startswith(DATA_PREFIXES) else stubs).append(symbol)
    assembly = [".data", ".globl oracle_thunk_slot", "oracle_thunk_slot: .quad 0", ".section .rodata"]
    assembly += [f".Lname{i}: .asciz \"{s}\"" for i, s in enumerate(stubs)]
    assembly.append(".text")
    for i, s in enumerate(stubs):
        assembly += [f".globl {s}", f"{s}:", f"  lea .Lname{i}(%rip), %r11", "  jmp *oracle_thunk_slot(%rip)"]
    assembly.append(".bss")
    for s in blobs:
        assembly += [f".globl {s}", ".balign 16", f"{s}: .zero 4096"]
    (out / f"{name}-stubs.s").write_text("\n".join(assembly) + "\n")
    run(["as", "-o", str(out / f"{name}-stubs.o"), str(out / f"{name}-stubs.s")])
    elf, linker_map = out / f"{name}.elf", out / f"{name}.map"
    padding = []
    if pad:
        # 4 KB ahead of the object's data, to tell behavior that depends on its own data layout.
        (out / "pad.s").write_text(".section .rodata\n.zero 4096\n.data\n.zero 4096\n.bss\n.zero 4096\n")
        run(["as", "-o", str(out / "pad.o"), str(out / "pad.s")])
        padding = [str(out / "pad.o")]
    run(["ld", "-static", "-nostdlib", "-z", "noexecstack", f"-Ttext-segment=0x{BASE:x}", "-e", function, *defsyms,
         "-Map", str(linker_map), *padding, str(obj), str(out / f"{name}-stubs.o"), "-o", str(elf)])
    addresses = {}
    for line in run(["nm", str(elf)]).splitlines():
        parts = line.split()
        if len(parts) == 3:
            addresses[parts[2]] = int(parts[0], 16)
    native = addresses.get("oracle_native_slot")
    ranges = translations(linker_map, known)
    # Indirect calls to a local copy retain the original callee identity. Stored code pointers likewise
    # compare by their executable address rather than the version's link address.
    ranges += [(address, size, known[n]) for n, (address, size) in functions(elf).items() if n in known]
    return elf, addresses[function], (addresses["oracle_thunk_slot"], native), stubs, ranges


def translations(linker_map, known):
    """Ranges of a version's own copies of executable data: an input section named after a symbol of the
    executable, such as .rodata._ZTV..., placed at (start, size), stands for that symbol's address."""
    ranges = []
    pattern = r"^ (\.(?:rodata|data|bss|data\.rel\.ro)(?:\.rel)?(?:\.local)?)\.(\S+)\s+0x(\w+)\s+0x(\w+)"
    for m in re.finditer(pattern, linker_map.read_text(), re.M):
        symbol, start, size = m.group(2), int(m.group(3), 16), int(m.group(4), 16)
        if symbol in known and size:
            ranges.append((start, size, known[symbol]))
    return ranges


def translate(value, ranges):
    for start, size, image in ranges:
        if start <= value < start + size:
            return image + (value - start)
    return value


def normalized_writes(writes, ranges):
    """Written words with every aligned 8-byte word that points into a translated range rewritten."""
    if not ranges:
        return writes
    result = []
    for address, data in writes:
        start, raw = int(address, 16), bytearray.fromhex(data)
        for offset in range((-start) % 8, len(raw) - 7, 8):
            value = int.from_bytes(raw[offset : offset + 8], "little")
            moved = translate(value, ranges)
            if moved != value:
                raw[offset : offset + 8] = moved.to_bytes(8, "little")
        result.append([address, raw.hex()])
    return result


# ucontext register numbers of the general-purpose registers, by 64-bit and 32-bit name.
UCONTEXT_REGISTERS = {"r8": 0, "r9": 1, "r10": 2, "r11": 3, "r12": 4, "r13": 5, "r14": 6, "r15": 7, "rdi": 8,
                      "rsi": 9, "rbp": 10, "rbx": 11, "rdx": 12, "rax": 13, "rcx": 14, "rsp": 15}
UCONTEXT_REGISTERS.update({"e" + n[1:] if n[0] == "r" and n[1:].isalpha() else n + "d": v
                           for n, v in list(UCONTEXT_REGISTERS.items())})


def instruction_parts(text):
    """Return the mnemonic and AT&T operands from one objdump instruction line."""
    text = text.split("#", 1)[0].strip()
    match = re.match(r"([a-z][a-z0-9]*)(?:\s+(.*))?", text)
    return (match.group(1), match.group(2) or "") if match else ("", "")


def guards(elf, function=None):
    """Reads of sized read-only data reached through indexed or short register and stack address sequences."""
    symbols = []
    for line in run(["nm", "-S", str(elf)]).splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[2] in "rR" and int(parts[1], 16):
            symbols.append((int(parts[0], 16), int(parts[0], 16) + int(parts[1], 16)))
    listing = run(["objdump", "-d", "--no-show-raw-insn", str(elf)])
    body = (listing.split(f"<{function}>:\n", 1)[1].split("\n\n", 1)[0] if function else listing).splitlines()
    instructions, entries = [], set()
    for line in body:
        label = re.match(r"\s*([0-9a-f]+)\s+<[^>]+>:", line)
        if label:
            entries.add(int(label.group(1), 16))
        instruction = re.match(r"\s*([0-9a-f]+):\s+(.*)", line)
        if instruction:
            instructions.append((int(instruction.group(1), 16), instruction.group(2)))
    targets = set()
    for _, text in instructions:
        mnemonic, operands = instruction_parts(text)
        if mnemonic.startswith("j"):
            target = re.match(r"\s*(0x[0-9a-f]+)", operands)
            if target:
                targets.add(int(target.group(1), 16))

    aliases = {}
    for names in (("rax", "eax", "ax", "al"), ("rbx", "ebx", "bx", "bl"),
                  ("rcx", "ecx", "cx", "cl"), ("rdx", "edx", "dx", "dl"),
                  ("rsi", "esi", "si", "sil"), ("rdi", "edi", "di", "dil"),
                  ("rbp", "ebp", "bp", "bpl"), ("rsp", "esp", "sp", "spl"),
                  *((f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b") for i in range(8, 16))):
        aliases.update((name, names[0]) for name in names)

    def register(operand):
        match = re.fullmatch(r"%([a-z0-9]+)", operand.strip())
        return aliases.get(match.group(1)) if match else None

    def extent_at(address):
        return next(((start, end) for start, end in symbols if start <= address < end), None)

    def split_operands(operands):
        result, start, depth = [], 0, 0
        for i, char in enumerate(operands):
            depth += (char == "(") - (char == ")")
            if char == "," and depth == 0:
                result.append(operands[start:i].strip())
                start = i + 1
        if operands.strip():
            result.append(operands[start:].strip())
        return result

    def reads_memory(mnemonic, operands, address_operand):
        if mnemonic == "lea" or mnemonic.startswith(("prefetch", "nop")):
            return False
        if address_operand < len(operands) - 1:
            return True
        if mnemonic.startswith(("cmpxchg", "bts", "btr", "btc")):
            return False
        return mnemonic.startswith(("cmp", "test", "bt", "push", "call", "jmp", "fld", "fild", "fcom",
                                    "ficom", "fucom", "fcomp", "ficomp"))

    result = []
    bases = {}
    stack_bases = {}

    def stack_slot(operand):
        match = re.fullmatch(r"(-?0x[0-9a-f]+)?\(%(rsp|rbp)\)", operand.strip())
        if not match:
            return None
        return aliases[match.group(2)], int(match.group(1) or "0", 16)

    def fact_extent(fact, displacement=0):
        if fact and (fact[3] or fact[0] <= fact[2] + displacement < fact[1]):
            return fact[:2]
        return None

    def address_fact(start, end, offset, dynamic=False):
        return start, end, offset, dynamic

    for (address, text), (following, _) in zip(instructions, instructions[1:] + [(None, None)]):
        if address in entries:
            bases.clear()
            stack_bases.clear()
        elif address in targets:
            bases.clear()
        mnemonic, operand_text = instruction_parts(text)
        operands = split_operands(operand_text)
        following_address = following if following is not None else address
        length = following_address - address

        indexed = None
        simple = None
        memory_operand = -1
        for i, operand in enumerate(operands):
            indexed = re.fullmatch(r"(-?0x[0-9a-f]+)?\((?:%([a-z0-9]+))?,%([a-z0-9]+),([1248])\)", operand)
            if indexed:
                memory_operand = i
                break
        if indexed is None:
            for i, operand in enumerate(operands):
                simple = re.fullmatch(r"(-?0x[0-9a-f]+)?\(%([a-z0-9]+)\)", operand)
                if simple:
                    memory_operand = i
                    break
        if memory_operand >= 0 and reads_memory(mnemonic, operands, memory_operand):
            if indexed:
                displacement = int(indexed.group(1) or "0", 16)
                base_name, index_name = indexed.group(2), indexed.group(3)
                extent = extent_at(displacement)
                if extent is None and base_name:
                    extent = fact_extent(bases.get(aliases.get(base_name)), displacement)
                if extent and index_name in UCONTEXT_REGISTERS:
                    base = UCONTEXT_REGISTERS.get(base_name, -1) if base_name else -1
                    wide = int((base_name or "").startswith("r") or index_name.startswith("r"))
                    result.append(f"{address:x}:{displacement & 0xffffffffffffffff:x}:{extent[0]:x}:{extent[1]:x}:"
                                  f"{base}:{UCONTEXT_REGISTERS[index_name]}:{indexed.group(4)}:{wide}")
            elif simple:
                displacement = int(simple.group(1) or "0", 16)
                base_name = simple.group(2)
                fact = bases.get(aliases.get(base_name))
                if fact and fact[3]:
                    extent = fact[:2]
                    base = UCONTEXT_REGISTERS[base_name]
                    result.append(f"{address:x}:{displacement & 0xffffffffffffffff:x}:{extent[0]:x}:{extent[1]:x}:"
                                  f"{base}:-1:0:1")

        destination = register(operands[-1]) if operands else None
        source_register = register(operands[0]) if operands else None
        immediate = re.fullmatch(r"\$(-?(?:0x[0-9a-f]+|[0-9]+))", operands[0]) if operands else None
        source_slot = stack_slot(operands[0]) if operands else None
        destination_slot = stack_slot(operands[-1]) if operands else None

        if mnemonic == "lea" and destination:
            source = operands[0]
            rip = re.fullmatch(r"(-?0x[0-9a-f]+)?\(%rip\)", source)
            address_operand = re.fullmatch(r"(-?0x[0-9a-f]+)?\((?:%([a-z0-9]+))?(?:,%([a-z0-9]+),([1248]))?\)",
                                           source)
            if rip:
                target = address + length + int(rip.group(1) or "0", 16)
                extent = extent_at(target)
                if extent:
                    bases[destination] = address_fact(*extent, target)
                else:
                    bases.pop(destination, None)
            elif address_operand:
                displacement = int(address_operand.group(1) or "0", 16)
                base_name, index_name = address_operand.group(2), address_operand.group(3)
                if base_name and aliases.get(base_name) in bases:
                    fact = bases[aliases[base_name]]
                    bases[destination] = address_fact(*fact[:2], fact[2] + displacement,
                                                      fact[3] or bool(index_name))
                elif not base_name and extent_at(displacement):
                    extent = extent_at(displacement)
                    bases[destination] = address_fact(*extent, displacement, bool(index_name))
                else:
                    bases.pop(destination, None)
            else:
                bases.pop(destination, None)
        elif mnemonic.startswith("mov") and destination:
            if source_register in bases:
                bases[destination] = bases[source_register]
            elif source_slot in stack_bases:
                bases[destination] = stack_bases[source_slot]
            elif immediate:
                target = int(immediate.group(1), 0)
                extent = extent_at(target)
                if extent:
                    bases[destination] = address_fact(*extent, target)
                else:
                    bases.pop(destination, None)
            else:
                bases.pop(destination, None)
        elif mnemonic.startswith(("add", "sub")) and destination:
            if immediate:
                amount = int(immediate.group(1), 0)
                if mnemonic.startswith("sub"):
                    amount = -amount
                if destination in bases:
                    fact = bases[destination]
                    offset = fact[2] if fact[3] else fact[2] + amount
                    bases[destination] = address_fact(*fact[:2], offset, fact[3])
                elif extent_at(amount):
                    extent = extent_at(amount)
                    bases[destination] = address_fact(*extent, amount, True)
                else:
                    bases.pop(destination, None)
            else:
                fact = bases.get(destination) or bases.get(source_register)
                if fact:
                    bases[destination] = address_fact(*fact[:2], fact[2], True)
                else:
                    bases.pop(destination, None)
        elif mnemonic.startswith("mov") and destination_slot:
            if source_register in bases:
                stack_bases[destination_slot] = bases[source_register]
            else:
                stack_bases.pop(destination_slot, None)
        elif mnemonic.startswith(("add", "sub")) and destination_slot:
            if destination_slot in stack_bases:
                fact = stack_bases[destination_slot]
                stack_bases[destination_slot] = address_fact(*fact[:2], fact[2], True)
        else:
            if destination and mnemonic not in {"cmp", "test", "bt", "push", "call", "jmp", "ret", "nop"}:
                if mnemonic.startswith(("shl", "sal", "shr", "sar", "inc", "dec", "neg")) and destination in bases:
                    fact = bases[destination]
                    bases[destination] = address_fact(*fact[:2], fact[2], True)
                else:
                    bases.pop(destination, None)
            if mnemonic.startswith("xchg"):
                for operand in operands:
                    source = register(operand)
                    if source:
                        bases.pop(source, None)
            if mnemonic.startswith("call"):
                for name in ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"):
                    bases.pop(name, None)
            elif mnemonic.startswith(("jmp", "ret")):
                bases.clear()
        if destination == "rsp" or mnemonic.startswith(("push", "pop")):
            stack_bases.clear()
    return ",".join(result)


def text_section(image):
    """The executable's .text section as (start, end)."""
    for line in run(["readelf", "-SW", str(image)]).splitlines():
        m = re.search(r"\]\s+\.text\s+PROGBITS\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)", line)
        if m:
            return int(m.group(1), 16), int(m.group(1), 16) + int(m.group(2), 16)
    raise SystemExit(f"{image} has no .text section")


def execute(harvest, elf, entry, slot, spec, cases, own=None, seeds=None, guard_list="", plan=None):
    """Run the harness on seeds 1 to CASES, or on SEEDS. ELF is a linked version, or "-" with
    OWN = (start, size) to run the executable's own code of the function in place."""
    if seeds is not None:
        return [r for seed in seeds
                for r in execute_range(harvest, elf, entry, slot, spec, 1, own, first=seed, guard_list=guard_list, plan=plan)]
    return execute_range(harvest, elf, entry, slot, spec, cases, own, guard_list=guard_list, plan=plan)


def execute_range(harvest, elf, entry, slot, spec, cases, own=None, first=1, guard_list="", plan=None):
    thunk, native = slot if isinstance(slot, tuple) else (slot, None)
    env = {"ORACLE_THUNK_SLOT": f"0x{thunk:x}"} if thunk else {}
    if native:
        env["ORACLE_NATIVE_SLOT"] = f"0x{native:x}"
    env["ORACLE_PLT"] = harvest.plt
    if plan:
        env["ORACLE_PLAN"] = str(plan)
        text = text_section(harvest.image)
        env["ORACLE_TEXT"] = f"0x{text[0]:x}:0x{text[1]:x}"
    if guard_list:
        env["ORACLE_GUARDS"] = guard_list
    if own and not plan:
        text = text_section(harvest.image)
        env.update(ORACLE_IMAGE_FUNCTION=f"0x{own[0]:x}:{own[1]}", ORACLE_TEXT=f"0x{text[0]:x}:0x{text[1]:x}")
    output = subprocess.run([str(harness_binary()), str(harvest.image), str(elf), f"0x{entry:x}", spec, str(first),
                             str(cases)], check=True, capture_output=True, text=True, env=env).stdout
    return [json.loads(line) for line in output.splitlines()]


GP_NAMES = [("rdi", "edi", "di", "dil"), ("rsi", "esi", "si", "sil"), ("rdx", "edx", "dx", "dl"),
            ("rcx", "ecx", "cx", "cl"), ("r8", "r8d", "r8w", "r8b"), ("r9", "r9d", "r9w", "r9b")]


def integer_setups(path, start, end):
    stat = Path(path).stat()
    return _integer_setups(str(path), stat.st_size, stat.st_mtime_ns, start, end)


@functools.lru_cache(maxsize=8)
def _integer_setups(path, size, mtime, start, end):
    """For each call in [START, END) of PATH, by return address, the integer argument registers written by the
    straight-line instructions before it, back to the previous call, jump or branch target. Code also uses those
    registers as scratch between calls, so for a call without a known signature only a register both versions
    set up for that call is compared."""
    instructions = [(a, op, args) for a, _, op, args in listing(path) if start <= a < end]
    targets = set()
    for _, mnemonic, operands in instructions:
        t = re.match(r"([0-9a-f]+)\b", operands) if mnemonic.startswith(("j", "call")) else None
        if t:
            targets.add(int(t.group(1), 16))
    setups = {}
    for i, (address, mnemonic, _) in enumerate(instructions):
        if not mnemonic.startswith("call") or i + 1 >= len(instructions):
            continue
        written = set()
        for j in range(i - 1, -1, -1):
            a, mn, ops = instructions[j]
            if mn.startswith(("call", "j", "ret")):
                break
            destination = ops.rsplit(",", 1)[-1].strip().lstrip("%") if ops else ""
            written.update(k for k, names in enumerate(GP_NAMES) if destination in names)
            if a in targets:
                break
        setups[instructions[i + 1][0]] = written
    return setups


def cached_image_run(harvest, start, size, spec, cases, plan=None):
    """The executable's own code run in place: the same for every check of a function, so it is kept in the user
    cache, keyed by the executable, the function, its arguments, the case count and the harness build."""
    image = harvest.image.stat()
    key = hashlib.sha256(f"{harvest.image.resolve()}:{image.st_size}:{image.st_mtime_ns}:{start}:{size}:{spec}:"
                         f"{cases}:{harness_binary().name}:{plan.read_text() if plan else ''}".encode()).hexdigest()[:24]
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "harvest-oracle" / "image-runs"
    path = cache / f"{key}.json"
    if path.exists():
        return json.loads(path.read_text())
    result = execute(harvest, "-", start, None, spec, cases, own=(start, size), plan=plan)
    cache.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(result))
    temporary.replace(path)
    return result


def inside_ranges(value, *range_lists):
    return any(start <= value < start + size for ranges in range_lists for start, size, _ in ranges)


def call_identity(call, names, ranges=()):
    target = call["to"]
    if "@" in target:
        return target.split("@")[0]
    address = translate(int(target, 16), ranges)
    return names.get(address, hex(address))


def case_differences(a, b, ranges_a, ranges_b, names, signatures, pointee, return_kind, setups_a=None,
                     setups_b=None, string_arguments=None):
    """How case A and case B differ, as a list of short descriptions; empty when they agree."""
    diffs = []
    if a["outcome"] != b["outcome"]:
        diffs.append(f"outcome {a['outcome']} vs {b['outcome']}")
    elif a["outcome"] == "crash" and int(a["detail"], 16) >> 12 != int(b["detail"], 16) >> 12:
        # A fault's page: within a page, which field of a bad pointer is read first is scheduling. Other
        # signals record the faulting instruction, whose address differs between any two builds.
        diffs.append(f"crash at {a['detail']} vs {b['detail']}")
    elif a["outcome"] == "return":
        masks = {"int": ("rax", 0xFFFFFFFF), "bool": ("rax", 0xFF), "float": ("xmm0", 0xFFFFFFFF)}
        if return_kind in masks:
            register, mask = masks[return_kind]
            if int(a[register], 16) & mask != int(b[register], 16) & mask:
                diffs.append(f"return {a[register]} vs {b[register]}")
    for i, (x, y) in enumerate(zip(a["calls"], b["calls"])):
        ix, iy = call_identity(x, names, ranges_a), call_identity(y, names, ranges_b)
        if ix != iy:
            diffs.append(f"call {i}: {ix} vs {iy}")
            break
        count = signatures.get(ix)
        if count:
            gp_indices = range(count[0])
        else:
            # Without a signature, such as a virtual call, compare the registers both versions set for it.
            sa = (setups_a or {}).get(int(x.get("site", "0x0"), 16))
            sb = (setups_b or {}).get(int(y.get("site", "0x0"), 16))
            gp_indices = [k for k in range(UNKNOWN_GP) if POISON not in (x["gp"][k], y["gp"][k])
                          and (k == 0 or sa is None or sb is None or (k in sa and k in sb))]
            xmm_indices = [k for k in range(UNKNOWN_XMM) if POISON not in (x["xmm"][k], y["xmm"][k])]
            fa, fb = [x["xmm"][k] for k in xmm_indices], [y["xmm"][k] for k in xmm_indices]
            if fa != fb:
                diffs.append(f"call {i} {ix} float registers {fa} vs {fb}")
                break
        sizes = pointee.get(ix, [])
        string_sizes = (string_arguments or {}).get(ix, {})

        def string_size(call, k, data):
            descriptor = string_sizes[k]
            raw = bytes.fromhex(data)
            if descriptor[0] == "cstring":
                width = descriptor[1]
                end = next((i for i in range(0, len(raw) - width + 1, width)
                            if raw[i : i + width] == bytes(width)), len(raw))
                return min(len(raw), end + width) if end < len(raw) else len(raw)
            if descriptor[0] == "counted":
                length = int(call["gp"][descriptor[1]], 16) * descriptor[2]
                return min(len(raw), length)
            if descriptor[0] == "bounded":
                length = min(len(raw), int(call["gp"][descriptor[1]], 16) * descriptor[2])
                raw = raw[:length]
                width = descriptor[2]
                end = next((i for i in range(0, len(raw) - width + 1, width)
                            if raw[i : i + width] == bytes(width)), len(raw))
                return min(len(raw), end + width) if end < len(raw) else len(raw)
            raise ValueError(f"unknown string argument descriptor {descriptor}")

        def shown(call, ranges):
            result = []
            for k in gp_indices:
                value, data = int(call["gp"][k], 16), call["deref"][k]
                moved = translate(value, ranges)
                # Code pointers keep address identity; data pointees still compare their contents.
                canonical = any(image <= moved < image + size and names.get(image) in signatures
                                for _, size, image in ranges_a + ranges_b)
                if canonical or (not data and k not in string_sizes):
                    result.append(hex(moved))
                elif k in string_sizes and data:
                    result.append("local:" + data[: 2 * string_size(call, k, data)])
                elif k in string_sizes and string_sizes[k][0] in ("counted", "bounded") and not int(
                        call["gp"][string_sizes[k][1]], 16):
                    result.append("local:")
                else:
                    if data:
                        result.append("local:" + normalized_writes([["0x0", data]], ranges)[0][1][:
                                          2 * (sizes[k] if k < len(sizes) else 8)])
                    else:
                        result.append(hex(moved))
            return result

        # Identical raw arguments, none pointing into translated data, are equal without translating.
        if (all(x["gp"][k] == y["gp"][k] and x["deref"][k] == y["deref"][k] for k in gp_indices)
                and not any(inside_ranges(int(x["gp"][k], 16), ranges_a, ranges_b) for k in gp_indices)):
            xa = xb = None
        else:
            xa, xb = shown(x, ranges_a), shown(y, ranges_b)
        if xa != xb:
            diffs.append(f"call {i} {ix} args {xa} vs {xb}")
            break
        if count and x["xmm"][: count[1]] != y["xmm"][: count[1]]:
            diffs.append(f"call {i} {ix} float args {x['xmm'][:count[1]]} vs {y['xmm'][:count[1]]}")
            break
    if len(a["calls"]) != len(b["calls"]) and not diffs:
        diffs.append(f"{len(a['calls'])} calls vs {len(b['calls'])}")
    # A case that stops on a fault compares its calls and fault address but not its writes, since which
    # stores precede a faulting load depends on instruction scheduling.
    if (a["outcome"] == b["outcome"] == "return" and a["writes"] != b["writes"]
            and normalized_writes(a["writes"], ranges_a) != normalized_writes(b["writes"], ranges_b)):
        diffs.append(f"writes differ ({len(a['writes'])} runs vs {len(b['writes'])})")
    return diffs


def check(harvest, function, versions, cases=400, returns="auto", static=False, arguments=None, out=None):
    """Run every version of FUNCTION (name -> object path) on the same cases and compare each with the first.

    Returns a report with per-version outcomes and, per pair, agreeing and differing case counts and up to
    five differing cases. ARGUMENTS gives the argument kinds (p, i, b, f, d) of a function whose name has no
    mangled parameter list. Run records are kept in OUT when given."""
    [signature] = demangle([function])
    if arguments is None and "(" not in signature:
        raise SystemExit(f"{function} has no mangled parameter list: give its arguments")
    spec = arguments if arguments is not None else argument_spec(signature, member=not static)
    return_kind = harvest.return_kind(signature) if returns == "auto" and "(" in signature else returns
    signatures, pointee, string_arguments = {}, {}, {}
    describe_callees(list(harvest.known), signatures, pointee, string_arguments)
    describe_callees([entry.split("=", 1)[1] for entry in harvest.plt.split(",") if "=" in entry], signatures,
                     pointee, string_arguments)
    follow = harvest.vague_functions | {function}
    for obj in versions.values():
        if str(obj) != IMAGE:
            follow.update(functions(obj))
    follow -= ALLOCATORS
    with tempfile.TemporaryDirectory() as scratch:
        directory = Path(out) if out else Path(scratch)
        directory.mkdir(parents=True, exist_ok=True)
        results, stub_lists, ranges, runners, setups = {}, {}, {}, {}, {}
        for name, obj in versions.items():
            if str(obj) == IMAGE:
                # The executable's own code of the function, run in place: no object, no delinking.
                if function not in harvest.known or not harvest.sizes.get(function):
                    raise SystemExit(f"{function} has no address and size in {harvest.symbols}")
                start, size = harvest.known[function], harvest.sizes[function]
                stubs, ranges[name] = [], []
                plan = execution_plan(harvest, "-", start, function, follow, directory)
                results[name] = cached_image_run(harvest, start, size, spec, cases, plan)
                setups[name] = integer_setups(harvest.image, 0, BASE)
            else:
                elf, entry, slot, stubs, ranges[name] = link(harvest, name, Path(obj), function, directory)
                plan = execution_plan(harvest, elf, entry, function, follow, directory)
                results[name] = execute(harvest, elf, entry, slot, spec, cases, guard_list=guards(elf), plan=plan)
                setups[name] = {**integer_setups(harvest.image, 0, BASE), **integer_setups(elf, BASE, 1 << 64)}
                # The same version with its own data 4 KB further on, for the layout check.
                padded = directory / "padded"
                padded.mkdir(exist_ok=True)
                runners[name] = (padded, Path(obj))
            stub_lists[name] = stubs
            describe_callees(stubs, signatures, pointee, string_arguments)
            if out:
                (directory / f"{name}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in results[name]))

        def differs(a, b, ra, rb, sa=None, sb=None):
            return case_differences(a, b, ra, rb, harvest.names, signatures, pointee, return_kind, sa, sb,
                                    string_arguments)

        reference, *others = list(results)
        # A case in which any version reads past a static table it indexes is undefined: what lies past the
        # table depends on each build's data layout.
        undefined = {i for rs in results.values() for i, r in enumerate(rs) if r["outcome"] == "undefined"}
        differing = {other: [i for i, (a, b) in enumerate(zip(results[reference], results[other]))
                             if i not in undefined and differs(a, b, ranges[reference], ranges[other],
                                                               setups[reference], setups[other])]
                     for other in others}
        # Layout check: a differing case that some version answers differently once its own data moves depends
        # on that layout (an out-of-range index into a static table, a value derived from an address), not on
        # what the code does, and is reported apart from the differences.
        layout_dependent = set()
        suspects = sorted({i for indices in differing.values() for i in indices})
        for name, (padded, obj) in runners.items() if suspects else ():
            elf, entry, slot, _, padded_ranges = link(harvest, name, obj, function, padded, pad=True)
            plan = execution_plan(harvest, elf, entry, function, follow, padded)
            moved = execute(harvest, elf, entry, slot, spec, None, plan=plan, seeds=[i + 1 for i in suspects],
                            guard_list=guards(elf))
            for i, again in zip(suspects, moved):
                if differs(results[name][i], again, ranges[name], padded_ranges):
                    layout_dependent.add(i)
    comparison = {}
    for other in others:
        real = [i for i in differing[other] if i not in layout_dependent]
        examples = [{"seed": results[reference][i]["seed"],
                     "differences": differs(results[reference][i], results[other][i], ranges[reference],
                                            ranges[other], setups[reference], setups[other])} for i in real[:5]]
        comparison[f"{reference} vs {other}"] = {
            "agree": cases - len(differing[other]) - len(undefined), "differ": len(real),
            "layout_dependent": len(differing[other]) - len(real), "undefined": len(undefined), "examples": examples}
    outcomes = {n: {} for n in results}
    for n, rs in results.items():
        for r in rs:
            outcomes[n][r["outcome"]] = outcomes[n].get(r["outcome"], 0) + 1
    # Distinct behaviors per version, by outcome, fault address and the sequence of callees.
    coverage = {n: len({(r["outcome"], r["detail"], tuple(call_identity(c, harvest.names, ranges[n]) for c in r["calls"]))
                        for r in rs}) for n, rs in results.items()}
    return {"function": function, "signature": signature, "argument_spec": spec, "returns": return_kind,
            "cases": cases, "outcomes": outcomes, "distinct_behaviors": coverage, "named_stubs": stub_lists,
            "comparison": comparison}
