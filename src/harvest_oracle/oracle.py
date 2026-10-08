"""Differential check of one Harvest function across versions of its machine code.

A version is a relocatable object that defines the function: a build of Harvest's source, the target object
delinked from the original executable, or an object compiled from a decompiler's C. Each is linked alone at
0x20000000 with every other symbol bound to its address in the original executable (symbols.tsv); callees
without a known address become named stubs. The harness runs every version on the same generated cases,
and the cases are compared: outcome, return value, the ordered calls out of the function with their
arguments, and every word written to generated memory or the executable's globals.
"""

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

# Integer argument counts of C library callees, which have no mangled signature.
C_ARGUMENTS = {"wcscmp": 2, "strcmp": 2, "strlen": 1, "wcslen": 1, "memcpy": 3, "memmove": 3, "memset": 3,
               "malloc": 1, "free": 1, "calloc": 2, "realloc": 2, "_Unwind_Resume": 1, "__cxa_begin_catch": 1,
               "__cxa_end_catch": 0, "__cxa_rethrow": 0, "__cxa_atexit": 3, "__cxa_pure_virtual": 0}


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


def describe_callees(callees, signatures, pointee):
    """Argument register counts (integer, float) and pointee sizes of callees, from their mangled names."""
    for name, demangled in zip(callees, demangle(callees)):
        if name in C_ARGUMENTS:
            signatures[name] = (C_ARGUMENTS[name], 0)
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


def link(harvest, name, obj, function, out):
    """Link OBJ alone so that FUNCTION is its only code that runs.

    Returns the linked executable, the function's address in it, the address of the named stubs' thunk slot,
    the named stubs and the ranges of the version's own copies of executable data."""
    known = harvest.known
    defined, undefined = set(), set()
    for line in run(["nm", str(obj)]).splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "U":
            undefined.add(parts[1])
        elif len(parts) == 3 and parts[1] in "TWVDBRGS" and parts[1].isupper():
            defined.add(parts[2])
    if function not in defined:
        raise SystemExit(f"{obj} does not define {function}")

    def inside(address):
        return function in known and known[function] <= address < known[function] + harvest.sizes.get(function, 0)

    defsyms, stubs, blobs = [], [], []
    for symbol in sorted((defined | undefined) - {function}):
        if symbol in known:
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
    run(["ld", "-static", "-nostdlib", "-z", "noexecstack", f"-Ttext-segment=0x{BASE:x}", "-e", function, *defsyms,
         "-Map", str(linker_map), str(obj), str(out / f"{name}-stubs.o"), "-o", str(elf)])
    addresses = {}
    for line in run(["nm", str(elf)]).splitlines():
        parts = line.split()
        if len(parts) == 3:
            addresses[parts[2]] = int(parts[0], 16)
    return elf, addresses[function], addresses["oracle_thunk_slot"], stubs, translations(linker_map, known)


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


def text_section(image):
    """The executable's .text section as (start, end)."""
    for line in run(["readelf", "-SW", str(image)]).splitlines():
        m = re.search(r"\]\s+\.text\s+PROGBITS\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)", line)
        if m:
            return int(m.group(1), 16), int(m.group(1), 16) + int(m.group(2), 16)
    raise SystemExit(f"{image} has no .text section")


def execute(harvest, elf, entry, slot, spec, cases, own=None):
    """Run the harness. ELF is a linked version, or "-" with OWN = (start, size) to run the executable's own
    code of the function in place."""
    env = {"ORACLE_THUNK_SLOT": f"0x{slot:x}"} if slot else {}
    env["ORACLE_PLT"] = harvest.plt
    if own:
        text = text_section(harvest.image)
        env.update(ORACLE_IMAGE_FUNCTION=f"0x{own[0]:x}:{own[1]}", ORACLE_TEXT=f"0x{text[0]:x}:0x{text[1]:x}")
    output = subprocess.run([str(harness_binary()), str(harvest.image), str(elf), f"0x{entry:x}", spec, "1",
                             str(cases)], check=True, capture_output=True, text=True, env=env).stdout
    return [json.loads(line) for line in output.splitlines()]


def call_identity(call, names):
    target = call["to"]
    if "@" in target:
        return target.split("@")[0]
    return names.get(int(target, 16), target)


def case_differences(a, b, ranges_a, ranges_b, names, signatures, pointee, return_kind):
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
        ix, iy = call_identity(x, names), call_identity(y, names)
        if ix != iy:
            diffs.append(f"call {i}: {ix} vs {iy}")
            break
        count = signatures.get(ix)
        if count:
            gp_indices = range(count[0])
        else:
            # Without a signature, such as a virtual call, compare the registers both versions set for it.
            gp_indices = [k for k in range(UNKNOWN_GP) if POISON not in (x["gp"][k], y["gp"][k])]
            xmm_indices = [k for k in range(UNKNOWN_XMM) if POISON not in (x["xmm"][k], y["xmm"][k])]
            fa, fb = [x["xmm"][k] for k in xmm_indices], [y["xmm"][k] for k in xmm_indices]
            if fa != fb:
                diffs.append(f"call {i} {ix} float registers {fa} vs {fb}")
                break
        sizes = pointee.get(ix, [])

        def shown(call, ranges):
            # The bytes behind a local are translated too: a local object's vtable pointer, say.
            return [d and "local:" + normalized_writes([["0x0", d]], ranges)[0][1][: 2 * (sizes[k] if k < len(sizes) else 8)]
                    or hex(translate(int(v, 16), ranges))
                    for k, v, d in ((k, call["gp"][k], call["deref"][k]) for k in gp_indices)]

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
    signatures, pointee = {}, {}
    describe_callees(list(harvest.known), signatures, pointee)
    with tempfile.TemporaryDirectory() as scratch:
        directory = Path(out) if out else Path(scratch)
        directory.mkdir(parents=True, exist_ok=True)
        results, stub_lists, ranges = {}, {}, {}
        for name, obj in versions.items():
            if str(obj) == IMAGE:
                # The executable's own code of the function, run in place: no object, no delinking.
                if function not in harvest.known or not harvest.sizes.get(function):
                    raise SystemExit(f"{function} has no address and size in {harvest.symbols}")
                start, size = harvest.known[function], harvest.sizes[function]
                stubs, ranges[name] = [], []
                results[name] = execute(harvest, "-", start, None, spec, cases, own=(start, size))
            else:
                elf, entry, slot, stubs, ranges[name] = link(harvest, name, Path(obj), function, directory)
                results[name] = execute(harvest, elf, entry, slot, spec, cases)
            stub_lists[name] = stubs
            describe_callees(stubs, signatures, pointee)
            if out:
                (directory / f"{name}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in results[name]))
    reference, *others = list(results)
    comparison = {}
    for other in others:
        agree, examples = 0, []
        for a, b in zip(results[reference], results[other]):
            diffs = case_differences(a, b, ranges[reference], ranges[other], harvest.names, signatures, pointee,
                                     return_kind)
            if diffs:
                if len(examples) < 5:
                    examples.append({"seed": a["seed"], "differences": diffs})
            else:
                agree += 1
        comparison[f"{reference} vs {other}"] = {"agree": agree, "differ": cases - agree, "examples": examples}
    outcomes = {n: {} for n in results}
    for n, rs in results.items():
        for r in rs:
            outcomes[n][r["outcome"]] = outcomes[n].get(r["outcome"], 0) + 1
    # Distinct behaviors per version, by outcome, fault address and the sequence of callees.
    coverage = {n: len({(r["outcome"], r["detail"], tuple(call_identity(c, harvest.names) for c in r["calls"]))
                        for r in rs}) for n, rs in results.items()}
    return {"function": function, "signature": signature, "argument_spec": spec, "returns": return_kind,
            "cases": cases, "outcomes": outcomes, "distinct_behaviors": coverage, "named_stubs": stub_lists,
            "comparison": comparison}
