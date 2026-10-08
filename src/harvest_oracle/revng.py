"""Build a version object of one function from rev.ng's C.

rev.ng writes a function whose model prototype is register based (raw) as C whose parameters name registers:
`f(generic64_t register_rcx _REG(rcx_x86_64), ...)`, returning a struct of registers. Compiled as it is, such a
function takes its arguments in the C calling convention's registers instead. This module wraps one function so
it runs and calls out exactly as the native code does:

- an entry under the function's own name takes the native argument registers and passes each to the parameter
  that names it, then returns the result in the native return registers;
- every raw callee becomes an adapter with rev.ng's prototype, which puts each argument back in the register its
  parameter names and calls the harness, which records it as a native call;
- the helpers rev.ng calls for operations C has no operator for get host implementations.

Callees with C prototypes need nothing: their arguments are already in the native registers, and the linker binds
them to the original executable.
"""

import re
import subprocess
import tempfile
import textwrap
from pathlib import Path

GP = {"rdi": 0, "rsi": 1, "rdx": 2, "rcx": 3, "r8": 4, "r9": 5}
PROTOTYPE = re.compile(r"^(?P<ret>[\w ]+?\**) ?(?P<name>\w+)\((?P<params>.*)\);$")
PARAMETER = re.compile(r"^(?P<type>.+?)\s*(?P<name>\w+) _REG\((?P<reg>\w+)_x86_64\)$")
STRUCT_START = re.compile(r"^struct _PACKED _SIZE\(\d+\) (\w+) \{$")
FIELD = re.compile(r"^\s+.*?\b(register_\w+) _STARTS_AT\((\d+)\);$")

# Host implementations of rev.ng helpers. The original code runs on SSE, so host float arithmetic gives its
# results; the env argument of the soft-float helpers carries rounding state the default already matches.
HELPERS = r"""
// QEMU's lshift: left for a non-negative count, arithmetic right for a negative one.
generic64_t lshift(generic64_t a, generic32_t b) {
  int32_t n = (int32_t)b;
  return n >= 0 ? (n >= 64 ? 0 : a << n) : (-n >= 64 ? (generic64_t)((int64_t)a >> 63) : (generic64_t)((int64_t)a >> -n));
}
// QEMU's parity_table: CC_P (4) for an even number of set bits.
generic8_t bit_parity(generic8_t x) { return __builtin_parity((unsigned)(uint8_t)x) ? 0 : 4; }
generic32_t llvm_smin_i32(generic32_t a, generic32_t b) { return (int32_t)a < (int32_t)b ? a : b; }
generic32_t llvm_smax_i32(generic32_t a, generic32_t b) { return (int32_t)a > (int32_t)b ? a : b; }
generic32_t llvm_umin_i32(generic32_t a, generic32_t b) { return a < b ? a : b; }
generic32_t llvm_umax_i32(generic32_t a, generic32_t b) { return a > b ? a : b; }
static inline float oracle_f(generic32_t x) { float f; __builtin_memcpy(&f, &x, 4); return f; }
static inline generic32_t oracle_fb(float f) { generic32_t x; __builtin_memcpy(&x, &f, 4); return x; }
static inline double oracle_d(generic64_t x) { double f; __builtin_memcpy(&f, &x, 8); return f; }
static inline generic64_t oracle_db(double f) { generic64_t x; __builtin_memcpy(&x, &f, 8); return x; }
generic32_t float32_add(generic32_t a, generic32_t b, void *e) { return oracle_fb(oracle_f(a) + oracle_f(b)); }
generic32_t float32_sub(generic32_t a, generic32_t b, void *e) { return oracle_fb(oracle_f(a) - oracle_f(b)); }
generic32_t float32_mul(generic32_t a, generic32_t b, void *e) { return oracle_fb(oracle_f(a) * oracle_f(b)); }
generic32_t float32_div(generic32_t a, generic32_t b, void *e) { return oracle_fb(oracle_f(a) / oracle_f(b)); }
generic64_t float64_add(generic64_t a, generic64_t b, void *e) { return oracle_db(oracle_d(a) + oracle_d(b)); }
generic64_t float64_sub(generic64_t a, generic64_t b, void *e) { return oracle_db(oracle_d(a) - oracle_d(b)); }
generic64_t float64_mul(generic64_t a, generic64_t b, void *e) { return oracle_db(oracle_d(a) * oracle_d(b)); }
generic64_t float64_div(generic64_t a, generic64_t b, void *e) { return oracle_db(oracle_d(a) / oracle_d(b)); }
generic32_t float64_to_float32(generic64_t a, void *e) { return oracle_fb((float)oracle_d(a)); }
generic64_t float32_to_float64(generic32_t a, void *e) { return oracle_db((double)oracle_f(a)); }
generic64_t int32_to_float64(generic32_t a, void *e) { return oracle_db((double)(int32_t)a); }
generic32_t int32_to_float32(generic32_t a, void *e) { return oracle_fb((float)(int32_t)a); }
generic32_t float32_to_int32_round_to_zero(generic32_t a, void *e) {
  float f = oracle_f(a);
  return f != f || f >= 2147483648.0f || f < -2147483648.0f ? 0x80000000u : (generic32_t)(int32_t)f;
}
generic32_t float64_to_int32_round_to_zero(generic64_t a, void *e) {
  double f = oracle_d(a);
  return f != f || f >= 2147483648.0 || f < -2147483648.0 ? 0x80000000u : (generic32_t)(int32_t)f;
}
// QEMU's comparison result: 0 less, 1 equal, 2 greater, 3 unordered.
generic32_t float32_compare_quiet(generic32_t a, generic32_t b, void *e) {
  float x = oracle_f(a), y = oracle_f(b);
  return x != x || y != y ? 3 : x < y ? 0 : x == y ? 1 : 2;
}
generic32_t float32_compare(generic32_t a, generic32_t b, void *e) { return float32_compare_quiet(a, b, e); }
generic32_t float64_compare_quiet(generic64_t a, generic64_t b, void *e) {
  double x = oracle_d(a), y = oracle_d(b);
  return x != x || y != y ? 3 : x < y ? 0 : x == y ? 1 : 2;
}
generic32_t float64_compare(generic64_t a, generic64_t b, void *e) { return float64_compare_quiet(a, b, e); }
generic32_t float32_sqrt(generic32_t a, void *e) { return oracle_fb(__builtin_sqrtf(oracle_f(a))); }
generic8_t float32_lt(generic32_t a, generic32_t b, void *e) { return oracle_f(a) < oracle_f(b); }
generic8_t float32_le(generic32_t a, generic32_t b, void *e) { return oracle_f(a) <= oracle_f(b); }
generic8_t float32_eq(generic32_t a, generic32_t b, void *e) { return oracle_f(a) == oracle_f(b); }
generic8_t float32_unordered(generic32_t a, generic32_t b, void *e) { return oracle_f(a) != oracle_f(a) || oracle_f(b) != oracle_f(b); }
generic8_t float64_lt(generic64_t a, generic64_t b, void *e) { return oracle_d(a) < oracle_d(b); }
generic8_t float64_le(generic64_t a, generic64_t b, void *e) { return oracle_d(a) <= oracle_d(b); }
generic8_t float64_eq(generic64_t a, generic64_t b, void *e) { return oracle_d(a) == oracle_d(b); }
generic8_t float64_unordered(generic64_t a, generic64_t b, void *e) { return oracle_d(a) != oracle_d(a) || oracle_d(b) != oracle_d(b); }
// rev.ng's undefined values read as zero bytes, and its unreachable code traps.
void const *undef_value(size_t size) { static const char zero[64]; return zero; }
void revng_abort(void *message) { __builtin_trap(); }
generic64_t float64_sqrt(generic64_t a, void *e) { return oracle_db(__builtin_sqrt(oracle_d(a))); }
"""

ORACLE_TYPES = r"""
struct oracle_regs { uint64_t gp[6], xmm[8], rax, site; };
struct oracle_result { uint64_t rax, rdx, xmm0, xmm1; };
void (*oracle_native_slot)(uint64_t, struct oracle_regs *, struct oracle_result *);
#define ORACLE_SET(destination, source) do { __typeof__(destination) oracle_value_; \
  __builtin_memset(&oracle_value_, 0, sizeof oracle_value_); \
  uint64_t oracle_source_ = (uint64_t)(source); \
  __builtin_memcpy(&oracle_value_, &oracle_source_, sizeof oracle_value_ < 8 ? sizeof oracle_value_ : 8); \
  destination = oracle_value_; } while (0)
#define ORACLE_LOW(variable) ({ uint64_t oracle_low_ = 0; \
  __builtin_memcpy(&oracle_low_, &(variable), sizeof (variable) < 8 ? sizeof (variable) : 8); oracle_low_; })
"""


def run(command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, text=True, **kwargs).stdout


def functions(plain):
    """Function bodies by entry address, from rev.ng's emit-c output converted with `revng ptml --plain`."""
    text = Path(plain).read_text()
    parts = re.split(r"^/function/(0x[0-9a-f]+):Code_x86_64: \|-\n", text, flags=re.M)
    return {int(parts[i], 16): textwrap.dedent(parts[i + 1]) for i in range(1, len(parts), 2)}


class Header:
    """Prototypes and register structs from rev.ng's types-and-globals.h."""

    def __init__(self, path):
        self.prototypes, self.structs = {}, {}
        current = None
        for line in Path(path).read_text().splitlines():
            m = STRUCT_START.match(line)
            if m:
                current = self.structs.setdefault(m.group(1), [])
                continue
            if current is not None:
                if line.startswith("}"):
                    current = None
                else:
                    f = FIELD.match(line)
                    if f:
                        current.append(f.group(1))
                continue
            if "_REG(" in line:
                p = PROTOTYPE.match(line.strip())
                if p:
                    self.prototypes[p.group("name")] = self.parse(p)

    @staticmethod
    def parse(match):
        params = []
        for raw in split_parameters(match.group("params")):
            m = PARAMETER.match(raw.strip())
            if not m:
                return None
            params.append((m.group("type").strip(), m.group("name"), m.group("reg")))
        return {"ret": match.group("ret").strip(), "params": params}


def split_parameters(text):
    depth, items, current = 0, [], ""
    for ch in text:
        depth += ch in "(<"
        depth -= ch in ")>"
        if ch == "," and depth == 0:
            items.append(current)
            current = ""
        else:
            current += ch
    return items + ([current] if current.strip() else [])


def register_value(register, regs):
    """C expression for the native value of REGISTER held in an oracle_regs named REGS."""
    if register in GP:
        return f"{regs}.gp[{GP[register]}]"
    m = re.fullmatch(r"[xyz]mm(\d+)", register)
    if m and int(m.group(1)) < 8:
        return f"{regs}.xmm[{m.group(1)}]"
    if register == "rax":
        return f"{regs}.rax"
    return "0"


def store_result(variable, prototype, header, result):
    """Statements setting VARIABLE, of the prototype's return type, from an oracle_result named RESULT."""
    ret = prototype["ret"]
    fields = header.structs.get(ret)
    if fields is None:
        return [f"ORACLE_SET({variable}, {result}.rax);"] if ret != "void" else []
    lines = [f"__builtin_memset(&{variable}, 0, sizeof {variable});"]
    sources = {"register_rax": "rax", "register_rdx": "rdx", "register_zmm0": "xmm0", "register_xmm0": "xmm0",
               "register_zmm1": "xmm1", "register_xmm1": "xmm1"}
    for field in fields:
        if field in sources:
            lines.append(f"ORACLE_SET({variable}.{field}, {result}.{sources[field]});")
    return lines


def adapter(name, prototype, header, target):
    """A definition of NAME with rev.ng's prototype that calls the harness as the native call to TARGET would."""
    params = ", ".join(f"{t} {n}" for t, n, _ in prototype["params"]) or "void"
    # Registers the call does not set hold the harness's poison, as after a native call.
    body = ["struct oracle_regs oracle_r_;", "struct oracle_result oracle_o_;",
            "for (int oracle_i_ = 0; oracle_i_ < 6; oracle_i_++) oracle_r_.gp[oracle_i_] = 0x0badc0de0badc0deUL;",
            "for (int oracle_i_ = 0; oracle_i_ < 8; oracle_i_++) oracle_r_.xmm[oracle_i_] = 0x0badc0de0badc0deUL;",
            "oracle_r_.rax = 0; oracle_r_.site = (uint64_t)__builtin_return_address(0);"]
    for _type, param, register in prototype["params"]:
        slot = register_value(register, "oracle_r_")
        if slot != "0":
            body.append(f"{slot} = ORACLE_LOW({param});")
    body.append(f"oracle_native_slot(0x{target:x}UL, &oracle_r_, &oracle_o_);")
    if prototype["ret"] != "void":
        body.append(f"{prototype['ret']} oracle_v_;")
        body += store_result("oracle_v_", prototype, header, "oracle_o_")
        body.append("return oracle_v_;")
    return f"{prototype['ret']} {name}({params}) {{\n  " + "\n  ".join(body) + "\n}\n"


def entry(name, prototype, header):
    """The function's entry under NAME: native registers in, rev.ng's function called with each register in the
    parameter that names it, native return registers out."""
    arguments = []
    setup = []
    for i, (type_, param, register) in enumerate(prototype["params"]):
        setup.append(f"{type_} oracle_a{i}_; ORACLE_SET(oracle_a{i}_, {register_value(register, '(*r)')});")
        arguments.append(f"oracle_a{i}_")
    call = f"oracle_revng_function({', '.join(arguments)})"
    lines = ["struct oracle_result *o = (struct oracle_result *)(r + 1);", *setup]
    ret = prototype["ret"]
    if ret == "void":
        lines.append(f"{call};")
    elif ret in header.structs:
        lines.append(f"{ret} oracle_v_ = {call};")
        fields = header.structs[ret]
        for field, out in (("register_rax", "rax"), ("register_rdx", "rdx"), ("register_zmm0", "xmm0"),
                           ("register_zmm1", "xmm1")):
            if field in fields:
                lines.append(f"o->{out} = ORACLE_LOW(oracle_v_.{field});")
    else:
        lines.append(f"{ret} oracle_v_ = {call};")
        lines.append("o->rax = ORACLE_LOW(oracle_v_);")
    c = "void oracle_entry_c(struct oracle_regs *r) {\n  " + "\n  ".join(lines) + "\n}\n"
    # Native registers to oracle_regs on the stack, followed by the oracle_result the C entry fills.
    asm = f"""__asm__(".globl {name}\\n{name}:\\n"
"  sub $200, %rsp\\n"
"  mov %rdi, 0(%rsp); mov %rsi, 8(%rsp); mov %rdx, 16(%rsp); mov %rcx, 24(%rsp); mov %r8, 32(%rsp); mov %r9, 40(%rsp)\\n"
"  movq %xmm0, 48(%rsp); movq %xmm1, 56(%rsp); movq %xmm2, 64(%rsp); movq %xmm3, 72(%rsp)\\n"
"  movq %xmm4, 80(%rsp); movq %xmm5, 88(%rsp); movq %xmm6, 96(%rsp); movq %xmm7, 104(%rsp); mov %rax, 112(%rsp)\\n"
"  movq $0, 128(%rsp); movq $0, 136(%rsp); movq $0, 144(%rsp); movq $0, 152(%rsp)\\n"
"  mov %rsp, %rdi\\n"
"  call oracle_entry_c\\n"
"  mov 128(%rsp), %rax; mov 136(%rsp), %rdx; movq 144(%rsp), %xmm0; movq 152(%rsp), %xmm1\\n"
"  add $200, %rsp\\n"
"  ret\\n");
"""
    return c + asm


def build(plain, header_path, include, address, function, known, plt, out):
    """Compile rev.ng's C of the function at ADDRESS into OUT/<address>.o, defining FUNCTION (its mangled name).
    KNOWN maps symbol names to addresses and PLT import names to their PLT entries."""
    body = functions(plain).get(address)
    if body is None:
        raise SystemExit(f"rev.ng's C has no function at 0x{address:x}")
    header = Header(header_path)
    declared = re.search(r"\b(\w+)\(", body.split("{", 1)[0].split("\n", 1)[-1])
    revng_name = declared.group(1) if declared else function
    prototype = header.prototypes.get(revng_name)
    preamble = (f'#include "{Path(header_path).name}"\n#include "helpers.h"\n#include <stdint.h>\n'
                + ORACLE_TYPES)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    first = out / f"{address:x}-probe.c"
    first.write_text(preamble + f"#define {revng_name} oracle_revng_function\n" + body + "\n")
    flags = ["-O1", "-fno-pic", "-fno-stack-protector", "-fno-math-errno", "-w", "-c", f"-I{include}",
             f"-I{Path(header_path).parent}"]
    run(["clang", *flags, str(first), "-o", str(out / f"{address:x}-probe.o")])
    undefined = [line.split()[-1] for line in run(["nm", "-u", str(out / f"{address:x}-probe.o")]).splitlines()]
    pieces = [preamble, f"#define {revng_name} oracle_revng_function", body, f"#undef {revng_name}"]
    helpers = HELPERS
    for name in undefined:
        if name in helpers or name.startswith("oracle_"):
            continue
        callee = header.prototypes.get(name)
        if not callee:
            continue  # a C prototype: the linker binds it to the executable or a named stub
        m = re.fullmatch(r"function_0x([0-9a-f]+)_Code_x86_64", name)
        target = int(m.group(1), 16) if m else plt.get(name, known.get(name))
        if target is None:
            raise SystemExit(f"no address for rev.ng callee {name}")
        pieces.append(adapter(name, callee, header, target))
    if prototype:
        pieces.append(entry(function, prototype, header))
    else:
        pieces.append(f"__asm__(\".globl {function}\\n.set {function}, oracle_revng_function\\n\");")
    pieces.append(helpers)
    source = out / f"{address:x}.c"
    source.write_text("\n".join(pieces) + "\n")
    function_object = out / f"{address:x}-function.o"
    run(["clang", *flags, str(source), "-o", str(function_object)])
    # Copies the compiler emits for struct assignments go to the shim, unless the program's own import of that
    # name is defined here as an adapter.
    still = set(run(["nm", "-u", str(function_object)]).split()) - {"U"}
    renames = [arg for name in ("memcpy", "memmove", "memset") if name in still
               for arg in ("--redefine-sym", f"{name}=oracle_{name}")]
    if renames:
        run(["objcopy", *renames, str(function_object)])
    obj = out / f"{address:x}.o"
    run(["ld", "-r", "-o", str(obj), str(function_object), str(runtime(include, out))])
    return obj


def runtime(include, out):
    """rev.ng's wide-integer runtime with its C library calls renamed to the shim's oracle_* stand-ins."""
    here = Path(__file__).resolve().parent
    library, shim = out / "runtime-library.o", out / "runtime-shim.o"
    flags = ["-O1", "-fno-pic", "-fno-stack-protector", "-w", "-c", f"-I{include}"]
    run(["clang", *flags, str(here / "revng_runtime_library.c"), "-o", str(library)])
    renames = []
    for symbol in run(["nm", "-u", str(library)]).split():
        if symbol != "U":
            renames += ["--redefine-sym", f"{symbol}=oracle_{symbol}"]
    run(["objcopy", *renames, str(library)])
    run(["clang", *flags, "-ffreestanding", "-fno-builtin", str(here / "revng_shim.c"), "-o", str(shim)])
    combined = out / "runtime.o"
    run(["ld", "-r", "-o", str(combined), str(library), str(shim)])
    return combined
