# harvest-oracle

harvest-oracle checks whether two builds of one function from the [Harvest decompilation](https://github.com/banteg/harvest) behave the same. It runs each version of the function's machine code on the same generated inputs and compares what it returns, which functions it calls and with what arguments, and every byte it writes. A source rewrite that is meant to change only code generation, such as one that brings a function closer to the original executable's bytes, should agree with the code it replaced in every case.

## How a case runs

Each version is an object file that defines the function, such as a build of Harvest's source or an object compiled from a decompiler's C, or `image`, the original executable's own code of the function. An object is linked alone at 0x20000000, retaining its text definitions and binding other known symbols to the original executable (`config/<build>/symbols.tsv`). Direct calls follow functions whose bodies the [GNU Compiler Collection (GCC)](https://gcc.gnu.org/) could have inlined: every text definition in the tested unit, including local functions, and every weak text symbol across `build/match/<build>/**/*.o`. The build-wide weak-symbol index is cached by object paths, sizes and modification times. Build these objects first to give the oracle the complete inline and template set.

All versions share the union of these names. Following continues transitively through direct calls and tail jumps within that fixed set; it does not add another unit's strong definitions. An object version uses its own definition whenever available, even for a call from an executable fallback body, and otherwise uses the executable's address and recorded size. A missing executable address or size leaves a boundary. `image` uses the executable's bodies throughout. Only reachable executable bodies become runnable: their bytes are restored into pages whose other `.text` bytes contain `int3`. References to executable data keep their original addresses. Transfers needing redirection and indirect transfers are trapped at their instruction, so indirect calls and external indirect tail jumps stay recorded even when their destination is runnable. An indirect jump within its own function still executes, allowing switch tables.

The harness maps the original executable's segments at their addresses, with its code not executable, then calls the function with argument registers generated from the case seed. Memory the function reaches through generated pointers is mapped on first touch, with bytes that depend only on the seed and the address, so every version reads the same memory whatever order it reads it in. Pointers carry float bit patterns in their low 32 bits, not-a-number (NaN) and the infinities included, so float fields read from memory see special values. Half the cases fill memory with pointers and zero, a quarter mix pointers with words whose two halves are NaN-heavy floats, and a quarter use a broader mix of small integers, floats and arbitrary words.

A call outside the follow set, an indirect call, or a call into generated memory is recorded with its argument registers and returns a generated value. A named stub stands in for a callee without a known address. Calls through the executable's procedure linkage table (PLT) stay import boundaries. Allocators remain boundaries even if the unit defines them. Allocators return fresh memory, and math library functions such as `sin` and `sqrt` run for real without being recorded, since a compiler may reorder or combine them. After every recorded call the argument registers a callee may clobber hold a fixed poison value, as do unused argument registers at entry, so a register still holding it at the next call was not set for that call. Stub handling runs on a stack of its own, so nothing of the harness is left where the function might read it. Each case runs in a forked child with one shared two-second alarm. Followed bodies use the same generated memory, stack and call budget as the entry function. Recursion executes normally; faults, stack exhaustion and the alarm end the whole case. A slow or faulting helper is never replaced by a generated return.

## What is compared

For each case:

- the outcome (return, fault or timeout) and the page of a fault address
- the return value, by the function's return type, read from its declaration under `src/`
- the ordered boundary calls from the function and its followed callees with their arguments, up to the callee's known parameter count from its mangled name or C API signature
- every 8-byte word written to generated memory or to the executable's globals, for cases that return

Followed calls themselves add no trace event and consume no generated return value. Their boundary calls and writes are compared as though their bodies had been inlined. Stack writes remain uncompared. Known code pointers in an object are translated to their executable addresses, including indirect-call targets. Known string parameters of the [Lua 5.1 C API](https://www.lua.org/manual/5.1/manual.html) and the [GNU C Library (glibc)](https://www.gnu.org/software/libc/) string functions use their parameter rules: counted strings compare their declared length, and zero-terminated strings compare through the terminator.

Calls without a known signature, such as virtual calls, compare `rdi`, `rsi` and `xmm0` to `xmm3`, skipping any register that still holds the poison in either version. An argument that points into the stack, into the version's own data or into the executable's read-only data is compared by the bytes it points at, up to the size of its parameter type. A known code pointer compares by its executable address. A pointer into a version's own copy of executable data (a section named after a symbol of the executable, such as `.rodata._ZTV...`) is translated to the executable's address before comparing. Writes are not compared for cases that fault, since which stores precede a faulting load depends on instruction scheduling.

An indexed read in the object, including a followed helper, is guarded when its displacement or a short register and stack address sequence identifies a version's own sized read-only data symbol, such as a static table. The harness computes the read address, and an address outside that symbol's extent ends the case as undefined. Such a case is left out of the comparison, since what lies past a static table depends on each build's data layout. In-bounds reads run unchanged. Writes, non-indexed loads from a fixed symbol address, and accesses without a read-only symbol base are not guarded.

A case that differs is run again with each linked version's own data placed 4 KB further on. If a version then disagrees with itself, the case depends on that version's data layout, for example an out-of-range index into a static table or a value derived from an address, and it is reported as layout-dependent instead of as a difference.

Delinked target objects can also be checked as objects. They need two more bindings, both by the label's name: `lbl_<address>` is bound to that address in the executable, and `sub_<address>` inside the function under test to the same offset in the linked copy. Prefer `image` for the original code: a delinked object can resolve a reference to the wrong data, such as a wide string literal to a narrow one in a merged string section, which the linker then shortens.

## Installation

Requires Linux on x86-64, gcc, binutils (`as`, `ld`, `nm`, `readelf`), `c++filt` and [uv](https://docs.astral.sh/uv/).

```
uv tool install git+https://github.com/wakamex/harvest-oracle
```

## Usage

Run from a Harvest checkout, or pass `--harvest PATH`. The checkout must hold the original executable under `orig/<build>/` and `config/<build>/symbols.tsv`.

Check two objects' versions of one function; one JSON line, exit status 0 when they agree and 1 when they differ:

```
harvest-oracle check build/master/X.o build/match/1.18-linux-amd64/X.o --symbol _ZN5daisy14CIrrDeviceStub29getAcceptsDragAndDropFileTypeEPKc
{"symbol": "...", "unit": null, "verdict": "agree", "cases": 5000, "agree": 5000, "differ": 0, "layout_dependent": 0, "undefined": 0, "returns": "bool", "distinct_behaviors": 341, "first_difference": null}
```

Compare any number of versions of a function, the first being the reference, and keep the per-case records:

```
harvest-oracle compare SYMBOL master=A.o branch=B.o original=image --keep runs/
harvest-oracle explain runs/ master target SEED
```

Check every function of a table of address, return type, unit and symbol (the built-in table holds a set of rewritten functions) against directories of unit objects:

```
harvest-oracle batch master=DIR_A branch=DIR_B original=image
```

`--cases` sets the number of generated cases (default 5000; a comparison changed to differ only on NaN, deep in a function, can differ in as few as 1 case in 500), `--returns` overrides the return type, `--static` marks a function without a `this` pointer, and `--arguments` gives the argument kinds of a function without a mangled parameter list.

## Memory accesses by base

`harvest-oracle accesses SYMBOL...` lists, for each function of the original executable, every memory access with its base, offset, size, direction and instruction, as JSON keyed by entry address:

```
{"0x4be1f0": {"symbol": "...", "signature": "...", "accesses": [
  {"instruction": "0x4be287", "base": "this", "offset": "0xe0", "size": 8, "access": "read"},
  {"instruction": "0x4be2a1", "base": "this.0xe0", "offset": "0x20", "size": 8, "access": "read"}, ...]}}
```

A forward dataflow over the function's code tracks which base each register holds: at entry `this` and the arguments in their argument registers, numbered by source parameter (a float parameter takes no integer register), then through register copies, `lea` and constant offsets, spills to and reloads from stack slots, and loads of pointer fields, so an access through a pointer loaded from `this+0xe0` has base `this.0xe0`. Globals are named by the `symbols.tsv` symbol containing the address. With `--object OBJECT`, the same analysis runs on the object's code of each function, linked alone with every other symbol bound to the executable as for `check`, so its list can be compared with the executable's access by access, under the same keys and base names. A call clobbers the caller-saved registers, and where paths join with different bases a register holds none; accesses relative to the stack are left out.

## rev.ng's C as a version

`harvest-oracle revng-object` builds a version object from [rev.ng](https://rev.ng)'s C of one function. rev.ng writes a function with a register-based prototype as C whose parameters name registers (`_REG(rcx_x86_64)`), so the object wraps it: an entry under the function's mangled name passes each native argument register to the parameter that names it, every callee with such a prototype becomes an adapter that puts its arguments back in their registers before the call is recorded, and rev.ng's helpers and wide-integer runtime are linked in. Segments and globals bind to the executable.

Two limits apply. A call through a function pointer with a register-based prototype, such as most virtual calls, still passes its arguments in the C calling convention's registers. And rev.ng's C drops the `fs` segment base, so the stack-protector load `%fs:0x28` reads address 0x28 and any function with a canary faults.

## Limitations

Generated memory has no types, so many cases fault after a few pointer hops; a faulting case still compares the calls before the fault and the fault address, but code deep in a function is exercised less often than code near its start. Arguments of calls without a known signature are compared on a fixed set of registers, and a register a callee ignores can hold a leftover value that differs between versions. A version's own data that is not named after a symbol of the executable, such as merged string literals, is compared by content only when a pointer to it is passed as an argument. Call traces currently capture at most 32 bytes behind a pointer, so a longer string is only compared within that captured prefix.

The indexed-data guard follows a base through RIP-relative `lea`, register copies, constant offsets, dynamic index arithmetic, and simple fixed stack spill slots. It does not track arbitrary memory copies or merge conflicting bases at control-flow joins. Bounds use the full symbol extent rather than nested array dimensions, and only sized read-only symbols qualify. Calls with unknown signatures keep the existing register heuristic; known C string parameters use their length or zero terminator within the 32-byte trace capture. The [validation report](evidence/REPORT.md) records cases exposing these limits.

## Development

```
uv run --locked python -m unittest discover -s tests -v
```

The tests build fixed-address executables and compare equivalent compiles, inline and out-of-line helpers, same-unit and executable fallback bodies, indirect boundaries, recursion, and a comparison that differs only on NaN. A changed write inside a followed helper must still be caught.

## License

MIT
