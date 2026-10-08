# harvest-oracle

harvest-oracle checks whether two builds of one function from the [Harvest decompilation](https://github.com/banteg/harvest) behave the same. It runs each version of the function's machine code on the same generated inputs and compares what it returns, which functions it calls and with what arguments, and every byte it writes. A source rewrite that is meant to change only code generation, such as one that brings a function closer to the original executable's bytes, should agree with the code it replaced in every case.

## How a case runs

Each version is an object file that defines the function: a build of Harvest's source, the target object delinked from the original executable, or an object compiled from a decompiler's C. It is linked alone at 0x20000000, with every other symbol bound to its address in the original executable (`config/<build>/symbols.tsv`).

The harness maps the original executable's segments at their addresses, with its code not executable, then calls the function with argument registers generated from the case seed. Memory the function reaches through generated pointers is mapped on first touch, with bytes that depend only on the seed and the address, so every version reads the same memory whatever order it reads it in. Pointers carry float bit patterns in their low 32 bits, NaN and the infinities included, so float fields read from memory see special values.

A call into the executable's code or into generated memory faults and is recorded with its argument registers as a call out of the function, then returns a generated value; so does a call to a named stub, which stands in for a callee without a known address. Allocators return fresh memory, and math library functions such as `sin` and `sqrt` run for real without being recorded, since a compiler may reorder or combine them. Each case runs in a forked child.

## What is compared

For each case:

- the outcome (return, fault or timeout) and the fault address
- the return value, by the function's return type, read from its declaration under `src/`
- the ordered calls out of the function with their arguments, up to the callee's parameter count from its mangled name
- every 8-byte word written to generated memory or to the executable's globals, for cases that return

Calls without a known signature, such as virtual calls, compare two integer and four float argument registers. An argument that points into the stack, into the version's own data or into the executable's read-only data is compared by the bytes it points at, up to the size of its parameter type. A pointer into a version's own copy of executable data (a section named after a symbol of the executable, such as `.rodata._ZTV...`) is translated to the executable's address before comparing. Writes are not compared for cases that fault, since which stores precede a faulting load depends on instruction scheduling.

Delinked target objects need two more bindings, both by the label's name: `lbl_<address>` is bound to that address in the executable, and `sub_<address>` inside the function under test to the same offset in the linked copy.

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
{"symbol": "...", "unit": null, "verdict": "agree", "cases": 400, "agree": 400, "differ": 0, "returns": "bool", "distinct_behaviors": 46, "first_difference": null}
```

Compare any number of versions of a function, the first being the reference, and keep the per-case records:

```
harvest-oracle compare SYMBOL master=A.o branch=B.o target=T.o --keep runs/
harvest-oracle explain runs/ master target SEED
```

Check every function of a table of address, return type, unit and symbol (the built-in table holds a set of rewritten functions) against directories of unit objects:

```
harvest-oracle batch master=DIR_A branch=DIR_B target=build/objdiff/1.18-linux-amd64/target
```

`--cases` sets the number of generated cases (default 400), `--returns` overrides the return type, `--static` marks a function without a `this` pointer, and `--arguments` gives the argument kinds of a function without a mangled parameter list.

## Limitations

Generated memory has no types, so many cases fault after a few pointer hops; a faulting case still compares the calls before the fault and the fault address, but code deep in a function is exercised less often than code near its start. Arguments of calls without a known signature are compared on a fixed set of registers, and a register a callee ignores can hold a leftover value that differs between versions. A version's own data that is not named after a symbol of the executable, such as merged string literals, is compared by content only when a pointer to it is passed as an argument.

## Development

```
uv run --locked python -m unittest discover -s tests -v
```

The tests build a small fixed-address executable and three compiles of one function: two that must agree and one with a comparison that differs only on NaN, which must be caught.

## License

MIT
