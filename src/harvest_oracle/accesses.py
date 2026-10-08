"""The memory accesses of one function, by base: which argument, global or stack slot each one is relative to.

Reads the function's machine code (the original executable's by default) and runs a forward dataflow over it.
At entry the integer argument registers hold `this` (for a member function) and the arguments; the analysis
follows register copies, `lea` and constant offsets, spills to and reloads from stack slots, and loads of pointer
fields, so an access through a pointer loaded from `this` is reported against that field (`this.0x18`). A call
clobbers the caller-saved registers. Where control flow joins with different bases for a register, it holds none.
"""

import re
import subprocess

ARGUMENT_REGISTERS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
CLOBBERED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
WIDTHS = {}
for full, names in {"rax": ("eax", "ax", "al"), "rbx": ("ebx", "bx", "bl"), "rcx": ("ecx", "cx", "cl"),
                    "rdx": ("edx", "dx", "dl"), "rsi": ("esi", "si", "sil"), "rdi": ("edi", "di", "dil"),
                    "rbp": ("ebp", "bp", "bpl"), "rsp": ("esp", "sp", "spl")}.items():
    WIDTHS[full] = (full, 8)
    for name, width in zip(names, (4, 2, 1)):
        WIDTHS[name] = (full, width)
for n in range(8, 16):
    WIDTHS[f"r{n}"] = (f"r{n}", 8)
    for suffix, width in (("d", 4), ("w", 2), ("b", 1)):
        WIDTHS[f"r{n}{suffix}"] = (f"r{n}", width)
SUFFIX_SIZES = {"b": 1, "w": 2, "l": 4, "q": 8}
MEMORY = re.compile(r"(-?0x[0-9a-f]+|-?\d+)?\(%(\w+)(?:,%(\w+),(\d))?\)")
NO_ACCESS = ("lea", "nop", "prefetch")
# Instructions that read their last operand without writing it.
READ_ONLY = ("cmp", "test", "ucomis", "comis", "bt", "push", "j")


def run(command):
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def instructions(path, start, end):
    listing = run(["objdump", "-d", "--no-show-raw-insn", "-M", "suffix", f"--start-address=0x{start:x}",
                   f"--stop-address=0x{end:x}", str(path)])
    result = []
    for line in listing.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+(\S+)\s*(.*)", line)
        if m:
            # objdump resolves a RIP-relative operand in a trailing comment: "# 86bf34 <name>".
            rip = re.search(r"#\s*([0-9a-f]+)", m.group(3))
            text = m.group(3).split("#")[0].split("<")[0].strip()
            if rip and "(%rip)" in text:
                text = re.sub(r"-?(0x[0-9a-f]+)?\(%rip\)", f"0x{rip.group(1)}", text)
            result.append((int(m.group(1), 16), m.group(2), text))
    return result


def operands(text):
    items, depth, current = [], 0, ""
    for ch in text:
        depth += ch == "("
        depth -= ch == ")"
        if ch == "," and depth == 0:
            items.append(current.strip())
            current = ""
        else:
            current += ch
    return items + ([current.strip()] if current.strip() else [])


def displacement(text):
    return int(text, 16) if text and "x" in text else int(text or 0)


def access_size(mnemonic, ops):
    # Extending loads (movzbl, movswq, ...) read the size their second letter names.
    m = re.match(r"mov[sz]([bwl])[wlq]$", mnemonic)
    if m:
        return SUFFIX_SIZES[m.group(1)]
    for op in ops:
        if op.startswith("%") and op[1:] in WIDTHS:
            return WIDTHS[op[1:]][1]
        if op.startswith("%xmm"):
            return 16 if mnemonic.startswith(("movdq", "movap", "movup")) else 8 if "sd" in mnemonic or mnemonic.startswith("movq") else 4
    suffix = mnemonic[-1]
    return SUFFIX_SIZES.get(suffix, 8)


def analyze(path, start, end, arguments, symbols):
    """Accesses of the function in [START, END) of PATH: ARGUMENTS names the entry's integer argument registers
    in order (`this`, `argument 1`, ...); SYMBOLS is a sorted list of (start, end, name) of the executable's
    globals."""
    code = instructions(path, start, end)
    index = {address: i for i, (address, _, _) in enumerate(code)}
    successors = {}
    for i, (address, mnemonic, text) in enumerate(code):
        targets = []
        jump = re.match(r"([0-9a-f]+)$", text.split()[0]) if text else None
        if mnemonic.startswith("j") and jump:
            targets.append(int(jump.group(1), 16))
        if not (mnemonic.startswith("jmp") or mnemonic.startswith("ret")) and i + 1 < len(code):
            targets.append(code[i + 1][0])
        successors[address] = [t for t in targets if t in index]

    entry = {name: (label, 0) for name, label in zip(ARGUMENT_REGISTERS, arguments)}
    entry["rsp"] = ("stack", 0)
    states = {code[0][0]: (entry, {})} if code else {}
    worklist = [code[0][0]] if code else []
    accesses = {}
    while worklist:
        address = worklist.pop()
        registers, slots = states[address]
        registers, slots = dict(registers), dict(slots)
        _, mnemonic, text = code[index[address]]
        ops = operands(text)
        record = step(mnemonic, ops, registers, slots, symbols)
        if record:
            accesses[address] = record
        for successor in successors[address]:
            merged = merge(states.get(successor), (registers, slots))
            if merged != states.get(successor):
                states[successor] = merged
                worklist.append(successor)
    return [dict(instruction=f"0x{a:x}", **accesses[a]) for a in sorted(accesses)]


def merge(old, new):
    if old is None:
        return new
    registers = {k: v for k, v in old[0].items() if new[0].get(k) == v}
    slots = {k: v for k, v in old[1].items() if new[1].get(k) == v}
    return registers, slots


def base_of(text, registers, symbols):
    """The (base, offset) a memory operand addresses, or None."""
    m = MEMORY.search(text)
    if not m:
        absolute = re.fullmatch(r"(0x[0-9a-f]+)", text)
        return containing(int(absolute.group(1), 16), symbols) if absolute else None
    disp, base, index = displacement(m.group(1)), m.group(2), m.group(3)
    if base == "rip":
        return None
    held = registers.get(WIDTHS.get(base, (base,))[0])
    if held is None or index:
        return (held[0], None) if held and index else None
    return held[0], held[1] + disp


def step(mnemonic, ops, registers, slots, symbols):
    """Apply one instruction to the register and stack-slot bases; return its access, if any."""
    destination = ops[-1] if ops else ""
    # An indirect call or jump through memory (`call *0x150(%rax)`) reads its target there; a direct one has none.
    memory = [op.lstrip("*") for op in ops if op.startswith("*") and is_memory(op.lstrip("*"))]
    if not mnemonic.startswith(("call", "j")):
        memory = [op for op in ops if is_memory(op)]
    record = None
    if memory and not mnemonic.startswith(NO_ACCESS):
        where = base_of(memory[0], registers, symbols)
        if where and where[0] != "stack":
            writes = memory[0] == destination and not mnemonic.startswith(("cmp", "test", "ucomis", "comis", "bt"))
            record = {"base": where[0], "offset": None if where[1] is None else f"0x{where[1]:x}" if where[1] >= 0
                      else f"-0x{-where[1]:x}", "size": 8 if mnemonic.startswith(("call", "j")) else access_size(mnemonic, ops),
                      "access": "write" if writes else "read"}
    if mnemonic.startswith("call"):
        for r in CLOBBERED:
            registers.pop(r, None)
        return record
    target = WIDTHS.get(destination.lstrip("%"), (None,))[0] if destination.startswith("%") else None
    if mnemonic.startswith(READ_ONLY):
        target = None
    if mnemonic.startswith("mov") and len(ops) == 2 and target:
        source = ops[0]
        if source.startswith("%") and source[1:] in WIDTHS and WIDTHS[source[1:]][1] == 8:
            held = registers.get(WIDTHS[source[1:]][0])
            registers[target] = held if held else None
        elif is_memory(source):
            where = base_of(source, registers, symbols)
            slot = slot_key(source, registers)
            if slot is not None and slot in slots:
                registers[target] = slots[slot]
            elif where and where[1] is not None and where[0] != "stack" and access_size(mnemonic, ops) == 8:
                registers[target] = (f"{where[0]}.0x{where[1]:x}" if where[1] >= 0 else f"{where[0]}.-0x{-where[1]:x}", 0)
            else:
                registers[target] = None
        else:
            registers[target] = None
    elif mnemonic.startswith("mov") and len(ops) == 2 and is_memory(destination):
        slot = slot_key(destination, registers)
        if slot is not None:
            source = ops[0]
            slots[slot] = registers.get(WIDTHS[source[1:]][0]) if source[1:] in WIDTHS else None
    elif mnemonic.startswith("lea") and target:
        where = base_of(ops[0], registers, symbols)
        registers[target] = (where[0], where[1]) if where and where[1] is not None else None
    elif mnemonic.startswith(("add", "sub")) and target and ops[0].startswith("$"):
        held = registers.get(target)
        if held and held[1] is not None:
            value = int(ops[0][1:], 16) if "x" in ops[0] else int(ops[0][1:])
            registers[target] = (held[0], held[1] + (value if mnemonic.startswith("add") else -value))
        if target == "rsp":
            pass
    elif target:
        registers[target] = None
    return record


def is_memory(op):
    """In AT&T syntax a memory operand has parentheses or is a bare absolute address."""
    return "(" in op or re.fullmatch(r"0x[0-9a-f]+", op) is not None


def containing(address, symbols):
    """(global name, offset) of the sized symbol holding ADDRESS; SYMBOLS is a sorted list of (start, end, name)."""
    for start, end, name in symbols:
        if start <= address < max(end, start + 1):
            return name, address - start
        if start > address:
            break
    return None


def slot_key(text, registers):
    m = MEMORY.search(text)
    if not m or m.group(3):
        return None
    held = registers.get(WIDTHS.get(m.group(2), (m.group(2),))[0])
    if held and held[0] == "stack" and held[1] is not None:
        return held[1] + displacement(m.group(1))
    return None
