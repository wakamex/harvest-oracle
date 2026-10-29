"""Static integer comparison provenance for shared generated inputs.

Only copies, fixed stack spills and constant additions preserve a value's origin. Control-flow joins
retain facts only when every incoming path agrees. Memory paths are relative to the entry's integer
arguments; helper-local paths are excluded because their arguments have different meanings.
"""

from . import accesses


def comparisons(code, call_names, memory=True):
    index = {row[0]: i for i, row in enumerate(code)}
    if not code:
        return {}
    bases = {r: (f'arg{i}', 0) for i, r in enumerate(accesses.ARGUMENT_REGISTERS)}
    bases['rsp'] = ('stack', 0)
    states = {code[0][0]: (bases, {}, {}, {})}
    pending = [code[0][0]]
    found = {}

    def register(op):
        return accesses.WIDTHS.get(op.lstrip('%'), (None,))[0] if op.startswith('%') else None

    def merge(old, new):
        if old is None:
            return new
        return tuple({k: v for k, v in a.items() if b.get(k) == v} for a, b in zip(old, new))

    while pending:
        address = pending.pop()
        pointers, stack_pointers, values, stack_values = (dict(x) for x in states[address])
        _, length, op, text = code[index[address]]
        ops = accesses.operands(text.split('<')[0].strip())
        dest = register(ops[-1]) if ops else None

        def origin(operand):
            reg = register(operand)
            if reg:
                return values.get(reg)
            slot = accesses.slot_key(operand, pointers)
            if slot is not None:
                return stack_values.get(slot)
            where = accesses.base_of(operand, pointers, [])
            if memory and where and where[1] is not None and where[0].startswith('arg'):
                size = accesses.access_size(op, ops)
                if size in (1, 2, 4):
                    return ('M', where[0], where[1], size, 0)
            return None

        if memory:
            for operand in ops:
                where = accesses.base_of(operand.lstrip('*'), pointers, [])
                if where and where[0] in {f'arg{i}.0x0' for i in range(6)}:
                    found.setdefault(('P', where[0].split('.')[0]), set()).add(0)
        source = origin(ops[0]) if ops else None
        if op.startswith('cmp') and len(ops) == 2 and ops[0].startswith('$'):
            value = origin(ops[1])
            if value:
                found.setdefault(value[:-1], set()).add((int(ops[0][1:], 0) - value[-1]) & 0xffffffffffffffff)
        elif op.startswith('test') and len(ops) == 2 and ops[0] == ops[1]:
            if source:
                found.setdefault(source[:-1], set()).add((-source[-1]) & 0xffffffffffffffff)

        if op.startswith('mov'):
            if dest:
                if source:
                    values[dest] = source
                else:
                    values.pop(dest, None)
            elif ops:
                slot = accesses.slot_key(ops[-1], pointers)
                if slot is not None:
                    if source:
                        stack_values[slot] = source
                    else:
                        stack_values.pop(slot, None)
        elif op.startswith(('add', 'sub')) and dest and ops[0].startswith('$') and dest in values:
            value = values[dest]
            delta = int(ops[0][1:], 0) * (-1 if op.startswith('sub') else 1)
            values[dest] = (*value[:-1], value[-1] + delta)
        elif op.startswith('call'):
            for r in accesses.CLOBBERED:
                values.pop(r, None)
            name = call_names.get(int(text.split()[0], 16)) if not text.startswith('*') else None
            if name:
                values['rax'] = ('S', name, 0)
        elif dest and not op.startswith(('cmp', 'test', 'push', 'j', 'nop')):
            values.pop(dest, None)

        accesses.step(op, ops, pointers, stack_pointers, [])
        successors = []
        if op.startswith('j') and text and not text.startswith('*'):
            successors.append(int(text.split()[0], 16))
        if not op.startswith(('jmp', 'ret')):
            successors.append(address + length)
        state = (pointers, stack_pointers, values, stack_values)
        for successor in successors:
            if successor in index:
                merged = merge(states.get(successor), state)
                if merged != states.get(successor):
                    states[successor] = merged
                    pending.append(successor)
    return found

