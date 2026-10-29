"""Optional first-visit probes for the entry function's basic blocks.

Probes are removed in each forked case after their first hit. Counts describe cases reaching a block,
including cases that later fault or time out. Measurement runs are separate from performance runs.
"""

from collections import Counter

from . import oracle


def basic_blocks(code):
    if not code:
        return []
    addresses = {row[0] for row in code}
    leaders = {code[0][0]}
    for address, length, op, arg in code:
        if op.startswith('j') or op.startswith('ret'):
            if address + length in addresses:
                leaders.add(address + length)
        if op.startswith('j') and not arg.startswith('*'):
            target = int(arg.split()[0], 16)
            if target in addresses:
                leaders.add(target)
    return sorted(leaders)


def add_probes(plan, elf, entry, image=None, size=None):
    path = image if str(elf) == '-' else elf
    if size is None:
        size = next(n for a, n in oracle.functions(path).values() if a == entry)
    blocks = basic_blocks([row for row in oracle.listing(path) if entry <= row[0] < entry + size])
    with plan.open('a') as stream:
        stream.writelines(f'C {address:x}\n' for address in blocks)
    return blocks


def summarize(blocks, records):
    hits = Counter(int(address, 16) for record in records for address in record.get('blocks', ()))
    return dict(cases=len(records), total=len(blocks), reached=len(hits),
                share=len(hits) / len(blocks) if blocks else 0,
                hits={hex(address): hits[address] for address in blocks})
