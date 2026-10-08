"""Show how two versions of a kept run differ on one case: the calls side by side and the differing writes."""

import json
from pathlib import Path


def case(directory, version, seed):
    for line in (Path(directory) / f"{version}.jsonl").open():
        record = json.loads(line)
        if record["seed"] == seed:
            return record
    raise SystemExit(f"no seed {seed} in {version}")


def show(directory, a_name, b_name, seed):
    a, b = case(directory, a_name, seed), case(directory, b_name, seed)
    for key in ("outcome", "detail", "rax", "xmm0"):
        print(f"{key}: {a.get(key)} | {b.get(key)}")
    for i in range(max(len(a["calls"]), len(b["calls"]))):
        x = a["calls"][i] if i < len(a["calls"]) else None
        y = b["calls"][i] if i < len(b["calls"]) else None
        mark = " " if x and y and x["to"] == y["to"] and x["gp"][:3] == y["gp"][:3] else "*"
        text = [f"{c['to']} {' '.join(c['gp'][:3])}" if c else "-" for c in (x, y)]
        print(f"{mark} {i:3} {text[0]:70} | {text[1]}")
    wa, wb = dict(map(tuple, a["writes"])), dict(map(tuple, b["writes"]))
    for address in sorted(set(wa) | set(wb), key=lambda s: int(s, 16)):
        if wa.get(address) != wb.get(address):
            print(f"write {address}: {wa.get(address)} | {wb.get(address)}")
    return 0
