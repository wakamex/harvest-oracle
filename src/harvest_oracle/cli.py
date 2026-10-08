"""Command line for differential checks of Harvest functions."""

import argparse
import json
import os
import sys
from importlib import resources
from pathlib import Path

from . import explain, oracle


def harvest_from(args):
    return oracle.Harvest(args.harvest, args.build)


def cmd_check(args):
    harvest = harvest_from(args)
    report = oracle.check(harvest, args.symbol, {"a": args.a, "b": args.b}, cases=args.cases, returns=args.returns,
                          static=args.static, arguments=args.arguments, out=args.keep)
    pair = report["comparison"]["a vs b"]
    line = {"symbol": args.symbol, "unit": args.unit, "verdict": "agree" if pair["differ"] == 0 else "differ",
            "cases": report["cases"], "agree": pair["agree"], "differ": pair["differ"],
            "layout_dependent": pair["layout_dependent"], "returns": report["returns"],
            "distinct_behaviors": report["distinct_behaviors"]["a"],
            "first_difference": pair["examples"][0] if pair["examples"] else None}
    print(json.dumps(line))
    return 0 if pair["differ"] == 0 else 1


def cmd_compare(args):
    harvest = harvest_from(args)
    versions = dict(item.split("=", 1) for item in args.versions)
    report = oracle.check(harvest, args.symbol, versions, cases=args.cases, returns=args.returns, static=args.static,
                          arguments=args.arguments, out=args.keep)
    print(json.dumps(report, indent=1))
    return 0 if all(p["differ"] == 0 for p in report["comparison"].values()) else 1


def cmd_batch(args):
    harvest = harvest_from(args)
    table = args.functions.read_text() if args.functions else (
        resources.files("harvest_oracle").joinpath("functions.tsv").read_text())
    directories = dict(item.split("=", 1) for item in args.builds)
    status = 0
    for line in table.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        address, returns, unit, symbol = line.split("\t")
        if args.only and address not in args.only:
            continue
        versions = {name: oracle.IMAGE if directory == oracle.IMAGE else Path(directory) / f"{unit}.o"
                    for name, directory in directories.items()}
        missing = [str(path) for path in versions.values() if path != oracle.IMAGE and not path.exists()]
        if missing:
            print(json.dumps({"address": address, "symbol": symbol, "skipped": f"missing {', '.join(missing)}"}))
            continue
        out = args.keep / address if args.keep else None
        report = oracle.check(harvest, symbol, versions, cases=args.cases, returns=returns, out=out)
        pairs = {k: f"{v['agree']}/{report['cases']}" + (f" ({v['layout_dependent']} layout-dependent)"
                                                       if v["layout_dependent"] else "")
                 for k, v in report["comparison"].items()}
        print(json.dumps({"address": address, "symbol": symbol, "outcomes": report["outcomes"][next(iter(versions))],
                          "pairs": pairs, "examples": {k: v["examples"][:1] for k, v in report["comparison"].items()}}))
        if any(v["differ"] for v in report["comparison"].values()):
            status = 1
    return status


def main(argv=None):
    parser = argparse.ArgumentParser(prog="harvest-oracle", description=__doc__)
    parser.add_argument("--harvest", type=Path, default=Path(os.environ.get("HARVEST_ROOT", ".")),
                        help="Harvest checkout holding orig/ and config/ (default: $HARVEST_ROOT or the current directory)")
    parser.add_argument("--build", default="1.18-linux-amd64", help="build name under orig/ and config/")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("--cases", type=int, default=5000, help="generated cases per version (default 5000)")
        p.add_argument("--returns", choices=["auto", "none", "int", "bool", "float"], default="auto",
                       help="return type to compare; auto reads it from the declarations under src/")
        p.add_argument("--static", action="store_true", help="the function takes no this pointer")
        p.add_argument("--arguments", help="argument kinds in order (p pointer, i integer, b bool, f float, "
                                           "d double), for a function without a mangled parameter list")
        p.add_argument("--keep", type=Path, help="keep linked versions and per-case records in this directory")

    p = sub.add_parser("check", help="compare two objects' versions of one function; print one JSON line")
    p.add_argument("a", type=Path, help="reference object, such as the master build")
    p.add_argument("b", type=Path, help="object to check, such as the branch build")
    p.add_argument("--symbol", required=True, help="mangled name of the function")
    p.add_argument("--unit", help="unit name, recorded in the output")
    common(p)
    p.set_defaults(run=cmd_check)

    p = sub.add_parser("compare", help="compare any number of versions; print the full report")
    p.add_argument("symbol", help="mangled name of the function")
    p.add_argument("versions", nargs="+", help="NAME=OBJECT, or NAME=image for the executable's own code run in place; "
                                               "the first is the reference")
    common(p)
    p.set_defaults(run=cmd_compare)

    p = sub.add_parser("batch", help="check every function of a table; one JSON line per function")
    p.add_argument("builds", nargs="+", help="NAME=DIRECTORY of <unit>.o files, or NAME=image for the executable's "
                                             "own code; the first is the reference")
    p.add_argument("--functions", type=Path, help="table of address, returns, unit, symbol (default: built in)")
    p.add_argument("--only", nargs="*", help="addresses to run")
    common(p)
    p.set_defaults(run=cmd_batch)

    p = sub.add_parser("explain", help="show how two versions differ on one case of a kept run")
    p.add_argument("directory", type=Path)
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("seed", type=int)
    p.set_defaults(run=lambda args: explain.show(args.directory, args.a, args.b, args.seed))

    args = parser.parse_args(argv)
    return args.run(args) or 0


if __name__ == "__main__":
    sys.exit(main())
