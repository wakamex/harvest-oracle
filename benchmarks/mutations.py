"""Compile real Harvest mutations through read-only source overlays and measure the oracle.

Run with the repository's Python environment. The Harvest checkout must already have its match
objects built. All generated source, compiler metadata, objects and records go in --output.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from harvest_oracle import oracle


TIME = "ox/algo/CTimeCounter.cpp"
SPRITE = "daisy/video/Null/CSpritePackage.cpp"
COLOR = "daisy/video/Null/CColorConverter.cpp"
BSP = "daisy/scene/CBspTree.cpp"
SPLITTER = "_ZN5daisy5scene8CBspTree12findSplitterEPNS1_7BspPolyEjRN2ox4core8CPlane3dIfEE"
DROP = "HarvestFull/harvest/entity/CDropshipEntity.cpp"
UPDATE = "_ZN7harvest6entity15CDropshipEntity11updateLogicEf"
BUTTON = "daisy/gui/CGUIButton.cpp"
BUTTON_DRAW = "_ZN5daisy3gui10CGUIButton4drawEv"
HIGHSCORE = "HarvestFull/harvest/gui/CHighscoreScreen.cpp"
HIGHSCORE_VISIBLE = "_ZN7harvest3gui16CHighscoreScreen10setVisibleEb"
LOAD = "_ZN5daisy5video14CSpritePackage4loadEPN2ox2io9IReadFileEPKc"

# Each replacement must occur exactly once in the recovered translation unit. The expected behavior
# follows from the source operation, independently of the oracle's verdict.
MUTATIONS = [
    ("dependent-reads", SPRITE, LOAD, "bool", False, False,
     "bundle.Columns = ox::io::CHelpIO::readInt(file);\n        int count = ox::io::CHelpIO::readInt(file);",
     "int count = ox::io::CHelpIO::readInt(file);\n        bundle.Columns = ox::io::CHelpIO::readInt(file);"),
    ("constant", TIME, "_ZN2ox4algo12CTimeCounter11getProgressEv", "float", False, False,
     "return 1.0f - Remaining / Delay;", "return 2.0f - Remaining / Delay;"),
    ("dropped-store", TIME, "_ZN2ox4algo12CTimeCounter8setDelayEf", "none", False, False,
     "    Remaining = delay;\n    Delay = delay;", "    Delay = delay;"),
    ("comparison", TIME, "_ZN2ox4algo12CTimeCounter9isStartedEv", "bool", False, False,
     "bool CTimeCounter::isStarted()\n{\n    return Remaining > 0.0f;",
     "bool CTimeCounter::isStarted()\n{\n    return Remaining >= 0.0f;"),
    ("loop-bound", COLOR, "_ZN5daisy5video15CColorConverter18convert8BitTo16BitEPKcPsiiiPKi", "none", True, False,
     "for (int y = 1; y <= height; ++y)", "for (int y = 1; y < height; ++y)"),
    ("nan-comparison", TIME, "_ZN2ox4algo12CTimeCounter9isDelayedEv", "bool", False, False,
     "bool CTimeCounter::isDelayed()\n{\n    return Remaining > 0.0f;",
     "bool CTimeCounter::isDelayed()\n{\n    return !(Remaining <= 0.0f);"),
    ("independent-stores", TIME, "_ZN2ox4algo12CTimeCounter8setDelayEf", "none", False, True,
     "    Remaining = delay;\n    Delay = delay;", "    Delay = delay;\n    Remaining = delay;"),
    ("renamed-local", TIME, "_ZN2ox4algo12CTimeCounter13updateCounterEf", "bool", False, True,
     "frameDelta", "elapsed"),
    ("outlining", TIME, "_ZN2ox4algo12CTimeCounter9isStartedEv", "bool", False, True,
     "bool CTimeCounter::isStarted()\n{\n    return Remaining > 0.0f;",
     "static __attribute__((noinline)) bool positiveTime(float value) { return value > 0.0f; }\n"
     "bool CTimeCounter::isStarted()\n{\n    return positiveTime(Remaining);"),
    ("independent-load-statements", SPRITE, LOAD, "bool", False, True,
     "    HeaderSize = SPRITE_PACKAGE_HEADER_SIZE;\n    TextureDataSize = TextureSize * TextureSize;",
     "    TextureDataSize = TextureSize * TextureSize;\n    HeaderSize = SPRITE_PACKAGE_HEADER_SIZE;"),
    ('load-version', SPRITE, LOAD, 'bool', False, False,
     'if (version > 3)', 'if (version >= 3)'),
    ('load-header', SPRITE, LOAD, 'bool', False, False,
     'HeaderSize = SPRITE_PACKAGE_HEADER_SIZE;', 'HeaderSize = SPRITE_PACKAGE_HEADER_SIZE + 1;'),
    ('load-texture-scale', SPRITE, LOAD, 'bool', False, False,
     'TextureDataSize *= 3;', 'TextureDataSize *= 2;'),
    ('splitter-score', BSP, SPLITTER, 'bool', False, False,
     '\t\t\tint score = abs(frontCount - backCount) + (splitCount*3) + planarCount;', '\t\t\tint score = abs(frontCount - backCount) + (splitCount*2) + planarCount;'),
    ('splitter-store', BSP, SPLITTER, 'bool', False, False,
     'bestSplitter->wasSplitter = true;', 'bestSplitter->wasSplitter = false;'),
    ('splitter-empty', BSP, SPLITTER, 'bool', False, False,
     'if (!bestSplitter)\n\t\treturn false;', 'if (!bestSplitter)\n\t\treturn true;'),
    ('drop-laugh-state', DROP, UPDATE, 'int', False, False,
     'LaughCooldown > 0 && State == 1', 'LaughCooldown > 0 && State == 2'),
    ('drop-landing-tag', DROP, UPDATE, 'int', False, False,
     'else if (State == 2)', 'else if (State == 7)'),
    ('drop-sprite', DROP, UPDATE, 'int', False, False,
     'SpriteIndex = 72;', 'SpriteIndex = 71;'),
    ('remaining-field', TIME, "_ZN2ox4algo12CTimeCounter16getRemainingTimeEv", 'float', False, False,
     'return Remaining;', 'return Delay;'),
    ('inverted-progress', TIME, "_ZN2ox4algo12CTimeCounter19getInvertedProgressEv", 'float', False, False,
     'return Remaining / Delay;', 'return Delay / Remaining;'),
    ('put-delay', TIME, "_ZN2ox4algo12CTimeCounter8putDelayEff", 'none', False, False,
     'Remaining += time;', 'Remaining = time;'),
    ('override-field', TIME, "_ZN2ox4algo12CTimeCounter21overrideStartingValueEf", 'none', False, False,
     'void CTimeCounter::overrideStartingValue(float delay)\n{\n    Delay = delay;', 'void CTimeCounter::overrideStartingValue(float delay)\n{\n    Remaining = delay;'),
    ('update-subtract', TIME, "_ZN2ox4algo12CTimeCounter13updateCounterEf", 'bool', False, False,
     'Remaining -= frameDelta;', 'Remaining += frameDelta;'),
    ('remaining-parentheses', TIME, "_ZN2ox4algo12CTimeCounter16getRemainingTimeEv", 'float', False, True,
     'return Remaining;', 'return (Remaining);'),
    ('progress-parentheses', TIME, "_ZN2ox4algo12CTimeCounter11getProgressEv", 'float', False, True,
     'return 1.0f - Remaining / Delay;', 'return 1.0f - (Remaining / Delay);'),
    ('splitter-declarations', BSP, SPLITTER, 'bool', False, True,
     'unsigned int frontCount = 0;\n\t\tunsigned int backCount = 0;', 'unsigned int backCount = 0;\n\t\tunsigned int frontCount = 0;'),
    ('drop-increment', DROP, UPDATE, 'int', False, True,
     '++LaughIndex;', 'LaughIndex += 1;'),
    ("button-relative-rect-local-copy", BUTTON, BUTTON_DRAW, "none", False, False,
     "    if (RelativeSizeChanged && States[EBS_NORMAL])\n"
     "    {\n"
     "        core::CDimension2d<int> size = States[EBS_NORMAL]->getFrameSize(0);\n"
     "        RelativeRect.LowerRightCorner.X = RelativeRect.UpperLeftCorner.X + size.Width;\n"
     "        RelativeRect.LowerRightCorner.Y = RelativeRect.UpperLeftCorner.Y + size.Height;\n"
     "        updateAbsolutePosition();\n"
     "    }",
     "    if (RelativeSizeChanged && States[EBS_NORMAL])\n"
     "    {\n"
     "        core::CDimension2d<int> size = States[EBS_NORMAL]->getFrameSize(0);\n"
     "        core::CPosition2d<int> lowerRightCorner = RelativeRect.LowerRightCorner;\n"
     "        lowerRightCorner.X = RelativeRect.UpperLeftCorner.X + size.Width;\n"
     "        lowerRightCorner.Y = RelativeRect.UpperLeftCorner.Y + size.Height;\n"
     "        updateAbsolutePosition();\n"
     "    }"),
    ("highscore-summary-local-copy", HIGHSCORE, HIGHSCORE_VISIBLE, "none", False, False,
     "            summaryArea.LowerRightCorner.Y = summaryTop + SpriteSizes[SPRITE_ALL_BACKGROUND].Height;",
     "            ox::core::CPosition2d<int> lowerRightCorner = summaryArea.LowerRightCorner;\n"
     "            lowerRightCorner.Y = summaryTop + SpriteSizes[SPRITE_ALL_BACKGROUND].Height;"),
]


def replace_source(text, old, new, name):
    # The loop-bound and identifier edits deliberately affect every occurrence in their unit.
    expected = {"loop-bound": 2, "renamed-local": 2}.get(name, 1)
    if text.count(old) != expected:
        raise ValueError(f"{name}: expected {expected} source matches, got {text.count(old)}")
    return text.replace(old, new)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(harvest, output):
    sys.path.insert(0, str(harvest / "tools"))
    from hv.toolchain import Compiler, load_flags

    compiler = Compiler(load_flags("1.18-linux-amd64"), output / "objects")
    originals, manifest = {}, []
    for name, unit, symbol, returns, static, preserving, old, new in MUTATIONS:
        # Avoid starting a compiler when the host lacks the requested memory headroom.
        while int(Path('/proc/meminfo').read_text().split('MemAvailable:')[1].split()[0]) < 4 * 1024**2:
            time.sleep(5)
        source = harvest / "src" / unit
        text = source.read_text()
        if unit not in originals:
            slug = unit.removesuffix(".cpp").replace("/", "__")
            obj, metadata = compiler.compile(source, slug)
            (compiler.out / f"{slug}.json").write_text(json.dumps(metadata, indent=2) + "\n")
            originals[unit] = str(obj)
        overlay = compiler.out / f"{name}.cpp"
        overlay.write_text(replace_source(text, old, new, name))
        obj, metadata = compiler.compile(source, name, source_override=overlay)
        (compiler.out / f"{name}.json").write_text(json.dumps(metadata, indent=2) + "\n")
        manifest.append(dict(name=name, unit=unit, symbol=symbol, returns=returns, static=static,
                             preserving=preserving, original=originals[unit], mutation=str(obj),
                             original_sha256=sha(originals[unit]), mutation_sha256=sha(obj)))
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def measure(harvest, output, label, cases, keep):
    destination = output / label
    destination.mkdir(parents=True, exist_ok=True)
    os.environ["XDG_CACHE_HOME"] = str(destination / "cache")
    h = oracle.Harvest(harvest)
    rows = []
    for mutation in json.loads((output / "manifest.json").read_text()):
        for key in ("original", "mutation"):
            if sha(mutation[key]) != mutation[f"{key}_sha256"]:
                raise ValueError(f"changed input: {mutation[key]}")
        start = time.perf_counter()
        report = oracle.check(h, mutation["symbol"], {"original": mutation["original"], "mutation": mutation["mutation"]},
                              cases=cases, returns=mutation["returns"], static=mutation["static"],
                              out=destination / mutation["name"] if keep else None)
        comparison = report["comparison"]["original vs mutation"]
        row = {"name": mutation["name"], "preserving": mutation["preserving"],
               "verdict": "differ" if comparison["differ"] else "agree", "differing_cases": comparison["differ"], "seconds": time.perf_counter() - start,
               "report": report}
        rows.append(row)
        with (destination / "results.jsonl").open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        print(json.dumps(row), flush=True)
    changed = [r for r in rows if not r["preserving"]]
    preserved = [r for r in rows if r["preserving"]]
    summary = {"cases_per_pair": cases, "mutations": len(changed),
               "detected": sum(r["verdict"] == "differ" for r in changed),
               "preserving_rewrites": len(preserved), "false_differences": sum(r["verdict"] == "differ" for r in preserved)}
    summary["detection_rate"] = summary["detected"] / len(changed)
    summary["false_difference_rate"] = summary["false_differences"] / len(preserved)
    (destination / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harvest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label", default="run")
    parser.add_argument("--cases", type=int, default=5000)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--run-only", action="store_true")
    args = parser.parse_args()
    args.output = args.output.resolve()
    if args.output.is_relative_to(Path(__file__).resolve().parents[1]):
        parser.error("--output must be outside the oracle repository")
    args.output.mkdir(parents=True, exist_ok=True)
    if not args.run_only:
        build(args.harvest.resolve(), args.output)
    if not args.build_only:
        measure(args.harvest.resolve(), args.output, args.label, args.cases, args.keep)


if __name__ == "__main__":
    main()
