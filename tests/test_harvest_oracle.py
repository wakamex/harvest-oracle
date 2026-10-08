"""Tests on a synthetic checkout: a small fixed-address executable stands in for Harvest's."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from harvest_oracle import oracle
from harvest_oracle.cli import main

EXECUTABLE = r"""
int counter = 7;
float scale = 2.0f;
__attribute__((noinline)) int callee(int value) { return value + 1; }
extern "C" void _start(void) { for (;;) {} }
"""

# The function under test: reads a global, calls a function of the executable, writes through its argument.
FUNCTION = r"""
struct item { int value; float weight; struct item *next; };
extern int counter;
extern float scale;
int callee(int value);
int update(struct item *item, float delta) {
    int total = 0;
    for (; item; item = item->next) {
        if (item->weight > delta)        /* COMPARE */
            item->value = callee(item->value) + counter;
        item->weight *= scale;
        total++;
        if (total > 8)
            break;
    }
    return total;
}
"""


UPDATE = "_Z6updateP4itemf"

# A function that indexes a static table with an integer it is given: a generated index is almost always out of
# range, and what lies past the table depends on the build.
TABLE = r"""
static const float factors[] = {0.0f, 0.5f, 1.0f, 2.0f};
static const char other[] = "data after the table";
const char *keep = other;
float scaled(float value, int index) { return value * factors[index]; }
"""
SCALED = "_Z6scaledfi"


def run(command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, text=True, **kwargs).stdout


class SyntheticCheckout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory()
        root = Path(cls.scratch.name)
        build = root / "orig" / "test"
        build.mkdir(parents=True)
        (root / "config" / "test").mkdir(parents=True)
        (root / "exe.cpp").write_text(EXECUTABLE + FUNCTION)
        executable = build / "Harvest"
        run(["g++", "-O1", "-static", "-no-pie", "-fno-pic", "-nostdlib", "-Wl,-Ttext-segment=0x400000",
             "-o", str(executable), str(root / "exe.cpp")])
        symbols = ["address\tsize\tsymbol\tevidence"]
        for line in run(["nm", "-S", str(executable)]).splitlines():
            parts = line.split()
            if len(parts) == 4 and parts[3] in ("counter", "scale", "_Z6calleei", UPDATE):
                symbols.append(f"0x{int(parts[0], 16):x}\t{int(parts[1], 16)}\t{parts[3]}\ttest")
        (root / "config" / "test" / "symbols.tsv").write_text("\n".join(symbols) + "\n")
        cls.root = root
        cls.objects = {}
        for name, source, flags in (("o2", FUNCTION, "-O2"), ("o1", FUNCTION, "-O1"),
                                    ("nan", FUNCTION.replace("item->weight > delta", "!(item->weight <= delta)"), "-O2")):
            path = root / f"{name}.cpp"
            path.write_text(source)
            run(["g++", flags, "-fno-pic", "-c", "-o", str(root / f"{name}.o"), str(path)])
            cls.objects[name] = root / f"{name}.o"

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def check(self, a, b):
        report = oracle.check(oracle.Harvest(self.root, "test"), UPDATE, {"a": self.objects[a], "b": self.objects[b]},
                              cases=200, returns="int", static=True)
        return report["comparison"]["a vs b"]

    def test_equivalent_compiles_agree(self):
        self.assertEqual(self.check("o2", "o1")["differ"], 0)

    def test_comparison_that_differs_only_on_nan_is_caught(self):
        self.assertGreater(self.check("o2", "nan")["differ"], 0)

    def test_object_agrees_with_the_executables_own_code_run_in_place(self):
        report = oracle.check(oracle.Harvest(self.root, "test"), UPDATE, {"a": self.objects["o2"], "b": "image"},
                              cases=200, returns="int", static=True)
        self.assertEqual(report["comparison"]["a vs b"]["differ"], 0)

    def test_reads_past_a_static_table_are_undefined(self):
        path = self.root / "table.cpp"
        path.write_text(TABLE)
        run(["g++", "-O2", "-fno-pic", "-c", "-o", str(self.root / "table.o"), str(path)])
        report = oracle.check(oracle.Harvest(self.root, "test"), SCALED,
                              {"a": self.root / "table.o", "b": self.root / "table.o"}, cases=200, returns="float",
                              static=True)
        pair = report["comparison"]["a vs b"]
        self.assertGreater(pair["undefined"], 0)
        self.assertEqual(pair["differ"], 0)
        self.assertEqual(pair["agree"] + pair["undefined"], 200)

    def test_check_command_prints_one_line(self):
        output = run([sys.executable, "-m", "harvest_oracle", "--harvest", str(self.root), "--build", "test", "check",
                      str(self.objects["o2"]), str(self.objects["o1"]), "--symbol", UPDATE, "--static",
                      "--returns", "int", "--cases", "50"])
        line = json.loads(output)
        self.assertEqual(line["verdict"], "agree")
        self.assertEqual(line["cases"], 50)


class Helpers(unittest.TestCase):
    def test_parameters_split_at_top_level(self):
        self.assertEqual(oracle.parameters("f(int, ox::core::CRect<float> const&, a<b, c>)"),
                         ["int", "ox::core::CRect<float> const&", "a<b, c>"])

    def test_argument_spec(self):
        self.assertEqual(oracle.argument_spec("C::f(float, char const*, bool, int)"), "pfpbi")

    def test_member_detection(self):
        self.assertTrue(oracle.is_member("ox::core::CString<char>::append"))
        self.assertFalse(oracle.is_member("std::_Rb_tree_increment"))

    def test_translation_rewrites_whole_words(self):
        ranges = [(0x20005058, 32, 0x5F0C60)]
        writes = [["0x1000", (0x20005068).to_bytes(8, "little").hex()]]
        self.assertEqual(oracle.normalized_writes(writes, ranges)[0][1], (0x5F0C70).to_bytes(8, "little").hex())


class Entrypoints(unittest.TestCase):
    def test_help(self):
        with self.assertRaises(SystemExit) as stop, contextlib.redirect_stdout(io.StringIO()):
            main(["--help"])
        self.assertEqual(stop.exception.code, 0)

    def test_module_help(self):
        self.assertIn("harvest-oracle", run([sys.executable, "-m", "harvest_oracle", "--help"]))


if __name__ == "__main__":
    unittest.main()
