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

from harvest_oracle import accesses, oracle
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

    def test_accesses_name_struct_fields_by_argument(self):
        harvest = oracle.Harvest(self.root, "test")
        start, size = harvest.known[UPDATE], harvest.sizes[UPDATE]
        globals_ = sorted((a, a + harvest.sizes.get(n, 0), n) for n, a in harvest.known.items())
        found = {(a["base"], a["offset"], a["size"], a["access"])
                 for a in accesses.analyze(harvest.image, start, start + size, ["argument 1"], globals_)}
        self.assertIn(("argument 1", "0x4", 4, "read"), found)  # item->weight
        self.assertIn(("argument 1", "0x0", 4, "write"), found)  # item->value
        self.assertIn(("argument 1", "0x8", 8, "read"), found)  # item->next
        self.assertIn(("scale", "0x0", 4, "read"), found)

    def test_check_command_prints_one_line(self):
        output = run([sys.executable, "-m", "harvest_oracle", "--harvest", str(self.root), "--build", "test", "check",
                      str(self.objects["o2"]), str(self.objects["o1"]), "--symbol", UPDATE, "--static",
                      "--returns", "int", "--cases", "50"])
        line = json.loads(output)
        self.assertEqual(line["verdict"], "agree")
        self.assertEqual(line["cases"], 50)


class FollowedFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory()
        cls.root = Path(cls.scratch.name)
        cls.build = cls.root / "orig" / "test"
        cls.build.mkdir(parents=True)
        (cls.root / "config" / "test").mkdir(parents=True)
        cls.source = r"""
extern "C" int boundary(int);
extern "C" __attribute__((noinline)) int boundary(int n) { return n; }
#ifdef INLINE
#define HELPER inline __attribute__((always_inline))
#else
#define HELPER __attribute__((weak, noinline))
#endif
HELPER int helper(int *p) { *p = *p + 3; return boundary(*p); }
__attribute__((noinline)) static int local(int *p) { *p = *p + 2; return helper(p); }
int work(int *p) { return local(p); }
int indirect(int *p, int (*f)(int *)) { return f(p); }
__attribute__((noinline)) int recursive(int *p, bool stop) { if (stop) return *p; return recursive(p, true) + 1; }
__attribute__((noinline)) void traphelper() { __asm__("int3"); }
void trapping() { traphelper(); }
extern "C" void _start() { for (;;) {} }
"""
        # The boundary's body belongs to another unit for the versions being checked.
        (cls.root / "image.cpp").write_text(cls.source)
        run(["g++", "-O1", "-static", "-no-pie", "-fno-pic", "-nostdlib", "-Wl,-Ttext-segment=0x400000",
             "-o", str(cls.build / "Harvest"), str(cls.root / "image.cpp")])
        symbols = ["address\tsize\tsymbol\tevidence"]
        for line in run(["nm", "-S", str(cls.build / "Harvest")]).splitlines():
            parts = line.split()
            if len(parts) == 4:
                symbols.append(f"0x{int(parts[0], 16):x}\t{int(parts[1], 16)}\t{parts[3]}\ttest")
        (cls.root / "config" / "test" / "symbols.tsv").write_text("\n".join(symbols) + "\n")
        cls.objects = {}
        for name in ("inline", "outline", "changed"):
            source = cls.source.replace('extern "C" __attribute__((noinline)) int boundary(int n) { return n; }', '')
            if name == "changed":
                source = source.replace('*p + 3', '*p + 4')
            path = cls.root / f"{name}.cpp"
            path.write_text(source)
            obj = path.with_suffix('.o')
            run(["g++", "-O1", "-fno-pic", *(["-DINLINE"] if name == "inline" else []), "-c", str(path), "-o", str(obj)])
            cls.objects[name] = obj
        weak = cls.root / 'build' / 'match' / 'test' / 'unit.o'
        weak.parent.mkdir(parents=True)
        weak.write_bytes(cls.objects['outline'].read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def test_same_unit_helpers_execute_and_preserve_external_boundary(self):
        out = self.root / "records"
        report = oracle.check(oracle.Harvest(self.root, "test"), "_Z4workPi",
                              {**self.objects, "original": "image"}, cases=100, returns="int", static=True, out=out)
        for pair in ("inline vs outline", "inline vs original"):
            self.assertEqual(report["comparison"][pair]["differ"], 0)
        self.assertGreater(report["comparison"]["inline vs changed"]["differ"], 0)
        records = [json.loads(line) for line in (out / "outline.jsonl").read_text().splitlines()]
        self.assertTrue(all(len(r['calls']) == 1 for r in records))
        self.assertTrue(all(r['writes'] for r in records))

    def test_weak_body_from_another_object_runs_in_image(self):
        # The called body is absent from the version, but weak in another built object.
        source = self.root / 'weak.cpp'
        source.write_text('__attribute__((weak)) int helper(int *p) { *p += 3; return *p; }')
        obj = self.root / 'build' / 'match' / 'test' / 'weak.o'
        obj.parent.mkdir(parents=True, exist_ok=True)
        run(['g++', '-O1', '-c', str(source), '-o', str(obj)])
        caller = self.root / 'fallback.cpp'
        caller.write_text('int helper(int *); int fallback(int *p) { return helper(p); }')
        run(['g++', '-O1', '-fno-pic', '-c', str(caller), '-o', str(caller.with_suffix('.o'))])
        h = oracle.Harvest(self.root, 'test')
        with tempfile.TemporaryDirectory() as directory:
            elf, entry, slot, _, _ = oracle.link(h, 'v', caller.with_suffix('.o'), '_Z8fallbackPi', Path(directory))
            plan = oracle.execution_plan(h, elf, entry, '_Z8fallbackPi', h.vague_functions, Path(directory))
            records = oracle.execute(h, elf, entry, slot, 'p', 20, plan=plan)
        self.assertTrue(all(r['writes'] for r in records))
        self.assertTrue(all(len(r['calls']) == 1 for r in records))  # helper's boundary, rather than helper
        self.assertTrue(all(int(r['calls'][0]['to'], 16) == h.known['boundary'] for r in records))

    def test_indirect_call_stays_recorded_when_target_is_followed(self):
        source = self.root / 'dispatch.cpp'
        source.write_text('int helper(int *p) { *p += 3; return *p; } '
                          'int dispatch(int *p) { int (*volatile f)(int *) = helper; return f(p); }')
        obj = source.with_suffix('.o')
        run(['g++', '-O1', '-fno-pic', '-c', str(source), '-o', str(obj)])
        out = self.root / 'indirect-records'
        oracle.check(oracle.Harvest(self.root, 'test'), '_Z8dispatchPi', {'v': obj}, cases=20,
                     returns='int', static=True, out=out)
        records = [json.loads(l) for l in (out / 'v.jsonl').read_text().splitlines()]
        self.assertTrue(all(len(r['calls']) == 1 and not r['writes'] for r in records))

    def test_image_fallback_calls_the_versions_own_definition(self):
        source = self.root / 'redirect.cpp'
        source.write_text('int helper(int *); extern "C" int boundary(int n) { return n + 1; } '
                          'int redirect(int *p) { return helper(p); }')
        obj = source.with_suffix('.o')
        run(['g++', '-O1', '-fno-pic', '-c', str(source), '-o', str(obj)])
        out = self.root / 'redirect-records'
        oracle.check(oracle.Harvest(self.root, 'test'), '_Z8redirectPi', {'v': obj}, cases=20,
                     returns='int', static=True, out=out)
        records = [json.loads(l) for l in (out / 'v.jsonl').read_text().splitlines()]
        self.assertTrue(all(r['outcome'] == 'return' and not r['calls'] and r['writes'] for r in records))

    def test_allocator_body_stays_a_boundary(self):
        source = self.root / 'allocator.cpp'
        source.write_text('extern "C" __attribute__((noinline)) void *malloc(unsigned long n) { return 0; } '
                          'void *allocate() { return malloc(8); }')
        obj = source.with_suffix('.o')
        run(['g++', '-O1', '-fno-pic', '-fno-builtin', '-c', str(source), '-o', str(obj)])
        out = self.root / 'allocator-records'
        oracle.check(oracle.Harvest(self.root, 'test'), '_Z8allocatev', {'v': obj}, cases=10,
                     returns='none', static=True, out=out)
        records = [json.loads(l) for l in (out / 'v.jsonl').read_text().splitlines()]
        self.assertTrue(all(len(r['calls']) == 1 and r['calls'][0]['to'].startswith('malloc@') for r in records))

    def test_fault_and_timeout_inside_helpers_end_the_case(self):
        source = self.root / 'outcomes.cpp'
        source.write_text('__attribute__((noinline)) void bad() { volatile int *p = (volatile int *)0x12345000; *p = 1; } '
                          '__attribute__((noinline)) void slow() { for (;;) {} } '
                          'void faulting() { bad(); } void hanging() { slow(); }')
        obj = source.with_suffix('.o')
        run(['g++', '-O1', '-fno-pic', '-c', str(source), '-o', str(obj)])
        for symbol, outcome in (('_Z8faultingv', 'crash'), ('_Z7hangingv', 'timeout')):
            report = oracle.check(oracle.Harvest(self.root, 'test'), symbol, {'v': obj}, cases=1,
                                  returns='none', static=True)
            self.assertEqual(report['outcomes']['v'], {outcome: 1})

    def test_real_trap_inside_a_followed_image_body_is_a_fault(self):
        report = oracle.check(oracle.Harvest(self.root, 'test'), '_Z8trappingv',
                              {'object': self.objects['outline'], 'original': 'image'}, cases=1,
                              returns='none', static=True)
        self.assertEqual(report['comparison']['object vs original']['differ'], 0)
        self.assertEqual(report['outcomes']['original'], {'signal': 1})

    def test_recursive_same_unit_calls_execute(self):
        report = oracle.check(oracle.Harvest(self.root, 'test'), '_Z9recursivePib',
                              {'object': self.objects['outline'], 'original': 'image'}, cases=20,
                              returns='int', static=True)
        self.assertEqual(report['comparison']['object vs original']['differ'], 0)


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

    def test_indirect_call_reads_its_vtable_slot(self):
        registers = {"rax": ("this.0x20.0x0", 0), "rdi": ("this", 0)}
        record = accesses.step("call", ["*0x150(%rax)"], registers, {}, [])
        self.assertEqual((record["base"], record["offset"], record["access"]), ("this.0x20.0x0", "0x150", "read"))
        self.assertNotIn("rdi", registers)
        self.assertIsNone(accesses.step("call", ["4a6e4c"], {}, {}, []))


class Entrypoints(unittest.TestCase):
    def test_help(self):
        with self.assertRaises(SystemExit) as stop, contextlib.redirect_stdout(io.StringIO()):
            main(["--help"])
        self.assertEqual(stop.exception.code, 0)

    def test_module_help(self):
        self.assertIn("harvest-oracle", run([sys.executable, "-m", "harvest_oracle", "--help"]))


if __name__ == "__main__":
    unittest.main()
