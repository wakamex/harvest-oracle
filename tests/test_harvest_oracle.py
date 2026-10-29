"""Tests on a synthetic checkout: a small fixed-address executable stands in for Harvest's."""

import contextlib
import hashlib
import io
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def test_dependent_reads_behind_scalar_gates_are_exercised(self):
        (self.root / 'src').mkdir(exist_ok=True)
        (self.root / 'src' / 'reads.h').write_text('int nextValue();\n')
        source = '''extern int nextValue();
int dependentReads() {
  if (nextValue() != 2) return 0;
  int first = nextValue();
  if (first < 0 || first > 3) return 0;
  int second = nextValue();
  if (second < 0 || second > 3) return 0;
  int columns = nextValue();
  int count = nextValue();
  if (count < 0 || count > 3) return 0;
  return columns + 7 * count;
}
'''
        swapped = source.replace('int columns = nextValue();\n  int count = nextValue();',
                                 'int count = nextValue();\n  int columns = nextValue();')
        versions = {}
        for name, text in (("original", source), ("renamed", source.replace("columns", "width")),
                           ("swapped", swapped)):
            path = self.root / f"reads-{name}.cpp"
            path.write_text(text)
            obj = path.with_suffix('.o')
            run(['g++', '-O2', '-fno-pic', '-c', str(path), '-o', str(obj)])
            versions[name] = obj
        report = oracle.check(oracle.Harvest(self.root, "test"), '_Z14dependentReadsv', versions,
                              cases=500, returns="int", static=True)
        self.assertEqual(report["comparison"]["original vs renamed"]["differ"], 0)
        self.assertGreater(report["comparison"]["original vs swapped"]["differ"], 0)

    def test_layout_reruns_release_each_record_before_next_seed(self):
        versions = {}
        for value in (0, 1):
            path = self.root / f'constant-{value}.cpp'
            path.write_text(f'int constantValue() {{ return {value}; }}')
            obj = path.with_suffix('.o')
            run(['g++', '-O2', '-fno-pic', '-c', str(path), '-o', str(obj)])
            versions[str(value)] = obj
        limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, limit[1]))
            report = oracle.check(oracle.Harvest(self.root, 'test'), '_Z13constantValuev', versions,
                                  cases=80, returns='int', static=True)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, limit)
        self.assertEqual(report['comparison']['0 vs 1']['differ'], 80)

    def test_scalar_return_declarations_exclude_pointer_and_ambiguous_types(self):
        (self.root / 'src').mkdir(exist_ok=True)
        (self.root / 'src' / 'return-model.h').write_text('''int scalarValue();
bool flagValue();
int* pointerValue();
const char* mixedValue();
int mixedValue(int);
unsigned int unsignedValue();
int operator[](int);
''')
        h = oracle.Harvest(self.root, 'test')
        self.assertEqual(h.scalar_return_kind('scalarValue()'), 'i')
        self.assertEqual(h.scalar_return_kind('flagValue()'), 'b')
        self.assertEqual(h.scalar_return_kind('unsignedValue()'), 'i')
        for name in ('pointerValue()', 'mixedValue()', 'undeclaredValue()'):
            self.assertIsNone(h.scalar_return_kind(name))
        self.assertEqual(h.return_kind('Thing::operator[](int)'), 'int')

    def test_object_agrees_with_the_executables_own_code_run_in_place(self):
        report = oracle.check(oracle.Harvest(self.root, "test"), UPDATE, {"a": self.objects["o2"], "b": "image"},
                              cases=200, returns="int", static=True)
        self.assertEqual(report["comparison"]["a vs b"]["differ"], 0)

    def test_case_workers_preserve_seed_order_and_records(self):
        h = oracle.Harvest(self.root, "test")
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            elf, entry, slot, _, _ = oracle.link(h, "workers", self.objects["o2"], UPDATE, out)
            plan = oracle.execution_plan(h, elf, entry, UPDATE, {UPDATE}, out)
            with patch.dict(os.environ, {"ORACLE_WORKERS": "1"}):
                serial = oracle.execute_range(h, elf, entry, slot, "pf", 11, first=8, plan=plan)
            actual_run = subprocess.run
            with patch.dict(os.environ, {"ORACLE_WORKERS": "3"}), patch.object(
                    oracle.subprocess, "run", wraps=actual_run) as calls:
                parallel = oracle.execute_range(h, elf, entry, slot, "pf", 11, first=8, plan=plan)
            shards = [c.args[0][-2:] for c in calls.call_args_list if len(c.args[0]) == 7]
            self.assertEqual(sorted(shards, key=lambda shard: int(shard[0])), [["8", "4"], ["12", "4"], ["16", "3"]])
            self.assertEqual([r["seed"] for r in parallel], list(range(8, 19)))
            self.assertEqual(serial, parallel)

    def test_run_cache_uses_execution_inputs_and_file_contents(self):
        h = oracle.Harvest(self.root, "test")
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_CACHE_HOME": directory}):
            out = Path(directory)
            elf, entry, slot, _, _ = oracle.link(h, "cached", self.objects["o2"], UPDATE, out)
            plan = oracle.execution_plan(h, elf, entry, UPDATE, {UPDATE}, out)
            with patch.object(oracle, "execute_range", wraps=oracle.execute_range) as execute:
                a = oracle.cached_run(h, elf, entry, slot, "pf", 10, plan=plan)
                copy = out / "copy.elf"
                copy.write_bytes(elf.read_bytes())
                self.assertEqual(a, oracle.cached_run(h, copy, entry, slot, "pf", 10, plan=plan))
                self.assertEqual(execute.call_count, 1)
                plan.write_text(plan.read_text() + "\n")
                self.assertEqual(a, oracle.cached_run(h, copy, entry, slot, "pf", 10, plan=plan))
                self.assertEqual(execute.call_count, 2)
                # Changing an unloaded symbol-table byte keeps execution valid. Preserve size and mtime
                # so metadata alone cannot satisfy this invalidation check.
                stamp = copy.stat()
                data = bytearray(copy.read_bytes())
                data[-1] ^= 1
                copy.write_bytes(data)
                os.utime(copy, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
                self.assertEqual(a, oracle.cached_run(h, copy, entry, slot, "pf", 10, plan=plan))
                self.assertEqual(execute.call_count, 3)
                self.assertEqual(len(oracle.cached_run(h, copy, entry, slot, "pf", 11, plan=plan)), 11)
                self.assertEqual(execute.call_count, 4)
                with patch.dict(os.environ, {"ORACLE_INSTRUCTION_BUDGET": "100000000"}):
                    limited = oracle.cached_run(h, copy, entry, slot, "pf", 11, plan=plan)
                self.assertEqual(limited[0]["execution_limit"]["budget"], 100_000_000)
                self.assertEqual(execute.call_count, 5)
                with patch.dict(os.environ, {"ORACLE_INSTRUCTION_BUDGET": "0"}):
                    fallback = oracle.cached_run(h, copy, entry, slot, "pf", 11, plan=plan)
                self.assertEqual(fallback[0]["execution_limit"]["mode"], "wall-clock")
                self.assertEqual(execute.call_count, 6)

    def test_call_storage_uses_file_mappings_instead_of_whole_run_copies(self):
        import mmap

        h = oracle.Harvest(self.root, "test")
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_CACHE_HOME": directory}):
            out = Path(directory)
            elf, entry, slot, _, _ = oracle.link(h, "mapped", self.objects["o2"], UPDATE, out)
            plan = oracle.execution_plan(h, elf, entry, UPDATE, {UPDATE}, out)
            subprocess_run = subprocess.run
            spools = []

            def observe_output(*args, **kwargs):
                stream = kwargs.get("stdout")
                if hasattr(stream, "fileno"):
                    stat = os.fstat(stream.fileno())
                    spools.append((stat.st_dev, stat.st_ino))
                return subprocess_run(*args, **kwargs)

            with patch.dict(os.environ, {"ORACLE_WORKERS": "1"}), patch.object(
                    oracle.subprocess, "run", side_effect=observe_output):
                a = oracle.cached_run(h, elf, entry, slot, "pf", 10, plan=plan)
            b = oracle.cached_run(h, elf, entry, slot, "pf", 10, plan=plan)
            self.assertIsInstance(a.data, mmap.mmap)
            self.assertIsInstance(b.data, mmap.mmap)
            self.assertEqual(a, b)
            [cached] = (out / "harvest-oracle" / "runs").glob("*.bin")
            stat = cached.stat()
            self.assertEqual(spools, [(stat.st_dev, stat.st_ino)])

    def test_regular_record_output_does_not_relay_through_a_pipe(self):
        h = oracle.Harvest(self.root, "test")
        source = self.root / "direct-output.c"
        source.write_text(Path(oracle.__file__).with_name("harness.c").read_text() +
                          "\nint forbidden_pipe(int fds[2]) { _exit(77); }\n")
        harness = self.root / "direct-output"
        run(["gcc", "-O2", "-fPIE", "-pie", "-Dpipe=forbidden_pipe", str(source), "-o", str(harness), "-lm"])
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            elf, entry, slot, _, _ = oracle.link(h, "direct", self.objects["o2"], UPDATE, out)
            plan = oracle.execution_plan(h, elf, entry, UPDATE, {UPDATE}, out)
            with patch.object(oracle, "harness_binary", return_value=harness):
                records = oracle.execute_range(h, elf, entry, slot, "pf", 3, plan=plan)
            self.assertEqual([r["seed"] for r in records], [1, 2, 3])

    def test_binary_records_retain_legacy_fields_limits_and_write_budget(self):
        source = self.root / "trace.cpp"
        source.write_text('''extern void boundary(const char *, const char *, const char *, const char *, const char *, const char *);
void trace(unsigned char *p) {
  char text[64] = "captured text";
  for (int i = 0; i < 1048576; i++) p[i] = (i * 27) | 1;
  for (int i = 0; i < 4097; i++) boundary(text, text, text, text, text, text);
}
''')
        obj = self.root / "trace.o"
        run(["g++", "-O2", "-fno-pic", "-c", str(source), "-o", str(obj)])
        h = oracle.Harvest(self.root, "test")
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            symbol = "_Z5tracePh"
            elf, entry, slot, _, _ = oracle.link(h, "trace", obj, symbol, out)
            plan = oracle.execution_plan(h, elf, entry, symbol, {symbol}, out)
            packed = oracle.execute_range(h, elf, entry, slot, "p", 1, plan=plan)
            legacy = oracle.execute_range(h, elf, entry, slot, "p", 1, plan=plan, binary=False)
            self.assertEqual(json.loads(json.dumps(packed, default=oracle.record_json)), legacy)
            self.assertEqual(len(packed[0]["calls"]), 4096)
            self.assertEqual(packed[0]["outcome"], "too-many-calls")
            self.assertEqual(packed[0]["calls"][0]["deref"], [legacy[0]["calls"][0]["deref"][0]] * 6)
            self.assertEqual(len(packed[0]["calls"][0]["deref"][0]), 64)
            captured = sum(len(data) // 2 for _, data in packed[0]["writes"])
            self.assertGreater(captured, 0)
            self.assertLess(captured, 1048576)

    def test_generated_page_bytes_are_stable(self):
        # A fixed digest covers every byte in 256 pages across all four generator modes.
        source = self.root / "page-bytes.c"
        source.write_text('''#define main harness_main
#include "harness.c"
#undef main
int main(void) {
  unsigned char buffer[PAGE];
  for (seed = 0; seed < 32; seed++)
    for (uint64_t i = 0; i < 8; i++) {
      fill(REGION_BASE + (mix(i) % REGION_SIZE & ~(PAGE-1)), buffer);
      if (fwrite(buffer, 1, PAGE, stdout) != PAGE) return 1;
    }
  return 0;
}
''')
        binary = self.root / "page-bytes"
        harness = oracle.resources.files("harvest_oracle").joinpath("harness.c")
        run(["gcc", "-O2", "-fPIE", "-pie", "-I", str(Path(str(harness)).parent),
             "-o", str(binary), str(source), "-lm"])
        data = subprocess.run([str(binary)], check=True, capture_output=True).stdout
        self.assertEqual(len(data), 256 * 4096)
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         "2569ede16dfd9078272684d5c42cc2a24353cd6250e4862493886c8881e630f8")

    def test_comparison_records_omit_only_uncompared_writes(self):
        source = self.root / "capture.cpp"
        source.write_text('''extern int callee(int);
void capture(unsigned long *p, int mode) {
  *p = 123;
  if (mode == 0) *(volatile int *)0 = 1;
  if (mode == 1) for (int i=0; i<4097; i++) callee(i);
  if (mode == 2) asm volatile("mov $0x7f800000, %%eax; movd %%eax, %%xmm0; "
                             "mov $0x3f800000, %%eax; movd %%eax, %%xmm1; "
                             "1: subss %%xmm1, %%xmm0; ucomiss %%xmm1, %%xmm0; ja 1b"
                             ::: "eax", "xmm0", "xmm1", "cc");
}
''')
        obj = self.root / "capture.o"
        run(["g++", "-O2", "-fno-pic", "-c", str(source), "-o", str(obj)])
        h = oracle.Harvest(self.root, "test")
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_CACHE_HOME": directory}):
            out = Path(directory)
            symbol = "_Z7capturePmi"
            elf, entry, slot, _, _ = oracle.link(h, "capture", obj, symbol, out)
            plan = oracle.execution_plan(h, elf, entry, symbol, {symbol}, out)
            full = oracle.execute_range(h, elf, entry, slot, "pi", 200, plan=plan)
            compact = oracle.execute_range(h, elf, entry, slot, "pi", 200, plan=plan, keep_writes=False)
            self.assertEqual({r["outcome"] for r in full}, {"return", "crash", "too-many-calls", "timeout"})
            for a, b in zip(full, compact):
                self.assertTrue(a["writes"])
                self.assertEqual(b["writes"], a["writes"] if a["outcome"] == "return" else [])
                self.assertEqual(a["calls"], b["calls"])
                self.assertFalse(oracle.case_differences(a, b, [], [], h.names, {}, {}, "none"))
            # Cache entries keep diagnostic writes separate from comparison-only records.
            with patch.object(oracle, "execute_range", wraps=oracle.execute_range) as execute:
                a = oracle.cached_run(h, elf, entry, slot, "pi", 200, plan=plan)
                b = oracle.cached_run(h, elf, entry, slot, "pi", 200, plan=plan, keep_writes=False)
                self.assertEqual(execute.call_count, 2)
                self.assertEqual([r["writes"] for r in a], [r["writes"] for r in full])
                self.assertEqual([r["writes"] for r in b], [r["writes"] for r in compact])

    def test_page_budget_retries_one_sided_exhaustion_and_keys_cache(self):
        source = self.root / "pages.cpp"
        source.write_text('''extern "C" int pages() {
  volatile unsigned long *p = (volatile unsigned long *)0x100000000000UL;
  for (int i=0; i<16; i++) p[i*512] = i;
  return 7;
}
''')
        obj = self.root / "pages.o"
        run(["g++", "-O2", "-fno-pic", "-c", str(source), "-o", str(obj)])
        h = oracle.Harvest(self.root, "test")
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_CACHE_HOME": directory}):
            out = Path(directory)
            elf, entry, slot, _, _ = oracle.link(h, "pages", obj, "pages", out)
            plan = oracle.execution_plan(h, elf, entry, "pages", {"pages"}, out)
            with patch.dict(os.environ, {"ORACLE_PAGE_BUDGET": "4"}):
                limited = oracle.cached_run(h, elf, entry, slot, "", 1, plan=plan)
            complete = oracle.cached_run(h, elf, entry, slot, "", 1, plan=plan)
            self.assertEqual(limited[0]["outcome"], "timeout")
            self.assertEqual(limited[0]["timeout_reason"], "page-budget")
            self.assertEqual(limited[0]["pages"], 4)
            self.assertEqual(limited[0]["execution_limit"]["pages"], 4)
            self.assertEqual(complete[0]["outcome"], "return")
            self.assertEqual(complete[0]["pages"], 16)
            # A finite candidate exceeding the initial budget gets its full verdict.
            quick_source = self.root / "quick.cpp"
            quick_source.write_text('extern "C" int pages() { return 7; }')
            quick = self.root / "quick.o"
            run(["g++", "-O2", "-fno-pic", "-c", str(quick_source), "-o", str(quick)])
            with patch.dict(os.environ, {"ORACLE_PAGE_BUDGET": "4"}):
                report = oracle.check(h, "pages", {"slow": obj, "quick": quick, "third": quick},
                                      cases=1, returns="int", static=True, arguments="", out=out / "kept")
            self.assertEqual(report["budget_retries"]["slow vs quick"], [1])
            self.assertEqual(report["outcomes"]["slow"], {"return": 1})
            # Different writes in the returning candidate remain a difference after confirmation.
            self.assertEqual(report["comparison"]["slow vs quick"]["differ"], 1)
            for name in ("slow", "quick", "third"):
                record = json.loads((out / "kept" / (name + ".jsonl")).read_text())
                self.assertGreater(record["execution_limit"]["pages"], 4)
            self.assertTrue(oracle.budget_mismatch(limited[0], complete[0]))
            self.assertFalse(oracle.budget_mismatch(limited[0], limited[0]))

    def test_indirect_read_of_existing_page_does_not_exhaust_page_budget(self):
        source = self.root / "existing.cpp"
        source.write_text('''extern int callee(int);
extern "C" int existing() {
  volatile unsigned long *p = (volatile unsigned long *)0x100000000000UL;
  *p = (unsigned long)&callee;
  return ((int (*)(int))*p)(42);
}
''')
        obj = self.root / "existing.o"
        run(["g++", "-O2", "-fno-pic", "-c", str(source), "-o", str(obj)])
        h = oracle.Harvest(self.root, "test")
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            elf, entry, slot, _, _ = oracle.link(h, "existing", obj, "existing", out)
            plan = oracle.execution_plan(h, elf, entry, "existing", {"existing"}, out)
            [record] = oracle.execute_range(h, elf, entry, slot, "", 1, plan=plan, pages=1)
            self.assertEqual(record["outcome"], "return")
            self.assertEqual(record["pages"], 1)
            self.assertEqual(len(record["calls"]), 1)

    def test_verdict_comparison_stops_after_an_outcome_difference(self):
        class Unreadable:
            def __iter__(self):
                raise AssertionError("read calls after outcome already differed")

        a = {"outcome": "return", "rax": "0x0", "writes": [], "calls": Unreadable()}
        b = {"outcome": "crash", "detail": "0x0", "writes": [], "calls": Unreadable()}
        self.assertEqual(oracle.case_differences(a, b, [], [], {}, {}, {}, "none", first_only=True),
                         ["outcome return vs crash"])

    def test_reading_records_keeps_no_descriptor_per_run(self):
        # A comparison holds thousands of single-seed reruns at once; one descriptor each exhausts the
        # open-file limit of a service, 1,024 by default.
        from harvest_oracle.records import HEADER, MAGIC, read_records

        body = json.dumps({"outcome": "return"}).encode()
        with tempfile.TemporaryFile() as stream:
            stream.write(HEADER.pack(MAGIC, len(body), 0, 0) + body)
            stream.flush()
            before = len(os.listdir("/proc/self/fd"))
            runs = [read_records(stream) for _ in range(3000)]
            self.assertEqual(runs[-1][0]["outcome"], "return")
            self.assertLess(len(os.listdir("/proc/self/fd")) - before, 100)

    def test_binary_record_decoder_rejects_truncated_frames(self):
        with self.assertRaises(ValueError):
            oracle.decode_records(b"ORCALL01")

    def test_completed_record_emission_is_outside_the_execution_alarm(self):
        source = self.root / "output.cpp"
        source.write_text("extern int callee(int); void output_trace() { for (int i=0; i<4097; i++) callee(i); }\n")
        obj = self.root / "output.o"
        run(["g++", "-O2", "-fno-pic", "-c", str(source), "-o", str(obj)])
        h = oracle.Harvest(self.root, "test")
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            symbol = "_Z12output_tracev"
            elf, entry, slot, _, _ = oracle.link(h, "output", obj, symbol, out)
            plan = oracle.execution_plan(h, elf, entry, symbol, {symbol}, out)
            start, end = oracle.text_section(h.image)
            env = {"ORACLE_BINARY": "1", "ORACLE_PLAN": str(plan), "ORACLE_TEXT": f"0x{start:x}:0x{end:x}",
                   "ORACLE_THUNK_SLOT": hex(slot[0]), "ORACLE_PLT": h.plt}
            with subprocess.Popen([str(oracle.harness_binary()), str(h.image), str(elf), hex(entry), "", "1", "1"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, bufsize=0) as process:
                header = process.stdout.read(32)
                self.assertEqual(len(header), 32)
                # Backpressure leaves the child in emission beyond its two-second execution budget.
                time.sleep(2.1)
                output, error = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, error)
            [record] = oracle.decode_records(header + output)
            self.assertEqual(record["outcome"], "too-many-calls")
            self.assertEqual(len(record["calls"]), 4096)

    def test_record_output_errors_fail_the_run(self):
        h = oracle.Harvest(self.root, "test")
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            elf, entry, slot, _, _ = oracle.link(h, "full", self.objects["o2"], UPDATE, out)
            plan = oracle.execution_plan(h, elf, entry, UPDATE, {UPDATE}, out)
            start, end = oracle.text_section(h.image)
            env = {"ORACLE_BINARY": "1", "ORACLE_PLAN": str(plan), "ORACLE_TEXT": f"0x{start:x}:0x{end:x}",
                   "ORACLE_THUNK_SLOT": hex(slot[0]), "ORACLE_PLT": h.plt}
            with open("/dev/full", "wb") as full:
                result = subprocess.run([str(oracle.harness_binary()), str(h.image), str(elf), hex(entry), "pf", "1", "1"],
                                        stdout=full, stderr=subprocess.PIPE, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"record output", result.stderr)

    def test_direct_boundary_thunks_retain_trap_records_and_register_state(self):
        source = self.root / "boundary.s"
        source.write_text('''
.text
.globl boundary_registers
.type boundary_registers,@function
boundary_registers:
  push %rbx
  mov %rdi, %rbx
  mov $0x1234, %r10
  mov $0x5678, %r11
  pcmpeqd %xmm0, %xmm0
  pcmpeqd %xmm3, %xmm3
  xor %ecx, %ecx
  cmp %ecx, %ecx
  call _Z6calleei
  mov %r10, (%rbx)
  mov %r11, 8(%rbx)
  movups %xmm0, 16(%rbx)
  movups %xmm3, 32(%rbx)
  pushfq
  pop %rax
  mov %rax, 48(%rbx)
  stmxcsr 56(%rbx)
  call boundary_tail
  pop %rbx
  ret
.size boundary_registers,.-boundary_registers
.globl boundary_tail
.type boundary_tail,@function
boundary_tail:
  jmp _Z6calleei
.size boundary_tail,.-boundary_tail
''')
        obj = self.root / "boundary.o"
        run(["as", str(source), "-o", str(obj)])
        h = oracle.Harvest(self.root, "test")
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            elf, entry, slot, _, _ = oracle.link(h, "boundary", obj, "boundary_registers", out)
            plan = oracle.execution_plan(h, elf, entry, "boundary_registers", set(oracle.functions(obj)), out)
            self.assertEqual(sum(line.startswith("D ") for line in plan.read_text().splitlines()), 2)
            native = oracle.execute_range(h, elf, entry, slot, "p", 4, plan=plan)
            plan.write_text("\n".join("B" + line[1:] if line.startswith("D ") else line
                                      for line in plan.read_text().splitlines()) + "\n")
            trapped = oracle.execute_range(h, elf, entry, slot, "p", 4, plan=plan)
            self.assertEqual(native, trapped)
            self.assertEqual({r["outcome"] for r in native}, {"return"})
            self.assertEqual({len(r["calls"]) for r in native}, {2})

    def test_known_packed_calls_compare_without_materializing_unused_registers(self):
        from harvest_oracle.records import CALL, PackedCalls

        def trace(site, unused, argument=123):
            row = [0, 1, argument, unused, 0, 0, 0, 0, *([0] * 8), 0, site, bytes(192)]
            return {"outcome": "too-many-calls", "detail": "0x0", "writes": [],
                    "calls": PackedCalls(CALL.pack(*row) * 4096, ["callee"])}

        a, b = trace(100, 7), trace(200, 9)
        expected = oracle.case_differences({**a, "calls": list(a["calls"])},
                                           {**b, "calls": list(b["calls"])}, [], [], {}, {"callee": (1, 0)}, {}, "none")
        with patch.object(PackedCalls, "__getitem__", side_effect=AssertionError("materialized a call")):
            self.assertEqual(oracle.case_differences(a, b, [], [], {}, {"callee": (1, 0)}, {}, "none"), expected)
        self.assertTrue(oracle.case_differences(a, trace(100, 7, 124), [], [], {}, {"callee": (1, 0)}, {}, "none"))

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

    def check_lua_string(self, api, prototype, args):
        objects = {}
        for name, suffix in (("a", "x"), ("b", "y")):
            path = self.root / f"{api}-{name}.cpp"
            path.write_text(f'''extern "C" void {api}({prototype});\n'''
                            f'''static const char text[] = {{'a', 'b', 'c', 0, '{suffix}'}};\n'''
                            f'''void api_case() {{ {api}(0, {args}); }}\n''')
            obj = self.root / f"{api}-{name}.o"
            run(["g++", "-O1", "-fno-pic", "-c", "-o", str(obj), str(path)])
            objects[name] = obj
        report = oracle.check(oracle.Harvest(self.root, "test"), "_Z8api_casev", objects, cases=20,
                              returns="none", static=True)
        return report["comparison"]["a vs b"]

    def test_lua_cstring_stops_at_its_terminator(self):
        self.assertEqual(self.check_lua_string("lua_pushstring", "void *, const char *", "text")["differ"], 0)

    def test_lua_counted_string_compares_its_length(self):
        self.assertEqual(self.check_lua_string("lua_pushlstring", "void *, const char *, unsigned long",
                                               "text, 3")["differ"], 0)

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
        self.assertIn("execution_limits", line)


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

    def budget_object(self, name, body):
        source = self.root / f"{name}.cpp"
        source.write_text('extern "C" void budget_work() { ' + body + ' }')
        obj = source.with_suffix(".o")
        run(["g++", "-O1", "-fno-pic", "-c", str(source), "-o", str(obj)])
        return obj

    def budget_run(self, obj, budget, out=None):
        with patch.dict(os.environ, {"ORACLE_INSTRUCTION_BUDGET": str(budget)}):
            return oracle.check(oracle.Harvest(self.root, "test"), "budget_work", {"v": obj},
                                cases=1, returns="none", static=True, arguments="", out=out)

    def require_counter(self):
        if hasattr(oracle, "counter_status") and oracle.counter_status() != "0":
            self.skipTest("hardware instruction counter unavailable")

    def test_progressing_loop_uses_instruction_overflow(self):
        self.require_counter()
        obj = self.budget_object("progress", 'asm volatile("1: inc %%rax; jmp 1b" ::: "rax");')
        out = self.root / "progress-records"
        started = time.monotonic()
        report = self.budget_run(obj, 1_000_000, out)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(report["outcomes"]["v"], {"timeout": 1})
        record = json.loads((out / "v.jsonl").read_text())
        self.assertEqual(record["timeout_reason"], "instruction-budget")
        self.assertEqual(record["execution_limit"]["mode"], "instructions")

    def test_budget_mismatch_retries_every_version_before_comparison(self):
        self.require_counter()
        fast = self.budget_object("fast", "")
        slow = self.budget_object("slow", 'asm volatile("mov $100000, %%ecx; 1: dec %%ecx; jnz 1b" ::: "ecx");')
        with patch.dict(os.environ, {"ORACLE_INSTRUCTION_BUDGET": "50000"}):
            out = self.root / "retry-records"
            report = oracle.check(oracle.Harvest(self.root, "test"), "budget_work",
                                  {"fast": fast, "slow": slow, "third": slow}, cases=1,
                                  returns="none", static=True, arguments="", out=out)
        self.assertEqual(report["budget_retries"], {"fast vs slow": [1], "fast vs third": [1]})
        for pair in report["comparison"].values():
            self.assertEqual(pair["agree"], 1)
        for name in ("fast", "slow", "third"):
            record = json.loads((out / f"{name}.jsonl").read_text())
            self.assertEqual(record["outcome"], "return")
            self.assertEqual(record["execution_limit"]["budget"], 5_000_000)

    def test_persistent_budget_mismatch_still_reports_difference(self):
        self.require_counter()
        fast = self.budget_object("finish", "")
        slow = self.budget_object("forever", 'asm volatile("1: inc %%rax; jmp 1b" ::: "rax");')
        with patch.dict(os.environ, {"ORACLE_INSTRUCTION_BUDGET": "50000"}):
            report = oracle.check(oracle.Harvest(self.root, "test"), "budget_work", {"fast": fast, "slow": slow},
                                  cases=1, returns="none", static=True, arguments="")
        pair = report["comparison"]["fast vs slow"]
        self.assertEqual(report["budget_retries"]["fast vs slow"], [1])
        self.assertEqual(pair["differ"], 1)
        self.assertEqual(pair["layout_dependent"], 0)

    def test_counter_unavailable_uses_wall_clock_and_reports_reason(self):
        # A real kernel filter rejects perf_event_open, as restricted runners do.
        source = self.root / "deny-perf.c"
        harness = str(oracle.harness_binary())
        source.write_text(r"""
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <unistd.h>
int main(int argc, char **argv) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_perf_event_open, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {4, filter};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) return 3;
  execv(HARNESS, argv);
  return 4;
}
""")
        launcher = source.with_suffix("")
        run(["gcc", f'-DHARNESS="{harness}"', str(source), "-o", str(launcher)])
        obj = self.budget_object("fallback", 'asm volatile("1: inc %%rax; jmp 1b" ::: "rax");')
        out = self.root / "fallback-records"
        with patch.object(oracle, "harness_binary", return_value=launcher):
            report = self.budget_run(obj, 1_000_000, out)
        record = json.loads((out / "v.jsonl").read_text())
        self.assertEqual(record["timeout_reason"], "wall-clock")
        self.assertEqual(record["execution_limit"]["error"], 1)
        self.assertIn("two-second wall-clock", report["execution_limits"]["v"]["note"])

    def test_alarm_is_backstop_when_counter_cannot_see_sleep(self):
        self.require_counter()
        obj = self.budget_object("sleeping", 'asm volatile("mov $34, %%eax; syscall" ::: "rax", "rcx", "r11");')
        out = self.root / "backstop-records"
        self.budget_run(obj, 1_000_000, out)
        record = json.loads((out / "v.jsonl").read_text())
        self.assertEqual(record["execution_limit"]["mode"], "instructions")
        self.assertEqual(record["timeout_reason"], "wall-clock")

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
    def test_fixed_point_float_loop_times_out_without_waiting_for_alarm(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "orig" / "test").mkdir(parents=True)
            (root / "config" / "test").mkdir(parents=True)
            source = root / "loops.s"
            source.write_text("""
.text
.globl stalled
.type stalled,@function
stalled:
  mov $0x7f800000, %eax
  movd %eax, %xmm0
  mov $0x3f800000, %eax
  movd %eax, %xmm1
  xorps %xmm2, %xmm2
1:
  subss %xmm1, %xmm0
  ucomiss %xmm2, %xmm0
  ja 1b
  ret
.size stalled,.-stalled
.globl stalled_add
.type stalled_add,@function
stalled_add:
  mov $0x7f7fffff, %eax
  movd %eax, %xmm0
  mov $0xbf800000, %eax
  movd %eax, %xmm1
  xorps %xmm2, %xmm2
3:
  addss %xmm1, %xmm0
  ucomiss %xmm2, %xmm0
  ja 3b
  ret
.size stalled_add,.-stalled_add
.globl writes_in_loop
.type writes_in_loop,@function
writes_in_loop:
  mov $0x7f800000, %eax
  movd %eax, %xmm0
  mov $0x3f800000, %eax
  movd %eax, %xmm1
  xorps %xmm2, %xmm2
  mov $3, %ecx
4:
  subss %xmm1, %xmm0
  mov %ecx, loop_counter(%rip)
  dec %ecx
  je 5f
  ucomiss %xmm2, %xmm0
  ja 4b
5:
  ret
.size writes_in_loop,.-writes_in_loop
.globl finite
.type finite,@function
finite:
  mov $0x49742400, %eax
  movd %eax, %xmm0
  mov $0x3f800000, %eax
  movd %eax, %xmm1
  xorps %xmm2, %xmm2
2:
  subss %xmm1, %xmm0
  ucomiss %xmm2, %xmm0
  ja 2b
  ret
.size finite,.-finite
.globl _start
_start: ret
.data
.globl loop_counter
loop_counter: .long 0
""")
            obj = root / "loops.o"
            image = root / "orig" / "test" / "Harvest"
            run(["gcc", "-c", str(source), "-o", str(obj)])
            run(["ld", "-static", "-Ttext=0x400000", str(obj), "-o", str(image)])
            symbols = ["address\tsize\tsymbol"]
            for line in run(["nm", "-S", str(image)]).splitlines():
                parts = line.split()
                if len(parts) == 4:
                    symbols.append(f"0x{parts[0]}\t{int(parts[1], 16)}\t{parts[3]}")
                elif len(parts) == 3 and parts[2] == "loop_counter":
                    symbols.append(f"0x{parts[0]}\t4\t{parts[2]}")
            (root / "config" / "test" / "symbols.tsv").write_text("\n".join(symbols) + "\n")
            h = oracle.Harvest(root, "test")
            for symbol in ("stalled", "stalled_add", "finite", "writes_in_loop"):
                started = time.monotonic()
                report = oracle.check(h, symbol, {"object": obj, "image": "image"}, cases=2,
                                      returns="float", static=True, arguments="", out=root / symbol)
                self.assertLess(time.monotonic() - started, 2)
                self.assertEqual(report["comparison"]["object vs image"]["differ"], 0)
                self.assertEqual(report["outcomes"]["object"], {"timeout" if symbol.startswith("stalled") else "return": 2})
                if symbol == "finite":
                    records = [json.loads(line) for line in (root / symbol / "object.jsonl").read_text().splitlines()]
                    self.assertTrue(all(int(r["xmm0"], 16) & 0xffffffff == 0 for r in records))

                if symbol == "writes_in_loop":
                    records = [json.loads(line) for line in (root / symbol / "object.jsonl").read_text().splitlines()]
                    self.assertTrue(all(r["writes"] for r in records))
                    self.assertFalse(any(line.startswith("L ") for line in
                                         (root / symbol / "object.plan").read_text().splitlines()))

    def test_translation_rejects_values_outside_all_ranges_without_scanning(self):
        class Address(int):
            comparisons = 0

            def __le__(self, other):
                Address.comparisons += 1
                return super().__le__(other)

        ranges = oracle.AddressRanges([(Address(0x20000000 + i * 16), 8, 0x400000 + i * 8)
                                       for i in range(1000)])
        Address.comparisons = 0
        self.assertEqual(oracle.translate(0x100000000000, ranges), 0x100000000000)
        self.assertFalse(oracle.inside_ranges(0x100000000000, ranges))
        self.assertLess(Address.comparisons, 4)
        self.assertEqual(oracle.translate(0x20000002, ranges), 0x400002)
        self.assertTrue(oracle.inside_ranges(0x20000002, ranges))
        self.assertEqual(oracle.translate(0x20000008, ranges), 0x20000008)
        # Overlapping aliases retain the first range's translation.
        aliases = oracle.AddressRanges([(16, 16, 100), (8, 16, 200)])
        self.assertEqual(oracle.translate(17, aliases), 101)

    def test_packed_name_validation_avoids_per_call_unpacking(self):
        from harvest_oracle import records

        def frame(name):
            row = [0, name, *([0] * 16), bytes(192)]
            data = b'{"calls": []}'
            return records.HEADER.pack(records.MAGIC, len(data), 100, 0) + data + records.CALL.pack(*row) * 100

        with patch.object(records.struct, "unpack_from", side_effect=AssertionError("unpacked each name")):
            self.assertEqual(len(records.decode_records(frame(0))[0]["calls"]), 100)
        with self.assertRaisesRegex(ValueError, "invalid oracle call name"):
            records.decode_records(frame(1))

    def test_packed_prefix_equality_avoids_per_call_unpacking(self):
        from harvest_oracle.records import CALL, PackedCalls

        def trace(site, count=100, argument=123, target=0x500000):
            row = [target, 0, argument, 0, 0, 0, 0, 0, *([0] * 8), 0, site, bytes(192)]
            return {"outcome": "timeout", "detail": "0x0", "writes": [],
                    "calls": PackedCalls(CALL.pack(*row) * count, [])}

        a, b = trace(100), trace(200, count=101)
        with patch.object(PackedCalls, "rows", side_effect=AssertionError("unpacked each call")):
            self.assertEqual(oracle.case_differences(a, b, [], [], {}, {}, {}, "none"), [])
        for changed in (trace(200, argument=124), trace(200, target=0x600000)):
            self.assertTrue(oracle.case_differences(a, changed, [], [], {}, {}, {}, "none"))
        self.assertTrue(oracle.case_differences(a, b, [(123, 1, 500)], [], {}, {}, {}, "none"))
        self.assertTrue(oracle.case_differences(a, b, [(0x500000, 1, 0x600000)], [], {}, {}, {}, "none"))
        self.assertTrue(oracle.case_differences({**a, "outcome": "too-many-calls"},
                                               {**b, "outcome": "too-many-calls"}, [], [], {}, {}, {}, "none"))

    def test_equal_unknown_packed_calls_avoid_diagnostic_decoding(self):
        from harvest_oracle.records import CALL, PackedCalls

        def trace(site, argument=123, extra=7):
            row = [0x500000, 0, argument, 8, 9, extra, 0, 0, *([0] * 8), 0, site, bytes(192)]
            return {"outcome": "too-many-calls", "detail": "0x0", "writes": [],
                    "calls": PackedCalls(CALL.pack(*row) * 4096, [])}

        a, b = trace(100), trace(200, extra=99)
        with patch.object(PackedCalls, "__getitem__", side_effect=AssertionError("decoded an equal unknown call")):
            self.assertEqual(oracle.case_differences(a, b, [], [], {}, {}, {}, "none"), [])
        self.assertTrue(oracle.case_differences(a, trace(200, argument=124), [], [], {}, {}, {}, "none"))
        # Equal raw pointers can require different translations in the two versions.
        self.assertTrue(oracle.case_differences(a, b, [(123, 1, 500)], [], {}, {}, {}, "none"))

    def test_only_one_sided_budget_exhaustion_requires_confirmation(self):
        budget = {"outcome": "timeout", "timeout_reason": "instruction-budget"}
        for outcome in ("return", "crash", "too-many-calls", "fpe", "ill", "bus", "signal"):
            other = {"outcome": outcome}
            self.assertTrue(oracle.budget_mismatch(budget, other))
            self.assertTrue(oracle.budget_mismatch(other, budget))
        for other in (budget, {"outcome": "undefined"}, {"outcome": "timeout", "timeout_reason": "wall-clock"}):
            self.assertFalse(oracle.budget_mismatch(budget, other))

    def test_timeout_compares_only_completed_common_calls(self):
        call = {"to": "0x400000", "gp": ["0x1"] * 6, "xmm": [oracle.POISON] * 8,
                "deref": [""] * 6}
        a = {"outcome": "timeout", "detail": "0x401000", "calls": [call], "writes": []}
        b = {**a, "detail": "0x402000", "calls": [call, call], "writes": [["0x1000", "01"]]}
        self.assertEqual(oracle.case_differences(a, b, [], [], {}, {}, {}, "none"), [])
        for left, right in ((133, 122), (63, 44), (0, 3)):
            self.assertEqual(oracle.case_differences({**a, "calls": [call] * left},
                                                   {**b, "calls": [call] * right},
                                                   [], [], {}, {}, {}, "none"), [])
        changed = {**call, "to": "0x500000"}
        self.assertTrue(oracle.case_differences(a, {**b, "calls": [changed, call]}, [], [], {}, {}, {}, "none"))
        self.assertTrue(oracle.case_differences(a, {**b, "outcome": "crash"}, [], [], {}, {}, {}, "none"))

    def test_indexed_table_guard_tracks_a_computed_base_and_skips_stores(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "indexed.s"
            source.write_text("""
.section .rodata
.local factors
.type factors,@object
.size factors,12
factors:
  .long 1,2,3
.text
.globl read_index
.type read_index,@function
read_index:
  lea factors(%rip), %rax
  mov (%rax,%rdi,4), %eax
  ret
.globl write_index
.type write_index,@function
write_index:
  lea factors(%rip), %rax
  mov %esi, (%rax,%rdi,4)
  ret
.globl add_index
.type add_index,@function
add_index:
  lea factors(%rip), %rax
  add %esi, (%rax,%rdi,4)
  ret
.globl read_scalar
.type read_scalar,@function
read_scalar:
  lea factors(%rip), %rax
  mov (%rax), %eax
  ret
.globl read_offset
.type read_offset,@function
read_offset:
  mov %rdi, %rax
  add $factors, %rax
  mov (%rax), %eax
  ret
.globl read_spill
.type read_spill,@function
read_spill:
  mov %rdi, %rax
  add $factors, %rax
  mov %rax, 8(%rsp)
  mov 8(%rsp), %rdx
  mov (%rdx), %eax
  ret
.globl _start
_start:
  ret
""")
            obj = root / "indexed.o"
            elf = root / "indexed"
            run(["gcc", "-c", "-o", str(obj), str(source)])
            run(["gcc", "-nostdlib", "-no-pie", "-Wl,-Ttext=0x400000", "-o", str(elf), str(obj)])
            guard_rows = [entry.split(":") for entry in oracle.guards(elf).split(",") if entry]
            self.assertEqual(len(guard_rows), 3)
            factor = next(line.split() for line in run(["nm", "-S", str(elf)]).splitlines() if line.endswith(" factors"))
            self.assertEqual(int(guard_rows[0][2], 16), int(factor[0], 16))

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
