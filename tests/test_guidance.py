"""Comparison constants must change inputs equally for every version."""

import unittest

from harvest_oracle import oracle
import test_harvest_oracle as fixtures

run = fixtures.run


class GuidanceTests(unittest.TestCase):
    setUpClass = fixtures.SyntheticCheckout.__dict__["setUpClass"]
    tearDownClass = fixtures.SyntheticCheckout.__dict__["tearDownClass"]
    def test_rare_boundary_and_memory_tags_reach_dependent_reads(self):
        (self.root / 'src').mkdir(exist_ok=True)
        (self.root / 'src' / 'guided.h').write_text('int taggedValue();\n')
        source = '''extern int taggedValue();
struct Header { int tag; int count; };
int guided(Header *p) {
  if (taggedValue() != 0x12345) return 0;
  if (p->tag != 0x73) return 0;
  int first = taggedValue();
  int second = taggedValue();
  return first + 7 * second;
}
'''
        versions = {}
        for name, text in [('a', source), ('b', source.replace('first + 7 * second', 'second + 7 * first')),
                           ('same', source.replace('first + 7 * second', '7 * second + first'))]:
            path = self.root / f'guided-{name}.cpp'
            path.write_text(text)
            obj = path.with_suffix('.o')
            run(['g++', '-O2', '-fno-pic', '-c', str(path), '-o', str(obj)])
            versions[name] = obj
        report = oracle.check(oracle.Harvest(self.root, 'test'), '_Z6guidedP6Header', versions,
                              cases=2000, returns='int', static=True)
        self.assertGreater(report['comparison']['a vs b']['differ'], 10)
        self.assertEqual(report['comparison']['a vs same']['differ'], 0)

    def test_zero_memory_lane_preserves_statically_used_root_pointer(self):
        (self.root / 'src').mkdir(exist_ok=True)
        (self.root / 'src' / 'root-pointer.h').write_text('int rootTag();\n')
        source = '''extern int rootTag();
struct File { virtual int touch() = 0; };
struct Empty { long begin; long end; };
int rootPointer(Empty *p, File *file) {
  if (rootTag() != 0x11 || p->begin || p->end) return 0;
  file->touch();
  int a = rootTag();
  int b = rootTag();
  return a + 7 * b;
}
'''
        versions = {}
        for name, text in [('a', source), ('b', source.replace('a + 7 * b', 'b + 7 * a'))]:
            path = self.root / f'root-{name}.cpp'
            path.write_text(text)
            obj = path.with_suffix('.o')
            run(['g++', '-O2', '-fno-pic', '-c', str(path), '-o', str(obj)])
            versions[name] = obj
        report = oracle.check(oracle.Harvest(self.root, 'test'), '_Z11rootPointerP5EmptyP4File', versions,
                              cases=500, returns='int', static=True)
        self.assertGreater(report['comparison']['a vs b']['differ'], 5)

    def test_unguided_seeds_retain_every_generated_input(self):
        from pathlib import Path
        import tempfile
        h = oracle.Harvest(self.root, 'test')
        with tempfile.TemporaryDirectory() as scratch:
            out = Path(scratch)
            elf, entry, slot, *_ = oracle.link(h, 'plain', self.objects['o2'], fixtures.UPDATE, out)
            plan = oracle.execution_plan(h, elf, entry, fixtures.UPDATE, {fixtures.UPDATE}, out)
            plain = oracle.execute(h, elf, entry, slot, 'pf', 32, plan=plan)
            oracle.guide_plans(h, [(elf, entry, plan)], fixtures.UPDATE)
            guided = oracle.execute(h, elf, entry, slot, 'pf', 32, plan=plan)
            for a, b in zip(plain, guided):
                if a['seed'] % 8 != 4:
                    self.assertEqual(a, b)

    def test_static_flow_copies_spills_and_joins(self):
        from harvest_oracle.guidance import comparisons
        code = [(10, 5, 'call', '100 <value>'), (15, 2, 'mov', '%eax,%ebx'),
                (17, 3, 'mov', '%ebx,0x8(%rsp)'), (20, 3, 'mov', '0x8(%rsp),%ecx'),
                (23, 3, 'sub', '$0x2,%ecx'), (26, 3, 'cmp', '$0x21,%ecx'),
                (29, 3, 'cmpl', '$0x73,0x4(%rdi)'), (32, 1, 'ret', '')]
        found = comparisons(code, {0x100: 'value'})
        self.assertEqual(found[('S', 'value')], {0x23})
        # rdi is caller-saved, so a memory base that crosses the call is unproven.
        self.assertFalse(any(key[0] == 'M' for key in found))
        memory = [(10, 3, 'mov', '%rdi,%rbx'), (13, 3, 'mov', '0x18(%rbx),%rax'),
                  (16, 4, 'cmpl', '$0x73,0x4(%rax)'), (20, 1, 'ret', '')]
        self.assertEqual(comparisons(memory, {}), {('M', 'arg0.0x18', 4, 4): {0x73}})

    def test_version_order_does_not_change_pooled_inputs(self):
        versions = {}
        for tag in (0x73, 0x74):
            path = self.root / f'tag-{tag}.cpp'
            path.write_text(f'int tag(int *p) {{ return *p == {tag}; }}')
            obj = path.with_suffix('.o')
            run(['g++', '-O2', '-fno-pic', '-c', str(path), '-o', str(obj)])
            versions[str(tag)] = obj
        h = oracle.Harvest(self.root, 'test')
        a = oracle.check(h, '_Z3tagPi', versions, cases=80, returns='int', static=True)
        b = oracle.check(h, '_Z3tagPi', dict(reversed(list(versions.items()))),
                         cases=80, returns='int', static=True)
        self.assertEqual(a['input_guidance'], b['input_guidance'])
        self.assertEqual(next(iter(a['comparison'].values()))['differ'],
                         next(iter(b['comparison'].values()))['differ'])
        self.assertGreater(next(iter(a['comparison'].values()))['differ'], 0)
