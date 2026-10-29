"""Basic-block measurement uses each block's first visit in a case."""

import tempfile
import unittest
from pathlib import Path

from harvest_oracle import oracle


class CoverageTests(unittest.TestCase):
    def test_blocks_include_jump_targets_and_fallthroughs(self):
        from harvest_oracle.coverage import basic_blocks
        code = [(10, 2, 'cmp', '$7,%eax'), (12, 2, 'je', '10 <f+6>'),
                (14, 2, 'jmp', '12 <f+8>'), (16, 2, 'xor', '%eax,%eax'),
                (18, 1, 'ret', '')]
        self.assertEqual(basic_blocks(code), [10, 14, 16, 18])

    def test_block_probe_preserves_native_result_and_counts_once(self):
        from harvest_oracle.coverage import add_probes, summarize
        # Reuse the real executable and object fixture, not an emulation of the plan format.
        from test_harvest_oracle import SyntheticCheckout, UPDATE
        SyntheticCheckout.setUpClass()
        try:
            h = oracle.Harvest(SyntheticCheckout.root, 'test')
            with tempfile.TemporaryDirectory() as scratch:
                out = Path(scratch)
                elf, entry, slot, *_ = oracle.link(h, 'probe', SyntheticCheckout.objects['o2'], UPDATE, out)
                plan = oracle.execution_plan(h, elf, entry, UPDATE, {UPDATE}, out)
                plain = oracle.execute(h, elf, entry, slot, 'pf', 20, plan=plan)
                blocks = add_probes(plan, elf, entry)
                measured = oracle.execute(h, elf, entry, slot, 'pf', 20, plan=plan)
                for a, b in zip(plain, measured):
                    b = dict(b)
                    hits = b.pop('blocks')
                    self.assertEqual(len(hits), len(set(hits)))
                    self.assertEqual(a, b)
                counts = summarize(blocks, measured)
                self.assertEqual(counts['cases'], 20)
                self.assertEqual(counts['hits'][hex(entry)], 20)
                self.assertGreater(counts['reached'], 1)
        finally:
            SyntheticCheckout.tearDownClass()
