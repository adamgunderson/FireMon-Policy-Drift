"""The last-run state file."""

import os
import shutil
import tempfile
import unittest

import support  # noqa: F401

from firemon_drift import state


class StateFile(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def test_path_is_per_pair_and_filesystem_safe(self):
        path = state.state_path(self.work, "us dr/pair:1")
        self.assertEqual(os.path.basename(path), "last-us_dr_pair_1.json")

    def test_missing_state_means_first_run(self):
        self.assertEqual(state.load_previous(os.path.join(self.work, "nope.json")), (None, None))

    def test_round_trip(self):
        path = state.state_path(self.work, "A")
        state.save(path, ["changed|r|action", "only_primary|x"], support.RUN_TIME,
                   {"changed": 1, "only_primary": 1, "only_secondary": 0})
        prints, when = state.load_previous(path)
        self.assertEqual(prints, ["changed|r|action", "only_primary|x"])
        self.assertTrue(when.startswith("2026-09-18T06:00:00"))
        self.assertFalse(os.path.exists(path + ".tmp"))

    def test_corrupt_state_is_ignored_with_a_warning(self):
        path = os.path.join(self.work, "bad.json")
        with open(path, "w") as handle:
            handle.write("{not json")
        with self.assertLogs("firemon_drift.state", level="WARNING"):
            self.assertEqual(state.load_previous(path), (None, None))
        with open(path, "w") as handle:
            handle.write('{"fingerprints": "not-a-list"}')
        with self.assertLogs("firemon_drift.state", level="WARNING"):
            self.assertEqual(state.load_previous(path), (None, None))


if __name__ == "__main__":
    unittest.main()
