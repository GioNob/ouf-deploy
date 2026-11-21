"""Functional network aliases: inherited container-ID aliases are not part of the reviewed binding."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from module_release import frame  # noqa: E402


class FunctionalAliases(unittest.TestCase):
    def test_inherited_short_ids_are_ignored(self):
        cid = "d238777c24a3" + "0" * 52
        ep = {"Aliases": ["ouf-onboarding", "6f1a42b69d2a", "d0b9ff8400f8", "d238777c24a3"]}
        self.assertEqual(frame.aliases(ep, cid), ["ouf-onboarding"])
        self.assertEqual(frame.functional(["ouf-onboarding", "4a8bc37fc065"]), ["ouf-onboarding"])

    def test_functional_alias_change_is_still_detected(self):
        cid = "a" * 64
        ep = {"Aliases": ["ouf-onboarding", "ouf-extra", "b" * 12]}
        self.assertNotEqual(frame.aliases(ep, cid), frame.functional(["ouf-onboarding"]))

    def test_names_that_only_look_short_are_kept(self):
        self.assertEqual(frame.functional(["ouf-udp", "abcdef12345", "ABCDEF123456"]),
                         ["ABCDEF123456", "abcdef12345", "ouf-udp"])


if __name__ == "__main__":
    unittest.main()
