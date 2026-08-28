import unittest

from ihc import cli


class DispatchTests(unittest.TestCase):
    def test_version(self):
        code, out = cli.dispatch(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("ihc 0.1.0", out)

    def test_unknown_verb_is_nonzero(self):
        code, _ = cli.dispatch(["definitely-not-a-verb"])
        self.assertNotEqual(code, 0)

    def test_review_does_not_activate_by_default(self):
        p = cli.build_parser()
        ns = p.parse_args(["review"])
        self.assertFalse(ns.activate)
        self.assertTrue(p.parse_args(["review", "--activate"]).activate)

    def test_parser_has_every_verb(self):
        verbs = {"facts", "status", "adopt", "check", "bump", "fix", "switch", "review", "run", "docs", "notify", "pending", "mcp"}
        sub = next(a for a in cli.build_parser()._actions if a.dest == "cmd")
        self.assertTrue(verbs <= set(sub.choices))


if __name__ == "__main__":
    unittest.main()
