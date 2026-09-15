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
        verbs = {"facts", "status", "adopt", "check", "bump", "fix", "switch", "review", "run", "docs", "aesthetics", "security", "notify", "pending", "mcp"}
        sub = next(a for a in cli.build_parser()._actions if a.dest == "cmd")
        self.assertTrue(verbs <= set(sub.choices))

    def test_security_declares_every_flag_it_reads(self):
        ns = cli.build_parser().parse_args(["security", "--fix", "--cve", "--json"])
        self.assertTrue(ns.fix and ns.cve and ns.json)
        self.assertEqual(ns.max_attempts, 3)


if __name__ == "__main__":
    unittest.main()


class VerbFlagsAreDeclaredTests(unittest.TestCase):
    """Every verb whose handler reads args.<flag> must declare that flag (a deleted flag is a crash)."""

    def test_fix_flag_exists_on_every_verb_whose_handler_uses_it(self):
        from ihc import cli
        parser = cli.build_parser()
        sub = next(a for a in parser._actions if hasattr(a, "choices") and a.choices)
        for verb in ("aesthetics", "security"):
            flags = {o for act in sub.choices[verb]._actions for o in act.option_strings}
            self.assertIn("--fix", flags, verb)
            self.assertIn("--json", flags, verb)
