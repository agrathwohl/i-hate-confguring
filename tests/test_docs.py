import shutil
import tempfile
import unittest
from pathlib import Path

from ihc import docs, nix

from fixture_helpers import HM_FIXTURE, NIXOS_FIXTURE


def _cfg(docs_dir):
    return nix.Config(
        platform="nixos",
        flake_dir=NIXOS_FIXTURE,
        host_attr="flynix",
        hm_attr="gwohl",
        hm_dir=HM_FIXTURE,
        impure=True,
        impure_reasons=[],
        nix_path_extra=[],
        hostname="flynix",
        user="gwohl",
        docs_dir=docs_dir,
    )


class CheckAllTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ihc-docs-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "GOALS.md").write_text(
            "Realtime kernel proven at `configuration.nix:53`.\n"
            "Bogus far pointer at configuration.nix:99999.\n"
        )
        (self.tmp / "MAINTENANCE.md").write_text(
            "Unresolved reference: nope.nix:1.\n"
            "Blank line reference: configuration.nix:21.\n"
        )
        self.cfg = _cfg(self.tmp)

    def test_counts_and_reports_exactly_three_problems(self):
        count, problems = docs.check_all(self.cfg, self.tmp)
        self.assertEqual(count, 4)
        self.assertEqual(len(problems), 3)
        joined = "\n".join(problems)
        self.assertIn("beyond EOF", joined)
        self.assertIn("unresolved path nope.nix", joined)
        self.assertIn("is a blank line", joined)


class CheckCitationsResolutionTests(unittest.TestCase):
    def test_backticked_and_hm_base_citations_resolve(self):
        tmp = Path(tempfile.mkdtemp(prefix="ihc-cite-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        doc = tmp / "NOTES.md"
        doc.write_text(
            "See `hardware-configuration.nix:32` for kernel params.\n"
            "Also see `core/base.nix:15` for stateVersion.\n"
        )
        problems = docs.check_citations(doc, [NIXOS_FIXTURE, HM_FIXTURE])
        self.assertEqual(problems, [])


class RegenPromptTests(unittest.TestCase):
    def test_contains_done_marker(self):
        cfg = _cfg(NIXOS_FIXTURE)
        prompt = docs.regen_prompt(cfg, "{}", NIXOS_FIXTURE)
        self.assertIn("IHC-DONE", prompt)


if __name__ == "__main__":
    unittest.main()


class HostRulesTests(unittest.TestCase):
    def test_parses_machine_readable_sections(self):
        import tempfile
        from pathlib import Path
        from ihc import docs
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "MAINTENANCE.md").write_text(
                "# M\n\n## Guarded units\n\n- jack.service\n- `docker.service`\n\n## Health probes\n\n"
                "- hdsp: grep -q HDSP /proc/asound/cards\n- `nvidia`: `nvidia-smi -L`\n\n## Busy checks\n\n- daw: pgrep -x ardour\n\n## Queue\n\n- [ ] (risk: low) x\n")
            r = docs.host_rules(Path(tmp))
            self.assertEqual(r["guarded_units"], ["jack.service", "docker.service"])
            self.assertEqual(r["health_probes"]["hdsp"], "grep -q HDSP /proc/asound/cards")
            self.assertEqual(r["health_probes"]["nvidia"], "nvidia-smi -L")
            self.assertEqual(r["busy_checks"], {"daw": "pgrep -x ardour"})
        self.assertEqual(docs.host_rules(Path("/nonexistent")), {"guarded_units": [], "health_probes": {}, "busy_checks": {}})
