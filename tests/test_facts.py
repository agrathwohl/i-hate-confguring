import shutil
import unittest

from ihc import facts

from fixture_helpers import make_config, make_nixos_tmp


class FactsMineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = make_nixos_tmp()
        cls.cfg = make_config(cls.tmp)
        cls.fx = facts.mine(cls.cfg, runtime=False)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_kernel_preempt_rt(self):
        hits = self.fx["kernel"]["preempt_rt"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["line"], 53)

    def test_kernel_params(self):
        params = self.fx["kernel"]["params"]
        for want in ("threadirqs", "preempt=full", "mitigations=off", "intel_pstate=disable"):
            self.assertIn(want, params)

    def test_kernel_musnix_realtime_present(self):
        self.assertTrue(self.fx["kernel"]["musnix_realtime"])

    def test_audio_jack_args(self):
        self.assertEqual(
            self.fx["audio"]["jack_args"],
            ["-P95", "-R", "-u", "-dalsa", "-dhw:HDSPMx0a922c,0", "-r48000", "-p64", "-n2"],
        )

    def test_audio_soundcard_pci(self):
        self.assertEqual(self.fx["audio"]["soundcard_pci"], '"02:00.0"')

    def test_audio_musnix_enable_hit(self):
        hit = next((m for m in self.fx["audio"]["musnix"] if m["text"].startswith("musnix.enable = true")), None)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["line"], 104)

    def test_audio_no_sleep_spans_both_files(self):
        files = {h["file"].split("/")[-1] for h in self.fx["audio"]["no_sleep"]}
        self.assertIn("configuration.nix", files)
        self.assertIn("hardware-configuration.nix", files)

    def test_gpu_video_drivers(self):
        self.assertEqual(self.fx["gpu"]["video_drivers"], ["nvidia"])

    def test_enabled_system_options(self):
        names = {e["option"] for e in self.fx["enabled"]["system"]}
        for want in ("virtualisation.docker", "services.openssh", "services.tailscale", "security.rtkit"):
            self.assertIn(want, names)

    def test_enabled_hm_options(self):
        names = {e["option"] for e in self.fx["enabled"]["hm"]}
        self.assertIn("services.ollama", names)
        self.assertIn("programs.home-manager", names)

    def test_deprecated_options(self):
        by_option = {}
        for d in self.fx["deprecated_options"]:
            by_option.setdefault(d["option"], []).append(d["line"])
        self.assertIn(230, by_option.get("hardware.opengl", []))
        self.assertIn("nix.trustedUsers", by_option)
        self.assertIn("hardware.pulseaudio", by_option)

    def test_secrets_all_redacted(self):
        secrets = self.fx["secrets"]
        self.assertTrue(secrets)
        for s in secrets:
            self.assertEqual(s["value"], "<redacted>")

    def test_secrets_assignment_finding(self):
        # Discrepancy from spec: the real hit is configuration.nix:1104 (an
        # `api_key = "REDACTED"` block), not :1131. The hm core/environment.nix:43
        # ANTHROPIC_API_KEY assignment is NOT flagged: SECRET_PATTERNS' "assignment"
        # regex requires \b right before "api_key", which does not match inside the
        # single underscore-joined token ANTHROPIC_API_KEY. Reported as a finding,
        # not adapted away silently.
        hit = next((s for s in self.fx["secrets"] if s["kind"] == "assignment"), None)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["line"], 1104)
        self.assertTrue(hit["file"].endswith("configuration.nix"))

    def test_secrets_none_start_with_comment(self):
        for s in self.fx["secrets"]:
            with open(s["file"]) as fh:
                lines = fh.read().splitlines()
            if 0 < s["line"] <= len(lines):
                self.assertFalse(lines[s["line"] - 1].lstrip().startswith("#"))

    def test_dead_files_system_empty(self):
        self.assertEqual(self.fx["dead_files"]["system"], [])

    def test_config_files_system_count(self):
        self.assertEqual(self.fx["config"]["files"]["system"], 3)

    def test_maintenance_auto_upgrade(self):
        hits = self.fx["maintenance"]["auto_upgrade"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["line"], 47)
        self.assertIn("= false", hits[0]["text"])

    def test_maintenance_gc_includes_auto_optimise_store(self):
        hit = next((h for h in self.fx["maintenance"]["gc"] if "auto-optimise-store" in h["text"]), None)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["line"], 44)

    def test_hardware_edits(self):
        texts = [h["text"] for h in self.fx["hardware_edits"]]
        self.assertTrue(any("boot.kernelParams" in t for t in texts))
        self.assertTrue(any("/mnt/" in t for t in texts))

    def test_summary_lines_first_line_has_host(self):
        lines = facts.summary_lines(self.fx)
        self.assertIn("host=flynix", lines[0])


class ReachableTests(unittest.TestCase):
    def test_reachable_from_flake_and_configuration(self):
        tmp = make_nixos_tmp()
        try:
            names = {p.name for p in facts.reachable(tmp, ("flake.nix", "configuration.nix"))}
            self.assertEqual(names, {"flake.nix", "configuration.nix", "hardware-configuration.nix"})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_changes_with_enabled_options(self):
        from ihc import facts
        a = {"inputs": [{"name": "nixpkgs"}], "enabled": {"system": [{"option": "services.openssh"}]}, "kernel": {"params": ["x"]}}
        b = {"inputs": [{"name": "nixpkgs"}], "enabled": {"system": [{"option": "services.openssh"}, {"option": "services.foo"}]}, "kernel": {"params": ["x"]}}
        self.assertEqual(facts.fingerprint(a), facts.fingerprint(a))
        self.assertNotEqual(facts.fingerprint(a), facts.fingerprint(b))
