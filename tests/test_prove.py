import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ihc import prove


class DecideModeTests(unittest.TestCase):
    def test_kernel_change_forces_boot(self):
        tmp = Path(tempfile.mkdtemp(prefix="ihc-kernel-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        current, new = tmp / "current", tmp / "new"
        current.mkdir()
        new.mkdir()
        target_a, target_b = tmp / "kernel-a", tmp / "kernel-b"
        target_a.write_text("A")
        target_b.write_text("B")
        (current / "kernel").symlink_to(target_a)
        (new / "kernel").symlink_to(target_b)
        mode, reasons = prove.decide_mode(current, new, {}, [])
        self.assertEqual(mode, "boot")
        self.assertTrue(reasons)

    def test_guarded_unit_restart_forces_boot(self):
        mode, reasons = prove.decide_mode(None, Path("/nonexistent-new"), {"restart": ["audio-daemon.service"]}, ["audio-daemon.service"])
        self.assertEqual(mode, "boot")
        self.assertTrue(any("audio-daemon.service" in r for r in reasons))

    def test_nothing_notable_switches(self):
        mode, reasons = prove.decide_mode(None, Path("/nonexistent-new"), {}, [])
        self.assertEqual(mode, "switch")
        self.assertEqual(reasons, [])


class HealthRegressionsTests(unittest.TestCase):
    def test_new_failed_unit(self):
        regs = prove.health_regressions({"failed_units": []}, {"failed_units": ["foo.service"]})
        self.assertTrue(any("foo.service" in r for r in regs))

    def test_true_to_false_is_a_regression(self):
        regs = prove.health_regressions({"docker.service": True}, {"docker.service": False})
        self.assertTrue(any("docker.service" in r for r in regs))

    def test_false_to_true_is_not_a_regression(self):
        regs = prove.health_regressions({"docker.service": False}, {"docker.service": True})
        self.assertEqual(regs, [])

    def test_unchanged_is_empty(self):
        before = {"failed_units": [], "docker.service": True}
        after = {"failed_units": [], "docker.service": True}
        self.assertEqual(prove.health_regressions(before, after), [])


class VerdictTests(unittest.TestCase):
    def test_summary_failed(self):
        v = prove.Verdict(ok=False, failed_step="build-system", failed_target="system")
        self.assertEqual(v.summary(), "FAILED at build-system (system)")

    def test_summary_ok(self):
        v = prove.Verdict(ok=True, system_path=Path("/a"), hm_path=Path("/b"), mode="switch")
        self.assertEqual(v.summary(), "ok: system built, hm built, mode=switch")

    def test_as_dict_keys(self):
        v = prove.Verdict()
        keys = set(v.as_dict().keys())
        self.assertEqual(
            keys,
            {
                "ok", "failed_step", "failed_target", "system_path", "hm_path", "units",
                "closure_bytes", "mode", "mode_reasons", "notes", "summary",
            },
        )


class BootShortTests(unittest.TestCase):
    def test_short_when_free_below_twice_need(self):
        facts = {"runtime": {"disk": {"boot": {"free_gib": 1.0}, "boot_need_mib": 1000}}}
        self.assertTrue(prove.boot_short(facts))

    def test_not_short_when_plenty_free(self):
        facts = {"runtime": {"disk": {"boot": {"free_gib": 10.0}, "boot_need_mib": 100}}}
        self.assertFalse(prove.boot_short(facts))



class StaleLocalInputTests(unittest.TestCase):
    def test_parses_path_input_from_error(self):
        import tempfile, json
        from pathlib import Path
        from ihc import nix, prove
        with tempfile.TemporaryDirectory() as d:
            fd = Path(d)
            (fd / "flake.nix").write_text('{ inputs.musnix.url = "path:/home/u/musnix"; outputs = _: {}; }')
            (fd / "flake.lock").write_text(json.dumps({"root": "root", "nodes": {"root": {"inputs": {"musnix": "musnix"}}, "musnix": {"locked": {"type": "path", "path": "/home/u/musnix", "lastModified": 1}}}}))
            cfg = nix.Config("nixos", fd, "h", None, None, True, [], [], "h", "u", fd)
            err = "error: NAR hash mismatch in input 'path:/home/u/musnix?lastModified=1&narHash=sha256-x', expected 'a' but got 'b'"
            self.assertEqual(prove.stale_local_input(err, cfg), "musnix")
            self.assertIsNone(prove.stale_local_input("error: something else", cfg))


class ActivationUnitsTests(unittest.TestCase):
    def test_parses_system_and_hm_activation_output(self):
        from ihc import prove
        text = ("stopping the following units: foo.service, bar.socket\n"
                "restarting the following units: audio-daemon.service\n"
                "starting the following units: baz.timer\n"
                "Starting units: bar.service notifier.service\n"
                "Restarting services: idle-daemon.service\n")
        u = prove.units_from_activation(text)
        self.assertEqual(u["stop"], ["foo.service", "bar.socket"])
        self.assertEqual(u["restart"], ["audio-daemon.service", "idle-daemon.service"])
        self.assertIn("baz.timer", u["start"])
        self.assertIn("bar.service", u["start"])


class GenericHealthTests(unittest.TestCase):
    def test_active_units_and_ports_regressions(self):
        from ihc import prove
        before = {"failed_units": [], "active_units": ["a.service", "audio-daemon.service"], "listening_ports": ["22", "5432"], "default_route": True, "probe:card": True}
        after = {"failed_units": ["x.service"], "active_units": ["a.service"], "listening_ports": ["22"], "default_route": True, "probe:card": False}
        regs = prove.health_regressions(before, after)
        self.assertTrue(any("x.service" in r for r in regs))
        self.assertTrue(any("audio-daemon.service" in r for r in regs))
        self.assertTrue(any("5432" in r for r in regs))
        self.assertTrue(any("probe:card" in r for r in regs))
        self.assertEqual(prove.health_regressions(before, before), [])

    def test_busy_checks_come_from_host_rules(self):
        from unittest.mock import patch
        from ihc import prove
        facts = {"host_rules": {"busy_checks": {"daw": "true", "never": "false"}}}
        self.assertEqual(prove.busy(facts), ["daw"])
        self.assertEqual(prove.busy({}), [])

    def test_guard_patterns_and_list(self):
        from pathlib import Path
        from ihc import prove
        mode, reasons = prove.decide_mode(None, Path("/"), {"restart": ["display-manager.service"]}, [], [r"display-manager"])
        self.assertEqual(mode, "boot")
        mode, _ = prove.decide_mode(None, Path("/"), {"restart": ["audio-daemon.service"]}, ["audio-daemon.service"], [])
        self.assertEqual(mode, "boot")
        mode, _ = prove.decide_mode(None, Path("/"), {"restart": ["foo.service"]}, ["audio-daemon.service"], [r"display-manager"])
        self.assertEqual(mode, "switch")
