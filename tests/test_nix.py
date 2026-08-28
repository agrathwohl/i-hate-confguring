import shutil
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from ihc import nix

from fixture_helpers import HM_FIXTURE, NIXOS_FIXTURE, make_nixos_tmp


class LockInputsTests(unittest.TestCase):
    def setUp(self):
        self.inputs = nix.lock_inputs(NIXOS_FIXTURE)
        self.by_name = {i.name: i for i in self.inputs}

    def test_count(self):
        self.assertEqual(len(self.inputs), 23)

    def test_nixpkgs(self):
        i = self.by_name["nixpkgs"]
        self.assertEqual(i.type, "github")
        self.assertEqual(i.ref, "NixOS/nixpkgs")
        self.assertEqual(i.rev, "56c02bc00adcf003215cc4bd996d6efaf4cff188")
        self.assertEqual(i.last_modified, "2026-08-23")

    def test_musnix_local_unpinned(self):
        i = self.by_name["musnix"]
        self.assertTrue(i.local)
        self.assertFalse(i.pinned)

    def test_hermes_agent_pinned(self):
        i = self.by_name["hermes-agent"]
        self.assertTrue(i.pinned)
        self.assertFalse(i.local)

    def test_nix_moltbot_local_and_pinned(self):
        i = self.by_name["nix-moltbot"]
        self.assertTrue(i.local)
        self.assertTrue(i.pinned)


class AttrNamesTests(unittest.TestCase):
    def setUp(self):
        self.text = (NIXOS_FIXTURE / "flake.nix").read_text()

    def test_nixos_configurations(self):
        self.assertEqual(nix._attr_names(self.text, "nixosConfigurations"), ["flynix"])

    def test_home_configurations(self):
        self.assertEqual(nix._attr_names(self.text, "homeConfigurations"), ["gwohl"])

    def test_pick_hm_exact_user_at_host(self):
        self.assertEqual(nix.pick_hm(["a", "gwohl@flynix", "gwohl"], "gwohl", "flynix"), "gwohl@flynix")

    def test_pick_hm_fallback_first(self):
        self.assertEqual(nix.pick_hm(["a", "b"], "gwohl", "flynix"), "a")

    def test_pick_host_prefers_hostname(self):
        self.assertEqual(nix.pick_host(["other", "flynix"], "flynix"), "flynix")

    def test_pick_host_prefers_suffix_match(self):
        self.assertEqual(nix.pick_host(["x", "user@flynix"], "flynix"), "user@flynix")

    def test_pick_host_fallback_first(self):
        self.assertEqual(nix.pick_host(["a", "b"], "nomatch"), "a")


class ImpureRequirementsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = make_nixos_tmp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.reasons, self.nix_path = nix.impure_requirements(self.tmp)

    def test_reasons_mention_expected_causes(self):
        joined = "\n".join(self.reasons)
        for needle in ("channel import", "fetchTarball", "copySystemConfiguration", "absolute path module"):
            self.assertIn(needle, joined, "missing reason for %r in: %s" % (needle, joined))

    def test_nix_path_points_at_configuration(self):
        expected = "nixos-config=%s" % (self.tmp / "configuration.nix")
        self.assertIn(expected, self.nix_path)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.flake_dir = Path("/tmp/does-not-need-to-exist")
        self.cfg = nix.Config(
            platform="nixos",
            flake_dir=self.flake_dir,
            host_attr="flynix",
            hm_attr="gwohl@flynix",
            hm_dir=HM_FIXTURE,
            impure=True,
            impure_reasons=[],
            nix_path_extra=["nixos-config=%s" % (self.flake_dir / "configuration.nix")],
            hostname="flynix",
            user="gwohl",
            docs_dir=self.flake_dir,
        )

    def test_nix_args(self):
        self.assertEqual(
            self.cfg.nix_args(),
            ["--impure", "-I", "nixos-config=%s" % (self.flake_dir / "configuration.nix")],
        )

    def test_env_nix_path_starts_with_extra(self):
        with mock.patch.dict("os.environ", {"NIX_PATH": "nixpkgs=flake:nixpkgs"}, clear=False):
            env = self.cfg.env()
        self.assertTrue(env["NIX_PATH"].startswith("nixos-config=%s" % (self.flake_dir / "configuration.nix")))

    def test_system_attr(self):
        self.assertEqual(
            self.cfg.system_attr,
            "%s#nixosConfigurations.flynix.config.system.build.toplevel" % self.flake_dir,
        )

    def test_hm_attr_path_quotes_at_sign(self):
        self.assertEqual(
            self.cfg.hm_attr_path,
            '%s#homeConfigurations."gwohl@flynix".activationPackage' % self.flake_dir,
        )

    def test_hm_attr_path_unquoted_when_simple(self):
        self.cfg.hm_attr = "gwohl"
        self.assertEqual(
            self.cfg.hm_attr_path,
            "%s#homeConfigurations.gwohl.activationPackage" % self.flake_dir,
        )


class GenerationsTests(unittest.TestCase):
    def test_counts_and_orders_numerically(self):
        tmp = Path(__import__("tempfile").mkdtemp(prefix="ihc-gens-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        for name in ("system-1-link", "system-2-link", "system-10-link", "system-old", "other-3-link"):
            (tmp / name).touch()
        gens = nix.generations(tmp / "system")
        self.assertEqual([p.name for p in gens], ["system-1-link", "system-2-link", "system-10-link"])


class StorePathDateTests(unittest.TestCase):
    def test_parses_date_from_version_file(self):
        tmp = Path(__import__("tempfile").mkdtemp(prefix="ihc-ver-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "nixos-version").write_text("26.11.20260804.e72e4f2")
        result = nix.store_path_date(tmp)
        self.assertEqual(result, datetime(2026, 8, 4, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()
