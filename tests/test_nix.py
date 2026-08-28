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
        self.assertEqual(len(self.inputs), 5)

    def test_nixpkgs(self):
        i = self.by_name["nixpkgs"]
        self.assertEqual(i.type, "github")
        self.assertEqual(i.ref, "NixOS/nixpkgs")
        self.assertEqual(i.rev, "2222222222222222222222222222222222222222")
        self.assertEqual(i.last_modified, "2026-01-15")

    def test_home_manager_follows_nixpkgs_unpinned(self):
        i = self.by_name["home-manager"]
        self.assertEqual(i.type, "github")
        self.assertFalse(i.local)
        self.assertFalse(i.pinned)

    def test_audio_tuning_local_unpinned(self):
        i = self.by_name["audio-tuning"]
        self.assertEqual(i.type, "path")
        self.assertTrue(i.local)
        self.assertFalse(i.pinned)

    def test_pinned_tool_pinned_not_local(self):
        i = self.by_name["pinned-tool"]
        self.assertTrue(i.pinned)
        self.assertFalse(i.local)
        self.assertEqual(i.rev, "0123456789abcdef0123456789abcdef01234567")

    def test_git_local_local_and_pinned(self):
        i = self.by_name["git-local"]
        self.assertTrue(i.local)
        self.assertTrue(i.pinned)


class AttrNamesTests(unittest.TestCase):
    def setUp(self):
        self.text = (NIXOS_FIXTURE / "flake.nix").read_text()

    def test_nixos_configurations(self):
        self.assertEqual(nix._attr_names(self.text, "nixosConfigurations"), ["example"])

    def test_home_configurations(self):
        self.assertEqual(nix._attr_names(self.text, "homeConfigurations"), ["alice"])

    def test_pick_hm_exact_user_at_host(self):
        self.assertEqual(nix.pick_hm(["a", "alice@example", "alice"], "alice", "example"), "alice@example")

    def test_pick_hm_fallback_first(self):
        self.assertEqual(nix.pick_hm(["a", "b"], "alice", "example"), "a")

    def test_pick_host_prefers_hostname(self):
        self.assertEqual(nix.pick_host(["other", "example"], "example"), "example")

    def test_pick_host_prefers_suffix_match(self):
        self.assertEqual(nix.pick_host(["x", "user@example"], "example"), "user@example")

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
            host_attr="example",
            hm_attr="alice@example",
            hm_dir=HM_FIXTURE,
            impure=True,
            impure_reasons=[],
            nix_path_extra=["nixos-config=%s" % (self.flake_dir / "configuration.nix")],
            hostname="example",
            user="alice",
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
            "%s#nixosConfigurations.example.config.system.build.toplevel" % self.flake_dir,
        )

    def test_hm_attr_path_quotes_at_sign(self):
        self.assertEqual(
            self.cfg.hm_attr_path,
            '%s#homeConfigurations."alice@example".activationPackage' % self.flake_dir,
        )

    def test_hm_attr_path_unquoted_when_simple(self):
        self.cfg.hm_attr = "alice"
        self.assertEqual(
            self.cfg.hm_attr_path,
            "%s#homeConfigurations.alice.activationPackage" % self.flake_dir,
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
