import os
import shutil
import unittest
from unittest import mock

from ihc import agent, nix

from fixture_helpers import HM_FIXTURE, make_config, make_nixos_tmp


def _cfg(flake_dir, hm_dir):
    return nix.Config(
        platform="nixos",
        flake_dir=flake_dir,
        host_attr="example",
        hm_attr="alice",
        hm_dir=hm_dir,
        impure=True,
        impure_reasons=[],
        nix_path_extra=["nixos-config=%s" % (flake_dir / "configuration.nix")],
        hostname="example",
        user="alice",
        docs_dir=flake_dir,
    )


class PinPolicyTests(unittest.TestCase):
    def test_moving_a_pinned_input_is_a_violation(self):
        from ihc import agent
        diff = ('+++ b/flake.nix\n-    x.url = "git+file:///r?rev=606418c4d5bc547b57b66d42abcb6b26511233cb";\n'
                '+    x.url = "git+file:///r?rev=64d410666821866c565e048a4d07d6cf5d8e494e";\n')
        self.assertTrue(any("pinned" in v for v in agent.policy_violations(diff)))

    def test_unpinned_url_change_is_fine(self):
        from ihc import agent
        self.assertEqual(agent.policy_violations('+++ b/flake.nix\n+    y.url = "github:a/b";\n'), [])


class AddDirOrderTests(unittest.TestCase):
    def test_add_dir_cannot_swallow_prompt(self):
        from pathlib import Path
        from ihc import agent, nix
        cfg = nix.Config("nixos", Path("/etc/nixos"), "h", "u", Path("/home/u/.config/home-manager"), True, [], [], "h", "u", Path("/etc/nixos"))
        argv = agent.build_cmd("claude", "PROMPT", cfg)
        i = argv.index("--add-dir")
        # the variadic --add-dir must be terminated by a flag before the prompt
        self.assertTrue(argv[i + 2].startswith("-"))
        self.assertEqual(argv[-1], "PROMPT")


class CleanEnvTests(unittest.TestCase):
    def test_strips_api_keys_and_sets_marker(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "x", "OPENAI_API_KEY": "y"}):
            env = agent.clean_env()
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertEqual(env["IHC_AGENT"], "1")


class BuildCmdTests(unittest.TestCase):
    def setUp(self):
        self.tmp = make_nixos_tmp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cfg = _cfg(self.tmp, HM_FIXTURE)

    def test_claude(self):
        argv = agent.build_cmd("claude", "P", self.cfg)
        i = argv.index("-p")
        self.assertEqual(argv[0], "claude")
        self.assertEqual(argv[i:i + 3], ["-p", "--permission-mode", "bypassPermissions"])
        self.assertIn("--add-dir", argv)
        self.assertEqual(argv[argv.index("--add-dir") + 1], str(HM_FIXTURE))
        self.assertEqual(argv[-1], "P")

    def test_codex(self):
        argv = agent.build_cmd("codex", "P", self.cfg)
        for want in ("--skip-git-repo-check", "-C", str(self.cfg.flake_dir), "--dangerously-bypass-approvals-and-sandbox"):
            self.assertIn(want, argv)
        self.assertEqual(argv[-1], "P")

    def test_opencode(self):
        argv = agent.build_cmd("opencode", "P", self.cfg)
        self.assertEqual(argv[:3], ["opencode", "run", "--dir"])
        self.assertEqual(argv[-1], "P")

    def test_unknown_agent_raises(self):
        with self.assertRaises(ValueError):
            agent.build_cmd("bogus", "P", self.cfg)


class PolicyViolationsTests(unittest.TestCase):
    def test_disabling_a_goals_invariant_is_a_violation(self):
        diff = "+++ b/configuration.nix\n+  services.openssh.enable = false;\n"
        self.assertTrue(agent.policy_violations(diff, invariants=["services.openssh.enable"]))

    def test_changing_state_version_is_a_violation(self):
        diff = '+++ b/configuration.nix\n+  system.stateVersion = "23.05";\n'
        self.assertTrue(agent.policy_violations(diff))

    def test_touching_hardware_configuration_is_a_violation(self):
        diff = "+++ b/hardware-configuration.nix\n+  boot.kernelParams = [ ];\n"
        violations = agent.policy_violations(diff)
        self.assertTrue(any("protected file" in v for v in violations))

    def test_removing_a_goals_invariant_is_a_violation(self):
        diff = "+++ b/configuration.nix\n-  services.openssh.enable = true;\n"
        self.assertTrue(agent.policy_violations(diff, invariants=["services.openssh.enable"]))

    def test_benign_package_addition_has_no_violation(self):
        diff = "+++ b/configuration.nix\n+    htop\n"
        self.assertEqual(agent.policy_violations(diff), [])


class FixPromptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = make_nixos_tmp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cfg = make_config(self.tmp)

    def test_contains_tail_roots_marker_and_flags(self):
        prompt = agent.fix_prompt(self.cfg, ["host=example"], "build-system", "system", "TAIL-TEXT-HERE")
        self.assertIn("TAIL-TEXT-HERE", prompt)
        self.assertIn(agent.DONE_MARKER, prompt)
        for repo in self.cfg.config_repos:
            self.assertIn(str(repo), prompt)
        self.assertIn("--impure", prompt)


class AvailableTests(unittest.TestCase):
    def test_filters_unauthed_and_preserves_order(self):
        fake_agents = [
            {"name": "a", "path": "/bin/a", "authed": True},
            {"name": "b", "path": "/bin/b", "authed": True},
            {"name": "c", "path": "/bin/c", "authed": False},
        ]
        with mock.patch("ihc.agent.agents_available", return_value=fake_agents):
            result = agent.available(["b", "c", "a"])
        self.assertEqual([a["name"] for a in result], ["b", "a"])


if __name__ == "__main__":
    unittest.main()
