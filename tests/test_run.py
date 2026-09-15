import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ihc import nix, run, store


def _cfg(docs_dir):
    return nix.Config(
        platform="nixos",
        flake_dir=docs_dir,
        host_attr="example",
        hm_attr="alice",
        hm_dir=None,
        impure=False,
        impure_reasons=[],
        nix_path_extra=[],
        hostname="example",
        user="alice",
        docs_dir=docs_dir,
    )


class BumpOrderTests(unittest.TestCase):
    def setUp(self):
        self.inputs = [
            nix.Input("nixpkgs", "github", "NixOS/nixpkgs", "rev1", "2026-08-23", local=False, pinned=False),
            nix.Input("zeta", "github", "foo/zeta", "rev2", None, local=False, pinned=False),
            nix.Input("alpha", "github", "foo/alpha", "rev3", None, local=False, pinned=True),
            nix.Input("musnix", "path", "/some/path", None, None, local=True, pinned=False),
        ]

    def test_nixpkgs_first_skips_pinned_and_local(self):
        names, skipped = run.bump_order(self.inputs, None)
        self.assertEqual(names, ["nixpkgs", "zeta"])
        self.assertIn("pinned", skipped["alpha"])
        self.assertIn("local checkout", skipped["musnix"])

    def test_only_includes_local_input_when_named(self):
        names, skipped = run.bump_order(self.inputs, ["musnix"])
        self.assertEqual(names, ["musnix"])
        self.assertEqual(skipped, {})


class QueueItemTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ihc-queue-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cfg = _cfg(self.tmp)

    def test_finds_low_risk_item_and_ticks_it(self):
        (self.tmp / "MAINTENANCE.md").write_text(
            "- [ ] (risk: high) x\n"
            "- [ ] (risk: low) y — a.nix:1\n"
            "- [x] (risk: low) done\n"
        )
        item = run.next_queue_item(self.cfg, max_risk="low")
        self.assertIsNotNone(item)
        line, task = item
        self.assertEqual(task, "y — a.nix:1")
        run.tick_queue_item(self.cfg, line)
        content = (self.tmp / "MAINTENANCE.md").read_text()
        self.assertIn("- [x] (risk: low) y — a.nix:1", content)
        self.assertIn("- [ ] (risk: high) x", content)

    def test_max_risk_medium_skips_high_only_queue(self):
        (self.tmp / "MAINTENANCE.md").write_text("- [ ] (risk: high) x\n")
        self.assertIsNone(run.next_queue_item(self.cfg, max_risk="medium"))


class EnsureGitignoreTests(unittest.TestCase):
    def test_idempotent(self):
        tmp = Path(tempfile.mkdtemp(prefix="ihc-gi-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        run._ensure_gitignore(tmp, ["honk.txt"])
        first = (tmp / ".gitignore").read_text()
        self.assertIn("honk.txt", first)
        for entry in run.GITIGNORE:
            self.assertIn(entry, first)
        run._ensure_gitignore(tmp, ["honk.txt"])
        self.assertEqual((tmp / ".gitignore").read_text(), first)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ihc-state-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        patches = [
            mock.patch.object(store, "STATE_DIR", self.tmp),
            mock.patch.object(store, "RUNS_DIR", self.tmp / "runs"),
            mock.patch.object(store, "PENDING_DIR", self.tmp / "pending"),
            mock.patch.object(store, "HISTORY", self.tmp / "history.jsonl"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_step_records_evidence_files_and_tail(self):
        r = store.new_run("test")
        step = r.step("hello", ["echo", "hello world"])
        self.assertTrue(step.ok)
        base = r.dir / "01-hello"
        self.assertTrue(base.with_suffix(".cmd").exists())
        self.assertTrue(base.with_suffix(".out").exists())
        self.assertTrue(base.with_suffix(".err").exists())
        self.assertEqual(base.with_suffix(".exit").read_text().strip(), "0")
        self.assertIn("hello world", step.tail())

    def test_new_run_creates_dir_and_records_last_run(self):
        r = store.new_run("test")
        self.assertTrue(r.dir.exists())
        self.assertEqual((store.STATE_DIR / "last-run").read_text().strip(), r.id)

    def test_prune_runs_keeps_two_newest(self):
        for name in ("20260101-000001-a", "20260101-000002-b", "20260101-000003-c"):
            d = store.RUNS_DIR / name
            d.mkdir(parents=True, exist_ok=True)
            (d / "note.txt").write_text("x")
        store.prune_runs(keep=2)
        remaining = {p.name for p in store.RUNS_DIR.iterdir()}
        self.assertEqual(remaining, {"20260101-000002-b", "20260101-000003-c"})

    def test_pending_round_trip(self):
        store.pending_add("policy", "Title", "Body", "Resolve it")
        lst = store.pending_list()
        self.assertEqual(len(lst), 1)
        self.assertEqual(lst[0]["title"], "Title")
        pid = lst[0]["id"]
        self.assertTrue(store.pending_resolve(pid))
        self.assertEqual(store.pending_list(), [])
        self.assertFalse(store.pending_resolve(pid))

    def test_history_append_and_read(self):
        store.history_append({"run": "x123", "ok": True})
        records = store.history_read()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["run"], "x123")
        self.assertIn("at", records[0])


if __name__ == "__main__":
    unittest.main()


class RevertIsHeadRelativeTests(unittest.TestCase):
    def test_reset_restores_committed_lock_even_after_staging(self):
        import subprocess, tempfile
        from pathlib import Path
        from unittest.mock import patch
        from ihc import agent, nix, store
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "cfg"
            repo.mkdir()
            git = lambda *a: subprocess.run(["git", "-C", str(repo)] + list(a), check=True, capture_output=True, env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/run/current-system/sw/bin:/usr/bin:/bin"})
            git("init", "-q")
            (repo / "flake.lock").write_text("good")
            git("add", "-A")
            git("commit", "-q", "-m", "base")
            (repo / "flake.lock").write_text("bumped")
            (repo / "new.nix").write_text("x")
            git("add", "-A")  # what prove.build does before every eval/build
            cfg = nix.Config("nixos", repo, "h", None, None, True, [], [], "h", "u", repo)
            with patch.object(store, "RUNS_DIR", Path(d) / "runs"), patch.object(store, "STATE_DIR", Path(d)), patch.object(store, "PENDING_DIR", Path(d) / "p"):
                run = store.new_run("t")
                agent.revert(cfg, run)
            self.assertEqual((repo / "flake.lock").read_text(), "good")
            self.assertFalse((repo / "new.nix").exists())


class FixLoopWritesDiffTests(unittest.TestCase):
    def test_fix_loop_records_diff_and_returns_ok_verdict(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from ihc import agent, nix, prove, run as runmod, store
        with tempfile.TemporaryDirectory() as d:
            cfg = nix.Config("nixos", Path(d), "h", None, None, True, [], [], "h", "u", Path(d))
            with patch.object(store, "RUNS_DIR", Path(d) / "runs"), patch.object(store, "STATE_DIR", Path(d)), patch.object(store, "PENDING_DIR", Path(d) / "p"):
                run = store.new_run("t")
                bad = prove.Verdict(ok=False, failed_step="build-hm", failed_target="hm")
                good = prove.Verdict(ok=True)
                with patch.object(agent, "run_agent", return_value=("claude", True, "IHC-DONE: x")), \
                     patch.object(agent, "diff_text", return_value="+++ b/x.nix\n+ foo = 1;\n"), \
                     patch.object(agent, "changed_files", return_value=["x.nix"]), \
                     patch.object(prove, "check", return_value=good):
                    fx = {"host": "h", "platform": "nixos", "config": {"flake_dir": d, "host_attr": "h", "hm_attr": None, "impure": True, "nix_args": []}}
                    v = runmod.fix_loop(cfg, run, fx, bad, 2)
                self.assertTrue(v.ok)
                self.assertTrue((run.dir / "fix-1.diff").exists())


class EscalationTests(unittest.TestCase):
    def test_third_consecutive_block_becomes_pending(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from ihc import run as runmod, store
        with tempfile.TemporaryDirectory() as d:
            with patch.object(store, "STATE_DIR", Path(d)), patch.object(store, "PENDING_DIR", Path(d) / "p"), patch.object(store, "HISTORY", Path(d) / "h.jsonl"), patch.object(store, "RUNS_DIR", Path(d) / "r"):
                store.history_append({"run": "a", "blocked": ["nixpkgs"]})
                store.history_append({"run": "b", "blocked": ["nixpkgs"]})
                self.assertEqual(runmod.escalate_repeated_blocks({"blocked": {"nixpkgs": "boom"}}), ["nixpkgs"])
                self.assertEqual(len(store.pending_list()), 1)
                # already pending: not duplicated
                self.assertEqual(runmod.escalate_repeated_blocks({"blocked": {"nixpkgs": "boom"}}), [])
                # a fresh block (no streak) is not escalated
                self.assertEqual(runmod.escalate_repeated_blocks({"blocked": {"stylix": "x"}}), [])


class PruneOutlinksTests(unittest.TestCase):
    def test_old_runs_lose_outlinks_but_keep_reports(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from ihc import store
        with tempfile.TemporaryDirectory() as d:
            runs = Path(d) / "runs"
            with patch.object(store, "RUNS_DIR", runs), patch.object(store, "STATE_DIR", Path(d)), patch.object(store, "PENDING_DIR", Path(d) / "p"):
                for i in range(5):
                    r = runs / ("2026-0%d-run" % i); r.mkdir(parents=True)
                    (r / "report.md").write_text("x"); (r / "system").symlink_to("/nix/store/fake-%d" % i)
                store.prune_runs(keep=10, keep_outlinks=2)
                have = sorted(p.name for p in runs.iterdir() if (p / "system").is_symlink())
                self.assertEqual(have, ["2026-03-run", "2026-04-run"])
                self.assertTrue(all((p / "report.md").exists() for p in runs.iterdir()))


class LockMovesTests(unittest.TestCase):
    def test_names_inputs_whose_rev_changed_since_head(self):
        import json, os, subprocess, tempfile
        from pathlib import Path
        from ihc import run as run_mod
        lock = lambda rev: json.dumps({"nodes": {
            "root": {"inputs": {"nixpkgs": "nixpkgs_2", "same": "same"}},
            "nixpkgs_2": {"locked": {"rev": rev}},
            "same": {"locked": {"rev": "c" * 40}}}})
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            git = lambda *a: subprocess.run(["git", "-C", str(repo)] + list(a), check=True, capture_output=True, env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})
            git("init", "-q")
            (repo / "flake.lock").write_text(lock("a" * 40))
            git("add", "-A")
            git("commit", "-q", "-m", "base")
            self.assertEqual(run_mod.lock_moves(repo), [])
            (repo / "flake.lock").write_text(lock("b" * 40))
            self.assertEqual(run_mod.lock_moves(repo), ["nixpkgs aaaaaaaa..bbbbbbbb"])


class HeavyBumpTests(unittest.TestCase):
    def test_step_streams_and_records_build_cost(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from ihc import store
        with tempfile.TemporaryDirectory() as d:
            with patch.object(store, "RUNS_DIR", Path(d) / "runs"), patch.object(store, "STATE_DIR", Path(d)), patch.object(store, "PENDING_DIR", Path(d) / "p"):
                run = store.new_run("t")
                st = run.step("build-hm", ["sh", "-c", "echo 'foo> start'; sleep 1.1; echo 'foo> done'; echo plain; echo err >&2"])
                self.assertTrue(st.ok)
                self.assertIn("plain", st.out)
                self.assertIn("err", st.err)
                self.assertGreaterEqual(store.ledger_read()["foo"]["seconds"], 1)
                self.assertEqual(store.ledger_top(1)[0][0], "foo")
                self.assertEqual(store.heavy_deferred("nixpkgs"), 0)
                self.assertEqual(store.heavy_deferred("nixpkgs"), 0)
                store.heavy_clear("nixpkgs")
                self.assertEqual(store.heavy_deferred("nixpkgs"), 0)

    def test_heavy_builds_uses_ledger_and_threshold(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from ihc import nix, prove, run as run_mod, store
        with tempfile.TemporaryDirectory() as d:
            cfg = nix.Config("nixos", Path(d), "h", "u", None, True, [], [], "h", "u", Path(d))
            with patch.object(store, "STATE_DIR", Path(d)), patch.object(prove, "local_builds", lambda c, r, t: ["ollama", "tiny"]):
                store.ledger_update({"ollama": 5000, "tiny": 3}, "r1")
                self.assertEqual(run_mod.heavy_builds(cfg, None), [("ollama", 5000), ("tiny", 3)])
                store.ledger_update({"ollama": 60}, "r2")
                self.assertEqual(run_mod.heavy_builds(cfg, None), [])
            (Path(d) / "MAINTENANCE.md").write_text("# M\n\n## Queue\n\n- [ ] (risk: low) existing\n\n## Other\n")
            run_mod.queue_heavy_split(cfg, "nixpkgs", [("ollama", 5000)])
            run_mod.queue_heavy_split(cfg, "nixpkgs", [("ollama", 5000)])
            text = (Path(d) / "MAINTENANCE.md").read_text()
            self.assertEqual(text.count("`ollama` rebuilds from source"), 1)
            self.assertLess(text.index("`ollama` rebuilds"), text.index("existing"))


class AskTests(unittest.TestCase):
    def _go(self, last, changed, proof_ok=True, violations=None):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from ihc import agent, docs, nix, prove, run as run_mod, store
        with tempfile.TemporaryDirectory() as d:
            cfg = nix.Config("nixos", Path(d), "h", "u", None, True, [], [], "h", "u", Path(d))
            with patch.object(store, "RUNS_DIR", Path(d) / "runs"), patch.object(store, "STATE_DIR", Path(d)), patch.object(store, "PENDING_DIR", Path(d) / "p"), \
                 patch.object(run_mod.facts_mod, "summary_lines", lambda f: ["fact"]), \
                 patch.object(agent, "run_agent", lambda c, r, p: ("claude", True, last)), \
                 patch.object(agent, "changed_files", lambda c: ["a.nix"] if changed else []), \
                 patch.object(agent, "diff_text", lambda c: "+ x"), \
                 patch.object(agent, "revert", lambda c, r: None), \
                 patch.object(agent, "policy_violations", lambda d2, inv: violations or []), \
                 patch.object(docs, "invariant_options", lambda p2: []), \
                 patch.object(prove, "check", lambda *a, **k: prove.Verdict(ok=proof_ok, failed_step=None if proof_ok else "build-hm")), \
                 patch.object(run_mod, "fix_loop", lambda *a, **k: prove.Verdict(ok=proof_ok, failed_step="build-hm")), \
                 patch.object(run_mod, "commit_drift", lambda *a, **k: []):
                run = store.new_run("ask")
                return run_mod.ask(cfg, run, {"runtime": {}}, "why is it broken")

    def test_fixed_when_changed_and_proof_passes(self):
        res = self._go("FIXED the clock module cached the date", True)
        self.assertEqual(res["verdict"], "FIXED")
        self.assertIn("next activation", res["detail"])

    def test_honest_unsolved_when_agent_claims_fix_but_changed_nothing(self):
        res = self._go("FIXED it", False)
        self.assertEqual(res["verdict"], "UNSOLVED")

    def test_blocked_when_proof_fails_and_reverted(self):
        res = self._go("FIXED it", True, proof_ok=False)
        self.assertEqual(res["verdict"], "BLOCKED")
        self.assertIn("reverted", res["detail"])

    def test_blocked_verdict_passes_through_without_changes(self):
        res = self._go("BLOCKED upstream widget bug", False)
        self.assertEqual(res["verdict"], "BLOCKED")
        self.assertEqual(res["detail"], "upstream widget bug")


class StepSurvivesLaunchFailureTests(unittest.TestCase):
    def test_unlaunchable_binary_becomes_exit_127_not_an_exception(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from ihc import store
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "notexec"
            bad.write_text("#!/bin/sh\n")
            bad.chmod(0o644)  # present but not executable -> PermissionError, not FileNotFoundError
            with patch.object(store, "RUNS_DIR", Path(d) / "runs"), patch.object(store, "STATE_DIR", Path(d)), \
                 patch.object(store, "PENDING_DIR", Path(d) / "p"):
                run = store.new_run("t")
                st = run.step("launch", [str(bad)])
                self.assertEqual(st.exit, 127)
                self.assertIn("Permission denied", st.err)
                st2 = run.step("missing", [str(Path(d) / "nope")])
                self.assertEqual(st2.exit, 127)


class UnitCannotKillItsOwnActivationTests(unittest.TestCase):
    """ihc runs the activation from inside its own unit, so the activation must not stop it.

    Without these directives sd-switch (home-manager) and switch-to-configuration (NixOS) stop
    the running unit mid-activation: units stay stopped, and the gcroot that records the current
    generation is never updated, so every later activation diffs against a frozen unit set.
    """

    def test_both_modules_declare_the_guard(self):
        from pathlib import Path
        flake = Path(__file__).resolve().parent.parent / "flake.nix"
        text = flake.read_text()
        self.assertIn('Unit.X-SwitchMethod = "keep-old";', text)       # home-manager / sd-switch
        self.assertIn("unitConfig.X-RestartIfChanged = false;", text)  # NixOS
