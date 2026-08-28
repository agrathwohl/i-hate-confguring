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
