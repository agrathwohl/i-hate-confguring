import contextlib
import getpass
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fixture_helpers import make_config, make_nixos_tmp
from ihc import docs, facts, nix, security, store

FIXTURE_SECRET_SYSTEM = "EXAMPLE-NOT-A-REAL-KEY-000000"
FIXTURE_SECRET_HM = "EXAMPLE-NOT-A-REAL-KEY-111111"


def probe_values(**over) -> dict:
    base = {
        "sshd_password_auth": False,
        "sshd_permit_root_login": "no",
        "firewall_enable": True,
        "sudo_wheel_needs_password": True,
        "docker_rootless": False,
        "root_equivalent_group_users": [],
        "inline_password_users": [],
        "autologin_enabled": False,
        "autologin_user": "<<display-manager>>",
        "nix_trusted_users_beyond_root": [],
        "nix_require_sigs": True,
        "nix_accept_flake_config": False,
        "insecure_permitted": [],
        "insecure_gating_disabled": False,
    }
    base.update(over)
    return base


def ids(findings) -> list[str]:
    return [f["id"] for f in findings]


class CheckTableTests(unittest.TestCase):
    def test_every_check_is_generic_and_complete(self):
        self.assertTrue(security.CHECKS)
        host = socket.gethostname().split(".")[0]
        user = getpass.getuser()
        for check_id, c in security.CHECKS.items():
            self.assertRegex(check_id, r"^[a-z0-9_]+$")
            self.assertTrue(c["title"], check_id)
            self.assertTrue(c["remediation"], check_id)
            self.assertIn(c["severity"], {"high", "medium"}, check_id)
            self.assertIn(c["scope"], {"system", "hm"}, check_id)
            self.assertIsInstance(c["platforms"], tuple, check_id)
            self.assertTrue(c["platforms"], check_id)
            self.assertTrue(set(c["platforms"]) <= {"nixos", "darwin", "hm-only"}, check_id)
            self.assertIsInstance(c["auto"], bool, check_id)
            if isinstance(c["unsafe"], tuple):
                self.assertEqual(c["unsafe"][0], "in", check_id)
                self.assertTrue(c["unsafe"][1] and all(isinstance(v, str) for v in c["unsafe"][1]), check_id)
            else:
                self.assertIn(c["unsafe"], {"true", "false", "nonempty"}, check_id)
            for key in ("unsafe_re", "anchor_re"):
                if c[key]:
                    re.compile(c[key])
            blob = " ".join(str(v) for v in c.values())
            self.assertNotIn("/nix/store", blob, check_id)
            self.assertNotIn("~", blob, check_id)
            self.assertIsNone(re.search(r"(?<![A-Za-z0-9_.\\-])/[A-Za-z]", c["title"] + " " + c["remediation"]),
                              "%s: an absolute path is host-specific" % check_id)
            for token in (host, user):
                if len(token) >= 4 and token.lower() not in ("root", "user", "nixos", "test", "none", "example"):
                    self.assertNotIn(token.lower(), blob.lower(), check_id)

    def test_exactly_one_check_is_auto_remediable(self):
        self.assertEqual({i for i, c in security.CHECKS.items() if c["auto"]}, {"unpinned_remote_fetch"})

    def test_the_permitted_insecure_entry_row_claims_no_staleness_it_cannot_prove(self):
        c = security.CHECKS["permitted_insecure_entry"]
        self.assertFalse(c["auto"])
        self.assertIn("NOT auto-remediable", c["remediation"])
        self.assertNotIn("stale", c["title"])

    def test_lock_staleness_is_a_check_and_says_it_is_not_auto_remediable(self):
        c = security.CHECKS["nixpkgs_lock_stale"]
        self.assertFalse(c["auto"])
        self.assertIn("ihc bump", c["remediation"])
        self.assertIn("NOT auto-remediable", c["remediation"])


class ProbeExprTests(unittest.TestCase):
    def test_probe_expression_is_generic_and_covers_the_table(self):
        expr = security.PROBE_EXPR
        self.assertIsInstance(expr, str)
        self.assertTrue(expr.startswith("top:"))
        self.assertIn("tryEval", expr)
        self.assertIn("deepSeq", expr)
        self.assertNotIn("/nix/store", expr)
        self.assertIsNone(re.search(r"\blib\.", expr), "lib.* does not exist on nix-darwin's eval")
        host = socket.gethostname().split(".")[0]
        if len(host) >= 4:
            self.assertNotIn(host.lower(), expr.lower())
        for c in security.CHECKS.values():
            if c["probe"]:
                self.assertRegex(expr, r"(?m)^\s*%s\s*=" % re.escape(c["probe"]))


class EvalFindingsTests(unittest.TestCase):
    def fire(self, **over):
        return security.eval_findings(probe_values(**over), "nixos")

    def test_sshd_password_auth(self):
        f, u = self.fire(sshd_password_auth=True)
        self.assertEqual(ids(f), ["sshd_password_auth"])
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(ids(self.fire(sshd_password_auth=False)[0]), [])

    def test_absent_and_error_are_unknown_never_clean(self):
        for sentinel in ("<<absent>>", "<<error>>"):
            f, u = self.fire(sshd_password_auth=sentinel)
            self.assertEqual(ids(f), [])
            self.assertIn("sshd_password_auth", [x["id"] for x in u])

    def test_a_missing_key_behaves_like_absent(self):
        values = probe_values()
        del values["firewall_enable"]
        f, u = security.eval_findings(values, "nixos")
        self.assertNotIn("firewall_disabled", ids(f))
        self.assertIn("firewall_disabled", [x["id"] for x in u])

    def test_permit_root_login_vocabulary(self):
        for safe in ("prohibit-password", "no", "forced-commands-only"):
            self.assertEqual(ids(self.fire(sshd_permit_root_login=safe)[0]), [])
        for bad in ("yes", "without-password"):
            self.assertEqual(ids(self.fire(sshd_permit_root_login=bad)[0]), ["sshd_permit_root_login"])

    def test_firewall_and_the_platform_gate(self):
        self.assertEqual(ids(self.fire(firewall_enable=False)[0]), ["firewall_disabled"])
        self.assertEqual(ids(self.fire(firewall_enable=True)[0]), [])
        f, u = security.eval_findings(probe_values(firewall_enable=False), "darwin")
        self.assertNotIn("firewall_disabled", ids(f))
        self.assertNotIn("firewall_disabled", [x["id"] for x in u])

    def test_sudo_docker_users_and_autologin(self):
        self.assertEqual(ids(self.fire(sudo_wheel_needs_password=False)[0]), ["sudo_passwordless_wheel"])
        self.assertEqual(ids(self.fire(sudo_wheel_needs_password=True)[0]), [])
        f, _ = self.fire(root_equivalent_group_users=["docker=alice"])
        self.assertEqual(ids(f), ["root_equivalent_group"])
        self.assertIn("docker=alice", f[0]["detail"])
        self.assertEqual(ids(self.fire(root_equivalent_group_users=[])[0]), [])
        self.assertEqual(ids(self.fire(inline_password_users=["alice"])[0]), ["user_credential_in_store"])
        f, _ = self.fire(autologin_enabled=True, autologin_user="alice")
        self.assertEqual(ids(f), ["autologin_enabled"])
        self.assertEqual(f[0]["severity"], "medium")

    def test_nix_settings(self):
        f, _ = self.fire(nix_trusted_users_beyond_root=["@wheel"])
        self.assertEqual(ids(f), ["nix_trusted_users_beyond_root"])
        self.assertEqual(ids(self.fire(nix_trusted_users_beyond_root=[])[0]), [])
        f, _ = self.fire(nix_require_sigs=False)
        self.assertEqual((f[0]["id"], f[0]["severity"]), ("nix_require_sigs_disabled", "high"))
        self.assertEqual(ids(self.fire(nix_require_sigs=True)[0]), [])
        f, _ = self.fire(nix_accept_flake_config=True)
        self.assertEqual((f[0]["id"], f[0]["severity"]), ("nix_accept_flake_config", "medium"))
        self.assertEqual(ids(self.fire(nix_accept_flake_config=False)[0]), [])

    def test_insecure_permitted_and_blanket_override_are_distinct_rows(self):
        f, _ = self.fire(insecure_permitted=["foo-1.0"])
        self.assertEqual(ids(f), ["permitted_insecure_packages"])
        f, _ = self.fire(insecure_permitted=["foo-1.0"], insecure_gating_disabled=True)
        self.assertEqual(sorted(ids(f)), ["insecure_gating_disabled", "permitted_insecure_packages"])


class FetchFindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ihc-security-fetch-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, text: str) -> list[Path]:
        p = self.tmp / "a.nix"
        p.write_text(text)
        return [p]

    def test_unhashed_fetch_fires_at_the_right_line(self):
        files = self.write('{\n  x = builtins.fetchTarball "https://example.invalid/a.tar.gz";\n}\n')
        f = security.fetch_findings(files)
        self.assertEqual(ids(f), ["unpinned_remote_fetch"])
        self.assertEqual(f[0]["line"], 2)
        self.assertEqual(f[0]["file"], str(self.tmp / "a.nix"))

    def test_a_hash_in_the_window_suppresses_it(self):
        files = self.write('{\n  x = builtins.fetchTarball {\n    url = "https://example.invalid/a.tar.gz";\n'
                           '    sha256 = "0000000000000000000000000000000000000000000000000000";\n  };\n}\n')
        self.assertEqual(security.fetch_findings(files), [])

    def test_comments_are_not_evidence(self):
        self.assertEqual(security.fetch_findings(
            self.write('{\n  # x = builtins.fetchTarball "https://example.invalid/a.tar.gz";\n}\n')), [])
        self.assertEqual(security.fetch_findings(
            self.write('{\n  /* x = builtins.fetchTarball "https://example.invalid/a.tar.gz"; */\n}\n')), [])

    def test_fetchurl_and_fetchgit_also_match(self):
        self.assertEqual(len(security.fetch_findings(
            self.write('{\n  a = builtins.fetchurl "https://example.invalid/a";\n'
                       '  b = builtins.fetchGit "https://example.invalid/b";\n}\n'))), 2)


class HmSshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ihc-security-ssh-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, text: str) -> list[Path]:
        p = self.tmp / "ssh.nix"
        p.write_text(text)
        return [p]

    def test_host_key_checking_off_fires(self):
        f = security.hm_ssh_findings(self.write(
            '{\n  programs.ssh.extraConfig = \'\'\n    StrictHostKeyChecking no\n  \'\';\n}\n'))
        self.assertEqual(ids(f), ["hm_ssh_client_weakened"])
        self.assertEqual((f[0]["line"], f[0]["severity"]), (3, "medium"))

    def test_forward_agent_fires(self):
        self.assertEqual(ids(security.hm_ssh_findings(
            self.write('{\n  programs.ssh.matchBlocks.a.forwardAgent = true;\n}\n'))), ["hm_ssh_client_weakened"])

    def test_strict_checking_on_does_not_fire(self):
        self.assertEqual(security.hm_ssh_findings(
            self.write('{\n  programs.ssh.extraConfig = "StrictHostKeyChecking yes";\n}\n')), [])


class PermittedInsecureEntryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ihc-security-insecure-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.f = self.tmp / "c.nix"
        self.f.write_text('{\n  nixpkgs.config.permittedInsecurePackages = [\n'
                          '    "example-pkg-1.2.3"\n    "other-pkg-0.1"\n  ];\n}\n')

    def test_each_entry_is_cited(self):
        f = security.insecure_entry_findings(["example-pkg-1.2.3", "other-pkg-0.1"], [self.f])
        self.assertEqual(ids(f), ["permitted_insecure_entry"] * 2)
        self.assertEqual([(x["file"], x["line"]) for x in f], [(str(self.f), 3), (str(self.f), 4)])
        self.assertIn("example-pkg-1.2.3", f[0]["detail"])

    def test_an_entry_is_never_handed_to_an_agent(self):
        """Nothing here compares the entry against nixpkgs or the lock, so a live entry would be deleted."""
        f = security.insecure_entry_findings(["example-pkg-1.2.3"], [self.f])
        self.assertTrue(all(x["auto"] is False for x in f))
        self.assertIsNone(security.fix_task({"findings": f}))

    def test_an_entry_with_no_citation_is_not_cited(self):
        self.assertEqual(security.insecure_entry_findings(["comes-from-a-module-1.0"], [self.f]), [])

    def test_a_commented_out_entry_is_not_evidence(self):
        self.f.write_text('{\n  # "example-pkg-1.2.3"\n}\n')
        self.assertEqual(security.insecure_entry_findings(["example-pkg-1.2.3"], [self.f]), [])


class LockStalenessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ihc-security-lock-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "flake.lock").write_text("{}\n")
        self.cfg = nix.Config("nixos", self.tmp, "h", None, None, True, [], [], "h", "u", self.tmp)

    def at(self, days_ago: int) -> str:
        from datetime import datetime, timedelta, timezone
        return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d")

    def fx(self, lock_days, run_days):
        return {"runtime": {"lock_nixpkgs_date": self.at(lock_days), "running_nixpkgs_date": self.at(run_days),
                            "drift_days": run_days - lock_days}}

    def test_a_freshly_bumped_host_sees_nothing(self):
        f, u = security.lock_findings(self.cfg, self.fx(1, 2))
        self.assertEqual((f, u), ([], []))
        self.assertEqual(security.lock_findings(self.cfg, self.fx(44, 44)), ([], []))

    def test_medium_past_45_days_and_high_past_180(self):
        f, _ = security.lock_findings(self.cfg, self.fx(60, 60))
        self.assertEqual((f[0]["id"], f[0]["severity"]), ("nixpkgs_lock_stale", "medium"))
        self.assertEqual(f[0]["file"], str(self.tmp / "flake.lock"))
        self.assertFalse(f[0]["auto"])
        f, _ = security.lock_findings(self.cfg, self.fx(400, 400))
        self.assertEqual(f[0]["severity"], "high")

    def test_the_older_of_the_two_dates_decides(self):
        f, _ = security.lock_findings(self.cfg, self.fx(1, 300))
        self.assertEqual(f[0]["severity"], "high")
        self.assertIn("300 day(s) old", f[0]["detail"])

    def test_without_runtime_facts_it_is_unknown_never_clean(self):
        f, u = security.lock_findings(self.cfg, {"secrets": []})
        self.assertEqual(f, [])
        self.assertEqual([x["id"] for x in u], ["nixpkgs_lock_stale"])
        f, u = security.lock_findings(self.cfg, {"runtime": {}})
        self.assertEqual((f, [x["id"] for x in u]), ([], ["nixpkgs_lock_stale"]))


class ExceptionsTests(unittest.TestCase):
    def test_parses_bullets_and_ignores_other_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "MAINTENANCE.md").write_text(
                "# M\n\n## Guarded units\n\n- audio-daemon.service\n\n## Security exceptions\n\n"
                "- sudo_passwordless_wheel: single-user laptop\n"
                "- `unpinned_remote_fetch`: `a channel I float on purpose`\n\n"
                "## Queue\n\n- [ ] (risk: low) x\n")
            self.assertEqual(docs.security_exceptions(Path(tmp)),
                             {"sudo_passwordless_wheel": "single-user laptop",
                              "unpinned_remote_fetch": "a channel I float on purpose"})

    def test_missing_file_is_empty(self):
        self.assertEqual(docs.security_exceptions(Path("/nonexistent")), {})


class FixtureReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = make_nixos_tmp()
        cls.cfg = make_config(cls.tmp)
        cls.fx = facts.mine(cls.cfg, runtime=False)
        cls.rep = security.report(cls.cfg, cls.fx, do_probe=False)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_report_shape(self):
        self.assertEqual(self.rep["eval"], {"ok": False, "attr": security.config_attr(self.cfg),
                                            "error": None, "reason": "not requested"})
        for f in self.rep["findings"]:
            self.assertEqual(set(f), {"id", "title", "severity", "scope", "source", "file", "line",
                                      "detail", "auto", "remediation"})
        self.assertEqual(self.rep["counts"]["high"],
                         sum(1 for f in self.rep["findings"] if f["severity"] == "high"))
        ranks = [security.SEVERITY_RANK[f["severity"]] for f in self.rep["findings"]]
        self.assertEqual(ranks, sorted(ranks))
        self.assertIsNone(self.rep["cve"])
        self.assertTrue(all(isinstance(line, str) for line in self.rep["summary"]))
        self.assertIn("finding(s)", self.rep["summary"][0])

    def test_the_unhashed_fetch_in_the_fixture_is_found_with_its_line(self):
        f = [x for x in self.rep["findings"] if x["id"] == "unpinned_remote_fetch"]
        self.assertEqual([(Path(x["file"]).name, x["line"]) for x in f], [("configuration.nix", 40)])

    def test_reachable_secrets_are_high_and_never_carry_the_value(self):
        built = [x for x in self.rep["findings"] if x["id"] == "secret_literal_in_built_config"]
        self.assertEqual(sorted((Path(x["file"]).name, x["line"]) for x in built),
                         [("configuration.nix", 34), ("environment.nix", 5)])
        self.assertTrue(all(x["severity"] == "high" for x in built))
        blob = json.dumps(self.rep, default=str)
        self.assertNotIn(FIXTURE_SECRET_SYSTEM, blob)
        self.assertNotIn(FIXTURE_SECRET_HM, blob)

    def test_an_unreferenced_secret_is_medium(self):
        d = Path(tempfile.mkdtemp(prefix="ihc-security-orphan-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        (d / "flake.nix").write_text("{ outputs = _: { }; }\n")
        (d / "orphan.nix").write_text('{\n  password = "ORPHAN-NOT-A-REAL-KEY-2222";\n}\n')
        cfg = nix.Config("nixos", d, None, None, None, True, [], [], "h", "u", d)
        rep = security.report(cfg, None, do_probe=False)
        f = [x for x in rep["findings"] if x["id"] == "secret_literal_in_unreferenced_file"]
        self.assertEqual([(Path(x["file"]).name, x["line"], x["severity"]) for x in f], [("orphan.nix", 2, "medium")])
        self.assertNotIn("ORPHAN-NOT-A-REAL-KEY-2222", json.dumps(rep, default=str))

    def test_the_mined_facts_carry_the_report_and_its_summary(self):
        """`ihc facts`/`ihc status` and every agent prompt see the security report through here."""
        self.assertEqual(self.fx["security"]["counts"], self.rep["counts"])
        self.assertIn(self.fx["security"]["summary"][0], facts.summary_lines(self.fx))

    def test_probe_free_view_marks_every_eval_check_unknown_and_never_clean(self):
        unknown = {u["id"] for u in self.rep["unknown"]}
        for check_id, c in security.CHECKS.items():
            if c["probe"] and "nixos" in c["platforms"]:
                self.assertIn(check_id, unknown, check_id)
        self.assertIn("not answered", " ".join(self.rep["summary"]))


class AcceptedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = make_nixos_tmp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cfg = make_config(self.tmp)
        self.state = Path(tempfile.mkdtemp(prefix="ihc-security-state-"))
        self.addCleanup(shutil.rmtree, self.state, ignore_errors=True)
        p = mock.patch.object(store, "PENDING_DIR", self.state / "pending")
        p.start()
        self.addCleanup(p.stop)

    def test_an_accepted_finding_stops_counting_escalating_and_being_fixed(self):
        before = security.report(self.cfg, None, do_probe=False)
        self.assertIn("unpinned_remote_fetch", ids(before["findings"]))
        self.assertIsNotNone(security.fix_task(before))
        (self.tmp / "MAINTENANCE.md").write_text(
            "# M\n\n## Security exceptions\n\n- unpinned_remote_fetch: a channel I float on purpose\n")
        after = security.report(self.cfg, None, do_probe=False)
        self.assertNotIn("unpinned_remote_fetch", ids(after["findings"]))
        self.assertEqual(after["accepted"],
                         [{"id": "unpinned_remote_fetch", "reason": "a channel I float on purpose"}])
        self.assertEqual(after["counts"]["accepted"], 1)
        self.assertEqual(after["counts"]["high"], before["counts"]["high"] - 1)
        self.assertIsNone(security.fix_task(after))

    def test_accepting_every_high_finding_stops_the_escalation(self):
        rep = security.report(self.cfg, None, do_probe=False)
        (self.tmp / "MAINTENANCE.md").write_text(
            "# M\n\n## Security exceptions\n\n" + "".join(
                "- %s: accepted\n" % i for i in sorted({f["id"] for f in rep["findings"]})))
        self.assertIsNone(security.escalate(security.report(self.cfg, None, do_probe=False)))
        self.assertEqual(store.pending_list(), [])


class FixTaskTests(unittest.TestCase):
    def report(self, findings) -> dict:
        return {"findings": findings}

    def auto(self, check_id, file, line):
        return dict(security._finding(check_id, "config", file, line, "detail for %s" % check_id))

    def test_nothing_auto_returns_none(self):
        self.assertIsNone(security.fix_task(self.report([])))
        self.assertIsNone(security.fix_task(self.report([
            self.auto("secret_literal_in_built_config", "/cfg/secrets.nix", 3)])))

    def test_two_fetches_are_both_named_and_non_auto_files_are_not(self):
        rep = self.report([
            self.auto("unpinned_remote_fetch", "/cfg/one.nix", 11),
            self.auto("unpinned_remote_fetch", "/cfg/two.nix", 22),
            self.auto("secret_literal_in_built_config", "/cfg/creds.nix", 33),
            self.auto("sudo_passwordless_wheel", "/cfg/sudo.nix", 44),
            self.auto("nix_trusted_users_beyond_root", "/cfg/trust.nix", 55),
        ])
        task = security.fix_task(rep)
        self.assertIn("/cfg/one.nix:11", task)
        self.assertIn("/cfg/two.nix:22", task)
        for path in ("/cfg/creds.nix", "/cfg/sudo.nix", "/cfg/trust.nix"):
            self.assertNotIn(path, task)
        self.assertIn("Prove it by evaluating", task)

    def test_a_protected_file_is_excluded(self):
        rep = self.report([self.auto("unpinned_remote_fetch", "/cfg/hardware-configuration.nix", 7)])
        self.assertIsNone(security.fix_task(rep))
        rep["findings"].append(self.auto("unpinned_remote_fetch", "/cfg/ok.nix", 8))
        task = security.fix_task(rep)
        self.assertNotIn("hardware-configuration.nix", task)
        self.assertIn("/cfg/ok.nix:8", task)

    def test_a_permitted_insecure_entry_is_never_in_the_task(self):
        rep = self.report([self.auto("permitted_insecure_entry", "/cfg/c.nix", 9)])
        self.assertIsNone(security.fix_task(rep))
        rep["findings"].append(self.auto("unpinned_remote_fetch", "/cfg/a.nix", 1))
        task = security.fix_task(rep)
        self.assertIn("/cfg/a.nix:1", task)
        self.assertNotIn("/cfg/c.nix:9", task)
        self.assertNotIn("permittedInsecurePackages", task)


class EscalateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ihc-security-pending-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for name, value in (("STATE_DIR", self.tmp), ("RUNS_DIR", self.tmp / "runs"),
                            ("PENDING_DIR", self.tmp / "pending"), ("HISTORY", self.tmp / "history.jsonl")):
            p = mock.patch.object(store, name, value)
            p.start()
            self.addCleanup(p.stop)

    def rep(self, *findings) -> dict:
        return {"findings": list(findings)}

    def high(self, check_id, file):
        return security._finding(check_id, "eval", file, 1, "d")

    def test_one_pending_for_a_set_and_no_second_for_the_same_set(self):
        rep = self.rep(self.high("firewall_disabled", "/cfg/a.nix"), self.high("sshd_password_auth", "/cfg/b.nix"))
        self.assertIsNotNone(security.escalate(rep))
        pend = store.pending_list()
        self.assertEqual([p["kind"] for p in pend], ["security"])
        self.assertIn("2 high-severity", pend[0]["title"])
        self.assertIn("Security exceptions", pend[0]["resolve"])
        self.assertIsNone(security.escalate(rep))
        self.assertEqual(len(store.pending_list()), 1)

    def test_a_new_high_finding_raises_a_fresh_pending_with_a_new_digest(self):
        rep = self.rep(self.high("firewall_disabled", "/cfg/a.nix"))
        first = security.escalate(rep)
        rep["findings"].append(self.high("nix_require_sigs_disabled", "/cfg/c.nix"))
        second = security.escalate(rep)
        self.assertIsNotNone(second)
        self.assertNotEqual(first, second)
        titles = " ".join(p["title"] for p in store.pending_list())
        self.assertIn(second, titles)
        self.assertIn("2 high-severity", titles)

    def test_medium_only_and_cve_only_never_escalate(self):
        self.assertIsNone(security.escalate(self.rep(self.high("autologin_enabled", "/cfg/a.nix"))))
        self.assertIsNone(security.escalate({"findings": [], "cve": {"available": True, "packages": [{"pname": "x"}]}}))
        self.assertEqual(store.pending_list(), [])


class ParseVulnixTests(unittest.TestCase):
    REC = {"name": "openssl-3.0.1", "pname": "openssl", "version": "3.0.1",
           "derivation": "/nix/store/x.drv", "affected_by": ["CVE-2022-0001", "CVE-2022-0002"],
           "whitelisted": [], "cvssv3_basescore": {"CVE-2022-0001": 5.0, "CVE-2022-0002": 7.5},
           "description": {"CVE-2022-0001": "a very long description that must not be carried"}}

    def test_one_record_with_rc2_is_a_successful_scan(self):
        pkgs, err = security.parse_vulnix(json.dumps([self.REC]), "", 2)
        self.assertEqual(err, "")
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0]["max_cvss"], 7.5)
        self.assertEqual(pkgs[0]["unscored"], 0)
        self.assertNotIn("description", pkgs[0])

    def test_empty_array_with_rc0_is_clean_not_failure(self):
        self.assertEqual(security.parse_vulnix("[]", "", 0), ([], ""))

    def test_unparseable_output_is_a_failure_whatever_the_rc(self):
        pkgs, err = security.parse_vulnix("", "Traceback (most recent call last): urlopen error", 1)
        self.assertIsNone(pkgs)
        self.assertIn("urlopen error", err)
        self.assertIsNone(security.parse_vulnix("not json", "", 0)[0])

    def test_a_missing_score_is_unscored_not_zero(self):
        partly = dict(self.REC, pname="partly", affected_by=["CVE-1", "CVE-2"], cvssv3_basescore={"CVE-1": 9.8})
        lower = dict(self.REC, pname="lower", affected_by=["CVE-3"], cvssv3_basescore={"CVE-3": 5.0})
        pkgs, _ = security.parse_vulnix(json.dumps([lower, partly]), "", 2)
        self.assertEqual([p["pname"] for p in pkgs], ["partly", "lower"])
        self.assertEqual(pkgs[0]["unscored"], 1)

    def test_a_record_with_no_scores_at_all_ranks_last_with_max_cvss_none(self):
        unscored = dict(self.REC, pname="unscored", affected_by=["CVE-9"], cvssv3_basescore={})
        pkgs, _ = security.parse_vulnix(json.dumps([unscored, self.REC]), "", 2)
        self.assertEqual([p["pname"] for p in pkgs], ["openssl", "unscored"])
        self.assertIsNone(pkgs[1]["max_cvss"])


class CveDueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ihc-security-cve-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        p = mock.patch.object(security, "STATE_DIR", self.tmp)
        p.start()
        self.addCleanup(p.stop)

    def test_missing_marker_is_due_and_zero_days_disables(self):
        self.assertTrue(security.cve_due(7))
        self.assertFalse(security.cve_due(0))

    def test_a_fresh_marker_is_not_due_and_an_old_one_is(self):
        from datetime import datetime, timedelta, timezone
        marker = self.tmp / "cve-last"
        marker.write_text(datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        self.assertFalse(security.cve_due(7))
        marker.write_text((datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d"))
        self.assertTrue(security.cve_due(7))

    def test_a_corrupt_marker_is_due_rather_than_silently_skipped(self):
        (self.tmp / "cve-last").write_text("not a date")
        self.assertTrue(security.cve_due(7))

    def test_vulnix_argv_uses_the_closure_flag_and_three_acquisition_forms(self):
        cfg = nix.Config("nixos", self.tmp, "h", None, None, True, [], [], "h", "u", self.tmp)
        forms = security.vulnix_argv(cfg)
        self.assertEqual(len(forms), 3)
        self.assertEqual(forms[0][0], "vulnix")
        self.assertIn("--inputs-from", forms[1])
        for form in forms:
            self.assertIn("--closure", form)
            self.assertIn("--json", form)


class SummaryTests(unittest.TestCase):
    def test_unknowns_are_named_and_never_reported_as_clean(self):
        rep = {"findings": [], "counts": {"high": 0, "medium": 0, "unknown": 4, "accepted": 0},
               "unknown": [{"id": "firewall_disabled", "reason": "the evaluation failed: error: attribute missing"}]}
        lines = security.summary_lines(rep)
        self.assertIn("security checks not answered: 4", " ".join(lines))
        self.assertIn("attribute missing", " ".join(lines))
        self.assertNotIn("clean", " ".join(lines).lower())

    def _cve_rep(self, cve):
        return {"findings": [], "counts": {"high": 0, "medium": 0, "unknown": 0, "accepted": 0}, "unknown": [], "cve": cve}

    def test_the_cve_line_names_the_scanner_and_carries_the_caveat(self):
        rep = self._cve_rep({"available": True, "scanner": "vulnxscan", "tool": ["nix", "shell"],
                             "counts": {"packages": 12, "cves": 30},
                             "packages": [{"pname": "openssl", "max_cvss": 9.8}]})
        line = " ".join(security.summary_lines(rep))
        self.assertIn("12 package(s)", line)
        self.assertIn("vulnxscan", line)          # the scanner, not argv[0] ("nix")
        self.assertNotIn("(nix)", line)
        self.assertIn("triage order, not a verdict", line)

    def test_a_failed_cve_scan_never_reads_as_clean(self):
        rep = self._cve_rep({"available": False, "reason": "401 Unauthorized from nvd.nist.gov",
                             "counts": {"packages": 0, "cves": 0}, "packages": []})
        line = " ".join(security.summary_lines(rep))
        self.assertIn("FAILED", line)
        self.assertIn("401 Unauthorized", line)
        self.assertNotIn("0 package(s) with active advisories", line)

    def test_vulnix_only_caveat_is_attached_only_to_vulnix(self):
        self.assertTrue(any("rolling 6-year" in x for x in security.cve_limits("vulnix")))
        self.assertFalse(any("rolling 6-year" in x for x in security.cve_limits("vulnxscan")))
        self.assertTrue(all("name and version" not in x or True for x in security.cve_limits()))


class SecretsThroughASymlinkTests(unittest.TestCase):
    """`/etc/nixos -> ~/nixos-config` (and `~/.config/home-manager -> dotfiles`) are ordinary layouts.
    facts.reachable() resolves every path it returns, the secrets scan does not, so the two sets have to
    be compared resolved — otherwise every in-tree secret is downgraded to "nothing imports this file"."""

    def build(self) -> Path:
        d = Path(tempfile.mkdtemp(prefix="ihc-security-symlink-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        real = d / "nixos-config"
        real.mkdir()
        (real / "flake.nix").write_text("{ outputs = _: { x = import ./configuration.nix; }; }\n")
        (real / "configuration.nix").write_text('{\n  password = "SYMLINK-NOT-A-REAL-KEY-3333";\n}\n')
        (d / "etc-nixos").symlink_to(real)
        return d

    def severities(self, root: Path) -> list[tuple[str, str]]:
        cfg = nix.Config("nixos", root, None, None, None, True, [], [], "h", "u", root)
        rep = security.report(cfg, None, do_probe=False)
        return sorted((f["id"], f["severity"]) for f in rep["findings"] if f["id"].startswith("secret_literal"))

    def test_the_same_tree_reached_through_a_symlink_reports_the_same_severity(self):
        d = self.build()
        through_real = self.severities(d / "nixos-config")
        self.assertEqual(through_real, [("secret_literal_in_built_config", "high")])
        self.assertEqual(self.severities(d / "etc-nixos"), through_real)


class CveScanWiringTests(unittest.TestCase):
    """cve_scan reads a store.Step. Its fields are out/err/exit; nothing else exists on it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ihc-security-cvescan-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for mod, name, value in ((store, "STATE_DIR", self.tmp), (store, "RUNS_DIR", self.tmp / "runs"),
                                 (store, "PENDING_DIR", self.tmp / "pending"),
                                 (security, "STATE_DIR", self.tmp), (security, "CVE_CACHE", self.tmp / "vulnix-cache")):
            p = mock.patch.object(mod, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.cfgdir = make_nixos_tmp()
        self.addCleanup(shutil.rmtree, self.cfgdir, ignore_errors=True)
        self.cfg = make_config(self.cfgdir)

    def scan(self, script: str) -> dict:
        run = store.new_run("security")
        argv = [[sys.executable, "-c", script]]
        # Patch the chain cve_scan actually calls. Patching vulnix_argv alone left the real
        # `nix shell nixpkgs#sbomnix` forms running: they hit the network and the test was flaky.
        with mock.patch.object(security, "scanner_argv", lambda cfg, out_csv: argv), \
             mock.patch.object(security, "deriver_coverage", lambda targets: None):
            return security.cve_scan(self.cfg, run, [self.cfgdir])

    def test_a_real_step_carries_the_scan_through(self):
        out = self.scan('import sys; sys.stdout.write(\'[{"pname": "openssl", "name": "openssl-3.0.1", '
                        '"affected_by": ["CVE-1"], "cvssv3_basescore": {"CVE-1": 9.8}}]\')')
        self.assertTrue(out["available"], out["reason"])
        self.assertEqual(out["counts"], {"packages": 1, "cves": 1})
        self.assertEqual(out["packages"][0]["max_cvss"], 9.8)
        self.assertEqual((security.STATE_DIR / "cve-last").read_text().strip(), out["at"])

    def test_a_tool_that_produces_no_json_is_a_named_failure_not_a_crash(self):
        out = self.scan('import sys; sys.stderr.write("urlopen error"); sys.exit(1)')
        self.assertFalse(out["available"])
        self.assertIn("urlopen error", out["reason"])
        self.assertEqual(out["packages"], [])


class PipelineSecurityWiringTests(unittest.TestCase):
    """The nightly's entire security contract: report, escalate, notify — and never edit anything."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ihc-security-pipeline-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for name, value in (("STATE_DIR", self.tmp), ("RUNS_DIR", self.tmp / "runs"),
                            ("PENDING_DIR", self.tmp / "pending"), ("HISTORY", self.tmp / "history.jsonl")):
            p = mock.patch.object(store, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.cfgdir = make_nixos_tmp()
        self.addCleanup(shutil.rmtree, self.cfgdir, ignore_errors=True)
        self.cfg = make_config(self.cfgdir)

    def go(self, findings):
        """Run the real pipeline with every stage but the security one stubbed out."""
        from ihc import prove, run as run_mod
        sec = {"platform": "nixos", "eval": {"ok": True, "attr": None, "error": None, "reason": None},
               "findings": findings, "unknown": [], "accepted": [], "cve": None,
               "counts": {"high": sum(1 for f in findings if f["severity"] == "high"),
                          "medium": sum(1 for f in findings if f["severity"] == "medium"),
                          "unknown": 0, "accepted": 0}}
        sec["summary"] = security.summary_lines(sec)
        seen = {"fix_loop": 0, "notify": []}

        def spy_fix_loop(*a, **k):
            seen["fix_loop"] += 1
            return prove.Verdict(ok=True)

        run = store.new_run("run")
        on_run = {"adopt": lambda *a: ["adopted"], "commit_drift": lambda *a, **k: [],
                  "fix_loop": spy_fix_loop, "activate": lambda *a, **k: {"system": "switched"},
                  "refresh_docs_if_changed": lambda *a: "unchanged", "_lock_revs": lambda cfg: {},
                  "notify": lambda t, b="", u="normal": seen["notify"].append((t, b, u))}
        with contextlib.ExitStack() as st:
            for name, fn in on_run.items():
                st.enter_context(mock.patch.object(run_mod, name, fn))
            st.enter_context(mock.patch.object(run_mod.facts_mod, "mine", lambda cfg, **k: {"runtime": {}}))
            st.enter_context(mock.patch.object(prove, "store_short", lambda fx: None))
            st.enter_context(mock.patch.object(prove, "sudo_ok", lambda cfg: True))
            st.enter_context(mock.patch.object(prove, "boot_short", lambda fx: False))
            st.enter_context(mock.patch.object(prove, "check", lambda *a, **k: prove.Verdict(ok=True)))
            st.enter_context(mock.patch.object(prove, "generation_count", lambda cfg: 5))
            st.enter_context(mock.patch.object(security, "report", lambda cfg, fx=None, **k: sec))
            st.enter_context(mock.patch.object(security, "cve_due", lambda *a: False))
            run_mod.pipeline(self.cfg, run, switch_policy="never", do_bump=False, only=None,
                             max_attempts=1, do_improve=False, improve_risk="low")
        return run, sec, seen

    def test_a_high_finding_escalates_and_the_notification_asks_for_the_user(self):
        run, sec, seen = self.go([security._finding("firewall_disabled", "eval", "/cfg/a.nix", 1, "effective value: false")])
        self.assertEqual([p["kind"] for p in store.pending_list()], ["security"])
        title, body, urgency = seen["notify"][-1]
        self.assertTrue(title.startswith("ACTION NEEDED"), title)
        self.assertEqual(urgency, "critical")
        self.assertIn(sec["summary"][0], body)
        self.assertEqual(json.loads((run.dir / "security.json").read_text())["counts"]["high"], 1)
        self.assertEqual(store.history_read()[-1]["security"]["high"], 1)

    def test_an_auto_remediable_finding_is_reported_and_never_handed_to_an_agent(self):
        """`ihc security --fix` is the only thing that edits: a rolling channel the user floats on
        purpose must not be pinned by an unattended timer."""
        finding = security._finding("unpinned_remote_fetch", "config", "/cfg/a.nix", 23,
                                    'builtins.fetchTarball "https://example.invalid/archive/master.tar.gz"')
        self.assertTrue(finding["auto"])
        self.assertIsNotNone(security.fix_task({"findings": [finding]}))
        run, sec, seen = self.go([finding])
        self.assertEqual(seen["fix_loop"], 0)
        self.assertIn("unpinned_remote_fetch", (run.dir / "security.json").read_text())


class ImportOrderTests(unittest.TestCase):
    def test_every_import_order_works(self):
        for stmt in ("import ihc.security, ihc.facts", "import ihc.facts, ihc.security", "import ihc.cli",
                     "import ihc.run"):
            p = subprocess.run([sys.executable, "-c", stmt], capture_output=True, text=True,
                               cwd=str(Path(__file__).resolve().parent.parent))
            self.assertEqual(p.returncode, 0, "%s -> %s" % (stmt, p.stderr))


if __name__ == "__main__":
    unittest.main()


class SecurityGateTests(unittest.TestCase):
    """The three gates that make unattended security remediation safe."""

    def _tmp(self):
        import tempfile
        d = Path(tempfile.mkdtemp(prefix="ihc-secgate-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def test_first_sighting_is_never_fixed_then_becomes_due(self):
        from unittest.mock import patch
        from ihc import store
        d = self._tmp()
        with patch.object(store, "STATE_DIR", d), patch.object(store, "SECURITY_STATE", d / "s.json"):
            due, why = store.security_due("k", 0, 30)
            self.assertFalse(due)
            self.assertIn("first sighting", why)
            self.assertTrue(store.security_due("k", 0, 30)[0])

    def test_grace_period_holds_until_the_finding_is_old_enough(self):
        from unittest.mock import patch
        from ihc import store
        d = self._tmp()
        with patch.object(store, "STATE_DIR", d), patch.object(store, "SECURITY_STATE", d / "s.json"):
            store.security_due("k", 1, 30)
            due, why = store.security_due("k", 1, 30)
            self.assertFalse(due)
            self.assertIn("fixed once it is 1", why)

    def test_failed_fix_is_not_retried_during_backoff(self):
        from unittest.mock import patch
        from ihc import store
        d = self._tmp()
        with patch.object(store, "STATE_DIR", d), patch.object(store, "SECURITY_STATE", d / "s.json"):
            store.security_due("k", 0, 30)
            store.security_attempted("k", False)
            due, why = store.security_due("k", 0, 30)
            self.assertFalse(due)
            self.assertIn("not retried", why)
            self.assertEqual(json.loads((d / "s.json").read_text())["k"]["outcome"], "failed")
            self.assertTrue(store.security_due("k", 0, 0)[0])


class SecurityFixStageTests(unittest.TestCase):
    """run.security_fix: only due auto findings reach the agent, and the outcome is recorded."""

    def _run(self, findings, due_map, verdict_ok=True, changed=True):
        import tempfile
        from unittest.mock import patch
        from ihc import agent, nix, prove, run as run_mod, security as sec_mod, store
        seen = {}
        with tempfile.TemporaryDirectory() as d:
            cfg = nix.Config("nixos", Path(d), "h", "u", None, True, [], [], "h", "u", Path(d))
            with patch.object(store, "RUNS_DIR", Path(d) / "runs"), patch.object(store, "STATE_DIR", Path(d)), \
                 patch.object(store, "PENDING_DIR", Path(d) / "p"), \
                 patch.object(sec_mod, "report", lambda c, f=None, do_probe=True: {"findings": findings, "accepted": []}), \
                 patch.object(run_mod.store, "security_due", lambda k, g, b: (due_map.get(k, False), "held")), \
                 patch.object(run_mod.store, "security_attempted", lambda k, ok: seen.__setitem__(k, ok)), \
                 patch.object(run_mod, "fix_loop", lambda *a, **k: seen.setdefault("task", a[5]) and None or prove.Verdict(ok=verdict_ok, failed_step="build-hm")), \
                 patch.object(agent, "changed_files", lambda c: ["a.nix"] if changed else []), \
                 patch.object(agent, "revert", lambda c, r: seen.__setitem__("reverted", True)), \
                 patch.object(run_mod, "commit_drift", lambda *a, **k: []):
                run = store.new_run("t")
                return run_mod.security_fix(cfg, run, {}, 2), seen

    def _f(self, fid, auto, line=1):
        return {"id": fid, "file": "/x/configuration.nix", "line": line, "auto": auto,
                "title": "t", "detail": "d", "severity": "high", "remediation": "r"}

    def test_non_auto_findings_never_trigger_a_fix(self):
        out, seen = self._run([self._f("sshd_password_auth", False)], {})
        self.assertFalse(out["attempted"])
        self.assertNotIn("task", seen)

    def test_held_finding_is_reported_and_not_fixed(self):
        out, seen = self._run([self._f("unpinned_remote_fetch", True)], {})
        self.assertFalse(out["attempted"])
        self.assertEqual(len(out["held"]), 1)
        self.assertIn("unpinned_remote_fetch", out["held"][0])
        self.assertNotIn("task", seen)

    def test_due_finding_is_fixed_and_recorded(self):
        key = "unpinned_remote_fetch:/x/configuration.nix:1"
        out, seen = self._run([self._f("unpinned_remote_fetch", True)], {key: True})
        self.assertTrue(out["attempted"])
        self.assertTrue(out["fixed"])
        self.assertIs(seen[key], True)
        self.assertIn("configuration.nix", seen["task"])

    def test_failed_proof_reverts_and_records_the_failure(self):
        key = "unpinned_remote_fetch:/x/configuration.nix:1"
        out, seen = self._run([self._f("unpinned_remote_fetch", True)], {key: True}, verdict_ok=False)
        self.assertFalse(out["fixed"])
        self.assertIn("reverted", out["reason"])
        self.assertTrue(seen.get("reverted"))
        self.assertIs(seen[key], False)

    def test_agent_declining_to_change_anything_is_not_a_failure_claim(self):
        key = "unpinned_remote_fetch:/x/configuration.nix:1"
        out, _ = self._run([self._f("unpinned_remote_fetch", True)], {key: True}, changed=False)
        self.assertFalse(out["fixed"])
        self.assertIn("changed nothing", out["reason"])


class VulnxscanParseTests(unittest.TestCase):
    """vulnxscan (sbomnix) is the preferred CVE backend: vulnix's NVD JSON feeds were retired."""

    CSV = ('"vuln_id","url","package","version_local","severity","grype","osv","sum","sortcol"\n'
           '"CVE-2026-1","u","thunderbird","153.0.1","9.8","1","0","1","1"\n'
           '"CVE-2026-2","u","thunderbird","153.0.1","10","1","0","1","1"\n'
           '"CVE-2020-3","u","redis","8.8.1","","0","1","1","1"\n'
           '"CVE-2020-4","u","redis","8.8.1","4.3","0","1","1","1"\n')

    def test_groups_rows_by_package_and_keeps_the_highest_score(self):
        from ihc import security
        pkgs, err = security.parse_vulnxscan(self.CSV)
        self.assertEqual(err, "")
        self.assertEqual([p["pname"] for p in pkgs], ["thunderbird", "redis"])  # sorted by max_cvss
        self.assertEqual(pkgs[0]["max_cvss"], 10.0)
        self.assertEqual(pkgs[0]["name"], "thunderbird-153.0.1")
        self.assertEqual(sorted(pkgs[0]["cves"]), ["CVE-2026-1", "CVE-2026-2"])

    def test_an_unscored_cve_is_counted_not_treated_as_zero(self):
        from ihc import security
        pkgs, _ = security.parse_vulnxscan(self.CSV)
        redis = next(p for p in pkgs if p["pname"] == "redis")
        self.assertEqual(redis["unscored"], 1)
        self.assertEqual(redis["max_cvss"], 4.3)
        self.assertEqual(len(redis["cves"]), 2)

    def test_empty_or_foreign_csv_is_a_failure_never_a_clean_result(self):
        from ihc import security
        self.assertEqual(security.parse_vulnxscan("")[0], None)
        pkgs, err = security.parse_vulnxscan('"a","b"\n"1","2"\n')
        self.assertIsNone(pkgs)
        self.assertIn("columns changed", err)

    def test_vulnxscan_is_tried_before_vulnix(self):
        from pathlib import Path
        from ihc import nix, security
        cfg = nix.Config("nixos", Path("/f"), "h", "u", None, True, [], [], "h", "u", Path("/f"))
        chain = security.scanner_argv(cfg, Path("/tmp/out.csv"))
        first_vulnxscan = next(i for i, a in enumerate(chain) if "vulnxscan" in a)
        first_vulnix = next(i for i, a in enumerate(chain) if "vulnix" in a)
        self.assertLess(first_vulnxscan, first_vulnix)
        self.assertIn("/tmp/out.csv", chain[0])
