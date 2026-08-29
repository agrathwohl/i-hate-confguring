"""Orchestration: adopt trees into git, bump per input, fix with an agent, prove, switch, report."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

from . import agent, docs, facts as facts_mod, nix, prove
from .notify import notify
from .store import Run, history_append, history_read, last_run_id, pending_add, pending_list, RUNS_DIR

GITIGNORE = ["result", "result-*", "*.bak", "*.old", "*.backup", "*.ihc-bak", "*.orig", "*.rej",
             "*.jpg", "*.jpeg", "*.png", "*.webp", "*.gif", ".direnv/", ".omc/", ".omo/", ".remember/", "claudedocs/", ".claude/settings.local.json"]


def _git(repo: Path, *args: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo)] + list(args), capture_output=True, text=True, check=check)


def is_git(repo: Path) -> bool:
    return _git(repo, "rev-parse", "--is-inside-work-tree").stdout.strip() == "true"


def _ensure_gitignore(repo: Path, extra: list[str]) -> list[str]:
    """Append missing ignore entries; returns what was added so callers can untrack matching files."""
    gi = repo / ".gitignore"
    have = gi.read_text().splitlines() if gi.exists() else []
    add = [e for e in GITIGNORE + extra if e not in have]
    if add:
        gi.write_text("\n".join(have + add) + "\n")
    return add


def adopt(cfg: nix.Config, run: Run, fx: dict) -> list[str]:
    """Put the live config trees under git so every change is reviewable and revertible. Idempotent."""
    notes = []
    secret_files = sorted({Path(s["file"]).name for s in fx.get("secrets", []) if s["kind"] == "secret-looking-filename"})
    for repo in cfg.config_repos:
        if not repo.exists():
            continue
        if not os.access(repo, os.W_OK) or any(not os.access(p, os.W_OK) for p in repo.glob("*.nix")):
            uid = os.getuid()
            gid = os.getgid()
            st = run.step("chown-" + repo.name, ["chown", "-R", "%d:%d" % (uid, gid), str(repo)], sudo=True)
            notes.append("%s: ownership taken by uid %d (%s); the tree was root-owned and the agent must edit it" % (repo, uid, "ok" if st.ok else "FAILED"))
        added = _ensure_gitignore(repo, secret_files)
        if added and is_git(repo):
            # files that were tracked before the rule existed stay tracked unless untracked explicitly
            run.step("git-untrack-" + repo.name, ["git", "rm", "-r", "-q", "--cached", "--ignore-unmatch", "--"] + [a.rstrip("/") for a in added], cwd=repo)
        if not is_git(repo):
            run.step("git-init-" + repo.name, ["git", "init", "-q"], cwd=repo)
            run.step("git-add-" + repo.name, ["git", "add", "-A"], cwd=repo)
            run.step("git-commit-" + repo.name, ["git", "commit", "-q", "-m", "ihc: adopt live tree (baseline)"], cwd=repo)
            notes.append("%s: initialised git and committed baseline (undo: rm -rf %s/.git)" % (repo, repo))
            inline = [s for s in fx.get("secrets", []) if s["kind"] != "secret-looking-filename" and str(s["file"]).startswith(str(repo))]
            if inline:
                where = ", ".join("%s:%s" % (Path(s["file"]).relative_to(repo), s["line"]) for s in inline[:6])
                notes.append("%s: inline secrets are now in local git history too (%s); move them to an env/sops file before adding any remote — ihc never adds remotes or pushes" % (repo, where))
                notify("Secrets inside the config tree", "Now also in local git history: %s. Move them before adding a remote." % where, "normal")
        else:
            notes.append("%s: already a git repo" % repo)
    for name in docs.DOC_NAMES:
        src = Path(os.environ.get("IHC_SEED_DOCS", "")).expanduser() / name if os.environ.get("IHC_SEED_DOCS") else None
        dst = cfg.docs_dir / name
        if src and src.exists() and not dst.exists():
            shutil.copy(src, dst)
            notes.append("seeded %s" % dst)
    return notes


def commit_drift(cfg: nix.Config, run: Run, msg: str) -> list[str]:
    committed = []
    for repo in cfg.config_repos:
        if not is_git(repo):
            continue
        status = _git(repo, "status", "--porcelain").stdout
        if status.strip():
            files = sorted({l[3:].strip() for l in status.splitlines() if len(l) > 3})
            run.step("git-add-" + repo.name, ["git", "add", "-A"], cwd=repo)
            st = run.step("git-commit-" + repo.name, ["git", "commit", "-q", "-m", msg + "\n\nfiles: " + ", ".join(files)[:800]], cwd=repo)
            if st.ok:
                committed.append(str(repo))
    return committed


# ---- fix loop -------------------------------------------------------------------

def fix_loop(cfg: nix.Config, run: Run, fx: dict, verdict: prove.Verdict, max_attempts: int, task: str | None = None, target: str = "all", eval_only: bool = False) -> prove.Verdict:
    summary = facts_mod.summary_lines(fx)
    if eval_only:
        summary = summary + ["DISK IS NEARLY FULL: verify with `nix eval --raw <attr>.drvPath` only; do NOT run nix build or home-manager build"]
    for attempt in range(1, max_attempts + 1):
        if run.expired():
            run.note("run deadline reached; no more fix attempts")
            break
        failed = next((s for s in reversed(run.steps) if not s.ok and s.name.startswith(("build-", "eval-", "dry-activate"))), None)
        tail = failed.tail(150) if failed else "(no failing build step recorded)"
        prompt = agent.fix_prompt(cfg, summary, verdict.failed_step or "build", verdict.failed_target or target, tail, task)
        run.note("fix attempt %d/%d (%s)" % (attempt, max_attempts, verdict.failed_step or task))
        name, completed, last = agent.run_agent(cfg, run, prompt)
        if not name:
            run.note("no agent available or every agent failed: %s" % last)
            break
        diff = agent.diff_text(cfg)
        violations = agent.policy_violations(diff, docs.invariant_options(cfg.docs_dir))
        if violations:
            (run.dir / ("rejected-%d.diff" % attempt)).write_text(diff)
            agent.revert(cfg, run)
            pending_add("policy", "Agent change rejected by policy", "\n".join(violations) + "\n\nDiff kept at %s" % (run.dir / ("rejected-%d.diff" % attempt)), "Apply the change by hand if you agree, then `ihc pending resolve <id>`.")
            notify("Agent change rejected", "; ".join(violations)[:300], "critical")
            run.note("policy violations: " + "; ".join(violations))
            break
        if not agent.changed_files(cfg):
            run.note("agent %s made no changes: %s" % (name, last[:160]))
            if last.startswith("BLOCKED"):
                break
            continue
        (run.dir / ("fix-%d.diff" % attempt)).write_text(diff)
        verdict = prove.check(cfg, run, fx, target, eval_only)
        if verdict.ok:
            run.note("fixed by %s on attempt %d: %s" % (name, attempt, last[:200]))
            return verdict
    return verdict


# ---- bump -----------------------------------------------------------------------

def _lock_revs(cfg: nix.Config) -> dict[str, str | None]:
    return {i.name: i.rev for i in nix.lock_inputs(cfg.flake_dir)}


def bump_order(inputs: list[nix.Input], only: list[str] | None) -> tuple[list[str], dict[str, str]]:
    skipped: dict[str, str] = {}
    names = []
    for i in sorted(inputs, key=lambda x: (x.name != "nixpkgs", x.name)):
        if only and i.name not in only:
            continue
        if i.pinned and not only:
            skipped[i.name] = "pinned to a commit in flake.nix"
            continue
        if i.local and not only:
            skipped[i.name] = "local checkout (%s); bump it by committing there" % i.ref
            continue
        names.append(i.name)
    return names, skipped


def bump(cfg: nix.Config, run: Run, fx: dict, only: list[str] | None, max_attempts: int, eval_only: bool = False) -> dict:
    inputs = nix.lock_inputs(cfg.flake_dir)
    names, skipped = bump_order(inputs, only)
    result: dict = {"bumped": [], "blocked": {}, "skipped": skipped, "last_verdict": None}
    lock = cfg.flake_dir / "flake.lock"
    for name in names:
        if run.expired():
            result["skipped"][name] = "run deadline reached"
            continue
        before = lock.read_text()
        revs_before = _lock_revs(cfg)
        st = run.step("flake-update-" + name, ["nix", "flake", "update", name] + cfg.nix_args(), cwd=cfg.flake_dir, env=cfg.env())
        if not st.ok:
            result["blocked"][name] = "flake update failed: " + st.tail(5)
            _git(cfg.flake_dir, "checkout", "HEAD", "--", "flake.lock")
            continue
        if lock.read_text() == before:
            result["skipped"][name] = "up to date"
            continue
        new_rev = _lock_revs(cfg).get(name)
        old_rev = revs_before.get(name)
        run.note("bump %s %s..%s" % (name, (old_rev or "?")[:8], (new_rev or "?")[:8]))
        verdict = prove.check(cfg, run, fx, eval_only=eval_only)
        if not verdict.ok:
            verdict = fix_loop(cfg, run, fx, verdict, max_attempts, eval_only=eval_only)
        if verdict.ok:
            commit_drift(cfg, run, "bump(%s): %s..%s" % (name, (old_rev or "?")[:8], (new_rev or "?")[:8]))
            result["bumped"].append("%s %s..%s" % (name, (old_rev or "?")[:8], (new_rev or "?")[:8]))
            result["last_verdict"] = verdict
        else:
            failed = next((s for s in reversed(run.steps) if not s.ok and s.name.startswith("build-")), None)
            result["blocked"][name] = "%s: %s" % (verdict.failed_step, (failed.tail(8) if failed else "")[:600])
            agent.revert(cfg, run)  # drops the lock change and any half-done agent edits
            run.note("blocked %s, lock restored" % name)
    return result


# ---- improve (MAINTENANCE.md queue) ---------------------------------------------

QUEUE_RE = re.compile(r"^- \[ \] \(risk: (low|medium|high)\) (.+)$", re.M)


def next_queue_item(cfg: nix.Config, max_risk: str = "low") -> tuple[str, str] | None:
    p = cfg.docs_dir / "MAINTENANCE.md"
    if not p.exists():
        return None
    allowed = {"low": ("low",), "medium": ("low", "medium"), "high": ("low", "medium", "high")}[max_risk]
    for m in QUEUE_RE.finditer(p.read_text()):
        if m.group(1) in allowed:
            return m.group(0), m.group(2)
    return None


def tick_queue_item(cfg: nix.Config, line: str) -> None:
    p = cfg.docs_dir / "MAINTENANCE.md"
    p.write_text(p.read_text().replace(line, line.replace("- [ ]", "- [x]", 1), 1))


def improve(cfg: nix.Config, run: Run, fx: dict, max_attempts: int, max_risk: str = "low") -> str | None:
    item = next_queue_item(cfg, max_risk)
    if not item:
        return None
    line, task = item
    run.note("improve: " + task)
    verdict = prove.Verdict(ok=False, failed_step="improve", failed_target="all")
    verdict = fix_loop(cfg, run, fx, verdict, max_attempts, task="MAINTENANCE.md queue item: " + task + "\nAfter the change, both system and home-manager must still build.")
    if verdict.ok and agent.changed_files(cfg):
        tick_queue_item(cfg, line)
        commit_drift(cfg, run, "improve: " + task[:60])
        return task
    agent.revert(cfg, run)
    return None


# ---- docs follow the system ------------------------------------------------------------

def refresh_docs_if_changed(cfg: nix.Config, run: Run, fx: dict) -> str:
    """When the mined facts changed since the docs were last generated, the agent refreshes GOALS/MAINTENANCE
    (including the machine-readable sections); a failed citation check reverts the docs."""
    from .store import STATE_DIR
    marker = STATE_DIR / "docs-fingerprint"
    fp = fx.get("fingerprint", "")
    fx = facts_mod.mine(cfg)  # re-mine: the run may have changed the tree
    fp = fx.get("fingerprint", fp)
    if marker.exists() and marker.read_text().strip() == fp and (cfg.docs_dir / "GOALS.md").exists():
        return "unchanged"
    prompt = docs.regen_prompt(cfg, facts_mod.to_json(fx), cfg.docs_dir)
    name, ok, last = agent.run_agent(cfg, run, prompt)
    if not name:
        return "no agent"
    n, problems = docs.check_all(cfg)
    if problems:
        agent.revert(cfg, run)
        run.note("docs regen rejected: " + "; ".join(problems)[:300])
        return "rejected (%d citation problems)" % len(problems)
    commit_drift(cfg, run, "docs: refresh for changed facts (%s)" % name)
    marker.write_text(fp + "\n")
    return "refreshed by %s (%d citations)" % (name, n)


# ---- post-activation review ----------------------------------------------------------

def review(cfg: nix.Config, run: Run, fx: dict, kind: str, since: str, since_epoch: float, activation_text: str, before: dict | None, reactivate: bool = False) -> dict:
    """Collect what changed, let the agent verify it for real (logs, unit status, program checks), fix config regressions,
    re-prove, and — only when the caller allows it — re-activate home-manager."""
    # clean baseline first: anything uncommitted now is the user's, not the agent's
    commit_drift(cfg, run, "chore(ihc): commit uncommitted changes before review")
    evidence = prove.switch_evidence(cfg, run, fx, kind, since, since_epoch, activation_text, before)
    result = {"kind": kind, "evidence": str(evidence), "verdict": "UNREVIEWED", "detail": ""}
    prompt = agent.review_prompt(cfg, facts_mod.summary_lines(fx), kind, evidence.read_text())
    name, completed, last = agent.run_agent(cfg, run, prompt)
    if not name:
        result["detail"] = "no agent available: " + last
        run.note("review %s: no agent (%s)" % (kind, last[:120]))
        return result
    verdict = last.split(" ", 1)[0].upper() if last else "UNKNOWN"
    result["verdict"], result["detail"], result["agent"] = verdict, last[:400], name
    diff = agent.diff_text(cfg)
    if diff.strip():
        violations = agent.policy_violations(diff, docs.invariant_options(cfg.docs_dir))
        if violations:
            (run.dir / "review-rejected.diff").write_text(diff)
            agent.revert(cfg, run)
            pending_add("policy", "Post-activation fix rejected by policy", "\n".join(violations) + "\n\nAgent's finding: " + last[:600] + "\nDiff kept at " + str(run.dir / "review-rejected.diff"), "Apply by hand if you agree, then `ihc pending resolve <id>`.")
            notify("ACTION NEEDED: %s regression found, fix blocked by policy" % kind, (last[:220] + " — see `ihc pending list`"), "critical")
            result["verdict"] = "BLOCKED"
            result["detail"] += " | fix rejected by policy: " + "; ".join(violations)[:200]
            return result
        (run.dir / "review-fix.diff").write_text(diff)
        v = prove.check(cfg, run, fx, kind)
        if not v.ok:
            agent.revert(cfg, run)
            result["verdict"] = "BLOCKED"
            result["detail"] += " | the fix did not build (%s); reverted" % v.failed_step
            return result
        commit_drift(cfg, run, "fix(post-%s review): %s" % (kind, last[:60]))
        if kind == "hm" and v.hm_path and reactivate:
            ok = prove.switch_hm(cfg, run, v.hm_path)
            result["reactivated"] = "switched" if ok else "FAILED"
            if ok:
                text = run.steps[-1].out + run.steps[-1].err
                prove.switch_evidence(cfg, run, fx, kind + "-after-fix", store_now(), time.time() - 5, text, None)
        else:
            result["reactivated"] = "built and committed; not activated (run `ihc switch --target %s` or wait for the nightly)" % kind
    if verdict == "BLOCKED":
        pending_add("review", "Post-%s review: regression the agent could not fix" % kind, last[:800] + "\n\nEvidence: " + str(evidence), "Fix by hand, then `ihc pending resolve <id>`.")
        notify("ACTION NEEDED: %s regression the agent could not fix" % kind, last[:220] + " — see `ihc pending list`", "critical")
    run.note("review %s: %s" % (kind, last[:200]))
    return result


def store_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---- switch -----------------------------------------------------------------------

def activate(cfg: nix.Config, run: Run, fx: dict, verdict: prove.Verdict, policy: str, force_mode: str | None = None, do_review: bool = True) -> dict:
    out = {"hm": None, "system": None, "mode": None, "rollback": False, "review": {}}
    if policy == "never" or not verdict.ok:
        return out
    if verdict.hm_path and policy in ("auto", "hm-only"):
        cur = cfg.hm_profile.resolve() if cfg.hm_profile.exists() else None
        if cur == verdict.hm_path:
            out["hm"] = "unchanged"
        else:
            since, since_epoch = store_now(), time.time() - 2
            before = prove.health_snapshot(cfg, fx)
            ok = prove.switch_hm(cfg, run, verdict.hm_path)
            out["hm"] = "switched" if ok else "FAILED"
            if ok and do_review:
                text = run.steps[-1].out + run.steps[-1].err
                out["review"]["hm"] = review(cfg, run, fx, "hm", since, since_epoch, text, before, reactivate=True)
    if verdict.system_path and policy in ("auto", "system-only"):
        cur = nix.current_system()
        if cur == verdict.system_path:
            out["system"] = "unchanged"
            return out
        mode = force_mode or verdict.mode or "switch"
        busy = prove.busy(fx)
        if mode == "switch" and busy:
            mode = "boot"
            verdict.mode_reasons.append("busy checks hit (%s) — activating at next boot instead" % ", ".join(busy))
        before = prove.health_snapshot(cfg, fx)
        since, since_epoch = store_now(), time.time() - 2
        ok = prove.switch_system(cfg, run, verdict.system_path, mode)
        out["mode"] = mode
        if not ok:
            out["system"] = "FAILED"
            if prove.rollback_system(cfg, run):
                out["rollback"] = True
            return out
        if mode == "switch":
            after = prove.health_snapshot(cfg, fx)
            regs = prove.health_regressions(before, after)
            (run.dir / "health.json").write_text(json.dumps({"before": before, "after": after, "regressions": regs}, indent=2))
            if regs:
                run.note("health regressions: " + "; ".join(regs))
                out["rollback"] = prove.rollback_system(cfg, run)
                out["system"] = "rolled back"
                return out
            if do_review:
                text = run.steps[-1].out + run.steps[-1].err
                out["review"]["system"] = review(cfg, run, fx, "system", since, since_epoch, text, before)
        out["system"] = "switched" if mode == "switch" else "activated-at-boot"
    return out


# ---- the scheduled run --------------------------------------------------------------

def pipeline(cfg: nix.Config, run: Run, *, switch_policy: str, do_bump: bool, only: list[str] | None, max_attempts: int, do_improve: bool, improve_risk: str) -> int:
    fx = facts_mod.mine(cfg)
    (run.dir / "facts.json").write_text(facts_mod.to_json(fx))
    eval_only = False
    short = prove.store_short(fx)
    if short is not None:
        eval_only = True
        msg = "/nix/store has %.1f GiB free (< %.0f GiB): this run proves by evaluation only and activates nothing. Free space (nh clean / nix-collect-garbage) to resume builds." % (short, prove.MIN_STORE_FREE_GIB)
        run.note(msg)
        notify("Disk nearly full: eval-only maintenance", msg, "critical")
        switch_policy = "never"
    if not prove.sudo_ok(cfg) and switch_policy in ("auto", "system-only"):
        run.note("sudo -n unavailable: system activation disabled for this run (proofs still run)")
        switch_policy = "hm-only" if switch_policy == "auto" else "never"
    pending_before = len(pending_list())
    run.note("adopt: " + "; ".join(adopt(cfg, run, fx)))
    if prove.boot_short(fx):
        prove.prune_boot(cfg, run, fx)
        fx = facts_mod.mine(cfg)
        if prove.boot_short(fx):
            d = fx["runtime"]["disk"]
            msg = "/boot has %.0f MiB free; a generation needs ~%.0f MiB. System activation is disabled until /boot has room (lower boot.loader.systemd-boot.configurationLimit or grow /boot)." % (d["boot"]["free_gib"] * 1024, d["boot_need_mib"])
            run.note(msg)
            notify("/boot is full", msg, "critical")
            if switch_policy in ("auto", "system-only"):
                switch_policy = "hm-only" if switch_policy == "auto" else "never"
    drift = commit_drift(cfg, run, "chore(ihc): commit live drift before maintenance")
    if drift:
        run.note("committed user drift in " + ", ".join(drift))

    bumped: dict = {"bumped": [], "blocked": {}, "skipped": {}, "last_verdict": None}
    if do_bump:
        bumped = bump(cfg, run, fx, only, max_attempts, eval_only)
    improved = improve(cfg, run, fx, max_attempts, improve_risk) if do_improve else None

    verdict = bumped.get("last_verdict") if (bumped.get("last_verdict") and not improved) else None
    if verdict is None:
        verdict = prove.check(cfg, run, fx, eval_only=eval_only)
        if not verdict.ok:
            verdict = fix_loop(cfg, run, fx, verdict, max_attempts, eval_only=eval_only)
            if verdict.ok:
                commit_drift(cfg, run, "fix: " + (verdict.failed_step or "build") + " (agent)")
    act = activate(cfg, run, fx, verdict, switch_policy, do_review=True)
    gens = prove.generation_count(cfg) if cfg.platform == "nixos" else None
    docs_result = refresh_docs_if_changed(cfg, run, fx)

    run.verdict = dict(verdict.as_dict(), bumped=bumped["bumped"], blocked=bumped["blocked"], skipped=bumped["skipped"], improved=improved, activation=act, generations=gens, docs=docs_result)
    run.write_report()
    history_append({
        "run": run.id, "ok": verdict.ok, "bumped": bumped["bumped"], "blocked": sorted(bumped["blocked"]), "improved": improved,
        "closure_bytes": verdict.closure_bytes, "activation": act, "generations": gens,
        "revs": {k: (v or "")[:8] for k, v in _lock_revs(cfg).items()},
    })
    escalated = escalate_repeated_blocks(bumped) if bumped.get("blocked") else []
    _notify_summary(verdict, bumped, act, improved, gens, run, escalated, pending_before)
    return 0 if verdict.ok and act.get("system") not in ("FAILED", "rolled back") and act.get("hm") != "FAILED" else 1


BLOCKED_NIGHTS = 3


def escalate_repeated_blocks(bumped: dict) -> list[str]:
    """An input blocked BLOCKED_NIGHTS runs in a row is beyond the agent: hand it to the user once."""
    hist = history_read(50)
    escalated = []
    for name, why in bumped.get("blocked", {}).items():
        streak = 1
        for h in reversed(hist):
            if name in (h.get("blocked") or []):
                streak += 1
            else:
                break
        if streak >= BLOCKED_NIGHTS and not any(p["kind"] == "bump" and name in p["title"] for p in pending_list()):
            pending_add("bump", "Input %s blocked %d runs in a row" % (name, streak), why[:1200], "Fix the breakage by hand or pin the input, then `ihc pending resolve <id>`.")
            escalated.append(name)
    return escalated


def _notify_summary(verdict: prove.Verdict, bumped: dict, act: dict, improved: str | None, gens: int | None, run: Run, escalated: list[str] | None = None, pending_before: int = 0) -> None:
    lines = []
    if bumped["bumped"]:
        lines.append("bumped: " + ", ".join(b.split(" ")[0] for b in bumped["bumped"]))
    if bumped["blocked"]:
        lines.append("blocked: " + ", ".join(bumped["blocked"]))
    if improved:
        lines.append("improved: " + improved[:80])
    if act.get("hm"):
        lines.append("home-manager: " + act["hm"])
    if act.get("system"):
        lines.append("system: %s" % act["system"])
        if act.get("mode") == "boot":
            lines.append("action: reboot when convenient to run the new generation (kernel/drivers changed); the previous one stays in the boot menu")
    blocked_reviews = []
    for k, rv in (act.get("review") or {}).items():
        lines.append("post-%s review: %s" % (k, (rv.get("verdict", "?") + " " + rv.get("detail", ""))[:160]))
        if rv.get("verdict") == "BLOCKED":
            blocked_reviews.append(k)
    if escalated:
        lines.append("action: inputs blocked %d runs in a row need you: %s" % (BLOCKED_NIGHTS, ", ".join(escalated)))
    new_pending = len(pending_list()) - pending_before
    if new_pending > 0:
        lines.append("action: %d new pending decision(s) — run `ihc pending list`" % new_pending)
    if act.get("rollback"):
        lines.append("ROLLED BACK after health regression — see %s" % (run.dir / "health.json"))
    if gens is not None and gens < 2:
        lines.append("WARNING: only %d system generation kept — no rollback target. Fix generation retention (see MAINTENANCE.md)." % gens)
    needs_user = bool(blocked_reviews or escalated or new_pending > 0)
    urgency = "critical" if (not verdict.ok or act.get("rollback") or act.get("system") == "FAILED" or (gens is not None and gens < 2) or needs_user) else ("normal" if (bumped["bumped"] or improved or act.get("system") == "switched" or act.get("hm") == "switched") else "low")
    title = ("ACTION NEEDED — " if needs_user else "") + "Maintenance %s" % ("failed at %s" % verdict.failed_step if not verdict.ok else "ok")
    notify(title, "\n".join(lines) or "nothing to do", urgency)


# ---- status ------------------------------------------------------------------------------

def status_text(cfg: nix.Config) -> str:
    fx = facts_mod.mine(cfg)
    lines = facts_mod.summary_lines(fx)
    hist = history_read(20)
    last_ok = next((h for h in reversed(hist) if h.get("ok")), None)
    last = hist[-1] if hist else None
    lines.append("last run: %s %s" % (last["run"], "ok" if last["ok"] else "FAILED") if last else "last run: none")
    lines.append("last successful run: %s" % (last_ok["run"] if last_ok else "never"))
    if last and last.get("blocked"):
        lines.append("blocked inputs (last run): " + ", ".join(last["blocked"]))
    pend = pending_list()
    if pend:
        lines.append("pending decisions (%d): run `ihc pending list`" % len(pend))
        for p in pend:
            lines.append("  - %s: %s" % (p["id"], p["title"]))
    rid = last_run_id()
    if rid:
        rep = RUNS_DIR / rid / "report.json"
        if rep.exists():
            try:
                lines.append("last evidence run: %s -> %s" % (rid, json.loads(rep.read_text()).get("verdict", {}).get("summary", "?")))
            except ValueError:
                pass
        lines.append("evidence: %s" % (RUNS_DIR / rid))
    return "\n".join(lines)
