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

from . import agent, docs, facts as facts_mod, nix, prove, security
from .notify import notify
from . import store
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


def lock_moves(repo: Path) -> list[str]:
    """Inputs whose locked rev differs between HEAD's flake.lock and the working copy (a bump made outside ihc)."""
    try:
        old = json.loads(_git(repo, "show", "HEAD:flake.lock").stdout)["nodes"]
        new = json.loads((repo / "flake.lock").read_text())["nodes"]
    except (ValueError, KeyError, OSError):
        return []
    names = {v: k for k, v in new.get("root", {}).get("inputs", {}).items() if isinstance(v, str)}

    def rev(nodes, n):
        return nodes[n].get("locked", {}).get("rev") or "?"

    return ["%s %s..%s" % (names.get(n, n), rev(old, n)[:8], rev(new, n)[:8])
            for n in sorted(set(old) & set(new)) if rev(old, n) != rev(new, n)]


def commit_drift(cfg: nix.Config, run: Run, msg: str) -> list[str]:
    committed = []
    for repo in cfg.config_repos:
        if not is_git(repo):
            continue
        status = _git(repo, "status", "--porcelain").stdout
        if status.strip():
            files = sorted({l[3:].strip() for l in status.splitlines() if len(l) > 3})
            moves = lock_moves(repo) if "flake.lock" in files and not msg.startswith("bump(") else []
            if moves:
                run.note("flake.lock moved outside a bump in %s: %s" % (repo.name, ", ".join(moves)))
                msg += "\n\nlock: " + ", ".join(moves)[:400]
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


HEAVY_SECONDS = int(os.environ.get("IHC_HEAVY_MINUTES", "20")) * 60
HEAVY_DAYS = int(os.environ.get("IHC_HEAVY_DAYS", "7"))


def heavy_builds(cfg: nix.Config, run: Run) -> list[tuple[str, int]]:
    """Local source builds the current tree forces whose known cost (build ledger) adds up to a heavy run."""
    names: list[str] = []
    for t in ("system", "hm"):
        if cfg.system_attr if t == "system" else cfg.hm_attr_path:
            names += prove.local_builds(cfg, run, t)
    ledger = store.ledger_read()
    known = sorted(((n, ledger[n]["seconds"]) for n in dict.fromkeys(names) if n in ledger), key=lambda x: -x[1])
    return known if sum(s for _, s in known) >= HEAVY_SECONDS else []


def queue_heavy_split(cfg: nix.Config, input_name: str, heavy: list[tuple[str, int]]) -> None:
    """Ask the improve loop to move packages that rebuild from source on every bump onto their own slow input."""
    path = cfg.docs_dir / "MAINTENANCE.md"
    if not path.exists():
        return
    text = path.read_text()
    for pkg, secs in heavy:
        if "`%s` rebuilds from source" % pkg in text:
            continue
        item = ("- [ ] (risk: low) `%s` rebuilds from source on every `%s` bump (%d min last time; no configured binary cache has it). "
                "Give it its own slow-moving input (e.g. `%s-%s` pinned to the current `%s` rev) and take the package from that input, "
                "so `%s` can move daily while ihc bumps the slow input every %d days.\n" % (pkg, input_name, secs // 60, input_name, pkg, input_name, input_name, HEAVY_DAYS))
        if "## Queue" in text:
            head, tail = text.split("## Queue", 1)
            nl = tail.find("\n") + 1
            text = head + "## Queue" + tail[:nl] + "\n" + item + tail[nl:].lstrip("\n")
        else:
            text += "\n## Queue\n\n" + item
    path.write_text(text)


def bump(cfg: nix.Config, run: Run, fx: dict, only: list[str] | None, max_attempts: int, eval_only: bool = False, allow_heavy: bool = False) -> dict:
    inputs = nix.lock_inputs(cfg.flake_dir)
    names, skipped = bump_order(inputs, only)
    result: dict = {"bumped": [], "blocked": {}, "skipped": skipped, "deferred": {}, "last_verdict": None}
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
        heavy = [] if (allow_heavy or eval_only) else heavy_builds(cfg, run)
        if heavy:
            what = ", ".join("%s (%d min)" % (n, secs // 60) for n, secs in heavy)
            days = store.heavy_deferred(name)
            if days < HEAVY_DAYS:
                agent.revert(cfg, run)
                result["deferred"][name] = "rebuilds from source, no configured binary cache has it: %s (deferred %d/%d days)" % (what, days, HEAVY_DAYS)
                run.note("deferred bump %s: %s" % (name, result["deferred"][name]))
                queue_heavy_split(cfg, name, heavy)
                continue
            run.note("heavy bump %s allowed after %d days: %s" % (name, days, what))
        try:
            verdict = prove.check(cfg, run, fx, eval_only=eval_only)
            if not verdict.ok:
                verdict = fix_loop(cfg, run, fx, verdict, max_attempts, eval_only=eval_only)
        except BaseException:
            agent.revert(cfg, run)  # a crash or a kill must not leave the bumped lock in the tree
            run.note("bump %s aborted, lock restored" % name)
            raise
        if verdict.ok:
            commit_drift(cfg, run, "bump(%s): %s..%s" % (name, (old_rev or "?")[:8], (new_rev or "?")[:8]))
            result["bumped"].append("%s %s..%s" % (name, (old_rev or "?")[:8], (new_rev or "?")[:8]))
            result["last_verdict"] = verdict
            store.heavy_clear(name)
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
        out["reasons"] = list(verdict.mode_reasons)
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


# ---- gated security remediation ------------------------------------------------

SECURITY_GRACE_DAYS = int(os.environ.get("IHC_SECURITY_GRACE_DAYS", "1"))
SECURITY_BACKOFF_DAYS = int(os.environ.get("IHC_SECURITY_BACKOFF_DAYS", "30"))


def finding_key(f: dict) -> str:
    return "%s:%s:%s" % (f.get("id"), f.get("file") or "", f.get("line") if f.get("line") is not None else "")


def security_fix(cfg: nix.Config, run: Run, fx: dict, max_attempts: int) -> dict:
    """Fix the auto class of security findings under the proof harness, with three gates.

    Accepted findings never arrive here (`security.report` moves them aside). A finding is not
    fixed the run it first appears, and a fix that fails to prove is not retried for a month.
    """
    out: dict = {"attempted": False, "fixed": False, "reason": "", "held": []}
    rep = security.report(cfg, fx)
    auto = [f for f in rep.get("findings", []) if f.get("auto") is True]
    if not auto:
        return out
    due = []
    for f in auto:
        ok, why = store.security_due(finding_key(f), SECURITY_GRACE_DAYS, SECURITY_BACKOFF_DAYS)
        (due if ok else out["held"]).append(f if ok else "%s (%s:%s): %s" % (f["id"], f["file"], f["line"], why))
    if out["held"]:
        run.note("security auto-fix held: " + "; ".join(out["held"])[:400])
    task = security.fix_task(dict(rep, findings=due)) if due else None
    if not task:
        out["reason"] = "nothing due"
        return out
    out["attempted"] = True
    run.note("security auto-fix: %d finding(s) due" % len(due))
    verdict = fix_loop(cfg, run, fx, prove.Verdict(ok=False, failed_step="security", failed_target="all"),
                       max_attempts, task, "all", False)
    changed = bool(agent.changed_files(cfg))
    out["fixed"] = bool(verdict.ok and changed)
    for f in due:
        store.security_attempted(finding_key(f), out["fixed"])
    if out["fixed"]:
        commit_drift(cfg, run, "security: fix %s (agent)" % ", ".join(sorted({f["id"] for f in due}))[:60])
        out["reason"] = "fixed %s" % ", ".join(sorted({f["id"] for f in due}))
    elif changed:
        agent.revert(cfg, run)
        out["reason"] = "the proof failed at %s; reverted" % (verdict.failed_step or "?")
    else:
        out["reason"] = "the agent changed nothing (it may have judged the finding deliberate)"
    run.note("security auto-fix: " + out["reason"])
    return out


# ---- ask: one-shot user-reported problem ---------------------------------------

def ask(cfg: nix.Config, run: Run, fx: dict, question: str) -> dict:
    """Diagnose and fix a problem the user described; FIXED / BLOCKED / UNSOLVED, always with the why."""
    prompt = agent.ask_prompt(cfg, facts_mod.summary_lines(fx), question)
    name, completed, last = agent.run_agent(cfg, run, prompt)
    if not name:
        return {"verdict": "UNSOLVED", "detail": "no usable agent: " + last}
    word = next((w for w in ("FIXED", "BLOCKED", "UNSOLVED") if last.startswith(w)), None)
    detail = last.split(" ", 1)[1].strip() if word and " " in last else last
    if not agent.changed_files(cfg):
        if word == "FIXED":
            return {"verdict": "UNSOLVED", "detail": "the agent claimed a fix but changed nothing: " + detail}
        return {"verdict": word or "UNSOLVED", "detail": detail}
    diff = agent.diff_text(cfg)
    violations = agent.policy_violations(diff, docs.invariant_options(cfg.docs_dir))
    if violations:
        (run.dir / "rejected-ask.diff").write_text(diff)
        agent.revert(cfg, run)
        return {"verdict": "BLOCKED", "detail": "the change broke policy (%s); reverted. Agent said: %s" % ("; ".join(violations)[:200], detail)}
    (run.dir / "ask.diff").write_text(diff)
    verdict = prove.check(cfg, run, fx)
    if not verdict.ok:
        verdict = fix_loop(cfg, run, fx, verdict, 2)
    if not verdict.ok:
        agent.revert(cfg, run)
        return {"verdict": "BLOCKED", "detail": "found and changed, but the proof failed at %s; reverted. Agent said: %s" % (verdict.failed_step, detail)}
    commit_drift(cfg, run, "ask: " + question[:60])
    return {"verdict": "FIXED", "detail": detail + " — committed; it takes effect at the next activation", "changed": True}


# ---- the scheduled run --------------------------------------------------------------

def pipeline(cfg: nix.Config, run: Run, *, switch_policy: str, do_bump: bool, only: list[str] | None, max_attempts: int, do_improve: bool, improve_risk: str, allow_heavy: bool = False) -> int:
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

    bumped: dict = {"bumped": [], "blocked": {}, "skipped": {}, "deferred": {}, "last_verdict": None}
    if do_bump:
        bumped = bump(cfg, run, fx, only, max_attempts, eval_only, allow_heavy=allow_heavy)
    improved = improve(cfg, run, fx, max_attempts, improve_risk) if do_improve else None
    # Only the auto class is ever fixed unattended, and only after the gates in security_fix().
    secfix = security_fix(cfg, run, fx, max_attempts) if not eval_only and not run.expired() else {"attempted": False, "fixed": False, "reason": "skipped", "held": []}
    verdict = bumped.get("last_verdict") if (bumped.get("last_verdict") and not improved and not secfix["fixed"]) else None
    if verdict is None:
        verdict = prove.check(cfg, run, fx, eval_only=eval_only)
        if not verdict.ok:
            verdict = fix_loop(cfg, run, fx, verdict, max_attempts, eval_only=eval_only)
            if verdict.ok:
                commit_drift(cfg, run, "fix: " + (verdict.failed_step or "build") + " (agent)")
    act = activate(cfg, run, fx, verdict, switch_policy, do_review=True)
    sec = security.report(cfg, fx)
    if not eval_only and verdict.ok and security.cve_due() and not run.expired():
        targets = [p for p in (verdict.system_path, verdict.hm_path) if p]
        if targets:
            sec["cve"] = security.cve_scan(cfg, run, targets)
    sec["auto_fix"] = secfix
    sec["summary"] = security.summary_lines(sec)
    if secfix["attempted"]:
        sec["summary"].insert(1, "security auto-fix: " + secfix["reason"])
    elif secfix.get("held"):
        sec["summary"].insert(1, "security auto-fix held: " + "; ".join(secfix["held"])[:200])
    (run.dir / "security.json").write_text(json.dumps(sec, indent=2, default=str))
    security.escalate(sec)
    for line in sec["summary"][:2]:
        run.note("security: " + line)
    gens = prove.generation_count(cfg) if cfg.platform == "nixos" else None
    docs_result = refresh_docs_if_changed(cfg, run, fx)

    run.verdict = dict(verdict.as_dict(), bumped=bumped["bumped"], blocked=bumped["blocked"], skipped=bumped["skipped"], deferred=bumped.get("deferred", {}), improved=improved, security_fix=secfix, activation=act, generations=gens, docs=docs_result, security=sec["counts"])
    run.write_report()
    history_append({
        "run": run.id, "ok": verdict.ok, "bumped": bumped["bumped"], "blocked": sorted(bumped["blocked"]), "deferred": bumped.get("deferred", {}), "improved": improved,
        "closure_bytes": verdict.closure_bytes, "activation": act, "generations": gens,
        "security": sec["counts"], "security_fix": secfix,
        "revs": {k: (v or "")[:8] for k, v in _lock_revs(cfg).items()},
    })
    escalated = escalate_repeated_blocks(bumped) if bumped.get("blocked") else []
    _notify_summary(verdict, bumped, act, improved, gens, run, escalated, pending_before, sec)
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


def _notify_summary(verdict: prove.Verdict, bumped: dict, act: dict, improved: str | None, gens: int | None, run: Run, escalated: list[str] | None = None, pending_before: int = 0, security_report: dict | None = None) -> None:
    lines = []
    if bumped["bumped"]:
        lines.append("bumped: " + ", ".join(b.split(" ")[0] for b in bumped["bumped"]))
    if bumped["blocked"]:
        lines.append("blocked: " + ", ".join(bumped["blocked"]))
    for k, why in (bumped.get("deferred") or {}).items():
        lines.append("deferred %s: %s — the queue asks the agent to move it to a slow input; `ihc run --allow-heavy` forces the bump" % (k, why))
    if improved:
        lines.append("improved: " + improved[:80])
    if act.get("hm"):
        lines.append("home-manager: " + act["hm"])
    if act.get("system"):
        lines.append("system: %s" % act["system"])
        if act.get("mode") == "boot":
            lines.append("REBOOT NEEDED: %s. The new generation is the default boot entry; the running system is unchanged until you reboot (the previous generation stays in the menu)."
                         % ("; ".join(act.get("reasons") or ["kernel or drivers changed"])))
    blocked_reviews = []
    for k, rv in (act.get("review") or {}).items():
        lines.append("post-%s review: %s" % (k, (rv.get("verdict", "?") + " " + rv.get("detail", ""))[:160]))
        if rv.get("verdict") == "BLOCKED":
            blocked_reviews.append(k)
    if escalated:
        lines.append("action: inputs blocked %d runs in a row need you: %s" % (BLOCKED_NIGHTS, ", ".join(escalated)))
    lines += (security_report or {}).get("summary", [])[:2]
    new_pending = len(pending_list()) - pending_before
    if new_pending > 0:
        lines.append("action: %d new pending decision(s) — run `ihc pending list`" % new_pending)
    if act.get("rollback"):
        lines.append("ROLLED BACK after health regression — see %s" % (run.dir / "health.json"))
    if gens is not None and gens < 2:
        lines.append("WARNING: only %d system generation kept — no rollback target. Fix generation retention (see MAINTENANCE.md)." % gens)
    reboot = act.get("mode") == "boot" and act.get("system") == "activated-at-boot"
    needs_user = bool(blocked_reviews or escalated or new_pending > 0 or reboot)
    urgency = "critical" if (not verdict.ok or act.get("rollback") or act.get("system") == "FAILED" or (gens is not None and gens < 2) or needs_user) else ("normal" if (bumped["bumped"] or improved or act.get("system") == "switched" or act.get("hm") == "switched") else "low")
    title = ("REBOOT NEEDED — " if reboot else "ACTION NEEDED — " if needs_user else "") + "Maintenance %s" % ("failed at %s" % verdict.failed_step if not verdict.ok else "ok")
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
    for k, why in ((last or {}).get("deferred") or {}).items():
        lines.append("deferred bump (last run): %s — %s" % (k, why))
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
