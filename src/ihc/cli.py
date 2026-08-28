"""ihc command line. `dispatch(argv)` is the in-process entry used by the MCP server."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

from . import __version__


def _cfg(args):
    from . import nix
    return nix.discover(getattr(args, "flake", None))


def cmd_facts(args) -> int:
    from . import facts
    fx = facts.mine(_cfg(args), runtime=not args.static)
    print(facts.to_json(fx) if args.json else "\n".join(facts.summary_lines(fx)))
    return 0


def cmd_status(args) -> int:
    from .run import status_text
    print(status_text(_cfg(args)))
    return 0


def cmd_adopt(args) -> int:
    from . import facts
    from .run import adopt
    from .store import lock, new_run
    cfg = _cfg(args)
    with lock():
        run = new_run("adopt")
        notes = adopt(cfg, run, facts.mine(cfg))
        run.verdict = {"ok": True, "summary": "adopted"}
        run.write_report()
    print("\n".join(notes))
    return 0


def cmd_check(args) -> int:
    from . import facts, prove
    from .store import lock, new_run
    cfg = _cfg(args)
    with lock():
        run = new_run("check")
        fx = facts.mine(cfg)
        eval_only = args.eval_only
        short = prove.store_short(fx)
        if short is not None and not args.force and not eval_only:
            print("/nix/store has %.1f GiB free: proving by evaluation only (use --force to build anyway)" % short)
            eval_only = True
        v = prove.check(cfg, run, fx, args.target, eval_only)
        run.verdict = v.as_dict()
        run.write_report()
    print(v.summary())
    if v.units:
        print("dry-activate: " + json.dumps(v.units))
    if v.mode_reasons:
        print("mode reasons: " + "; ".join(v.mode_reasons))
    if not v.ok:
        failed = next((s for s in reversed(run.steps) if not s.ok), None)
        if failed:
            print(failed.tail(40))
    print("evidence: %s" % run.dir)
    return 0 if v.ok else 1


def cmd_bump(args) -> int:
    from . import facts
    from .run import bump, commit_drift
    from .store import lock, new_run
    cfg = _cfg(args)
    with lock():
        run = new_run("bump")
        fx = facts.mine(cfg)
        commit_drift(cfg, run, "chore(ihc): commit live drift before bump")
        res = bump(cfg, run, fx, args.inputs or None, args.max_attempts)
        run.verdict = {"ok": not res["blocked"], "summary": "bumped %d, blocked %d" % (len(res["bumped"]), len(res["blocked"])), **{k: v for k, v in res.items() if k != "last_verdict"}}
        run.write_report()
    print(json.dumps({k: v for k, v in res.items() if k != "last_verdict"}, indent=2))
    print("evidence: %s" % run.dir)
    return 0 if not res["blocked"] else 1


def cmd_fix(args) -> int:
    from . import facts, prove
    from .run import commit_drift, fix_loop
    from .store import lock, new_run
    cfg = _cfg(args)
    with lock():
        run = new_run("fix")
        fx = facts.mine(cfg)
        commit_drift(cfg, run, "chore(ihc): commit live drift before fix")
        if args.task:
            v = prove.Verdict(ok=False, failed_step="task", failed_target=args.target)
        else:
            v = prove.check(cfg, run, fx, args.target, args.eval_only)
            if v.ok:
                print("nothing to fix: " + v.summary())
                run.verdict = v.as_dict()
                run.write_report()
                return 0
        v = fix_loop(cfg, run, fx, v, args.max_attempts, args.task, args.target, args.eval_only)
        if v.ok:
            commit_drift(cfg, run, "fix: %s (agent)" % (args.task or v.failed_step or "build")[:60])
        run.verdict = v.as_dict()
        run.write_report()
    print(v.summary())
    print("evidence: %s" % run.dir)
    return 0 if v.ok else 1


def cmd_switch(args) -> int:
    from . import facts, prove
    from .run import activate
    from .store import lock, new_run
    cfg = _cfg(args)
    with lock():
        run = new_run("switch")
        fx = facts.mine(cfg)
        if prove.boot_short(fx):
            prove.prune_boot(cfg, run, fx)
            fx = facts.mine(cfg)
        v = prove.check(cfg, run, fx, args.target)
        act = {}
        if v.ok:
            policy = {"all": "auto", "hm": "hm-only", "system": "system-only"}[args.target]
            if prove.boot_short(fx) and policy != "hm-only" and not args.force:
                print("/boot is short on space: system activation refused (use --force to override)")
                policy = "hm-only" if policy == "auto" else "never"
            act = activate(cfg, run, fx, v, policy, None if args.mode == "auto" else args.mode, do_review=not args.no_review)
        run.verdict = dict(v.as_dict(), activation=act)
        run.write_report()
    print(v.summary())
    print(json.dumps(act))
    print("evidence: %s" % run.dir)
    return 0 if v.ok and act.get("system") not in ("FAILED", "rolled back") and act.get("hm") != "FAILED" else 1


def cmd_review(args) -> int:
    """Review an activation that already happened: what changed since <since>, is it healthy, fix if not."""
    from datetime import datetime
    from . import facts
    from .run import review
    from .store import lock, new_run
    cfg = _cfg(args)
    with lock():
        run = new_run("review")
        fx = facts.mine(cfg)
        (run.dir / "facts.json").write_text(facts.to_json(fx))
        profile = cfg.hm_profile if args.target == "hm" else cfg.system_profile
        since_epoch = profile.lstat().st_mtime if not args.since else datetime.strptime(args.since, "%Y-%m-%d %H:%M:%S").timestamp()
        since = datetime.fromtimestamp(since_epoch).strftime("%Y-%m-%d %H:%M:%S")
        res = review(cfg, run, fx, args.target, since, since_epoch, "", None, reactivate=args.activate)
        run.verdict = {"ok": res["verdict"] in ("HEALTHY", "FIXED"), "summary": "review %s: %s %s" % (args.target, res["verdict"], res["detail"][:120]), **res}
        run.write_report()
    print(json.dumps(res, indent=2))
    print("evidence: %s" % run.dir)
    return 0 if res["verdict"] in ("HEALTHY", "FIXED") else 1


def cmd_run(args) -> int:
    from .run import pipeline
    from .store import lock, new_run
    cfg = _cfg(args)
    with lock():
        run = new_run("run")
        code = pipeline(cfg, run, switch_policy=args.switch, do_bump=not args.no_bump, only=args.inputs or None,
                        max_attempts=args.max_attempts, do_improve=args.improve, improve_risk=args.improve_risk)
    print(json.dumps(run.verdict, indent=2, default=str))
    print("evidence: %s" % run.dir)
    return code


def cmd_docs(args) -> int:
    from . import docs, facts, agent
    cfg = _cfg(args)
    if args.action == "check":
        n, problems = docs.check_all(cfg, args.dir)
        print("%d citations checked" % n)
        for p in problems:
            print("problem: " + p)
        return 1 if problems else 0
    from .run import commit_drift
    from .store import lock, new_run
    with lock():
        run = new_run("docs")
        fx = facts.mine(cfg)
        prompt = docs.regen_prompt(cfg, facts.to_json(fx), args.dir or cfg.docs_dir)
        name, ok, last = agent.run_agent(cfg, run, prompt)
        n, problems = docs.check_all(cfg, args.dir)
        if problems:
            print("regeneration rejected: " + "; ".join(problems))
            agent.revert(cfg, run)
            run.verdict = {"ok": False, "summary": "docs citations failed"}
            run.write_report()
            return 1
        commit_drift(cfg, run, "docs: refresh GOALS.md / MAINTENANCE.md (%s)" % name)
        run.verdict = {"ok": True, "summary": "docs refreshed by %s: %s" % (name, last[:120])}
        run.write_report()
    print("docs refreshed by %s; %d citations ok" % (name, n))
    return 0


def cmd_notify(args) -> int:
    from .notify import notify
    return 0 if notify(args.title, args.body, args.urgency) or args.quiet else 1


def cmd_pending(args) -> int:
    from .store import pending_list, pending_resolve
    if args.action == "list":
        for p in pending_list():
            print("%s  %s\n  %s\n  resolve: %s\n" % (p["id"], p["title"], p["body"].replace("\n", "\n  "), p["resolve"]))
        return 0
    return 0 if pending_resolve(args.id) else 1


def cmd_mcp(args) -> int:
    from .mcp import serve
    serve()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ihc", description="proof-first Nix maintenance loop driven by your already-logged-in agent CLIs")
    p.add_argument("--version", action="version", version="ihc " + __version__)
    p.add_argument("--flake", help="flake directory (default: discovered, or $IHC_FLAKE)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("facts", help="mine the system; print a summary or --json")
    s.add_argument("--json", action="store_true")
    s.add_argument("--static", action="store_true", help="config files only, no runtime probes")
    s.set_defaults(fn=cmd_facts)

    s = sub.add_parser("status", help="drift, last run, blocked inputs, pending decisions")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("adopt", help="put the live config trees under git (idempotent)")
    s.set_defaults(fn=cmd_adopt)

    def target(sp):
        sp.add_argument("--target", choices=["all", "system", "hm"], default="all")

    s = sub.add_parser("check", help="prove the current tree: build, dry-activate, diff (never switches)")
    target(s)
    s.add_argument("--force", action="store_true", help="build even when /nix/store is short on space")
    s.add_argument("--eval-only", action="store_true", help="evaluate only (no downloads/builds); the proof a full disk still allows")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("bump", help="update inputs one at a time; fix breakage with an agent; revert what cannot be fixed")
    s.add_argument("inputs", nargs="*", help="input names (default: all non-local, non-pinned; nixpkgs first)")
    s.add_argument("--max-attempts", type=int, default=3)
    s.set_defaults(fn=cmd_bump)

    s = sub.add_parser("fix", help="let an agent repair the failing build (or do --task), then prove it")
    target(s)
    s.add_argument("--task", help="free-text task instead of 'make the build pass'")
    s.add_argument("--max-attempts", type=int, default=3)
    s.add_argument("--eval-only", action="store_true", help="prove by evaluation only (no builds)")
    s.set_defaults(fn=cmd_fix)

    s = sub.add_parser("switch", help="prove, then activate with the safety policy (rollback on health regression)")
    target(s)
    s.add_argument("--mode", choices=["auto", "switch", "boot"], default="auto")
    s.add_argument("--force", action="store_true")
    s.add_argument("--no-review", action="store_true", help="skip the agent's post-activation review")
    s.set_defaults(fn=cmd_switch)

    s = sub.add_parser("review", help="review an activation that already happened: what changed, is it healthy, fix if not")
    s.add_argument("--target", choices=["hm", "system"], default="hm")
    s.add_argument("--since", help='"YYYY-MM-DD HH:MM:SS" (default: the profile\'s last switch time)')
    s.add_argument("--activate", action="store_true", help="if the review fixed something, activate the rebuilt home-manager generation")
    s.set_defaults(fn=cmd_review)

    s = sub.add_parser("run", help="the scheduled pipeline: preflight, adopt, bump, fix, prove, switch, notify")
    s.add_argument("--switch", choices=["auto", "never", "hm-only", "system-only"], default="auto")
    s.add_argument("--no-bump", action="store_true")
    s.add_argument("--inputs", nargs="*")
    s.add_argument("--max-attempts", type=int, default=3)
    s.add_argument("--improve", action="store_true", help="also do one MAINTENANCE.md queue item")
    s.add_argument("--improve-risk", choices=["low", "medium", "high"], default="low")
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("docs", help="GOALS.md / MAINTENANCE.md: check citations or regen with an agent")
    s.add_argument("action", choices=["check", "regen"])
    s.add_argument("--dir", type=lambda v: Path(v).expanduser(), help="docs directory (default: $IHC_DOCS_DIR or the flake dir)")
    s.set_defaults(fn=cmd_docs)

    s = sub.add_parser("notify", help="send a desktop notification (and log it)")
    s.add_argument("title")
    s.add_argument("body", nargs="?", default="")
    s.add_argument("-u", "--urgency", choices=["low", "normal", "critical"], default="normal")
    s.add_argument("-q", "--quiet", action="store_true", help="exit 0 even without a desktop notifier")
    s.set_defaults(fn=cmd_notify)

    s = sub.add_parser("pending", help="decisions that need you")
    s.add_argument("action", choices=["list", "resolve"])
    s.add_argument("id", nargs="?")
    s.set_defaults(fn=cmd_pending)

    s = sub.add_parser("mcp", help="serve the verbs over MCP stdio for Claude Code / opencode / codex")
    s.set_defaults(fn=cmd_mcp)
    return p


def dispatch(argv: list[str]) -> tuple[int, str]:
    """Run a verb in-process and capture its stdout (used by the MCP server)."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            code = main(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        if exc.code and not isinstance(exc.code, int):
            buf.write(str(exc.code) + "\n")
    return code, buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
