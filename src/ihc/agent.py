"""Drive already-authenticated agent CLIs headlessly. Never API keys: subscription logins only."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from . import nix
from .facts import agents_available
from .notify import notify
from .store import Run, pending_add

DEFAULT_ORDER = ["claude", "opencode", "codex"]
AGENT_TIMEOUT = int(os.environ.get("IHC_AGENT_TIMEOUT", "3600"))
STRIP_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL",
             "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "CODEX_API_KEY",
             "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SSE_PORT")
DONE_MARKER = "IHC-DONE:"

# Agent diffs that touch these are reverted and turned into a pending decision for the user.
FORBIDDEN_PATTERNS = [
    (r"stateVersion", "stateVersion must never change"),
    (r"fileSystems\.\"", "filesystem definitions are hardware truth"),
    (r"boot\.loader\.", "bootloader settings are hardware truth"),
    (r"swapDevices", "swap devices are hardware truth"),
    (r"users\.users\.", "user accounts"),
    (r"sops", "secrets wiring"),
    (r"security\.sudo", "sudo policy"),
    (r"services\.openssh\.enable\s*=\s*false", "ssh must stay on (remote access)"),
    (r"nix\.settings\.trusted", "nix trust settings"),
]
PIN_URL_RE = re.compile(r"\b([A-Za-z0-9_-]+)\.url\s*=\s*\"[^\"]*(\?rev=|/[0-9a-f]{40})")
FORBIDDEN_FILES = [r"hardware-configuration\.nix$", r"(password|secret|token|credentials|\.env)$", r"\.age$", r"\.gpg$"]


def clean_env() -> dict:
    env = {k: v for k, v in os.environ.items() if k not in STRIP_ENV}
    env["IHC_AGENT"] = "1"
    env.setdefault("TERM", "dumb")
    return env


PROBE_PROMPT = "Reply with exactly: IHC-DONE: hello"
PROBE_TIMEOUT = int(os.environ.get("IHC_PROBE_TIMEOUT", "180"))
RELOGIN = {"claude": "run `claude` and type /login", "codex": "run `codex login`", "opencode": "run `opencode auth login`"}
LAST_PROBE: dict[str, str] = {}
_PROBED: dict[str, list[dict]] = {}  # per process: one live probe round per flake, not one per fix attempt


def probe(name: str, cfg: nix.Config) -> tuple[bool, str]:
    """Is this CLI really logged in? A credentials file is not proof (expired OAuth, reused refresh token...)."""
    try:
        proc = subprocess.run(build_cmd(name, PROBE_PROMPT, cfg), cwd=cfg.flake_dir, env=clean_env(),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=PROBE_TIMEOUT, errors="replace")
    except subprocess.TimeoutExpired:
        return False, "no answer within %ss" % PROBE_TIMEOUT
    except OSError as exc:
        return False, str(exc)
    ok = proc.returncode == 0 and DONE_MARKER in proc.stdout
    lines = [l for l in (proc.stdout + "\n" + proc.stderr).splitlines() if l.strip()]
    return ok, (lines[-1][:160] if lines else "exit %d" % proc.returncode)


def available(order: list[str] | None = None, cfg: nix.Config | None = None) -> list[dict]:
    """Installed + login file present; with cfg also live-probed (slow: one short agent call each, cached per process)."""
    order = order or [a.strip() for a in os.environ.get("IHC_AGENTS", ",".join(DEFAULT_ORDER)).split(",") if a.strip()]
    key = "%s|%s" % (cfg.flake_dir if cfg else "", ",".join(order))
    if cfg is not None and key in _PROBED:
        return _PROBED[key]
    table = {a["name"]: a for a in agents_available()}
    out = []
    for name in order:
        a = table.get(name)
        if not (a and a["path"] and a["authed"]):
            if a:
                LAST_PROBE[name] = "not installed" if not a["path"] else "no login file (%s)" % a.get("auth_file", "?")
            continue
        if cfg is not None:
            ok, why = probe(name, cfg)
            LAST_PROBE[name] = "ok" if ok else why
            if not ok:
                continue
        out.append(a)
    if cfg is not None:
        _PROBED[key] = out
    return out


def build_cmd(name: str, prompt: str, cfg: nix.Config, model: str | None = None) -> list[str]:
    extra_dirs = [str(r) for r in cfg.config_repos if r != cfg.flake_dir]
    if name == "claude":
        # no --bare: minimal mode skips the stored claude.ai login and reports "Not logged in"
        # --add-dir is variadic and would swallow the prompt: it goes first, `-p` terminates it
        argv = ["claude"] + (["--add-dir"] + extra_dirs if extra_dirs else [])
        argv += ["-p", "--permission-mode", "bypassPermissions", "--output-format", "text", "--no-session-persistence"]
        if model:
            argv += ["--model", model]
        return argv + [prompt]
    if name == "opencode":
        argv = ["opencode", "run", "--dir", str(cfg.flake_dir), "--format", "default"]
        if model:
            argv += ["-m", model]
        return argv + [prompt]
    if name == "codex":
        argv = ["codex", "exec", "--skip-git-repo-check", "-C", str(cfg.flake_dir), "--dangerously-bypass-approvals-and-sandbox"]
        if model:
            argv += ["-m", model]
        return argv + [prompt]
    raise ValueError("unknown agent %s" % name)


def _docs(cfg: nix.Config) -> str:
    parts = []
    for name in ("GOALS.md", "MAINTENANCE.md"):
        p = cfg.docs_dir / name
        if p.exists():
            parts.append("### %s\n\n%s" % (name, p.read_text()[:12000]))
    return "\n\n".join(parts) if parts else "(no GOALS.md / MAINTENANCE.md yet — be conservative)"


def fix_prompt(cfg: nix.Config, facts_summary: list[str], failing_step: str, failing_target: str, tail: str, task: str | None = None) -> str:
    roots = "\n".join("- %s" % r for r in cfg.config_repos)
    objective = task or "Make `%s` pass again with the smallest correct change." % failing_step
    return f"""You are ihc, an unattended maintenance agent for a Nix configuration. Nobody will answer questions: decide, act, report.

## Objective
{objective}

## Where you may edit (and nowhere else)
{roots}
Absolute paths only. Do NOT edit files outside these roots. Do NOT run `nixos-rebuild switch`, `home-manager switch`, `darwin-rebuild switch`, `nix-collect-garbage`, `git push`, or anything that activates or deletes.
Verify your change by EVALUATION only: `nix eval --raw '<flake>#<attr>.drvPath'` with the flags `{shlex.join(cfg.nix_args())}` (attributes: `{cfg.system_attr or "-"}` and `{cfg.hm_attr_path or "-"}`). Do NOT run `nix build` or `home-manager build` on the whole configuration — the harness builds it after you finish, and a full build here can take longer than your time budget. Building a single package to confirm a fix (`nix build nixpkgs#<pkg>`) is fine.

## System summary (mined, trust it)
{chr(10).join('- ' + l for l in facts_summary)}

## Failing step: {failing_step} (target: {failing_target})
```
{tail}
```

## Hard rules (a policy check reverts your diff if you break these)
- Never change stateVersion, filesystems, bootloader, swap, users, sudo, sops/secrets wiring, hardware-configuration.nix.
- Never turn off or delete an option listed under "Invariants" in GOALS.md below, ssh, or any service that holds state (databases, containers).
- Prefer the smallest diff: remove or rename the one thing that broke; do not refactor, reformat, or "improve" unrelated code.
- If a package was removed/archived upstream, remove it or swap to the documented successor named in the error, and leave a one-line comment with the date and reason.
- If an option was renamed, use the new name exactly as the warning says.
- Keep the user's intent as documented in GOALS.md below.

## Context documents
{_docs(cfg)}

## Finish
When the evaluation passes (and, if the failure was a package build error, the single package builds), print exactly one final line:
{DONE_MARKER} <one sentence: what you changed and why>
If you cannot fix it safely, print exactly: {DONE_MARKER} BLOCKED <reason>
"""


def run_agent(cfg: nix.Config, run: Run, prompt: str, order: list[str] | None = None) -> tuple[str | None, bool, str]:
    """Try agents in order. Returns (agent_name, completed_without_block, last_line)."""
    n = len(list(run.dir.glob("prompt-*.md"))) + 1
    (run.dir / ("prompt-%d.md" % n)).write_text(prompt)
    last = ""
    agents = available(order, cfg)
    run.note("agent probe: " + ", ".join("%s=%s" % kv for kv in LAST_PROBE.items()))
    if not agents:
        body = "\n".join("- %s: %s — %s" % (n, LAST_PROBE.get(n, "?"), RELOGIN.get(n, "")) for n in (order or DEFAULT_ORDER))
        pending_add("auth", "No agent CLI is logged in; automatic fixes are paused",
                    body + "\n\nihc never uses API keys. Log in to at least one CLI with your subscription.", "Log in, then `ihc pending resolve <id>`; the next run retries.")
        notify("No agent CLI is logged in", "Automatic fixes paused. " + "; ".join("%s: %s" % (n, LAST_PROBE.get(n, "?")) for n in (order or DEFAULT_ORDER)), "critical")
        return None, False, "no usable agent"
    for a in agents:
        step = run.step("agent-" + a["name"], build_cmd(a["name"], prompt, cfg), cwd=cfg.flake_dir, env=clean_env(), timeout=AGENT_TIMEOUT)
        text = step.out + "\n" + step.err
        marker = [l for l in text.splitlines() if DONE_MARKER in l]
        last = marker[-1].split(DONE_MARKER, 1)[1].strip() if marker else step.tail(3)
        run.note("agent %s exit=%d: %s" % (a["name"], step.exit, last[:200]))
        if step.ok and marker and not last.startswith("BLOCKED"):
            return a["name"], True, last
        if step.ok and not marker and changed_files(cfg):
            return a["name"], True, last  # it edited something and exited cleanly; the proof decides
    return None, False, last


# ---- diff policy ----------------------------------------------------------------

def changed_files(cfg: nix.Config) -> list[str]:
    out = []
    for repo in cfg.config_repos:
        if not (repo / ".git").exists():
            continue
        subprocess.run(["git", "-C", str(repo), "add", "-A", "-N"], capture_output=True)
        # against HEAD: the proof step stages the tree, so an index diff would hide the agent's edits
        res = subprocess.run(["git", "-C", str(repo), "diff", "HEAD", "--name-only"], capture_output=True, text=True)
        out += ["%s/%s" % (repo, f) for f in res.stdout.splitlines() if f.strip()]
    return out


def diff_text(cfg: nix.Config) -> str:
    parts = []
    for repo in cfg.config_repos:
        if (repo / ".git").exists():
            subprocess.run(["git", "-C", str(repo), "add", "-A", "-N"], capture_output=True)
            parts.append(subprocess.run(["git", "-C", str(repo), "diff", "HEAD"], capture_output=True, text=True).stdout)
    return "\n".join(parts)


def policy_violations(diff: str, invariants: list[str] | None = None) -> list[str]:
    """Generic protections plus the host's own invariants (option paths from GOALS.md `## Invariants`)."""
    viol = []
    current_file = ""
    inv = [re.escape(o) for o in (invariants or [])]
    inv_off = re.compile(r"(%s)\s*=\s*(false|no|0)\b" % "|".join(inv)) if inv else None
    inv_on = re.compile(r"(%s)\s*=\s*(true|yes|1)\b" % "|".join(inv)) if inv else None
    # moving an existing pin is the user's call; adding a pin to an unpinned input is a legitimate freeze
    removed_pins = {m.group(1) for line in diff.splitlines() if line.startswith("-") and not line.startswith("---") for m in [PIN_URL_RE.search(line)] if m}
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current_file = line[4:].strip()
            for rx in FORBIDDEN_FILES:
                if re.search(rx, current_file):
                    viol.append("%s: protected file" % current_file)
        elif line.startswith("+") and not line.startswith("+++"):
            for rx, why in FORBIDDEN_PATTERNS:
                if re.search(rx, line):
                    viol.append("%s: %s (%s)" % (current_file, why, line.strip()[:80]))
            if inv_off and inv_off.search(line):
                viol.append("%s: turns off a GOALS invariant (%s)" % (current_file, line.strip()[:80]))
            m = PIN_URL_RE.search(line)
            if m and m.group(1) in removed_pins:
                viol.append("%s: moves the commit pin of input %s; that is the user's call (%s)" % (current_file, m.group(1), line.strip()[:80]))
        elif line.startswith("-") and not line.startswith("---"):
            if inv_on and inv_on.search(line):
                viol.append("%s: removes a GOALS invariant (%s)" % (current_file, line.strip()[:80]))
            elif re.search(r"services\.openssh\.enable\s*=\s*true", line):
                viol.append("%s: removes ssh (%s)" % (current_file, line.strip()[:80]))
    return sorted(set(viol))


def revert(cfg: nix.Config, run: Run) -> None:
    """Back to HEAD. Builds stage everything (flakes only see the index), so the restore must be HEAD-relative.
    Safe because every run commits user drift before any bump or agent edit."""
    for repo in cfg.config_repos:
        if (repo / ".git").exists():
            run.step("revert-" + repo.name, ["git", "reset", "-q", "--hard", "HEAD"], cwd=repo)
            run.step("clean-" + repo.name, ["git", "clean", "-fdq", "-e", "result", "-e", "result-*"], cwd=repo)


def review_prompt(cfg: nix.Config, facts_summary: list[str], kind: str, evidence: str) -> str:
    roots = "\n".join("- %s" % r for r in cfg.config_repos)
    return f"""You are ihc, an unattended maintenance agent. A {kind} activation just happened on this machine. Nobody will answer questions: investigate, verify, fix if needed, report.

## Your job
1. Read the evidence below: what changed (closure diff), which units the activation stopped/restarted/started, the failed-unit list, each touched unit's status, and the journal since the activation.
2. For every touched unit and every changed program that has a runtime configuration, verify it actually works now — do not assume. Use the real tools: `systemctl [--user] status`, `journalctl [--user] -u <unit> --since ...`, the program's own status/validation commands (compositors, bars, daemons, audio servers, notification daemons, shells...), its log files under ~/.local/state, ~/.cache, /var/log, /run/user/<uid>. Find the logs; do not stop at "active".
3. Identify regressions: units that failed or flap, programs that reject their configuration, deprecated/renamed options, missing binaries, errors that did not exist before.
4. If a regression comes from the configuration, fix it with the smallest change inside the allowed roots and rebuild to prove it (`nix build` / `home-manager build` only — never activate, never GC, never push). If it is not a configuration problem, do not touch anything.

## Where you may edit (and nowhere else)
{roots}
Nix flags for this tree: `{shlex.join(cfg.nix_args())}`.

## Hard rules
- Never change stateVersion, filesystems, bootloader, users, sudo, secrets wiring, hardware-configuration.nix. Never turn off an option listed under "Invariants" in GOALS.md, ssh, or stateful services.
- Secret values never go into your output.

## System summary (mined)
{chr(10).join('- ' + l for l in facts_summary)}

## Evidence
{evidence[:90000]}

## Finish
Print exactly one final line:
{DONE_MARKER} HEALTHY <one sentence: what you verified>
or
{DONE_MARKER} FIXED <one sentence: what regressed and what you changed>
or
{DONE_MARKER} BLOCKED <one sentence: what is wrong and why you could not fix it>
"""
