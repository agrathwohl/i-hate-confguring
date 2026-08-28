"""GOALS.md / MAINTENANCE.md: citation checking and agent-driven regeneration."""

from __future__ import annotations

import re
from pathlib import Path

from . import nix

CITE_RE = re.compile(r"`?((?:/|~/|\./)?[A-Za-z0-9_./@-]+\.(?:nix|lock|md|toml|json|txt|conf))`?:(\d+)(?:-(\d+))?")
DOC_NAMES = ("GOALS.md", "MAINTENANCE.md")


def resolve(path: str, base: Path, extra_bases: list[Path]) -> Path | None:
    p = Path(path).expanduser()
    if p.is_absolute():
        return p if p.exists() else None
    for b in [base] + extra_bases:
        cand = (b / p).resolve()
        if cand.exists():
            return cand
    return None


def check_citations(doc: Path, bases: list[Path]) -> list[str]:
    """Every `path:line` must point at an existing, non-empty line. Returns problems."""
    problems = []
    text = doc.read_text(errors="replace")
    for m in CITE_RE.finditer(text):
        path, line = m.group(1), int(m.group(2))
        if path.endswith(".md") and path in DOC_NAMES:
            continue
        target = resolve(path, doc.parent, bases)
        if target is None:
            problems.append("%s: unresolved path %s" % (doc.name, path))
            continue
        lines = target.read_text(errors="replace").splitlines()
        if line < 1 or line > len(lines):
            problems.append("%s: %s:%d beyond EOF (%d lines)" % (doc.name, path, line, len(lines)))
        elif not lines[line - 1].strip():
            problems.append("%s: %s:%d is a blank line" % (doc.name, path, line))
    return problems


def check_all(cfg: nix.Config, docs_dir: Path | None = None) -> tuple[int, list[str]]:
    d = docs_dir or cfg.docs_dir
    bases = [cfg.flake_dir] + ([cfg.hm_dir] if cfg.hm_dir else [])
    problems = []
    count = 0
    for name in DOC_NAMES:
        p = d / name
        if not p.exists():
            problems.append("%s missing in %s" % (name, d))
            continue
        count += len(CITE_RE.findall(p.read_text(errors="replace")))
        problems += check_citations(p, bases)
    return count, problems


def regen_prompt(cfg: nix.Config, facts_json: str, docs_dir: Path) -> str:
    return f"""You maintain two documents for an unattended Nix maintenance agent: {docs_dir}/GOALS.md and {docs_dir}/MAINTENANCE.md.
Update them in place (create if missing). Do not touch any other file. Do not ask questions.

Source of truth is the mined facts JSON below and the configuration files it points at (read them). Every claim about the user's priorities must carry evidence as `path:line` citations to real lines (a checker rejects the docs otherwise). Never copy secret values; refer to them as `path:line` only.

GOALS.md: ranked priorities the configuration proves (what the user cares about, from strongest evidence to weakest), then "Invariants" (things the agent must never change), then "Non-goals" (things the config deliberately does not do). Keep the existing ranking unless the facts contradict it; append a dated "Changes" line when you change something.
MAINTENANCE.md: keep the methodology sections intact; refresh the "Findings" and "Queue" sections from the facts (queue items are `- [ ] (risk: low|medium|high) <task> — <evidence path:line>`; tick items that are fixed). Maintain three machine-readable sections the harness parses (derive them from what the configuration enables and the hardware; no speculation):
## Guarded units      one bullet per unit whose restart must not interrupt the running session (audio servers, display manager, container runtimes, databases, VM managers...): `- jack.service`
## Health probes      `- name: shell command` that must exit 0 after an activation (e.g. a sound card present in /proc/asound/cards, a GPU tool answering, a daemon listening) — one per priority in GOALS.md
## Busy checks        `- name: shell command` whose exit 0 means the user is in the middle of something (a DAW running, a recording, a render) so activation must wait for the next boot
Drift facts (`runtime.drift`): files under /etc that are regular files where the system expects store symlinks, home-manager backup collisions, packages installed imperatively into the user profile — list them in Findings and add queue items to adopt them into the configuration or remove them.

Facts:
```json
{facts_json[:60000]}
```
When done print exactly one final line: IHC-DONE: <what changed>
"""


SECTION_RE = re.compile(r"^## (Guarded units|Health probes|Busy checks)\s*$", re.M)
BULLET_RE = re.compile(r"^- `?([^`:\n]+?)`?\s*(?::\s*`?(.+?)`?)?\s*$", re.M)


def host_rules(docs_dir: Path) -> dict:
    """Machine-readable parts of MAINTENANCE.md:
    ## Guarded units   -> `- unit.service`            (restart forces boot-mode activation)
    ## Health probes   -> `- name: command`           (must exit 0 after an activation)
    ## Busy checks     -> `- name: command`           (exit 0 = someone is working; defer the switch)"""
    out = {"guarded_units": [], "health_probes": {}, "busy_checks": {}}
    p = docs_dir / "MAINTENANCE.md"
    if not p.exists():
        return out
    text = p.read_text(errors="replace")
    parts = SECTION_RE.split(text)
    for i in range(1, len(parts) - 1, 2):
        title, body = parts[i], parts[i + 1].split("\n## ", 1)[0]
        for m in BULLET_RE.finditer(body):
            key, val = m.group(1).strip(), (m.group(2) or "").strip()
            if title == "Guarded units":
                out["guarded_units"].append(key)
            elif val:
                out["health_probes" if title == "Health probes" else "busy_checks"][key] = val
    return out


INVARIANTS_RE = re.compile(r"^## Invariants\b[^\n]*$(.*?)(?=^## |\Z)", re.M | re.S)
OPTION_RE = re.compile(r"`([A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)+|[A-Z][A-Z0-9_]{3,})(?:\s*=\s*[^`]+)?`")


def invariant_options(docs_dir: Path) -> list[str]:
    """Option paths named in backticks under GOALS.md `## Invariants` (e.g. `services.openssh.enable`).
    Turning one off or deleting it is a policy violation for agent edits."""
    p = docs_dir / "GOALS.md"
    if not p.exists():
        return []
    m = INVARIANTS_RE.search(p.read_text(errors="replace"))
    if not m:
        return []
    return sorted({o for o in OPTION_RE.findall(m.group(1)) if not o.endswith((".md", ".nix"))})
