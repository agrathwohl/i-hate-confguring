"""State directory, evidence bundles (runs), history, pending decisions, lock."""

from __future__ import annotations

import fcntl
import json
import os
import shlex
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path(os.environ.get("IHC_STATE_DIR", "~/.local/state/ihc")).expanduser()
RUNS_DIR = STATE_DIR / "runs"
PENDING_DIR = STATE_DIR / "pending"
HISTORY = STATE_DIR / "history.jsonl"
KEEP_RUNS = 30


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dirs() -> None:
    for d in (STATE_DIR, RUNS_DIR, PENDING_DIR):
        d.mkdir(parents=True, exist_ok=True)


@contextmanager
def lock():
    """One ihc process at a time. Raises SystemExit(75) when another run holds the lock."""
    ensure_dirs()
    fh = open(STATE_DIR / "lock", "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("ihc: another run holds the lock (%s)" % (STATE_DIR / "lock"), file=sys.stderr)
        raise SystemExit(75)  # EX_TEMPFAIL: a concurrent run, not a failure
    try:
        fh.write(str(os.getpid()))
        fh.flush()
        yield
    finally:
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


@dataclass
class Step:
    name: str
    argv: list[str]
    exit: int
    out: str
    err: str
    seconds: float
    cwd: str | None = None

    @property
    def ok(self) -> bool:
        return self.exit == 0

    def tail(self, n: int = 150) -> str:
        text = (self.out + "\n" + self.err).strip().splitlines()
        return "\n".join(text[-n:])


@dataclass
class Run:
    """An evidence bundle: every command is recorded as NN-name.{cmd,out,err,exit}."""

    kind: str
    id: str
    dir: Path
    steps: list[Step] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    verdict: dict = field(default_factory=dict)
    started: float = field(default_factory=time.monotonic)
    deadline: float = float(os.environ.get("IHC_RUN_DEADLINE", str(6 * 3600)))  # seconds for the whole run

    def expired(self) -> bool:
        """The nightly window is finite: no new bump/fix work starts after the deadline."""
        return time.monotonic() - self.started > self.deadline

    def note(self, text: str) -> None:
        self.notes.append("%s %s" % (now_iso(), text))
        with open(self.dir / "notes.log", "a") as fh:
            fh.write(self.notes[-1] + "\n")

    def step(
        self,
        name: str,
        argv: list[str],
        cwd: str | Path | None = None,
        env: dict | None = None,
        timeout: float | None = None,
        sudo: bool = False,
        stdin: str | None = None,
    ) -> Step:
        if sudo and os.geteuid() != 0:
            argv = ["sudo", "-n"] + list(argv)
        idx = len(self.steps) + 1
        base = self.dir / ("%02d-%s" % (idx, name))
        base.with_suffix(".cmd").write_text(
            "cd %s\n%s\n" % (shlex.quote(str(cwd or os.getcwd())), shlex.join(argv))
        )
        t0 = time.monotonic()
        try:
            # own process group: a timeout must also stop whatever the command spawned (an agent's nix build)
            proc = subprocess.Popen(
                argv,
                cwd=str(cwd) if cwd else None,
                env=env,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                start_new_session=True,
            )
            try:
                out, err = proc.communicate(input=stdin, timeout=timeout)
                code = proc.returncode
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, 15)
                    out, err = proc.communicate(timeout=20)
                except (subprocess.TimeoutExpired, ProcessLookupError):
                    try:
                        os.killpg(proc.pid, 9)
                    except ProcessLookupError:
                        pass
                    out, err = proc.communicate()
                code = 124
                err = (err or "") + "\nihc: timeout after %ss (process group killed)" % timeout
        except FileNotFoundError as exc:
            code, out, err = 127, "", "ihc: %s" % exc
        seconds = time.monotonic() - t0
        base.with_suffix(".out").write_text(out)
        base.with_suffix(".err").write_text(err)
        base.with_suffix(".exit").write_text("%d\n" % code)
        step = Step(name, argv, code, out, err, seconds, str(cwd) if cwd else None)
        self.steps.append(step)
        return step

    def report(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "dir": str(self.dir),
            "verdict": self.verdict,
            "steps": [
                {"name": s.name, "exit": s.exit, "seconds": round(s.seconds, 1), "cmd": shlex.join(s.argv)}
                for s in self.steps
            ],
            "notes": self.notes,
        }

    def write_report(self) -> Path:
        rep = self.report()
        (self.dir / "report.json").write_text(json.dumps(rep, indent=2))
        lines = ["# ihc run %s (%s)" % (self.id, self.kind), ""]
        v = self.verdict
        lines.append("**Verdict:** %s" % (v.get("summary") or ("ok" if v.get("ok") else "not ok")))
        lines.append("")
        lines.append("| # | step | exit | seconds |")
        lines.append("|---|------|-----:|--------:|")
        for i, s in enumerate(self.steps, 1):
            lines.append("| %d | %s | %d | %.1f |" % (i, s.name, s.exit, s.seconds))
        if self.notes:
            lines += ["", "## Notes", ""] + ["- " + n for n in self.notes]
        failed = [s for s in self.steps if not s.ok]
        if failed:
            lines += ["", "## Failures", ""]
            for s in failed:
                lines += ["### %s" % s.name, "", "```", s.tail(60), "```", ""]
        path = self.dir / "report.md"
        path.write_text("\n".join(lines) + "\n")
        return path


def new_run(kind: str) -> Run:
    ensure_dirs()
    rid = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + kind
    d = RUNS_DIR / rid
    d.mkdir(parents=True, exist_ok=True)
    (STATE_DIR / "last-run").write_text(rid + "\n")
    prune_runs()
    return Run(kind=kind, id=rid, dir=d)


KEEP_OUTLINKS = 3  # runs whose built system/home stay GC-rooted; older bundles keep only their reports


def prune_runs(keep: int = KEEP_RUNS, keep_outlinks: int = KEEP_OUTLINKS) -> None:
    runs = sorted(p for p in RUNS_DIR.iterdir() if p.is_dir()) if RUNS_DIR.exists() else []
    for old in runs[:-keep]:
        for f in old.iterdir():
            f.unlink()
        old.rmdir()
    for old in runs[:-keep_outlinks]:
        for name in ("system", "hm"):
            link = old / name
            if link.is_symlink():
                link.unlink()  # drops the indirect GC root; the evidence files stay


def last_run_id() -> str | None:
    p = STATE_DIR / "last-run"
    return p.read_text().strip() if p.exists() else None


def history_append(record: dict) -> None:
    ensure_dirs()
    record = dict(record, at=now_iso())
    with open(HISTORY, "a") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


def history_read(limit: int = 200) -> list[dict]:
    if not HISTORY.exists():
        return []
    lines = HISTORY.read_text().splitlines()[-limit:]
    return [json.loads(l) for l in lines if l.strip()]


def pending_add(kind: str, title: str, body: str, how_to_resolve: str) -> Path:
    """A decision only the user can make. Nothing blocks on it; `ihc status` shows it."""
    ensure_dirs()
    pid = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + kind
    path = PENDING_DIR / (pid + ".json")
    path.write_text(json.dumps({"id": pid, "kind": kind, "title": title, "body": body, "resolve": how_to_resolve, "at": now_iso()}, indent=2))
    return path


def pending_list() -> list[dict]:
    if not PENDING_DIR.exists():
        return []
    return [json.loads(p.read_text()) for p in sorted(PENDING_DIR.glob("*.json"))]


def pending_resolve(pid: str) -> bool:
    p = PENDING_DIR / (pid + ".json")
    if p.exists():
        p.unlink()
        return True
    return False
