"""Proof-before-switch: build, dry-activate, diff, health probes, switch, rollback."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import nix
from .store import Run, Step

MIN_STORE_FREE_GIB = float(os.environ.get("IHC_MIN_STORE_FREE_GIB", "10"))
BOOT_MULTIPLIER = 2.0
HM_BACKUP_EXT = "ihc-bak"


@dataclass
class Verdict:
    ok: bool = True
    failed_step: str | None = None
    failed_target: str | None = None  # system | hm
    system_path: Path | None = None
    hm_path: Path | None = None
    units: dict = field(default_factory=dict)
    system_diff: str = ""
    hm_diff: str = ""
    closure_bytes: int | None = None
    mode: str | None = None
    mode_reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if not self.ok:
            return "FAILED at %s (%s)" % (self.failed_step, self.failed_target)
        parts = ["eval ok"] if any("eval-only" in n for n in self.notes) else []
        if self.system_path:
            parts.append("system built")
        if self.hm_path:
            parts.append("hm built")
        if self.mode:
            parts.append("mode=%s" % self.mode)
        return "ok: " + ", ".join(parts)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok, "failed_step": self.failed_step, "failed_target": self.failed_target,
            "system_path": str(self.system_path) if self.system_path else None,
            "hm_path": str(self.hm_path) if self.hm_path else None,
            "units": self.units, "closure_bytes": self.closure_bytes, "mode": self.mode,
            "mode_reasons": self.mode_reasons, "notes": self.notes, "summary": self.summary(),
        }


# ---- preflight gates (store -> eval-only, /boot -> no system activation, sudo -> no system activation) ----

def boot_short(facts: dict) -> bool:
    disk = facts.get("runtime", {}).get("disk", {})
    boot, need = disk.get("boot"), disk.get("boot_need_mib")
    return bool(boot and need and boot["free_gib"] * 1024 < need * BOOT_MULTIPLIER)


def prune_boot(cfg: nix.Config, run: Run, facts: dict) -> bool:
    """Re-run the bootloader install for the *current* generation: it drops entries whose generations no longer exist."""
    entries = facts.get("runtime", {}).get("boot_entries")
    gens = facts.get("runtime", {}).get("system_generations") or 0
    cur = nix.current_system()
    if cfg.platform != "nixos" or not cur or entries is None or entries <= gens + 1:
        return False
    st = run.step("boot-prune", [str(cur / "bin/switch-to-configuration"), "boot"], sudo=True, env=cfg.env())
    run.note("boot-prune: %d entries for %d generations -> %s" % (entries, gens, "pruned" if st.ok else "FAILED"))
    return st.ok


def store_short(facts: dict) -> float | None:
    """GiB free in /nix/store when below MIN_STORE_FREE_GIB, else None."""
    free = facts.get("runtime", {}).get("disk", {}).get("nix_store", {}).get("free_gib")
    return free if (free is not None and free < MIN_STORE_FREE_GIB) else None


def sudo_ok(cfg: nix.Config) -> bool:
    """System activation and rollback need passwordless sudo; proofs do not."""
    if cfg.platform == "hm-only" or os.geteuid() == 0:
        return True
    res = _probe(["sudo", "-n", "true"], timeout=15)
    return bool(res and res.returncode == 0)


# ---- health probes ----------------------------------------------------------

def _probe(argv: list[str], timeout: float = 30) -> subprocess.CompletedProcess | None:
    """A health probe must never raise after a switch: a hang or a missing binary counts as down."""
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _active(unit: str, user: bool = False) -> bool:
    argv = ["systemctl"] + (["--user"] if user else []) + ["is-active", "--quiet", unit]
    res = _probe(argv)
    return bool(res and res.returncode == 0)


def _units_active(user: bool) -> set[str]:
    res = _probe(["systemctl"] + (["--user"] if user else []) + ["list-units", "--type=service", "--state=active", "--plain", "--no-legend", "--no-pager"], timeout=60)
    return {l.split()[0] for l in (res.stdout if res else "").splitlines() if l.strip()}


def _listening_ports() -> set[str]:
    res = _probe(["ss", "-Hltn"], timeout=30)
    ports = set()
    for l in (res.stdout if res else "").splitlines():
        cols = l.split()
        if len(cols) >= 4:
            ports.add(cols[3].rsplit(":", 1)[-1])
    return ports


def health_snapshot(cfg: nix.Config, facts: dict) -> dict:
    """Host-agnostic: failed units, every active service, listening ports, default route — plus the
    host's own probes from MAINTENANCE.md `## Health probes` (command exit 0 = ok)."""
    snap: dict = {}
    if cfg.platform == "nixos":
        res = _probe(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"])
        snap["failed_units"] = sorted(l.split()[0] for l in (res.stdout if res else "").splitlines() if l.strip())
        snap["active_units"] = sorted(_units_active(False))
        snap["listening_ports"] = sorted(_listening_ports())
        res = _probe(["ip", "route"])
        snap["default_route"] = "default" in (res.stdout if res else "")
    res = _probe(["systemctl", "--user", "--failed", "--no-legend", "--plain", "--no-pager"])
    snap["failed_user_units"] = sorted(l.split()[0] for l in (res.stdout if res else "").splitlines() if l.strip())
    snap["active_user_units"] = sorted(_units_active(True))
    for name, cmd in facts.get("host_rules", {}).get("health_probes", {}).items():
        res = _probe(["sh", "-c", cmd], timeout=60)
        snap["probe:" + name] = bool(res and res.returncode == 0)
    return snap


def health_regressions(before: dict, after: dict) -> list[str]:
    regs = []
    for key, label in (("failed_units", "new failed units"), ("failed_user_units", "new failed user units")):
        new = sorted(set(after.get(key, [])) - set(before.get(key, [])))
        if new:
            regs.append("%s: %s" % (label, ", ".join(new)))
    for key, label in (("active_units", "services no longer active"), ("active_user_units", "user services no longer active")):
        gone = sorted(set(before.get(key, [])) - set(after.get(key, [])))
        if gone:
            regs.append("%s: %s" % (label, ", ".join(gone[:12])))
    gone_ports = sorted(set(before.get("listening_ports", [])) - set(after.get("listening_ports", [])))
    if gone_ports:
        regs.append("listening ports gone: " + ", ".join(gone_ports[:12]))
    for k, v in before.items():
        if isinstance(v, bool) and v and after.get(k) is False:
            regs.append("%s went down" % k)
    return regs


def busy(facts: dict) -> list[str]:
    """Names of MAINTENANCE.md `## Busy checks` whose command exits 0 (= someone is working; do not switch now)."""
    hits = []
    for name, cmd in facts.get("host_rules", {}).get("busy_checks", {}).items():
        res = _probe(["sh", "-c", cmd], timeout=30)
        if res and res.returncode == 0:
            hits.append(name)
    return hits


# ---- build / diff -----------------------------------------------------------

def _stage_all(repo: Path, run: Run) -> None:
    """Flakes only see git-tracked files: stage everything before eval/build."""
    if (repo / ".git").exists():
        run.step("git-add-" + repo.name, ["git", "add", "-A"], cwd=repo)


NAR_MISMATCH_RE = re.compile(r"NAR hash mismatch in input '(?:path:|git\+file://)([^?']+)")


def stale_local_input(err: str, cfg: nix.Config) -> str | None:
    """Name of a local (path / git+file) input whose on-disk content no longer matches flake.lock."""
    m = NAR_MISMATCH_RE.search(err)
    if not m:
        return None
    path = m.group(1).rstrip("/")
    for i in nix.lock_inputs(cfg.flake_dir):
        if i.local and i.ref.replace("file://", "").rstrip("/") == path:
            return i.name
    return None


def relock_local_input(cfg: nix.Config, run: Run, name: str) -> bool:
    """Local inputs are user-controlled checkouts: re-locking only records what is already on disk."""
    st = run.step("relock-" + name, ["nix", "flake", "update", name] + cfg.nix_args(), cwd=cfg.flake_dir, env=cfg.env())
    run.note("local input %s changed on disk; re-locked (%s)" % (name, "ok" if st.ok else "FAILED"))
    return st.ok


def evaluate(cfg: nix.Config, run: Run, target: str) -> Step:
    """Fast proof: every module option and package reference must evaluate. No downloads."""
    attr = cfg.system_attr if target == "system" else cfg.hm_attr_path
    if not attr:
        raise ValueError("no attribute for target %s" % target)
    _stage_all(cfg.flake_dir, run)
    argv = ["nix", "eval", "--raw"] + cfg.nix_args() + [attr + ".drvPath"]
    return run.step("eval-" + target, argv, cwd=cfg.flake_dir, env=cfg.env())


def build(cfg: nix.Config, run: Run, target: str) -> tuple[Step, Path | None]:
    attr = cfg.system_attr if target == "system" else cfg.hm_attr_path
    if not attr:
        raise ValueError("no attribute for target %s" % target)
    _stage_all(cfg.flake_dir, run)
    out_link = run.dir / target
    argv = ["nix", "build", "-L", "--out-link", str(out_link)] + cfg.nix_args() + [attr]
    step = run.step("build-" + target, argv, cwd=cfg.flake_dir, env=cfg.env())
    path = out_link.resolve() if step.ok and out_link.exists() else None
    return step, path


def dry_activate(cfg: nix.Config, run: Run, system_path: Path) -> dict:
    stc = system_path / "bin/switch-to-configuration"
    if cfg.platform != "nixos" or not stc.exists():
        return {}
    step = run.step("dry-activate", [str(stc), "dry-activate"], sudo=True, env=cfg.env())
    units: dict[str, list[str]] = {}
    for m in re.finditer(r"would (stop|restart|start|reload) the following units: (.*)", step.out + step.err):
        units[m.group(1)] = [u.strip() for u in m.group(2).split(",") if u.strip()]
    if not step.ok:
        units["error"] = [step.tail(5)]
    return units


def diff_closures(run: Run, old: Path | None, new: Path, name: str) -> str:
    if not old or not old.exists():
        return "(no previous closure)"
    step = run.step("diff-" + name, ["nix", "store", "diff-closures", str(old), str(new)])
    return step.out if step.ok else step.tail(20)


def kernel_changed(current: Path | None, new: Path) -> list[str]:
    reasons = []
    if not current:
        return reasons
    for f in ("kernel", "initrd", "kernel-modules", "sw/bin/nvidia-smi"):
        try:
            a, b = (current / f).resolve(), (new / f).resolve()
        except OSError:
            continue
        if (current / f).exists() and (new / f).exists() and a != b:
            reasons.append("%s changed" % ("nvidia driver" if "nvidia" in f else f))
    return reasons


def decide_mode(current: Path | None, new: Path, units: dict, guarded: list[str], patterns: list[str] | None = None) -> tuple[str, list[str]]:
    """switch = activate now; boot = activate at next reboot (running session untouched)."""
    reasons = kernel_changed(current, new)
    touched = set(units.get("restart", []) + units.get("stop", []))
    pats = [re.compile(x) for x in (patterns or [])]
    hit = sorted(u for u in touched if u in guarded or any(px.search(u) for px in pats))
    if hit:
        reasons.append("guarded units would restart: " + ", ".join(hit))
    return ("boot" if reasons else "switch"), reasons


def check(cfg: nix.Config, run: Run, facts: dict, target: str = "all", eval_only: bool = False) -> Verdict:
    v = Verdict()
    cur = nix.current_system()
    if eval_only:
        v.notes.append("eval-only proof (no build): options and package references verified, nothing activatable")
    for t in ("system", "hm"):
        if target in ("all", t) and (cfg.system_attr if t == "system" else cfg.hm_attr_path):
            step = evaluate(cfg, run, t)
            if not step.ok:
                stale = stale_local_input(step.err, cfg)
                if stale and relock_local_input(cfg, run, stale):
                    step = evaluate(cfg, run, t)
            if not step.ok:
                v.ok, v.failed_step, v.failed_target = False, step.name, t
                return v
    if eval_only:
        return v
    if target in ("all", "system") and cfg.system_attr:
        step, path = build(cfg, run, "system")
        if not step.ok:
            v.ok, v.failed_step, v.failed_target = False, step.name, "system"
            return v
        v.system_path = path
        v.units = dry_activate(cfg, run, path)
        if "error" in v.units:
            v.ok, v.failed_step, v.failed_target = False, "dry-activate", "system"
            return v
        v.system_diff = diff_closures(run, cur, path, "system")
        v.closure_bytes = nix.closure_size(path)
        v.mode, v.mode_reasons = decide_mode(cur, path, v.units, facts.get("guarded_units", []), facts.get("guarded_unit_patterns", []))
        (run.dir / "system-diff.txt").write_text(v.system_diff)
    if target in ("all", "hm") and cfg.hm_attr_path:
        step, path = build(cfg, run, "hm")
        if not step.ok:
            v.ok, v.failed_step, v.failed_target = False, step.name, "hm"
            return v
        v.hm_path = path
        old = cfg.hm_profile.resolve() if cfg.hm_profile.exists() else None
        v.hm_diff = diff_closures(run, old, path, "hm")
        (run.dir / "hm-diff.txt").write_text(v.hm_diff)
    return v


# ---- activation ---------------------------------------------------------------

def switch_system(cfg: nix.Config, run: Run, new: Path, mode: str) -> bool:
    if cfg.platform == "nixos":
        s1 = run.step("set-system-profile", ["nix-env", "-p", str(cfg.system_profile), "--set", str(new)], sudo=True)
        if not s1.ok:
            return False
        s2 = run.step("switch-to-configuration-" + mode, [str(new / "bin/switch-to-configuration"), mode], sudo=True, env=cfg.env())
        return s2.ok
    if cfg.platform == "darwin":
        s1 = run.step("set-system-profile", ["nix-env", "-p", str(cfg.system_profile), "--set", str(new)], sudo=True)
        if not s1.ok:
            return False
        return run.step("darwin-activate", [str(new / "activate")], sudo=True).ok
    return False


def rollback_system(cfg: nix.Config, run: Run) -> bool:
    s1 = run.step("rollback-profile", ["nix-env", "-p", str(cfg.system_profile), "--rollback"], sudo=True)
    if not s1.ok:
        return False
    if cfg.platform == "nixos":
        return run.step("rollback-switch", [str(cfg.system_profile / "bin/switch-to-configuration"), "switch"], sudo=True, env=cfg.env()).ok
    return run.step("rollback-activate", [str(cfg.system_profile / "activate")], sudo=True).ok


def switch_hm(cfg: nix.Config, run: Run, new: Path) -> bool:
    env = dict(os.environ, HOME_MANAGER_BACKUP_EXT=HM_BACKUP_EXT)
    return run.step("hm-activate", [str(new / "activate")], env=env).ok


def generation_count(cfg: nix.Config) -> int:
    return len(nix.generations(cfg.system_profile))


# ---- post-activation evidence -------------------------------------------------------

UNIT_LINE_RE = re.compile(r"(?:would )?(stopp?ing|restarting|starting|reloading|activating)(?: the following units)?:?\s*(.+)", re.I)
HM_UNIT_LINE_RE = re.compile(r"(Starting|Restarting|Stopping|Reloading) (?:units?|services?): (.+)", re.I)


def units_from_activation(text: str) -> dict[str, list[str]]:
    """Units named by switch-to-configuration / home-manager (sd-switch) output."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = UNIT_LINE_RE.search(line) or HM_UNIT_LINE_RE.search(line)
        if not m:
            continue
        verb = {"stopping": "stop", "stoping": "stop", "restarting": "restart", "starting": "start", "reloading": "reload", "activating": "activate"}.get(m.group(1).lower(), m.group(1).lower())
        units = [u.strip().rstrip(".") for u in re.split(r"[,\s]+", m.group(2)) if u.strip().endswith((".service", ".socket", ".timer", ".target", ".path", ".mount"))]
        if units:
            out.setdefault(verb, []).extend(units)
    return out


def units_changed_since(user: bool, since_epoch: float) -> list[str]:
    """Units whose state changed after the timestamp (from systemd's own records, so a past activation can be reviewed)."""
    scope = ["--user"] if user else []
    res = _probe(["systemctl"] + scope + ["list-units", "--all", "--plain", "--no-legend", "--no-pager"], timeout=60)
    names = [l.split()[0] for l in (res.stdout if res else "").splitlines() if l.strip() and not l.startswith("●")]
    names = [n.lstrip("●").strip() for n in names if n]
    out = []
    for chunk in (names[i:i + 200] for i in range(0, len(names), 200)):
        res = _probe(["systemctl"] + scope + ["show", "-p", "Id,StateChangeTimestampMonotonic,StateChangeTimestamp"] + chunk, timeout=60)
        rec: dict = {}
        for line in (res.stdout if res else "").splitlines() + [""]:
            if not line:
                if rec.get("Id") and rec.get("StateChangeTimestamp"):
                    try:
                        ts = datetime.strptime(rec["StateChangeTimestamp"].split(" ", 1)[1].rsplit(" ", 1)[0], "%Y-%m-%d %H:%M:%S").timestamp()
                        if ts >= since_epoch:
                            out.append(rec["Id"])
                    except (ValueError, IndexError):
                        pass
                rec = {}
                continue
            k, _, v = line.partition("=")
            rec[k] = v
    return sorted(set(out))


def switch_evidence(cfg: nix.Config, run: Run, fx: dict, kind: str, since: str, since_epoch: float, activation_text: str, before: dict | None) -> Path:
    """Everything a reviewer needs after an activation: what changed, what restarted, what the journal says."""
    user = kind == "hm"
    units = units_from_activation(activation_text)
    changed = units_changed_since(user, since_epoch)
    units["state_changed_since_activation"] = changed
    lines = ["# post-%s evidence (since %s)" % (kind, since), ""]
    lines += ["## units touched by the activation", "", "```json", json.dumps(units, indent=1), "```", ""]
    after = health_snapshot(cfg, fx)
    if before is not None:
        lines += ["## health probes before -> after", "", "```json", json.dumps({"before": before, "after": after, "regressions": health_regressions(before, after)}, indent=1), "```", ""]
    scope = ["--user"] if user else []
    failed = run.step("post-failed-units", ["systemctl"] + scope + ["--failed", "--no-legend", "--plain", "--no-pager"])
    lines += ["## failed units now (%s)" % ("user" if user else "system"), "", "```", failed.out.strip() or "(none)", "```", ""]
    touched = sorted({u for us in units.values() for u in us if u.endswith((".service", ".socket", ".timer", ".target", ".path", ".mount"))})
    for u in touched[:40]:
        st = run.step("post-status-" + re.sub(r"[^A-Za-z0-9_.-]", "_", u), ["systemctl"] + scope + ["status", "--no-pager", "-n", "20", u])
        lines += ["## %s (exit %d)" % (u, st.exit), "", "```", (st.out + st.err).strip()[-3000:], "```", ""]
    tr = run.step("post-transitions", ["journalctl"] + scope + ["--since", since, "--no-pager", "-o", "short-iso", "_COMM=systemd"])
    trans = [l for l in tr.out.splitlines() if re.search(r"(Started|Stopped|Stopping|Starting|Reloaded|Failed|Reached target|Deactivated)", l)]
    lines += ["## systemd unit transitions since activation (%s)" % ("user" if user else "system"), "", "```", ("\n".join(trans[-200:]) or "(none)"), "```", ""]
    jr = run.step("post-journal", ["journalctl"] + scope + ["--since", since, "-p", "warning", "--no-pager", "-o", "short-iso"])
    lines += ["## journal since activation, priority warning and above (%s)" % ("user" if user else "system"), "", "```", (jr.out.strip() or "(nothing)")[-12000:], "```", ""]
    diff = run.dir / ("%s-diff.txt" % ("hm" if user else "system"))
    if diff.exists():
        lines += ["## closure diff (old -> new)", "", "```", diff.read_text()[-12000:], "```", ""]
    path = run.dir / ("post-%s.md" % kind)
    path.write_text("\n".join(lines) + "\n")
    return path
