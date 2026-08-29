"""Deterministic system miner. Everything here is evidence with file:line pointers; no LLM involved."""

from __future__ import annotations

import json
import os
import re
import resource
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from . import docs, nix

SECRET_PATTERNS = [
    ("assignment", re.compile(r'(api[_-]?key|apikey|password|passwd|token|secret|client_secret)\s*=\s*"([^"]{6,})"', re.I)),
    ("sql-password", re.compile(r"PASSWORD\s+'([^']{3,})'", re.I)),
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    ("synthetic-key", re.compile(r"\bsyn_[0-9a-f]{16,}")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("slack-token", re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY")),
]
SECRET_FILENAMES = re.compile(r"(password|passwd|secret|token|\.env$|\.key$|\.pem$|credentials)", re.I)

# option -> (replacement, note). Names still present in a config are lint findings, not errors.
RENAMED_OPTIONS = {
    "hardware.opengl": "hardware.graphics",
    "nix.trustedUsers": "nix.settings.trusted-users",
    "hardware.pulseaudio": "services.pulseaudio",
    "sound.enable": "(removed; use services.pipewire / services.pulseaudio)",
    "services.xserver.displayManager.defaultSession": "services.displayManager.defaultSession",
}

MAINTENANCE_TIMER_RE = re.compile(r"(nix|nixos|upgrade|hm-|home-manager|nh-clean|gc|optimise|fstrim|ihc)", re.I)
# Restarting these classes of units disrupts sessions or state on any host; the host's own list lives in MAINTENANCE.md.
GUARDED_UNIT_PATTERNS = [r"display-manager", r"greetd", r"sddm", r"gdm", r"docker", r"podman", r"containerd", r"libvirtd", r"postgresql", r"mysql", r"mariadb", r"redis", r"pipewire", r"pulseaudio", r"jack"]


def _nix_files(root: Path) -> list[Path]:
    if not root or not root.exists():
        return []
    files = []
    for p in sorted(root.rglob("*.nix")):
        if any(part in (".git", "result", "node_modules", ".omc", ".remember") for part in p.parts):
            continue
        files.append(p)
    return files


def reachable(root: Path, entry_names: tuple[str, ...]) -> list[Path]:
    """Files reachable from entry points via relative imports (./x.nix, ./dir, dir/default.nix)."""
    if not root or not root.exists():
        return []
    root = root.resolve()
    seen: list[Path] = []
    queue = [root / n for n in entry_names if (root / n).exists()]
    while queue:
        f = queue.pop(0)
        f = f / "default.nix" if f.is_dir() else f
        if not f.exists() or f in seen or f.suffix != ".nix":
            continue
        seen.append(f)
        text = "\n".join(l.split("#", 1)[0] for l in f.read_text(errors="replace").splitlines())
        for rel in re.findall(r'(?<![A-Za-z0-9_])(\.{1,2}/[A-Za-z0-9_./-]+)', text):
            cand = (f.parent / rel).resolve()
            if cand.is_dir():
                cand = cand / "default.nix"
            if cand.exists() and cand.suffix == ".nix":
                queue.append(cand)
    return seen


def _grep(files: list[Path], pattern: str, flags: int = 0) -> list[dict]:
    """Return [{file, line, text}] for every source line (comments stripped) matching pattern."""
    rx = re.compile(pattern, flags)
    hits = []
    for f in files:
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
            if code.strip() and rx.search(code):
                hits.append({"file": str(f), "line": i, "text": line.strip()[:160]})
    return hits


def _block_comment_lines(f: Path) -> set[int]:
    """Line numbers inside /* ... */ comments — lines there are not evidence."""
    out: set[int] = set()
    depth = 0
    for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
        if depth > 0:
            out.add(i)
        if "/*" in line:
            depth += 1
            out.add(i)
        if "*/" in line and depth > 0:
            depth -= 1
    return out


def _grep_active(files: list[Path], pattern: str, flags: int = 0) -> list[dict]:
    hits = _grep(files, pattern, flags)
    commented: dict[str, set[int]] = {}
    keep = []
    for h in hits:
        cl = commented.setdefault(h["file"], _block_comment_lines(Path(h["file"])))
        if h["line"] not in cl:
            keep.append(h)
    return keep


_ENABLE_PREFIX = r"(?:[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*)"


def _enabled(files: list[Path]) -> list[dict]:
    """`x.y.enable = true;` plus block style `x.y = { enable = true; ... }` (enable within 6 lines)."""
    out = []
    for h in _grep_active(files, r"\b" + _ENABLE_PREFIX + r"\.([A-Za-z0-9_.-]+?)\.enable\s*=\s*true\b"):
        m = re.search(r"\b(" + _ENABLE_PREFIX + r"\.[A-Za-z0-9_.-]+?)\.enable\s*=\s*true", h["text"])
        if m:
            out.append({"option": m.group(1), "file": h["file"], "line": h["line"]})
    for f in files:
        lines = f.read_text(errors="replace").splitlines()
        commented = _block_comment_lines(f)
        for i, line in enumerate(lines, 1):
            m = re.match(r"\s*(" + _ENABLE_PREFIX + r"\.[A-Za-z0-9_.-]+)\s*=\s*\{\s*$", line.split("#", 1)[0])
            if m and i not in commented and any(re.match(r"\s*enable\s*=\s*true;", l) for l in lines[i:i + 6]):
                out.append({"option": m.group(1), "file": str(f), "line": i})
    # block style: `services = { foo = { enable = true; ... }; }` is common in home-manager
    for f in files:
        lines = f.read_text(errors="replace").splitlines()
        stack: list[str] = []
        for i, raw in enumerate(lines, 1):
            line = raw.split("#", 1)[0]
            m = re.match(r"\s*([A-Za-z0-9_.-]+)\s*=\s*\{\s*$", line)
            if m:
                stack.append(m.group(1))
                if len(stack) >= 2 and stack[-2] in ("services", "programs") and any(re.match(r"\s*enable\s*=\s*true;", l) for l in lines[i:i + 6]):
                    out.append({"option": stack[-2] + "." + stack[-1], "file": str(f), "line": i})
            elif re.match(r"\s*\};?\s*$", line) and stack:
                stack.pop()
    seen = set()
    uniq = []
    for e in out:
        key = (e["option"], e["file"])
        if key not in seen:
            seen.add(key)
            uniq.append(e)
    return uniq


def _run(argv: list[str], timeout: float = 20) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _version(cmd: str) -> str | None:
    out = _run([cmd, "--version"], timeout=30).strip().splitlines()
    return out[0][:60] if out else None


def agents_available() -> list[dict]:
    home = Path.home()
    table = [
        ("claude", home / ".claude/.credentials.json"),
        ("opencode", home / ".local/share/opencode/auth.json"),
        ("codex", home / ".codex/auth.json"),
    ]
    out = []
    for name, auth in table:
        path = shutil.which(name)
        out.append({
            "name": name,
            "path": path,
            "version": _version(name) if path else None,
            "authed": auth.exists(),
            "auth_file": str(auth),
        })
    return out


def secrets_scan(roots: list[Path]) -> list[dict]:
    findings = []
    for root in roots:
        if not root or not root.exists():
            continue
        for p in sorted(root.rglob("*")):
            if not p.is_file() or any(part in (".git", "result", "node_modules", ".omc", ".remember", ".venv") for part in p.parts):
                continue
            if SECRET_FILENAMES.search(p.name) and p.suffix != ".nix":
                findings.append({"file": str(p), "line": 0, "kind": "secret-looking-filename", "value": "<redacted>"})
                continue
            if p.suffix not in (".nix", ".toml", ".json", ".yaml", ".yml", ".conf", ".env", ".sh"):
                continue
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                for kind, rx in SECRET_PATTERNS:
                    m = rx.search(line)
                    if m:
                        if kind == "assignment" and re.search(r"(sops|age|\$\{|config\.|environment\.|path|File)", line):
                            continue
                        findings.append({"file": str(p), "line": i, "kind": kind, "value": "<redacted>"})
                        break
    return findings


def deprecated_options(files: list[Path]) -> list[dict]:
    out = []
    for opt, repl in RENAMED_OPTIONS.items():
        for h in _grep_active(files, r"(^|[^A-Za-z0-9_.])" + re.escape(opt) + r"(\b|\.)"):
            out.append({"option": opt, "replacement": repl, "file": h["file"], "line": h["line"]})
    return out


def _list_values(text: str, key: str) -> list[str]:
    m = re.search(r"%s\s*=\s*\[(.*?)\];" % re.escape(key), text, re.S)
    if not m:
        return []
    body = "\n".join(l.split("#", 1)[0] for l in m.group(1).splitlines())
    return re.findall(r'"([^"]+)"', body)


def _kv(text: str, key: str) -> str | None:
    m = re.search(r"(?m)^\s*%s\s*=\s*([^;]+);" % re.escape(key), text)
    return m.group(1).strip() if m else None


def git_state(path: Path | None) -> dict:
    if not path or not path.exists():
        return {"exists": False}
    inside = _run(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"]).strip() == "true"
    if not inside:
        return {"exists": True, "git": False}
    dirty = [l for l in _run(["git", "-C", str(path), "status", "--porcelain"]).splitlines() if l.strip()]
    head = _run(["git", "-C", str(path), "log", "-1", "--format=%h %ad %s", "--date=short"]).strip()
    remote = _run(["git", "-C", str(path), "remote", "-v"]).strip().splitlines()
    return {"exists": True, "git": True, "dirty": len(dirty), "head": head, "remote": remote[0] if remote else None}


def disk() -> dict:
    out = {}
    for name, p in (("root", "/"), ("boot", "/boot"), ("nix_store", "/nix/store")):
        try:
            u = shutil.disk_usage(p)
            out[name] = {"path": p, "total_gib": round(u.total / 2**30, 1), "free_gib": round(u.free / 2**30, 2), "used_pct": round(100 * (u.total - u.free) / u.total)}
        except OSError:
            pass
    cur = nix.current_system()
    if cur:
        need = 0
        for f in ("kernel", "initrd"):
            try:
                need += os.stat(cur / f, follow_symlinks=True).st_size
            except OSError:
                pass
        out["boot_need_mib"] = round(need / 2**20, 1)
    return out


def boot_entries() -> int | None:
    """Count of bootloader entries; /boot is usually root-only, so fall back to sudo -n."""
    d = Path("/boot/loader/entries")
    if os.access(d, os.R_OK):
        return len(list(d.glob("*.conf")))
    out = _run(["sudo", "-n", "ls", str(d)], timeout=15)
    return len([l for l in out.splitlines() if l.endswith(".conf")]) if out else None


def timers() -> list[dict]:
    out = []
    for scope in ("--system", "--user"):
        text = _run(["systemctl", scope, "list-timers", "--all", "--no-pager", "--no-legend"])
        for line in text.splitlines():
            if MAINTENANCE_TIMER_RE.search(line):
                cols = line.split()
                unit = next((c for c in cols if c.endswith(".timer")), None)
                if unit:
                    out.append({"scope": scope.lstrip("-"), "timer": unit, "raw": " ".join(cols)[:140]})
    return out


def failed_units() -> dict:
    return {
        "system": [l.split()[0] for l in _run(["systemctl", "--failed", "--no-legend", "--no-pager", "--plain"]).splitlines() if l.strip()],
        "user": [l.split()[0] for l in _run(["systemctl", "--user", "--failed", "--no-legend", "--no-pager", "--plain"]).splitlines() if l.strip()],
    }


def hardware() -> dict:
    hw: dict = {}
    hw["kernel_running"] = os.uname().release
    try:
        cpu = Path("/proc/cpuinfo").read_text()
        m = re.search(r"model name\s*:\s*(.+)", cpu)
        hw["cpu"] = m.group(1).strip() if m else None
        hw["cpu_threads"] = cpu.count("processor\t:")
        mem = re.search(r"MemTotal:\s+(\d+)", Path("/proc/meminfo").read_text())
        hw["mem_gib"] = round(int(mem.group(1)) / 2**20) if mem else None
    except OSError:
        pass
    try:
        hw["sound_cards"] = [l.strip() for l in Path("/proc/asound/cards").read_text().splitlines() if re.match(r"\s*\d+\s*\[", l)]
    except OSError:
        hw["sound_cards"] = []
    if shutil.which("nvidia-smi"):
        hw["gpu"] = _run(["nvidia-smi", "--query-gpu=name,driver_version", "--format=csv,noheader"]).strip() or None
    if not hw.get("gpu") and shutil.which("lspci"):
        hw["gpu"] = next((l.split(":", 2)[-1].strip() for l in _run(["lspci"]).splitlines() if re.search(r"VGA|3D|Display", l)), None)
    try:
        hw["rtprio_limit"] = resource.getrlimit(resource.RLIMIT_RTPRIO)[1]
        ml = resource.getrlimit(resource.RLIMIT_MEMLOCK)[1]
        hw["memlock_limit"] = "unlimited" if ml == resource.RLIM_INFINITY else ml
    except (ValueError, OSError):
        pass
    return hw


def drift(cfg: nix.Config) -> dict:
    """Imperative residue Nix does not manage: files where store symlinks are expected, HM backup collisions, profile packages."""
    out: dict = {"etc_files_not_from_store": [], "hm_backup_collisions": [], "user_profile_packages": []}
    cur = nix.current_system()
    if cur and (cur / "etc").exists():
        # NixOS installs some /etc entries as copies (sudoers, crontab...). Drift = a live regular file whose
        # content differs from what the generation provides, or a live file with no counterpart in the generation.
        for p in sorted((cur / "etc").rglob("*")):
            if not (p.is_symlink() or p.is_file()):
                continue
            live = Path("/etc") / p.relative_to(cur / "etc")
            try:
                if live.exists() and not live.is_symlink() and live.is_file():
                    if live.read_bytes() != p.resolve().read_bytes():
                        out["etc_files_not_from_store"].append(str(live))
            except OSError:
                pass
            if len(out["etc_files_not_from_store"]) >= 50:
                break
    home = Path.home()
    exts = ["ihc-bak"] + list(cfg_backup_exts(cfg))
    for ext in exts:
        for p in list(home.glob("*." + ext)) + list(home.glob(".config/*." + ext)) + list(home.glob(".config/*/*." + ext)):
            sibling = p.with_name(p.name[: -len(ext) - 1])
            try:
                if sibling.is_symlink() and "/nix/store/" in str(sibling.resolve()):
                    out["hm_backup_collisions"].append(str(p))
            except OSError:
                pass
    res = _run(["nix-env", "-q"], timeout=60)
    out["user_profile_packages"] = [l.strip() for l in res.splitlines() if l.strip()][:50]
    return out


def cfg_backup_exts(cfg: nix.Config) -> set[str]:
    """home-manager backup extensions configured in the trees (home-manager.backupFileExtension / -b flag habits)."""
    exts = set()
    for root in cfg.config_repos:
        for p in _nix_files(root):
            try:
                m = re.search(r'backupFileExtension\s*=\s*"([^"]+)"', p.read_text(errors="replace"))
            except OSError:
                continue
            if m:
                exts.add(m.group(1))
    return exts


def fingerprint(facts: dict) -> str:
    """Stable digest of what would change the docs: inputs, enabled options, kernel/audio/gpu settings, hardware, drift."""
    import hashlib
    keys = {
        "inputs": sorted(i["name"] for i in facts.get("inputs", [])),
        "enabled": sorted(e["option"] for scope in facts.get("enabled", {}).values() for e in scope),
        "kernel": facts.get("kernel", {}).get("params"),
        "hw": {k: v for k, v in facts.get("runtime", {}).get("hardware", {}).items() if k in ("cpu", "gpu", "sound_cards", "kernel_running")},
        "drift": facts.get("runtime", {}).get("drift"),
        "unused_inputs": facts.get("unused_inputs"),
        "theming": [(h["file"], h["line"]) for h in facts.get("theming", [])][:50],
        "secrets": [(s["file"], s["line"]) for s in facts.get("secrets", [])],
        "deprecated": [(d["option"], d["file"], d["line"]) for d in facts.get("deprecated_options", [])],
    }
    return hashlib.sha256(json.dumps(keys, sort_keys=True, default=str).encode()).hexdigest()[:16]


def unused_inputs(flake_text: str, names: list[str]) -> list[str]:
    """Inputs declared in flake.nix but never referenced outside the `inputs = { ... }` block."""
    m = re.search(r"inputs\s*=\s*\{", flake_text)
    body = flake_text
    if m:
        depth, i = 0, m.end() - 1
        while i < len(flake_text):
            depth += {"{": 1, "}": -1}.get(flake_text[i], 0)
            if depth == 0:
                break
            i += 1
        body = flake_text[:m.start()] + flake_text[i + 1:]
    code = "\n".join(l.split("#", 1)[0] for l in body.splitlines())
    return [n for n in names if not re.search(r"(?<![A-Za-z0-9_-])%s(?![A-Za-z0-9_-])" % re.escape(n), code)]


def config_assets(roots: list[Path], min_mb: float = 1.0) -> list[dict]:
    """Non-Nix files the configuration references by name (images, fonts, sounds...): they are inputs, not clutter."""
    out = []
    for root in roots:
        if not root or not root.exists():
            continue
        texts = " ".join(p.read_text(errors="replace") for p in _nix_files(root))
        for p in sorted(root.rglob("*")):
            if p.is_file() and p.suffix.lower() in (".jpg", ".jpeg", ".png", ".webp", ".gif", ".svg", ".ttf", ".otf", ".wav", ".ogg", ".mp3", ".flac") and p.name in texts:
                out.append({"file": str(p), "mb": round(p.stat().st_size / 2**20, 1), "tracked": _run(["git", "-C", str(root), "ls-files", "--error-unmatch", str(p)]).strip() != ""})
    return out


def mine(cfg: nix.Config, runtime: bool = True) -> dict:
    all_sys = _nix_files(cfg.flake_dir)
    sys_files = reachable(cfg.flake_dir, ("flake.nix", "configuration.nix", "darwin-configuration.nix"))
    all_hm = _nix_files(cfg.hm_dir) if cfg.hm_dir and cfg.hm_dir != cfg.flake_dir else []
    hm_files = reachable(cfg.hm_dir, ("home.nix", "flake.nix")) if all_hm else []
    all_text = {str(f): f.read_text(errors="replace") for f in sys_files + hm_files}
    conf = all_text.get(str(cfg.flake_dir / "configuration.nix"), "")
    hwconf = all_text.get(str(cfg.flake_dir / "hardware-configuration.nix"), "")

    facts: dict = {
        "mined_at": nix.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": cfg.hostname,
        "user": cfg.user,
        "platform": cfg.platform,
        "config": {
            "flake_dir": str(cfg.flake_dir),
            "host_attr": cfg.host_attr,
            "hm_attr": cfg.hm_attr,
            "hm_dir": str(cfg.hm_dir) if cfg.hm_dir else None,
            "impure": cfg.impure,
            "impure_reasons": cfg.impure_reasons,
            "nix_args": cfg.nix_args(),
            "state_version": _kv(conf, "system.stateVersion"),
            "hm_state_version": next((_kv(t, "home.stateVersion") for t in all_text.values() if "home.stateVersion" in t), None),
            "git": {str(r): git_state(r) for r in cfg.config_repos},
            "files": {"system": len(sys_files), "hm": len(hm_files), "system_unreachable": len(all_sys) - len(sys_files), "hm_unreachable": len(all_hm) - len(hm_files)},
        },
        "inputs": [i.__dict__ for i in nix.lock_inputs(cfg.flake_dir)],
        "kernel": {
            "configured_packages": _grep_active(sys_files, r"(kernel\.packages|boot\.kernelPackages)\s*="),
            "preempt_rt": _grep_active(sys_files, r"PREEMPT_RT\s*=\s*yes"),
            "realtime": _grep_active(sys_files, r"(kernel\.realtime\s*=\s*true|linuxPackages(_[a-z0-9]+)?_rt\b|linux_rt|-rt\d)"),
            "params": _list_values(hwconf + "\n" + conf, "boot.kernelParams"),
            "sysctl_rt": _grep_active(sys_files, r"sched_rt_runtime_us|vm\.dirty_ratio|vm\.vfs_cache_pressure"),
            "blacklisted_modules": _list_values(conf, "boot.blacklistedKernelModules"),
        },
        "audio": {
            "tuning": _grep_active(sys_files, r"^\s*(musnix|services\.jack|security\.rtkit|boot\.kernel\.sysctl\.\"kernel\.sched_rt|hardware\.ksm)[A-Za-z0-9_.\"]*\s*="),
            "jack_args": _list_values(conf, "extraOptions"),
            "jack_enabled": _grep_active(sys_files, r"services\.jack\.jackd\.enable\s*=\s*true|jackd\s*=\s*\{|jackd\.enable\s*=\s*true"),
            "irq_priorities": _grep_active(sys_files, r"rtirq|nameList|highList|threadirqs"),
            "rtkit": _grep_active(sys_files, r"security\.rtkit\.enable\s*=\s*true"),
            "pipewire": _grep_active(sys_files, r"services\.pipewire\.[a-z.]*enable\s*="),
            "pulseaudio": _grep_active(sys_files, r"pulseaudio\.enable\s*=\s*true"),
            "soundcard_pci": _kv(conf, "musnix.soundcardPciId") or _kv(conf, "soundcardPciId"),
            "no_sleep": _grep_active(sys_files, r"(AllowSuspend|AllowHibernation|targets\.(sleep|suspend|hibernate|hybrid-sleep)\.enable\s*=\s*false)"),
            "cpu_governor": _grep_active(sys_files, r"cpuFreqGovernor|cpufreq\.default_governor"),
            "hm_audio_modules": [str(f) for f in hm_files if "/audio/" in str(f)],
        },
        "gpu": {
            "video_drivers": _list_values(conf, "services.xserver.videoDrivers"),
            "nvidia": _grep_active(sys_files, r"hardware\.nvidia[.-][A-Za-z0-9_.-]*\s*=|hardware\.nvidia\s*=\s*\{"),
            "cuda": _grep_active(sys_files + hm_files, r"cuda|acceleration\s*=\s*\"cuda\""),
        },
        "enabled": {"system": _enabled(sys_files), "hm": _enabled(hm_files)},
        "ai": _grep_active(sys_files + hm_files, r"(ollama|llama|open-webui|lmstudio|vllm|comfyui|whisper|cuda|rocm|claude-code|codex|opencode|copilot|aider|\bagent\b)"),
        "maintenance": {
            "auto_upgrade": _grep_active(sys_files, r"system\.autoUpgrade\.enable\s*="),
            "gc": _grep_active(sys_files, r"nix\.gc\.|nh\.clean|autoExpire|auto-optimise-store|optimise\.automatic"),
            "boot_limit": _kv(conf, "boot.loader.systemd-boot.configurationLimit"),
            "nightly_jobs": [str(f) for f in hm_files + sys_files if re.search(r"(nightly|auto-?update|autoupgrade)", f.name, re.I)],
            "timers": timers() if runtime else [],
            "cron": _grep_active(sys_files, r"systemCronJobs|services\.cron\.enable"),
        },
        "privacy": _grep_active(sys_files + hm_files, r"(DO_NOT_TRACK|TELEMETRY|NO_ANALYTICS|telemetry_disabled|enable_metrics\s*=\s*false|searx|\btor\b|tor-browser|sops|agenix|privacy)"),
        "network": _grep_active(sys_files, r"(tailscale|openssh|mosh|networkmanager|firewall|hosts\s*=|extraHosts)"),
        "hardware_edits": _grep_active([f for f in sys_files if f.name == "hardware-configuration.nix"], r"(boot\.kernelParams|systemd\.|watchdog|sleep\.settings|enableEmergencyMode|/mnt/)"),
        "theming": _grep_active(sys_files + hm_files, r"(stylix|base16|polarity|colorScheme|colorscheme|palette|wallpaper|\bimage\s*=|accentColor|profileName|registry\.profiles)"),
        "unused_inputs": unused_inputs(all_text.get(str(cfg.flake_dir / "flake.nix"), ""), [i.name for i in nix.lock_inputs(cfg.flake_dir)]),
        "config_assets": config_assets([cfg.flake_dir] + ([cfg.hm_dir] if cfg.hm_dir and cfg.hm_dir != cfg.flake_dir else [])),
        "deprecated_options": deprecated_options(sys_files + hm_files),
        "secrets": secrets_scan([cfg.flake_dir] + ([cfg.hm_dir] if cfg.hm_dir and cfg.hm_dir != cfg.flake_dir else [])),
        "dead_files": {"system": [str(f) for f in all_sys if f not in sys_files], "hm": [str(f) for f in all_hm if f not in hm_files]},
    }
    rules = docs.host_rules(cfg.docs_dir)
    env_guard = [u.strip() for u in os.environ.get("IHC_GUARDED_UNITS", "").split(",") if u.strip()]
    facts["host_rules"] = rules
    facts["guarded_units"] = sorted(set(rules["guarded_units"] + env_guard))
    facts["guarded_unit_patterns"] = GUARDED_UNIT_PATTERNS
    if runtime:
        cur = nix.current_system()
        sys_gens = nix.generations(cfg.system_profile)
        hm_gens = nix.generations(cfg.hm_profile)
        lock_nixpkgs = next((i for i in facts["inputs"] if i["name"] == "nixpkgs"), None)
        running_date = nix.store_path_date(cur) if cur else None
        lock_date = datetime.strptime(lock_nixpkgs["last_modified"], "%Y-%m-%d").replace(tzinfo=timezone.utc) if lock_nixpkgs and lock_nixpkgs.get("last_modified") else None
        facts["runtime"] = {
            "current_system": str(cur) if cur else None,
            "running_nixpkgs_date": running_date.strftime("%Y-%m-%d") if running_date else None,
            "lock_nixpkgs_date": lock_date.strftime("%Y-%m-%d") if lock_date else None,
            "drift_days": (lock_date - running_date).days if (lock_date and running_date) else None,
            "system_generations": len(sys_gens),
            "hm_generations": len(hm_gens),
            "last_system_switch": datetime.fromtimestamp(cfg.system_profile.lstat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if cfg.system_profile.exists() else None,
            "last_hm_switch": datetime.fromtimestamp(cfg.hm_profile.lstat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if cfg.hm_profile.exists() else None,
            "boot_entries": boot_entries(),
            "disk": disk(),
            "hardware": hardware(),
            "failed_units": failed_units(),
            "agents": agents_available(),
            "api_keys_in_env": [k for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY") if os.environ.get(k)],
            "notifier": {"notify_send": shutil.which("notify-send"), "daemon": _run(["pgrep", "-l", "-x", "mako|dunst|swaync|fnott|hyprpanel"]).strip() or _run(["pgrep", "-lf", "mako|dunst|swaync"]).strip()[:60] or None},
            "local_inputs": {i["name"]: git_state(Path(i["ref"].replace("file://", ""))) for i in facts["inputs"] if i["local"]},
            "drift": drift(cfg),
        }
        facts["fingerprint"] = fingerprint(facts)
    return facts


def summary_lines(facts: dict) -> list[str]:
    """Short human summary used by `ihc status` and agent prompts."""
    rt = facts.get("runtime", {})
    lines = [
        "host=%s platform=%s flake=%s host_attr=%s hm_attr=%s" % (facts["host"], facts["platform"], facts["config"]["flake_dir"], facts["config"]["host_attr"], facts["config"]["hm_attr"]),
        "impure=%s nix_args=%s" % (facts["config"]["impure"], " ".join(facts["config"]["nix_args"])),
    ]
    if rt:
        d = rt.get("disk", {})
        lines += [
            "running nixpkgs %s, lock nixpkgs %s, drift %s days; generations system=%s hm=%s" % (rt.get("running_nixpkgs_date"), rt.get("lock_nixpkgs_date"), rt.get("drift_days"), rt.get("system_generations"), rt.get("hm_generations")),
            "disk free: / %s GiB, /boot %s GiB (need ~%s MiB per generation), failed units: %s" % (d.get("root", {}).get("free_gib"), d.get("boot", {}).get("free_gib"), d.get("boot_need_mib"), rt.get("failed_units")),
            "agents: " + ", ".join("%s(%s%s)" % (a["name"], "authed" if a["authed"] else "no-auth", "" if a["path"] else ",missing") for a in rt.get("agents", [])),
        ]
    if facts.get("secrets"):
        lines.append("secrets in config: %d finding(s), e.g. %s:%s" % (len(facts["secrets"]), facts["secrets"][0]["file"], facts["secrets"][0]["line"]))
    if facts.get("deprecated_options"):
        lines.append("deprecated options: %d" % len(facts["deprecated_options"]))
    dr = rt.get("drift", {})
    if dr and any(dr.values()):
        lines.append("drift: %d /etc files not from the store, %d home-manager backup collisions, %d imperative profile packages" % (len(dr.get("etc_files_not_from_store", [])), len(dr.get("hm_backup_collisions", [])), len(dr.get("user_profile_packages", []))))
    if facts.get("unused_inputs"):
        lines.append("unused flake inputs: " + ", ".join(facts["unused_inputs"]))
    assets = facts.get("config_assets", [])
    if assets:
        lines.append("config assets: %d files, %.0f MB, %d not tracked by git" % (len(assets), sum(a["mb"] for a in assets), sum(1 for a in assets if not a["tracked"])))
    hr = facts.get("host_rules", {})
    lines.append("host rules from MAINTENANCE.md: %d guarded units, %d health probes, %d busy checks" % (len(facts.get("guarded_units", [])), len(hr.get("health_probes", {})), len(hr.get("busy_checks", {}))))
    return lines


def to_json(facts: dict) -> str:
    return json.dumps(facts, indent=2, default=str)
