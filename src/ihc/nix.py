"""Discovery of the flake, host, home-manager, platform commands, and lock inputs."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT_CHANNELS = "/nix/var/nix/profiles/per-user/root/channels"


@dataclass
class Input:
    name: str
    type: str
    ref: str  # owner/repo, path, or url
    rev: str | None
    last_modified: str | None  # ISO date
    local: bool  # path: / git+file: — user-controlled checkout
    pinned: bool  # url pins a commit on purpose
    url: str | None = None


@dataclass
class Config:
    platform: str  # nixos | darwin | hm-only
    flake_dir: Path
    host_attr: str | None
    hm_attr: str | None
    hm_dir: Path | None
    impure: bool
    impure_reasons: list[str]
    nix_path_extra: list[str]  # e.g. nixos-config=/etc/nixos/configuration.nix
    hostname: str
    user: str
    docs_dir: Path

    # ---- attribute paths -------------------------------------------------
    @property
    def system_attr(self) -> str | None:
        if self.platform == "nixos" and self.host_attr:
            return "%s#nixosConfigurations.%s.config.system.build.toplevel" % (self.flake_dir, self.host_attr)
        if self.platform == "darwin" and self.host_attr:
            return "%s#darwinConfigurations.%s.system" % (self.flake_dir, self.host_attr)
        return None

    @property
    def hm_attr_path(self) -> str | None:
        if not self.hm_attr:
            return None
        name = self.hm_attr if re.fullmatch(r"[A-Za-z0-9_-]+", self.hm_attr) else '"%s"' % self.hm_attr
        return "%s#homeConfigurations.%s.activationPackage" % (self.flake_dir, name)

    @property
    def system_profile(self) -> Path:
        return Path("/nix/var/nix/profiles/system")

    @property
    def hm_profile(self) -> Path:
        xdg = Path(os.environ.get("XDG_STATE_HOME", "~/.local/state")).expanduser() / "nix/profiles/home-manager"
        if xdg.exists():
            return xdg
        return Path("/nix/var/nix/profiles/per-user/%s/home-manager" % self.user)

    @property
    def config_repos(self) -> list[Path]:
        repos = [self.flake_dir]
        if self.hm_dir and self.hm_dir.resolve() != self.flake_dir.resolve() and not str(self.hm_dir.resolve()).startswith(str(self.flake_dir.resolve()) + "/"):
            repos.append(self.hm_dir)
        return repos

    def nix_args(self) -> list[str]:
        args = ["--impure"] if self.impure else []
        for entry in self.nix_path_extra:
            args += ["-I", entry]
        return args

    def env(self) -> dict:
        env = dict(os.environ)
        parts = [p for p in env.get("NIX_PATH", "").split(":") if p]
        if not parts:
            parts = ["nixpkgs=flake:nixpkgs", str(Path("~/.nix-defexpr/channels").expanduser()), ROOT_CHANNELS]
        for entry in self.nix_path_extra:
            if entry not in parts:
                parts.insert(0, entry)
        if ROOT_CHANNELS not in parts and Path(ROOT_CHANNELS).exists():
            parts.append(ROOT_CHANNELS)
        env["NIX_PATH"] = ":".join(parts)
        return env


# ---- platform -----------------------------------------------------------

def detect_platform() -> str:
    if Path("/etc/NIXOS").exists() or Path("/run/current-system/nixos-version").exists():
        return "nixos"
    if Path("/run/current-system/darwin-version").exists() or shutil.which("darwin-rebuild"):
        return "darwin"
    return "hm-only"


def default_flake_dir(platform: str) -> Path | None:
    env = os.environ.get("IHC_FLAKE")
    if env:
        return Path(env).expanduser()
    candidates = {
        "nixos": ["/etc/nixos"],
        "darwin": ["~/.config/nix-darwin", "/etc/nix-darwin", "~/.config/darwin"],
        "hm-only": ["~/.config/home-manager"],
    }[platform] + ["~/.config/home-manager"]
    for c in candidates:
        p = Path(c).expanduser()
        if (p / "flake.nix").exists():
            return p
    return None


# ---- flake.nix parsing ------------------------------------------------------

def _attr_names(text: str, container: str) -> list[str]:
    names = re.findall(r'%s\.("?)([^"\s=.]+)\1\s*=' % container, text)
    names = [n for _, n in names]
    m = re.search(r'%s\s*=\s*\{(.*?)\n\s*\};' % container, text, re.S)
    if m:
        names += [n for _, n in re.findall(r'\n\s*("?)([^"\s=]+)\1\s*=\s*', m.group(1))]
    seen: list[str] = []
    for n in names:
        if n not in seen:
            seen.append(n)
    return seen


def pick_host(names: list[str], hostname: str) -> str | None:
    if not names:
        return None
    for n in names:
        if n == hostname or n.endswith("@" + hostname):
            return n
    return names[0]


def pick_hm(names: list[str], user: str, hostname: str) -> str | None:
    if not names:
        return None
    for n in names:
        if n == "%s@%s" % (user, hostname):
            return n
    for n in names:
        if n == user:
            return n
    return names[0]


def impure_requirements(flake_dir: Path) -> tuple[list[str], list[str]]:
    """Why `nix eval` needs --impure / -I for this tree. Mined from the .nix sources."""
    reasons: list[str] = []
    nix_path: list[str] = []
    files = list(flake_dir.glob("*.nix")) + list((flake_dir / "modules").glob("*.nix")) if flake_dir.exists() else []
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            s = line.split("#", 1)[0]
            if re.search(r"(^\s*|import\s+)<[A-Za-z0-9_-]+(/[^>]*)?>", s):
                reasons.append("%s:%d channel import %s" % (f.name, i, s.strip()))
            if "fetchTarball" in s and "sha256" not in text[max(0, text.find(s) - 200): text.find(s) + 300]:
                reasons.append("%s:%d builtins.fetchTarball without hash" % (f.name, i))
            if re.search(r"copySystemConfiguration\s*=\s*true", s):
                reasons.append("%s:%d system.copySystemConfiguration needs <nixos-config>" % (f.name, i))
                nix_path.append("nixos-config=%s" % (flake_dir / "configuration.nix"))
            if f.name == "flake.nix" and re.search(r'^\s*/(home|Users)/[^\s;"]+\.nix\s*$', s):
                reasons.append("%s:%d absolute path module %s" % (f.name, i, s.strip()))
    return reasons, nix_path


def discover(flake_dir: Path | None = None) -> Config:
    platform = detect_platform()
    hostname = socket.gethostname().split(".")[0]
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or "root"
    fd = Path(flake_dir).expanduser() if flake_dir else default_flake_dir(platform)
    if fd is None:
        raise SystemExit("ihc: no flake.nix found; set IHC_FLAKE=/path/to/flake")
    text = (fd / "flake.nix").read_text(errors="replace") if (fd / "flake.nix").exists() else ""
    container = "darwinConfigurations" if platform == "darwin" else "nixosConfigurations"
    host_attr = pick_host(_attr_names(text, container), hostname) if platform != "hm-only" else None
    hm_attr = os.environ.get("IHC_HM_ATTR") or pick_hm(_attr_names(text, "homeConfigurations"), user, hostname)
    hm_dir = None
    m = re.search(r'^\s*(/(?:home|Users)/[^\s;"]+\.nix)\s*$', text, re.M)
    if m:
        hm_dir = Path(m.group(1)).parent
    elif hm_attr:
        hm_dir = fd
    elif Path("~/.config/home-manager/home.nix").expanduser().exists():
        hm_dir = Path("~/.config/home-manager").expanduser()
    reasons, nix_path = impure_requirements(fd)
    impure = bool(reasons)
    docs_dir = Path(os.environ.get("IHC_DOCS_DIR", str(fd))).expanduser()
    return Config(platform, fd, host_attr, hm_attr, hm_dir, impure, reasons, nix_path, hostname, user, docs_dir)


# ---- lock file ------------------------------------------------------------

def lock_inputs(flake_dir: Path) -> list[Input]:
    lock = flake_dir / "flake.lock"
    if not lock.exists():
        return []
    data = json.loads(lock.read_text())
    nodes = data.get("nodes", {})
    root = nodes.get(data.get("root", "root"), {})
    text = (flake_dir / "flake.nix").read_text(errors="replace") if (flake_dir / "flake.nix").exists() else ""
    out: list[Input] = []
    for name, node_name in sorted(root.get("inputs", {}).items()):
        if not isinstance(node_name, str):
            continue
        node = nodes.get(node_name, {})
        locked = node.get("locked", {})
        typ = locked.get("type", "?")
        if typ in ("github", "gitlab", "sourcehut"):
            ref = "%s/%s" % (locked.get("owner"), locked.get("repo"))
        elif typ == "path":
            ref = locked.get("path", "")
        else:
            ref = locked.get("url") or locked.get("path") or ""
        lm = locked.get("lastModified")
        date = datetime.fromtimestamp(lm, tz=timezone.utc).strftime("%Y-%m-%d") if lm else None
        url = _input_url(text, name)
        pinned = bool(url and (re.search(r"[?&]rev=", url) or re.search(r"/[0-9a-f]{40}(\b|$)", url)))
        local = typ == "path" or (url or "").startswith(("path:", "git+file:")) or ref.startswith("/")
        out.append(Input(name, typ, ref, locked.get("rev"), date, local, pinned, url))
    return out


def _input_url(flake_text: str, name: str) -> str | None:
    m = re.search(r'\b%s\.url\s*=\s*"([^"]+)"' % re.escape(name), flake_text)
    if m:
        return m.group(1)
    m = re.search(r'\b%s\s*=\s*\{[^}]*?url\s*=\s*"([^"]+)"' % re.escape(name), flake_text, re.S)
    return m.group(1) if m else None


# ---- profiles / generations -------------------------------------------------

def generations(profile: Path) -> list[Path]:
    parent, base = profile.parent, profile.name
    if not parent.exists():
        return []
    gens = [p for p in parent.iterdir() if re.fullmatch(r"%s-\d+-link" % re.escape(base), p.name)]
    return sorted(gens, key=lambda p: int(p.name.split("-")[-2]))


def current_system() -> Path | None:
    p = Path("/run/current-system")
    return p.resolve() if p.exists() else None


def store_path_date(path: Path) -> datetime | None:
    """Date of a nixos system from its nixos-version file (e.g. 26.11.20260804.e72e4f2)."""
    for f in ("nixos-version", "darwin-version"):
        vp = path / f
        if vp.exists():
            m = re.search(r"\.(\d{8})\.", vp.read_text())
            if m:
                return datetime.strptime(m.group(1), "%Y%m%d").replace(tzinfo=timezone.utc)
    return None


def nix_json(argv: list[str], env: dict | None = None, cwd: Path | None = None) -> dict | list | None:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=cwd, timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def closure_size(path: Path) -> int | None:
    data = nix_json(["nix", "path-info", "-S", "--json", str(path)])
    if isinstance(data, list) and data:
        return data[0].get("closureSize")
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, dict) and "closureSize" in v:
                return v["closureSize"]
    return None
