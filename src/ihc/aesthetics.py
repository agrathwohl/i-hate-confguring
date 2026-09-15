"""Aesthetics: does the user's configured look derive from one source of truth on every surface?

Generic for any NixOS / nix-darwin / home-manager user. The theming frameworks are discovered in
the config trees, the palette is what the theming engine actually wrote, and every enabled surface's
*generated* config is scanned for colours that are not in that palette. Nothing here is host
specific and nothing is fixed here: drift is evidence, the fix belongs in the config trees.
"""

from __future__ import annotations

import functools
import json
import re
from pathlib import Path

from . import docs, facts as facts_mod, nix

# A surface's own config "derives" from the source of truth when it references one of these.
THEME_REF = r"config\.lib\.stylix\.colors|base0[0-9A-Fa-f]\b|withHashtag|colorScheme\.|colorscheme\.|currentProfile|profileName|stylix\."
NIX_HEX = r'"#[0-9a-fA-F]{3,8}"|rgba?\(\s*[0-9a-fA-F]{6,8}\s*\)'
COLOUR_RE = re.compile(
    r"#([0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3})(?![0-9a-zA-Z_-])"  # a CSS id like #backlight is not #bac
    r"|rgba?\(\s*#?([0-9a-fA-F]{6,8})\s*[,)]"
    r"|rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})"
)
FONT_RES = [
    re.compile(r"font[_-]family\s*[:=]?\s*(.+)", re.I),
    re.compile(r"(?<![\w-])font\s*[:=]\s*([^;\n{}]+)", re.I),
]
NEUTRAL = ("#000000", "#ffffff")

# surface -> label, option prefix regex (its `.enable` marks it on), generated files relative to
# $HOME, and the stylix target name that would theme it.
SURFACES: dict[str, dict] = {
    "kitty": {"label": "kitty", "option": r"programs\.kitty", "paths": [".config/kitty/kitty.conf"], "stylix": "kitty"},
    "alacritty": {"label": "alacritty", "option": r"programs\.alacritty", "paths": [".config/alacritty/alacritty.toml", ".config/alacritty/alacritty.yml"], "stylix": "alacritty"},
    "foot": {"label": "foot", "option": r"programs\.foot", "paths": [".config/foot/foot.ini"], "stylix": "foot"},
    "ghostty": {"label": "ghostty", "option": r"programs\.ghostty", "paths": [".config/ghostty/config"], "stylix": "ghostty"},
    "wezterm": {"label": "wezterm", "option": r"programs\.wezterm", "paths": [".config/wezterm/wezterm.lua"], "stylix": "wezterm"},
    "zsh": {"label": "zsh prompt", "option": r"programs\.zsh", "paths": [".zshrc", ".p10k.zsh"], "stylix": "zsh"},
    "bash": {"label": "bash prompt", "option": r"programs\.bash", "paths": [".bashrc"], "stylix": None},
    "nushell": {"label": "nushell prompt", "option": r"programs\.nushell", "paths": [".config/nushell/config.nu", ".config/nushell/env.nu"], "stylix": "nushell"},
    "tmux": {"label": "tmux", "option": r"programs\.tmux", "paths": [".config/tmux/tmux.conf", ".tmux.conf"], "stylix": "tmux"},
    "neovim": {"label": "neovim", "option": r"programs\.neovim", "paths": [".config/nvim/init.lua"], "stylix": "vim"},
    "nixvim": {"label": "nixvim", "option": r"programs\.nixvim", "paths": [".config/nvim/init.lua"], "stylix": "nixvim"},
    "helix": {"label": "helix", "option": r"programs\.helix", "paths": [".config/helix/config.toml"], "stylix": "helix"},
    "vscode": {"label": "vscode", "option": r"programs\.vscode", "paths": [".config/Code/User/settings.json", ".config/VSCodium/User/settings.json"], "stylix": "vscode"},
    "hyprland": {"label": "hyprland", "option": r"wayland\.windowManager\.hyprland|programs\.hyprland", "paths": [".config/hypr/hyprland.conf"], "stylix": "hyprland"},
    "sway": {"label": "sway", "option": r"wayland\.windowManager\.sway", "paths": [".config/sway/config"], "stylix": "sway"},
    "niri": {"label": "niri", "option": r"programs\.niri|niri\.settings", "paths": [".config/niri/config.kdl"], "stylix": "niri"},
    "i3": {"label": "i3", "option": r"xsession\.windowManager\.i3", "paths": [".config/i3/config"], "stylix": "i3"},
    "waybar": {"label": "waybar", "option": r"programs\.waybar", "paths": [".config/waybar/config", ".config/waybar/style.css"], "stylix": "waybar"},
    "quickshell": {"label": "quickshell", "option": r"programs\.quickshell|quickshell\.", "paths": [".config/quickshell/shell.qml"], "stylix": None},
    "ags": {"label": "ags", "option": r"programs\.ags", "paths": [".config/ags/config.js", ".config/ags/style.css"], "stylix": "ags"},
    "hyprpanel": {"label": "hyprpanel", "option": r"programs\.hyprpanel", "paths": [".config/hyprpanel/config.json"], "stylix": "hyprpanel"},
    "polybar": {"label": "polybar", "option": r"services\.polybar", "paths": [".config/polybar/config.ini"], "stylix": "polybar"},
    "rofi": {"label": "rofi", "option": r"programs\.rofi", "paths": [".config/rofi/config.rasi"], "stylix": "rofi"},
    "wofi": {"label": "wofi", "option": r"programs\.wofi", "paths": [".config/wofi/config", ".config/wofi/style.css"], "stylix": "wofi"},
    "fuzzel": {"label": "fuzzel", "option": r"programs\.fuzzel", "paths": [".config/fuzzel/fuzzel.ini"], "stylix": "fuzzel"},
    "mako": {"label": "mako", "option": r"services\.mako", "paths": [".config/mako/config"], "stylix": "mako"},
    "dunst": {"label": "dunst", "option": r"services\.dunst", "paths": [".config/dunst/dunstrc"], "stylix": "dunst"},
    "swaync": {"label": "swaync", "option": r"services\.swaync|services\.swaynotificationcenter", "paths": [".config/swaync/config.json", ".config/swaync/style.css"], "stylix": "swaync"},
    "hyprlock": {"label": "hyprlock", "option": r"programs\.hyprlock", "paths": [".config/hypr/hyprlock.conf"], "stylix": "hyprlock"},
    "swaylock": {"label": "swaylock", "option": r"programs\.swaylock", "paths": [".config/swaylock/config"], "stylix": "swaylock"},
    "gtk": {"label": "gtk", "option": r"gtk", "paths": [".config/gtk-3.0/settings.ini", ".config/gtk-4.0/settings.ini", ".gtkrc-2.0"], "stylix": "gtk"},
    "qt": {"label": "qt", "option": r"qt", "paths": [".config/qt5ct/qt5ct.conf", ".config/Kvantum/kvantum.kvconfig"], "stylix": "qt"},
    "firefox": {"label": "firefox", "option": r"programs\.firefox", "paths": [".mozilla/firefox/*/user.js", ".mozilla/firefox/*/chrome/userChrome.css"], "stylix": "firefox"},
    "cursor": {"label": "pointer cursor", "option": r"home\.pointerCursor", "paths": [".icons/default/index.theme"], "stylix": "cursor"},
    "fonts": {"label": "fonts", "option": r"fonts\.fontconfig|stylix\.fonts", "paths": [".config/fontconfig/conf.d/10-hm-fonts.conf"], "stylix": None},
}


@functools.lru_cache(maxsize=None)
def _read(path: str, mtime: int, size: int) -> str:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def _text(path: str) -> str:
    """File text, cached on (path, mtime, size) so an agent's edits are never read stale."""
    try:
        st = Path(path).stat()
    except OSError:
        return ""
    return _read(str(path), st.st_mtime_ns, st.st_size)


def _with(files: list[Path], pattern: str) -> list[Path]:
    """The subset of files whose text matches pattern (cheap pre-filter before a real grep)."""
    rx = re.compile(pattern)
    return [f for f in files if rx.search(_text(str(f)))]


# ---- frameworks -------------------------------------------------------------

def frameworks(nix_files: list[Path]) -> dict:
    """Which theming sources exist in the config trees, as file/line/text evidence."""
    patterns = {
        "stylix": r"stylix\.|base16Scheme|polarity\s*=|^\s*image\s*=",
        "nix_colors": r"colorScheme|colorschemes",
        "catppuccin": r"catppuccin\.",
        "base16_refs": r"config\.lib\.stylix\.colors|base0[0-9A-F]|withHashtag",
    }
    out = {name: facts_mod._grep_active(_with(nix_files, pat), pat)[:10] for name, pat in patterns.items()}
    registries = [f for f in nix_files if re.search(r"profiles\s*=\s*\{", _text(str(f))) and re.search(r"image\s*=", _text(str(f)))]
    out["profile_registry"] = facts_mod._grep_active(registries, r"profiles\s*=\s*\{")[:10]
    return out


def present(nix_files: list[Path]) -> list[str]:
    return sorted(k for k, v in frameworks(nix_files).items() if v)


# ---- profile registries ------------------------------------------------------

def _block(text: str, open_idx: int) -> tuple[str, int]:
    """Body of the `{...}` opening at open_idx and the index past its `}`.
    Nix strings ('' '' and " ") and # comments are skipped so braces inside them do not count."""
    i, depth, n = open_idx, 0, len(text)
    while i < n:
        if text.startswith("''", i):
            j = text.find("''", i + 2)
            i = n if j < 0 else j + 2
            continue
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
            continue
        if c == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i + 1
        i += 1
    return text[open_idx + 1:], n


_KEY_BLOCK = re.compile(r'([A-Za-z_][A-Za-z0-9_-]*|"[^"]+")\s*=\s*(?:[A-Za-z_][A-Za-z0-9_.]*\s+)*\{')
_KEY_VALUE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*")
_STRING = re.compile(r'"([^"]*)"')


def _entries(body: str) -> list[tuple[str, str, int]]:
    """Top-level `name = { ... }` / `name = mk { ... }` entries: (name, inner body, offset)."""
    out: list[tuple[str, str, int]] = []
    i, n = 0, len(body)
    while i < n:
        if body.startswith("''", i):
            j = body.find("''", i + 2)
            i = n if j < 0 else j + 2
            continue
        c = body[i]
        if c == '"':
            i += 1
            while i < n and body[i] != '"':
                i += 2 if body[i] == "\\" else 1
            i += 1
            continue
        if c == "#":
            j = body.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        m = _KEY_BLOCK.match(body, i)
        if m:
            inner, nxt = _block(body, m.end() - 1)
            out.append((m.group(1).strip('"'), inner, i))
            i = nxt
            continue
        if c == "{":
            _, i = _block(body, i)
            continue
        i += 1
    return out


def _fields(inner: str) -> dict:
    """Top-level `key = value;` of one profile block; string values are kept, others are None."""
    out: dict = {}
    i, n = 0, len(inner)
    while i < n:
        if inner.startswith("''", i):
            j = inner.find("''", i + 2)
            i = n if j < 0 else j + 2
            continue
        c = inner[i]
        if c == '"':
            i += 1
            while i < n and inner[i] != '"':
                i += 2 if inner[i] == "\\" else 1
            i += 1
            continue
        if c == "#":
            j = inner.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if c == "{":
            _, i = _block(inner, i)
            continue
        m = _KEY_VALUE.match(inner, i)
        if m:
            s = _STRING.match(inner, m.end())
            out.setdefault(m.group(1), s.group(1) if s else None)
            i = s.end() if s else m.end()
            continue
        i += 1
    return out


def current_name(nix_files: list[Path]) -> str | None:
    """The selected profile: a plain identifier, so a shell snippet's regex in a string does not win."""
    for f in _with(nix_files, r'profileName\s*=\s*"'):
        for m in re.finditer(r'profileName\s*=\s*"([^"]+)"', _text(str(f))):
            if re.fullmatch(r"[A-Za-z0-9_.-]+", m.group(1)):
                return m.group(1)
    return None


def _asset_names(roots: list[Path]) -> set[str]:
    names = set()
    for root in roots:
        if not root or not root.exists():
            continue
        for p in root.rglob("*"):
            if p.is_file() and ".git" not in p.parts:
                names.add(p.name)
    return names


def profiles(nix_files: list[Path], roots: list[Path]) -> list[dict]:
    """Profiles declared in any registry file (`profiles = { <name> = mk { ... }; }`)."""
    assets = _asset_names(roots)
    current = current_name(nix_files)
    out: list[dict] = []
    for f in _with(nix_files, r"profiles\s*=\s*\{"):
        text = _text(str(f))
        m = re.search(r"profiles\s*=\s*\{", text)
        if not m or not re.search(r"image\s*=", text):
            continue
        body, _ = _block(text, m.end() - 1)
        base = m.end() - 1 + 1
        for name, inner, off in _entries(body):
            fields = _fields(inner)
            image = fields.get("image")
            out.append({
                "name": name,
                "file": str(f),
                "line": text[:base + off].count("\n") + 1,
                "image": image,
                "image_exists": (Path(image).name in assets) if image else None,
                "title": fields.get("title") or (fields.get("name") if fields.get("name") != name else None),
                "artist": fields.get("artist"),
                "polarity": fields.get("polarity"),
                "accentColor": fields.get("accentColor"),
                "fields": sorted(fields),
                "current": name == current,
            })
    common = [k for k in {k for p in out for k in p["fields"]} if sum(k in p["fields"] for p in out) * 2 > len(out)]
    for p in out:
        p["missing_fields"] = sorted(k for k in common if k not in p["fields"])
    return out


# ---- palette -----------------------------------------------------------------

def _hex(value: str) -> str | None:
    m = re.fullmatch(r"#?([0-9a-fA-F]{6})", value.strip())
    return "#" + m.group(1).lower() if m else None


def palette(cfg: nix.Config, generation: Path | None = None) -> dict | None:
    """The colours the theming engine actually wrote: stylix's palette.json (in a built generation
    or in $HOME), else a colour-scheme attrset in the configuration. None when there is no such source."""
    rel = ".config/stylix/palette.json"
    for p in ([Path(generation) / "home-files" / rel] if generation else []) + [Path.home() / rel]:
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            out = {k: _hex(v) for k, v in data.items() if isinstance(v, str) and _hex(v)}
            if out:
                return out
    for root in cfg.config_repos:
        for f in facts_mod._nix_files(root):
            text = _text(str(f))
            m = re.search(r"(colorScheme\.palette|palette|base16Scheme)\s*=\s*\{", text)
            if not m:
                continue
            body, _ = _block(text, m.end() - 1)
            out = {k: _hex(v) for k, v in _fields(body).items() if isinstance(v, str) and _hex(v)}
            if out:
                return out
    return None


# ---- generated surfaces -------------------------------------------------------

def _colours(line: str) -> list[str]:
    out = []
    for m in COLOUR_RE.finditer(line):
        h, packed, r, g, b = m.groups()
        if h:
            v = h if len(h) != 3 else "".join(c * 2 for c in h)
            out.append("#" + v[:6].lower())
        elif packed:
            out.append("#" + packed[:6].lower())
        elif r:
            out.append("#%02x%02x%02x" % tuple(min(255, int(x)) for x in (r, g, b)))
    return out


def _fonts(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        for rx in FONT_RES:
            m = rx.search(line)
            if not m:
                continue
            name = m.group(1).split(";")[0].split("/*")[0].split(",")[0].split(":")[0].strip().strip('"\'=;').strip()
            name = re.sub(r"\s+\d+(\.\d+)?$", "", name)
            if name and not name.replace(".", "").isdigit() and name not in out:
                out.append(name)
    return out[:5]


def scan_surface(path: Path, palette: dict | None) -> dict | None:
    """Colours and fonts actually written into one generated config. None if missing or binary."""
    p = Path(path)
    if not p.is_file():
        return None
    try:
        raw = p.read_bytes()
    except OSError:
        return None
    if b"\0" in raw[:4096]:
        return None
    values = {v for v in (palette or {}).values()}
    total = in_palette = neutral = 0
    foreign: dict[str, list[int]] = {}
    for i, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
        for col in _colours(line):
            total += 1
            if col in values:
                in_palette += 1
            elif col in NEUTRAL:
                neutral += 1
            else:
                foreign.setdefault(col, []).append(i)
    return {
        "path": str(p),
        "total": total,
        "in_palette": in_palette,
        "neutral": neutral,
        "foreign_unique": len(foreign),
        "foreign": [{"colour": c, "lines": ls[:5]} for c, ls in list(foreign.items())[:5]],
        "fonts": _fonts(raw.decode("utf-8", "replace")),
    }


# ---- static status ------------------------------------------------------------

def static_status(surface: dict, nix_files: list[Path]) -> str:
    """What the configuration itself says about this surface: themed | hardcoded | unknown."""
    target = surface.get("stylix")
    if target:
        pat = r"stylix\.targets\.%s\.enable\s*=\s*true" % re.escape(target)
        if facts_mod._grep_active(_with(nix_files, pat), pat):
            return "themed"
    option = surface.get("option")
    if not option:
        return "unknown"
    own = _with(nix_files, r"(?<![A-Za-z0-9_])(%s)\b" % option)
    if not own:
        return "unknown"
    if facts_mod._grep_active(own, THEME_REF):
        return "themed"
    if facts_mod._grep_active(own, NIX_HEX):
        return "hardcoded"
    return "unknown"


# ---- report -------------------------------------------------------------------

def all_surfaces(docs_dir: Path | None) -> dict:
    """The built-in table plus any surface declared under `## Aesthetic surfaces` in MAINTENANCE.md."""
    out = dict(SURFACES)
    for label, rel in (docs.aesthetic_surfaces(docs_dir) if docs_dir else {}).items():
        key = re.sub(r"[^a-z0-9]+", "-", label.lower())
        if key in out:
            paths = out[key]["paths"] + ([rel] if rel not in out[key]["paths"] else [])
            out[key] = dict(out[key], paths=paths)
        else:
            out[key] = {"label": label, "option": None, "paths": [rel], "stylix": None, "from_docs": True}
    return out


def _enabled(surface: dict, nix_files: list[Path], options: set[str]) -> bool:
    option = surface.get("option")
    if option is None:
        return True  # declared by the user in MAINTENANCE.md
    if any(re.fullmatch(option, o) for o in options):
        return True
    for pat in (r"(?<![A-Za-z0-9_])(%s)\.enable\s*=\s*true" % option, r"(?<![A-Za-z0-9_])(%s)\s*=\s*\{" % option):
        if facts_mod._grep_active(_with(nix_files, pat), pat):
            return True
    return False


def _generated_paths(base: Path, rels: list[str]) -> list[Path]:
    out: list[Path] = []
    for rel in rels:
        out += sorted(base.glob(rel)) if "*" in rel else [base / rel]
    return out


def report(cfg: nix.Config, fx: dict | None = None, generation: Path | None = None) -> dict:
    """Everything: theming frameworks, profile registry, palette, and every enabled surface's drift.
    `generated` is the list of scans for the surface's generated files (None when nothing exists)."""
    roots = cfg.config_repos
    # only files the flake actually imports: dead files must not enable surfaces
    nix_files = facts_mod.reachable(cfg.flake_dir, ("flake.nix", "configuration.nix", "darwin-configuration.nix"))
    if cfg.hm_dir and cfg.hm_dir != cfg.flake_dir:
        nix_files = nix_files + facts_mod.reachable(cfg.hm_dir, ("home.nix", "flake.nix"))
    pal = palette(cfg, generation)
    profs = profiles(nix_files, roots)
    options = {e["option"] for scope in (fx or {}).get("enabled", {}).values() for e in scope}
    base = (Path(generation) / "home-files") if generation else Path.home()
    surfaces = []
    for key, surface in all_surfaces(cfg.docs_dir).items():
        if not _enabled(surface, nix_files, options):
            continue
        scans = [s for s in (scan_surface(p, pal) for p in _generated_paths(base, surface["paths"])) if s]
        verdict = "not_generated" if not scans else ("drift" if any(s["foreign_unique"] for s in scans) else "consistent")
        surfaces.append({
            "key": key,
            "label": surface["label"],
            "static": static_status(surface, nix_files),
            "generated": scans or None,
            "verdict": verdict,
        })
    rep = {
        "frameworks": frameworks(nix_files),
        "current": current_name(nix_files),
        "profiles": profs,
        "incomplete": [p["name"] for p in profs if p["missing_fields"]],
        "missing_images": [p["name"] for p in profs if p["image_exists"] is False],
        "palette_size": len(pal or {}),
        "generation": str(generation) if generation else None,
        "surfaces": surfaces,
    }
    rep["summary"] = summary_lines(rep)
    return rep


def summary_lines(report: dict) -> list[str]:
    surfaces = report.get("surfaces", [])
    drifting = [s for s in surfaces if s["verdict"] == "drift"]
    profs = report.get("profiles", [])
    lines = ["theming sources: %s; palette: %d colours%s" % (
        ", ".join(sorted(k for k, v in report.get("frameworks", {}).items() if v)) or "none found",
        report.get("palette_size", 0),
        "" if report.get("palette_size") else " (no source of truth found)")]
    if profs:
        lines.append("profiles: %d in the registry, current=%s, %d incomplete, %d with a missing image" % (
            len(profs), report.get("current"), len(report.get("incomplete", [])), len(report.get("missing_images", []))))
    lines.append("surfaces: %d consistent, %d drifting, %d enabled but not generated (of %d)" % (
        sum(1 for s in surfaces if s["verdict"] == "consistent"), len(drifting),
        sum(1 for s in surfaces if s["verdict"] == "not_generated"), len(surfaces)))
    if drifting:
        lines.append("drift: " + ", ".join("%s (%d foreign colour(s), static=%s)" % (
            s["label"], sum(g["foreign_unique"] for g in s["generated"]), s["static"]) for s in drifting)[:500])
    if report.get("incomplete"):
        lines.append("incomplete profiles: " + ", ".join("%s(missing %s)" % (p["name"], ",".join(p["missing_fields"][:3]))
                                                         for p in profs if p["missing_fields"])[:400])
    return lines


def fix_task(report: dict) -> str | None:
    """The task text for `run.fix_loop` when the user asks to fix what this found."""
    parts = []
    for s in report.get("surfaces", []):
        if s["verdict"] != "drift":
            continue
        for g in s["generated"]:
            examples = ", ".join("%s (line %s)" % (f["colour"], f["lines"][0]) for f in g["foreign"][:3])
            parts.append("- %s: %s has %d colour(s) outside the palette, e.g. %s" % (s["label"], g["path"], g["foreign_unique"], examples))
    for p in report.get("profiles", []):
        if p["missing_fields"]:
            parts.append("- profile %s (%s:%d) is missing %s" % (p["name"], p["file"], p["line"], ", ".join(p["missing_fields"])))
        if p["image_exists"] is False:
            parts.append("- profile %s (%s:%d) points at a missing image %s" % (p["name"], p["file"], p["line"], p["image"]))
    if not parts:
        return None
    return ("Make every surface derive its colours and fonts from the theming source of truth (%s), and complete the "
            "profile registry. Findings:\n%s\nFix this in the configuration trees so the generated files come out right; "
            "never edit generated files under ~/.config (they are store symlinks) and never change the palette to match a "
            "surface. Prove it by building home-manager." % (
                ", ".join(sorted(k for k, v in report.get("frameworks", {}).items() if v)) or "the configured colours",
                "\n".join(parts[:40])))
