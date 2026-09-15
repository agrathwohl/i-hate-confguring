"""Security: what in this configuration grants privilege, exposes a credential, or ships a package
nixpkgs itself marks as vulnerable?

Generic for any NixOS / nix-darwin / home-manager user. Two independent sources of truth: the user's own
files (grep, always available, always cited) and the *effective* option values (one batched `nix eval`,
which is the only thing that sees nixpkgs' defaults). Nothing here is host specific; host-specific accepted
risk arrives through `## Security exceptions` in MAINTENANCE.md. Nothing here is ever fixed unattended: the
one class `ihc security --fix` will hand to an agent is pinning an unhashed remote fetch, and every other
finding is a decision only the user can make.
"""

from __future__ import annotations

import hashlib
import csv
import io
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from . import docs, facts as facts_mod, nix
from .store import STATE_DIR, Run, pending_add, pending_list

# One batched `nix eval --apply` over the whole configuration. Pure builtins (no `lib`), so it is
# identical on nixos and nix-darwin; no import-from-derivation, no store writes.
# Two traps it deliberately avoids:
#   (1) `safe` (deepSeq) is never applied to `users.users` or to `nixpkgs.config` as a whole — deepSeq on
#       the users attrset forces every user's `packages` and overflows the call stack. Force leaves only.
#   (2) per-key `tryEval` is mandatory: JSON serialisation forces every key, so one throwing attribute
#       would kill the whole probe. `nixpkgs.config` cannot be serialised at all (packageOverrides is a
#       function), hence the `npkg` accessor.
PROBE_EXPR = """top:
let
  c = top.config;
  get = obj: path: def:
    if path == [ ] then obj
    else if builtins.isAttrs obj && builtins.hasAttr (builtins.head path) obj
    then get (builtins.getAttr (builtins.head path) obj) (builtins.tail path) def
    else def;
  safe = v: let r = builtins.tryEval (builtins.deepSeq v v); in if r.success then r.value else "<<error>>";
  p = path: def: safe (get c path def);
  sshd = p [ "services" "openssh" "enable" ] false;
  users = get c [ "users" "users" ] { };
  userList = if builtins.isAttrs users then builtins.attrNames users else [ ];
  groupsOf = n: let g = safe (get users.${n} [ "extraGroups" ] [ ]); in if builtins.isList g then g else [ ];
  inGroup = g: builtins.filter (n: builtins.elem g (groupsOf n)) userList;
  npkgs = let r = builtins.tryEval (get c [ "nixpkgs" "config" ] null); in if r.success then r.value else null;
  npkg = k: def: if builtins.isAttrs npkgs && builtins.hasAttr k npkgs then safe (builtins.getAttr k npkgs) else def;
  pwKeys = [ "password" "initialPassword" "hashedPassword" "initialHashedPassword" ];
  getty = p [ "services" "getty" "autologinUser" ] null;
  dm = p [ "services" "displayManager" "autoLogin" "enable" ] false;
in
{
  sshd_password_auth = if sshd == true then p [ "services" "openssh" "settings" "PasswordAuthentication" ] "<<absent>>" else false;
  sshd_permit_root_login = if sshd == true then p [ "services" "openssh" "settings" "PermitRootLogin" ] "<<absent>>" else "no";
  firewall_enable = p [ "networking" "firewall" "enable" ] "<<absent>>";
  sudo_wheel_needs_password =
    let a = p [ "security" "sudo" "wheelNeedsPassword" ] "<<absent>>";
        b = p [ "security" "sudo-rs" "wheelNeedsPassword" ] "<<absent>>";
    in if a == false || b == false then false
       else if a == "<<absent>>" && b == "<<absent>>" then "<<absent>>" else true;
  docker_rootless = p [ "virtualisation" "docker" "rootless" "enable" ] "<<absent>>";
  root_equivalent_group_users = builtins.concatMap
    (e: let g = builtins.head e; in
        if (p (builtins.tail e) false) == true then map (u: g + "=" + u) (inGroup g) else [ ])
    [ [ "docker" "virtualisation" "docker" "enable" ]
      [ "lxd" "virtualisation" "lxd" "enable" ]
      [ "incus-admin" "virtualisation" "incus" "enable" ]
      [ "libvirtd" "virtualisation" "libvirtd" "enable" ] ];
  inline_password_users = builtins.filter
    (n: builtins.any (k: (safe (get users.${n} [ k ] null)) != null) pwKeys) userList;
  autologin_enabled = getty != null || dm == true;
  autologin_user = if getty != null then getty else "<<display-manager>>";
  nix_trusted_users_beyond_root =
    let tu = p [ "nix" "settings" "trusted-users" ] [ ];
    in if builtins.isList tu then builtins.filter (u: u != "root") tu else [ ];
  nix_require_sigs = p [ "nix" "settings" "require-sigs" ] "<<absent>>";
  nix_accept_flake_config = p [ "nix" "settings" "accept-flake-config" ] "<<absent>>";
  insecure_permitted = npkg "permittedInsecurePackages" [ ];
  insecure_gating_disabled = (npkg "allowInsecure" false) == true
    || (builtins.isAttrs npkgs && builtins.hasAttr "allowInsecurePredicate" npkgs);
}
"""

# The generic catalogue. Every value here is a generic upstream option name or a generic regex:
# nothing about any particular host belongs in this table.
CHECKS: dict[str, dict] = {
    "sshd_password_auth": {
        "title": "sshd accepts password authentication",
        "severity": "high",
        "platforms": ("nixos",),
        "scope": "system",
        "probe": "sshd_password_auth",
        "unsafe": "true",
        "unsafe_re": r"services\.openssh\.(?:settings\.PasswordAuthentication|passwordAuthentication)\s*=\s*true",
        "anchor_re": r"services\.openssh\.enable\s*=\s*true",
        "auto": False,
        "remediation": "services.openssh.settings.PasswordAuthentication = false; (and KbdInteractiveAuthentication = false). "
                       "UNSAFE unless at least one account that can reach root already has "
                       "users.users.<n>.openssh.authorizedKeys.keys or keyFiles set — with no key configured this is a "
                       "permanent remote lockout on a box with no console; also unsafe behind a bastion that uses "
                       "keyboard-interactive or 2FA.",
    },
    "sshd_permit_root_login": {
        "title": "sshd permits direct root login",
        "severity": "high",
        "platforms": ("nixos",),
        "scope": "system",
        "probe": "sshd_permit_root_login",
        "unsafe": ("in", ["yes", "without-password"]),
        "unsafe_re": r"(?:services\.openssh\.settings\.PermitRootLogin|services\.openssh\.permitRootLogin)\s*=\s*\"(?:yes|without-password)\"",
        "anchor_re": r"services\.openssh\.enable\s*=\s*true",
        "auto": False,
        "remediation": "services.openssh.settings.PermitRootLogin = \"prohibit-password\"; UNSAFE when the only route in "
                       "is root-with-password (a fresh cloud image, a rescue workflow, a CI job that ssh's in as root) — "
                       "flipping it removes the only door.",
    },
    "firewall_disabled": {
        "title": "the NixOS firewall is turned off",
        "severity": "high",
        "platforms": ("nixos",),
        "scope": "system",
        "probe": "firewall_enable",
        "unsafe": "false",
        "unsafe_re": r"networking\.firewall\.enable\s*=\s*false",
        "anchor_re": None,
        "auto": False,
        "remediation": "networking.firewall.enable = true; plus explicit networking.firewall.allowedTCPPorts for what must "
                       "stay reachable. UNSAFE as an unattended change on any host: turning the firewall on drops every port "
                       "that was not enumerated, including the ssh session doing the switch. Enumerating those ports is "
                       "exactly the judgement ihc does not have.",
    },
    "sudo_passwordless_wheel": {
        "title": "the wheel group gets sudo without a password",
        "severity": "high",
        "platforms": ("nixos",),
        "scope": "system",
        "probe": "sudo_wheel_needs_password",
        "unsafe": "false",
        "unsafe_re": r"security\.sudo(?:-rs)?\.wheelNeedsPassword\s*=\s*false",
        "anchor_re": None,
        "auto": False,
        "remediation": "security.sudo.wheelNeedsPassword = true; UNSAFE when unattended automation on the box shells out to "
                       "sudo — ihc itself calls `sudo -n`, as do CI runners and backup scripts. It is also an explicit "
                       "convenience-versus-threat-model trade-off the owner made.",
    },
    "root_equivalent_group": {
        "title": "a user is in a group that is root-equivalent on this machine",
        "severity": "high",
        "platforms": ("nixos",),
        "scope": "system",
        "probe": "root_equivalent_group_users",
        "unsafe": "nonempty",
        "unsafe_re": None,
        "anchor_re": None,
        "auto": False,
        "remediation": "Drop the user from the group and use rootless docker "
                       "(virtualisation.docker.rootless = { enable = true; setSocketVariable = true; }), or keep it and "
                       "accept it. UNSAFE to change automatically: a container that bind-mounts the host root gives any "
                       "member uid 0 on the host, but removing the group breaks every container workflow, rootless has real "
                       "gaps (privileged ports, storage drivers, cgroup limits), and group changes only take effect at the "
                       "next login, so the breakage is delayed and confusing.",
    },
    "user_credential_in_store": {
        "title": "a user account password is set inline instead of from a file",
        "severity": "high",
        "platforms": ("nixos",),
        "scope": "system",
        "probe": "inline_password_users",
        "unsafe": "nonempty",
        "unsafe_re": None,
        "anchor_re": None,
        "auto": False,
        "remediation": "Set users.users.<n>.hashedPasswordFile to a file outside the store (mode 0600) and set the password "
                       "out of band. UNSAFE to change automatically and already forbidden: the agent policy check reverts "
                       "any diff touching users.users., and a wrong edit locks the account out at the next activation.",
    },
    "autologin_enabled": {
        "title": "the console or display manager logs a user in automatically",
        "severity": "medium",
        "platforms": ("nixos",),
        "scope": "system",
        "probe": "autologin_enabled",
        "unsafe": "true",
        "unsafe_re": r"(?:services\.getty\.autologinUser|autoLogin\.enable\s*=\s*true|autoLoginUser)",
        "anchor_re": None,
        "auto": False,
        "remediation": "Remove the autologin, or pair it with a locked session and full-disk encryption if the box is a "
                       "kiosk. UNSAFE to change automatically: on an HTPC, a kiosk, or a machine that must come back after a "
                       "power cut without a human, removing autologin means the machine stops doing its job.",
    },
    "nix_trusted_users_beyond_root": {
        "title": "nix trusted-users includes someone other than root",
        "severity": "high",
        "platforms": ("nixos", "darwin"),
        "scope": "system",
        "probe": "nix_trusted_users_beyond_root",
        "unsafe": "nonempty",
        "unsafe_re": None,
        "anchor_re": r"(?:nix\.settings\.\"?trusted-users|nix\.trustedUsers)",
        "auto": False,
        "remediation": "nix.settings.trusted-users = [ \"root\" ]; Nix's own documentation states that adding a user here is "
                       "essentially equivalent to giving them root. UNSAFE when the user relies on non-root `nix copy --to "
                       "ssh://`, remote builders, cachix push, devenv or lorri, or per-flake substituters — all of those stop "
                       "working. Removing a name here is a policy statement about who the machine trusts, not a bug fix.",
    },
    "nix_require_sigs_disabled": {
        "title": "Nix will substitute unsigned store paths",
        "severity": "high",
        "platforms": ("nixos", "darwin"),
        "scope": "system",
        "probe": "nix_require_sigs",
        "unsafe": "false",
        "unsafe_re": r"require-sigs\s*=\s*false",
        "anchor_re": None,
        "auto": False,
        "remediation": "nix.settings.require-sigs = true; and add the cache's key to trusted-public-keys. UNSAFE when the "
                       "user pushes unsigned paths from a build farm or does laptop-to-server `nix copy`: turning it on "
                       "breaks that pipeline and the failure mode (silent source rebuilds, or a hard refusal) is confusing.",
    },
    "nix_accept_flake_config": {
        "title": "flakes may inject Nix settings without prompting",
        "severity": "medium",
        "platforms": ("nixos", "darwin"),
        "scope": "system",
        "probe": "nix_accept_flake_config",
        "unsafe": "true",
        "unsafe_re": r"accept-flake-config\s*=\s*true",
        "anchor_re": None,
        "auto": False,
        "remediation": "nix.settings.accept-flake-config = false; UNSAFE for ihc specifically: with it false, a flake whose "
                       "nixConfig proposes a substituter prompts interactively, and in a headless nightly timer that is a "
                       "hang, not a question. Report it and let the human weigh it.",
    },
    "permitted_insecure_packages": {
        "title": "knowingly-vulnerable packages are explicitly permitted",
        "severity": "high",
        "platforms": ("nixos", "darwin"),
        "scope": "system",
        "probe": "insecure_permitted",
        "unsafe": "nonempty",
        "unsafe_re": r"permittedInsecurePackages",
        "anchor_re": None,
        "auto": False,
        "remediation": "Update or replace the package and delete the entry. UNSAFE to remove blindly: if something still "
                       "needs it, eval fails outright and the whole system stops building, converting a security finding "
                       "into an outage. Entries are version-pinned, so they also go stale silently after a nixpkgs bump — "
                       "each entry is cited at the line that permits it as permitted_insecure_entry.",
    },
    "permitted_insecure_entry": {
        "title": "a permittedInsecurePackages entry, cited at the line that permits it",
        "severity": "medium",
        "platforms": ("nixos", "darwin"),
        "scope": "system",
        "probe": None,  # derived from the probe's insecure_permitted list plus a grep for the citation
        "unsafe": "nonempty",
        "unsafe_re": None,
        "anchor_re": r"permittedInsecurePackages",
        "auto": False,
        "remediation": "Update or replace the package and delete this entry. Entries are exact name-version strings, so a "
                       "nixpkgs bump silently makes them dead: the package they named no longer exists and the entry only "
                       "keeps nixpkgs' insecure-package gate disarmed for that name if it ever comes back. NOT "
                       "auto-remediable: nothing here compares the entry against nixpkgs or the lock, so ihc cannot tell a "
                       "dead entry from a live one, and deleting a live one makes the whole tree stop evaluating. Delete it "
                       "yourself and let `ihc check` say whether anything still needed it.",
    },
    "insecure_gating_disabled": {
        "title": "the insecure-package gate is disabled for everything",
        "severity": "high",
        "platforms": ("nixos", "darwin"),
        "scope": "system",
        "probe": "insecure_gating_disabled",
        "unsafe": "true",
        "unsafe_re": r"(?:allowInsecurePredicate|allowInsecure\s*=\s*true)",
        "anchor_re": None,
        "auto": False,
        "remediation": "Delete allowInsecure or allowInsecurePredicate and list the specific name-version entries in "
                       "permittedInsecurePackages instead. UNSAFE to remove automatically for the same reason as above: "
                       "eval starts refusing whatever it was covering and nothing builds.",
    },
    "unpinned_remote_fetch": {
        "title": "the configuration downloads and evaluates code from a mutable URL with no hash",
        "severity": "high",
        "platforms": ("nixos", "darwin", "hm-only"),
        "scope": "system",
        "probe": None,
        "unsafe": "nonempty",
        "unsafe_re": None,
        "anchor_re": None,
        "auto": True,
        "remediation": "Replace the mutable URL with an archive URL containing the revision it resolves to today plus a "
                       "sha256 (from `nix-prefetch-url --unpack`), or convert it into a flake input so it lands in "
                       "flake.lock. Behaviour is unchanged at pin time. Fixed only when the user asks "
                       "(`ihc security --fix`), never by the nightly — a rolling fetch can be deliberate, and the agent is "
                       "told to leave those alone and report BLOCKED.",
    },
    "secret_literal_in_built_config": {
        "title": "a credential literal sits in a file that is part of the built configuration",
        "severity": "high",
        "platforms": ("nixos", "darwin", "hm-only"),
        "scope": "system",
        "probe": None,
        "unsafe": "nonempty",
        "unsafe_re": None,
        "anchor_re": None,
        "auto": False,
        "remediation": "Move the value to sops-nix, agenix or a systemd LoadCredential and reference it by path "
                       "(passwordFile, or a *_FILE variable), then ROTATE it — it is already readable by every uid on the "
                       "machine and is in git history. UNSAFE to fix automatically on every axis: the agent would have to "
                       "hold the plaintext, choose a key, and it cannot rotate the upstream credential; the agent policy "
                       "check already reverts any diff touching sops or a secret-shaped filename.",
    },
    "secret_literal_in_unreferenced_file": {
        "title": "a credential literal sits in a config file nothing imports",
        "severity": "medium",
        "platforms": ("nixos", "darwin", "hm-only"),
        "scope": "system",
        "probe": None,
        "unsafe": "nonempty",
        "unsafe_re": None,
        "anchor_re": None,
        "auto": False,
        "remediation": "Delete the file or the lines and rotate; if the file is git-tracked the value is in history and "
                       "rotation is mandatory. UNSAFE to delete automatically: an unreferenced .nix file is usually a "
                       "config mid-migration, and a secret-looking file may be a live runtime credential something outside "
                       "Nix reads.",
    },
    "hm_ssh_client_weakened": {
        "title": "the home-manager ssh client disables host-key checking or forwards the agent",
        "severity": "medium",
        "platforms": ("nixos", "darwin", "hm-only"),
        "scope": "hm",
        "probe": None,
        "unsafe": "nonempty",
        "unsafe_re": None,
        "anchor_re": None,
        "auto": False,
        "remediation": "Remove the weakening, or scope it to one Host block for an ephemeral-host workflow. UNSAFE to "
                       "change automatically: turning host-key checking off is often deliberate for CI runners and cloud "
                       "instances that get new host keys constantly, and removing it makes those connections start "
                       "prompting in a non-interactive context.",
    },
    "nixpkgs_lock_stale": {
        "title": "the nixpkgs this host pins and runs is old",
        "severity": "medium",  # becomes high past LOCK_HIGH_DAYS; the finding carries the real severity
        "platforms": ("nixos", "darwin", "hm-only"),
        "scope": "system",
        "probe": None,  # read from the runtime facts the miner already produced
        "unsafe": "true",
        "unsafe_re": None,
        "anchor_re": None,
        "auto": False,
        "remediation": "Bump the lock and activate the result: `ihc bump` is the remedy and it already runs nightly, so "
                       "this is NOT auto-remediable here — a lock that stays old means the nightly is failing, blocked or "
                       "not running, and that is what to look at (`ihc status`, `ihc pending list`). Every unpatched "
                       "upstream vulnerability fixed since that date is still present in what this host runs.",
    },
}

FETCH_RE = r"builtins\.fetch(?:Tarball|url|Git)\b"
HASH_RE = r"sha256|narHash|hash\s*="
HM_SSH_RE = r"(?:StrictHostKeyChecking\s+no|UserKnownHostsFile\s+/dev/null|forwardAgent\s*=\s*true|ForwardAgent\s+yes)"

# Lock age thresholds (days), measured against the older of the locked and the running nixpkgs date.
LOCK_STALE_DAYS = 45
LOCK_HIGH_DAYS = 180

SEVERITY_RANK = {"high": 0, "medium": 1}


# ---- eval probe ----------------------------------------------------------------

def config_attr(cfg: nix.Config) -> str | None:
    """The flake attribute of the *configuration itself* (not its toplevel derivation)."""
    if not cfg.host_attr:
        return None
    if cfg.platform == "nixos":
        return "%s#nixosConfigurations.%s" % (cfg.flake_dir, cfg.host_attr)
    if cfg.platform == "darwin":
        return "%s#darwinConfigurations.%s" % (cfg.flake_dir, cfg.host_attr)
    return None


def probe(cfg: nix.Config) -> tuple[dict | None, str]:
    """One `nix eval --apply PROBE_EXPR`. Returns (values, "") or (None, the real nix error)."""
    attr = config_attr(cfg)
    if not attr:
        return None, "no system configuration on this platform"
    argv = ["nix", "eval", "--json"] + cfg.nix_args() + [attr, "--apply", PROBE_EXPR]
    try:
        p = subprocess.run(argv, cwd=str(cfg.flake_dir), env=cfg.env(), capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, ("%s: %s" % (type(exc).__name__, exc))[-2000:]
    if p.returncode != 0:
        return None, (p.stderr.strip() or "nix eval exited %d with no stderr" % p.returncode)[-2000:]
    try:
        value = json.loads(p.stdout)
    except ValueError as exc:
        return None, ("nix eval exited 0 but its output did not parse: %s" % exc)[-2000:]
    if not isinstance(value, dict):
        return None, "nix eval returned %s, not an attribute set" % type(value).__name__
    return value, ""


def _fires(value, unsafe) -> bool | None:
    """True = the unsafe condition holds, False = it does not, None = unknown (never a finding, never clean)."""
    if isinstance(value, str) and value in ("<<absent>>", "<<error>>"):
        return None
    if unsafe == "true":
        return value is True
    if unsafe == "false":
        return value is False
    if unsafe == "nonempty":
        return bool(value) if isinstance(value, list) else None
    if isinstance(unsafe, tuple) and unsafe and unsafe[0] == "in":
        return value in unsafe[1] if isinstance(value, str) else None
    return None


def _finding(check_id: str, source: str, file: str | None, line: int | None, detail: str, severity: str | None = None) -> dict:
    c = CHECKS[check_id]
    return {
        "id": check_id,
        "title": c["title"],
        "severity": severity or c["severity"],
        "scope": c["scope"],
        "source": source,
        "file": file,
        "line": line,
        "detail": detail,
        "auto": c["auto"],
        "remediation": c["remediation"],
    }


def eval_findings(probe_json: dict, platform: str) -> tuple[list[dict], list[dict]]:
    """Pure function over the probe values. Returns (findings, unknowns)."""
    findings, unknown = [], []
    for check_id, c in CHECKS.items():
        if not c["probe"] or platform not in c["platforms"]:
            continue
        value = probe_json.get(c["probe"], "<<absent>>")
        fires = _fires(value, c["unsafe"])
        if fires is None:
            unknown.append({"id": check_id, "reason": "the evaluated value was %s" % (
                value if isinstance(value, str) and value.startswith("<<") else json.dumps(value, default=str)[:120])})
            continue
        if not fires:
            continue
        detail = "effective value: %s" % json.dumps(value, default=str)[:300]
        if check_id == "root_equivalent_group":
            detail += "; virtualisation.docker.rootless = %s" % json.dumps(probe_json.get("docker_rootless", "<<absent>>"), default=str)
        if check_id == "autologin_enabled":
            detail += "; user: %s" % json.dumps(probe_json.get("autologin_user", "<<absent>>"), default=str)
        findings.append(_finding(check_id, "eval", None, None, detail))
    return findings, unknown


def unanswered(platform: str, reason: str) -> list[dict]:
    """Every eval-backed check that applies to this platform, marked unknown with why."""
    return [{"id": i, "reason": reason} for i, c in CHECKS.items() if c["probe"] and platform in c["platforms"]]


# ---- grep-mined findings --------------------------------------------------------

def _scope_files(scope: str, files_sys: list[Path], files_hm: list[Path]) -> list[Path]:
    # a merged tree (hm_dir == flake_dir) has no separate hm file list; its hm config is in files_sys
    return (files_hm or files_sys) if scope == "hm" else files_sys


def config_findings(files_sys: list[Path], files_hm: list[Path]) -> list[dict]:
    """Checks the user WROTE into their own files. These fire without any evaluation."""
    out = []
    for check_id, c in CHECKS.items():
        if not c["unsafe_re"]:
            continue
        for h in facts_mod._grep_active(_scope_files(c["scope"], files_sys, files_hm), c["unsafe_re"]):
            out.append(_finding(check_id, "config", h["file"], h["line"], h["text"]))
    return out


def fetch_findings(files: list[Path]) -> list[dict]:
    """`builtins.fetchTarball/fetchurl/fetchGit` with no hash within three lines either side."""
    out = []
    hash_rx = re.compile(HASH_RE)
    texts: dict[str, list[str]] = {}
    for h in facts_mod._grep_active(files, FETCH_RE):
        lines = texts.get(h["file"])
        if lines is None:
            try:
                lines = Path(h["file"]).read_text(errors="replace").splitlines()
            except OSError:
                continue
            texts[h["file"]] = lines
        window = lines[max(0, h["line"] - 4):h["line"] + 3]
        if any(hash_rx.search(line) for line in window):
            continue
        out.append(_finding("unpinned_remote_fetch", "config", h["file"], h["line"], h["text"]))
    return out


def secret_findings(fx: dict | None, cfg: nix.Config, reachable: set[str]) -> list[dict]:
    """facts.secrets_scan's findings, split by whether the file is part of the built configuration.
    The value is never read here: facts already redacted it."""
    raw = (fx or {}).get("secrets")
    if raw is None:
        raw = facts_mod.secrets_scan(cfg.config_repos)
    out = []
    for s in raw:
        line = s.get("line") or None
        built = bool(line) and (s["file"] in reachable or str(Path(s["file"]).resolve()) in reachable)
        check_id = "secret_literal_in_built_config" if built else "secret_literal_in_unreferenced_file"
        out.append(_finding(check_id, "config", s["file"], line, "%s (value redacted by the miner)" % s.get("kind", "secret")))
    return out


def hm_ssh_findings(files_hm: list[Path]) -> list[dict]:
    return [_finding("hm_ssh_client_weakened", "config", h["file"], h["line"], h["text"])
            for h in facts_mod._grep_active(files_hm, HM_SSH_RE)]


def insecure_entry_findings(entries: list, files: list[Path]) -> list[dict]:
    """One finding per `permittedInsecurePackages` entry we can point at in the user's own files, so the
    high-severity row has a `path:line` per entry rather than one for the whole list. Whether an entry is
    still needed is NOT knowable from here — nothing compares it against nixpkgs or the lock."""
    out = []
    for entry in entries or []:
        if not isinstance(entry, str) or not entry.strip():
            continue
        hits = facts_mod._grep_active(files, r"\"%s\"" % re.escape(entry))
        if not hits:
            continue  # no citation to hand the agent; the permitted_insecure_packages finding still covers it
        h = hits[0]
        out.append(_finding("permitted_insecure_entry", "eval+config", h["file"], h["line"],
                            "%s is permitted here" % json.dumps(entry)))
    return out


def anchor_findings(findings: list[dict], probe_json: dict, files_sys: list[Path], files_hm: list[Path]) -> list[dict]:
    """Best-effort `path:line` for an eval-only finding: the line the user wrote that turned it on.
    A finding is NEVER suppressed for lack of one — the citation is an anchor, the eval is the truth."""
    for f in findings:
        if f["file"] or f["source"] != "eval":
            continue
        c = CHECKS[f["id"]]
        if f["id"] == "root_equivalent_group":
            groups = sorted({str(e).split("=")[0] for e in (probe_json.get("root_equivalent_group_users") or [])})
            pats = [r"extraGroups[^;]*\"%s\"|^\s*\"%s\"\s*,?\s*$" % (re.escape(g), re.escape(g)) for g in groups]
        else:
            pats = [c["anchor_re"]] if c["anchor_re"] else []
        for pat in pats:
            hits = facts_mod._grep_active(_scope_files(c["scope"], files_sys, files_hm), pat, re.M)
            if hits:
                f["file"], f["line"] = hits[0]["file"], hits[0]["line"]
                break
    return findings


def lock_findings(cfg: nix.Config, fx: dict | None) -> tuple[list[dict], list[dict]]:
    """Lock age as a security row, from the runtime dates the miner already produced."""
    if not fx or "runtime" not in fx:
        return [], [{"id": "nixpkgs_lock_stale", "reason": "no runtime facts in this view (nothing measured the running system)"}]
    rt = fx["runtime"] or {}
    lock_s, run_s = rt.get("lock_nixpkgs_date"), rt.get("running_nixpkgs_date")
    dates = [d for d in (lock_s, run_s) if d]
    if not dates:
        return [], [{"id": "nixpkgs_lock_stale", "reason": "neither the locked nor the running nixpkgs date is known"}]
    try:
        oldest = min(datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc) for d in dates)
    except ValueError as exc:
        return [], [{"id": "nixpkgs_lock_stale", "reason": "unparseable nixpkgs date: %s" % exc}]
    age = (datetime.now(timezone.utc) - oldest).days
    if age < LOCK_STALE_DAYS:
        return [], []
    lock_file = cfg.flake_dir / "flake.lock"
    detail = ("locked nixpkgs %s, running nixpkgs %s, drift %s day(s); the older of the two is %d day(s) old"
              % (lock_s, run_s, rt.get("drift_days"), age))
    return [_finding("nixpkgs_lock_stale", "runtime", str(lock_file) if lock_file.exists() else None, None,
                     detail, "high" if age > LOCK_HIGH_DAYS else "medium")], []


# ---- report ---------------------------------------------------------------------

def _merge(grep_findings: list[dict], ev: list[dict]) -> list[dict]:
    """An eval finding whose id already came from grep keeps the grep citation and gains the eval detail."""
    by_id: dict[str, dict] = {}
    for f in grep_findings:
        by_id.setdefault(f["id"], f)
    out = list(grep_findings)
    for f in ev:
        seen = by_id.get(f["id"])
        if seen is None:
            out.append(f)
            continue
        seen["source"] = "config+eval"
        seen["detail"] = "%s; %s" % (seen["detail"], f["detail"])
        seen["severity"] = f["severity"]
    return out


def report(cfg: nix.Config, fx: dict | None = None, do_probe: bool = True) -> dict:
    """Everything this module knows, with the evidence source of each finding named."""
    files_sys = facts_mod.reachable(cfg.flake_dir, ("flake.nix", "configuration.nix", "darwin-configuration.nix"))
    files_hm = facts_mod.reachable(cfg.hm_dir, ("home.nix", "flake.nix")) if (cfg.hm_dir and cfg.hm_dir != cfg.flake_dir) else []
    reachable = {str(f) for f in files_sys + files_hm}

    findings = config_findings(files_sys, files_hm)
    findings += fetch_findings(files_sys + files_hm)
    findings += secret_findings(fx, cfg, reachable)
    findings += hm_ssh_findings(files_hm or files_sys)
    lock_f, unknown = lock_findings(cfg, fx)
    findings += lock_f

    attr = config_attr(cfg)
    ev: dict = {"ok": False, "attr": attr, "error": None, "reason": None}
    if not do_probe:
        ev["reason"] = "not requested"
        unknown += unanswered(cfg.platform, "no evaluation probe was run — `ihc security` runs it")
    elif cfg.platform not in ("nixos", "darwin") or not attr:
        ev["reason"] = "no system configuration on this platform"
        unknown += unanswered(cfg.platform, ev["reason"])
    else:
        values, err = probe(cfg)
        if values is None:
            ev["error"] = err
            unknown += unanswered(cfg.platform, "the evaluation failed: %s" % err.splitlines()[0][:200] if err else "the evaluation failed")
        else:
            ev["ok"] = True
            ef, ev_unknown = eval_findings(values, cfg.platform)
            findings = anchor_findings(_merge(findings, ef), values, files_sys, files_hm)
            findings += insecure_entry_findings(values.get("insecure_permitted") or [], files_sys + files_hm)
            unknown += ev_unknown

    exceptions = docs.security_exceptions(cfg.docs_dir)
    accepted = [{"id": f["id"], "reason": exceptions[f["id"]]} for f in findings if f["id"] in exceptions]
    findings = [f for f in findings if f["id"] not in exceptions]
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["id"], f["file"] or ""))

    rep = {
        "platform": cfg.platform,
        "eval": ev,
        "findings": findings,
        "unknown": unknown,
        "accepted": accepted,
        "counts": {
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "unknown": len(unknown),
            "accepted": len(accepted),
        },
        "cve": None,
    }
    rep["summary"] = summary_lines(rep)
    return rep


def summary_lines(report: dict) -> list[str]:
    lines = []
    fs = report.get("findings", [])
    c = report.get("counts", {})
    head = "security: %d finding(s) — %d high, %d medium" % (len(fs), c.get("high", 0), c.get("medium", 0))
    if fs:
        head += "; e.g. %s (%s:%s)" % (fs[0]["title"], fs[0]["file"], fs[0]["line"])
    if c.get("accepted"):
        head += "; %d accepted in MAINTENANCE.md" % c["accepted"]
    lines.append(head[:400])
    if c.get("unknown"):
        reason = (report.get("unknown") or [{}])[0].get("reason", "unknown")
        lines.append(("security checks not answered: %d (%s)" % (c["unknown"], reason))[:400])
    cve = report.get("cve")
    if cve:
        top = (cve.get("packages") or [{}])[0]
        if not cve.get("available"):
            lines.append(("CVE scan FAILED, so nothing here is a clean bill of health: %s" % (cve.get("reason") or "no reason recorded"))[:400])
        else:
            lines.append(("CVE scan (%s): %d package(s) with active advisories, %d advisory/ies, top %s %.1f; matched by name and version, "
                          "so treat it as a triage order, not a verdict"
                          % (cve.get("scanner") or "unknown scanner", cve.get("counts", {}).get("packages", 0),
                             cve.get("counts", {}).get("cves", 0), top.get("pname", "-"), top.get("max_cvss") or 0.0))[:400])
    return lines


def fix_task(report: dict) -> str | None:
    """The task text for `run.fix_loop`. ONLY findings marked auto, and never a protected file:
    everything else in this report is a decision the agent is not allowed to make."""
    from . import agent
    auto = [f for f in report.get("findings", []) if f.get("auto") is True]
    auto = [f for f in auto if not (f.get("file") and any(re.search(p, f["file"]) for p in agent.FORBIDDEN_FILES))]
    if not auto:
        return None
    parts = ["- %s:%s: %s" % (f["file"], f["line"], (f["detail"] or f["title"])[:120]) for f in auto[:40]]
    body = [
        "Pin every remote fetch in the configuration to the content it resolves to today, so a rebuild cannot "
        "silently execute different code.",
        "Findings:", "\n".join(parts),
        "For each unpinned fetch: resolve the current revision, replace the mutable URL with an archive URL "
        "containing that revision and add the `sha256` from `nix-prefetch-url --unpack <url>`, or convert it "
        "into a proper flake input so it is recorded in flake.lock. Do not change WHICH code is fetched — pin "
        "what is already being fetched now. If a fetch is a deliberately rolling channel the user wants to "
        "float (a NUR-style overlay, a channel tarball), leave it exactly as it is and say so.",
        "Change nothing else: no secrets wiring, no users, no sudo, no ssh, no firewall. Prove it by evaluating "
        "both attributes.",
    ]
    return "\n".join(body)


def escalate(report: dict) -> str | None:
    """The only place this module raises a pending decision. One pending per distinct set of high
    findings, so an unchanged set never re-raises and the nightly cannot become a notification loop."""
    highs = [f for f in report.get("findings", []) if f["severity"] == "high"]
    if not highs:
        return None
    digest = hashlib.sha256(json.dumps(sorted((f["id"], f["file"] or "") for f in highs)).encode()).hexdigest()[:12]
    if any(p["kind"] == "security" and digest in p["title"] for p in pending_list()):
        return None
    body = "\n\n".join("%s\n  %s:%s\n  %s\n  remediation: %s" % (f["title"], f["file"], f["line"], f["detail"], f["remediation"])
                       for f in highs)
    pending_add("security", "Security: %d high-severity finding(s) [%s]" % (len(highs), digest), body[:8000],
                "Decide each one. Record what you accept under `## Security exceptions` in MAINTENANCE.md "
                "(`- <check id>: <why it is fine here>`), then `ihc pending resolve <id>`.")
    return digest


# ---- CVE (a separate cost class; never called from report()) ----------------------

CVE_CACHE = STATE_DIR / "vulnix-cache"
CVE_TIMEOUT = int(os.environ.get("IHC_CVE_TIMEOUT", "2400"))
CVE_DAYS = int(os.environ.get("IHC_CVE_DAYS", "7"))
NVD_WINDOW_YEARS = 6
CVE_LIMITS = [
    "Matching is by package name and version, not by vendor, so a package that merely shares a name with another product inherits its advisories: same-name matches are expected false positives.",
    "A nixpkgs backport that patches a CVE without changing the version is still reported, because the version is all the scanner compares.",
    "A CVE with no published score is reported as unscored, never as 0.0.",
    "This scans what was built, not necessarily what is running; the scanned paths are listed above.",
    "Service reachability and exploitability are not assessed. Ranking by CVSS base score is a triage order, not a severity assessment.",
]
VULNIX_LIMIT = "NVD feed coverage is a rolling 6-year window (currently %s onward): older unpatched vulnerabilities are invisible."


def nvd_from() -> str:
    return str(datetime.now(timezone.utc).year - NVD_WINDOW_YEARS)


def cve_limits(scanner: str | None = None) -> list[str]:
    """The caveats that belong to the scanner that actually answered."""
    return list(CVE_LIMITS) + ([VULNIX_LIMIT % nvd_from()] if scanner == "vulnix" else [])


def cve_due(days: int | None = None) -> bool:
    days = CVE_DAYS if days is None else days
    if days <= 0:
        return False
    marker = STATE_DIR / "cve-last"
    try:
        last = datetime.strptime(marker.read_text().strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (OSError, ValueError):
        return True
    return (datetime.now(timezone.utc) - last).days >= days


def scan_targets(cfg: nix.Config) -> list[Path]:
    """The live artefacts, for the standalone verb. An empty list is a valid answer."""
    out = []
    if cfg.platform in ("nixos", "darwin"):
        cur = nix.current_system()
        if cur:
            out.append(cur)
    if cfg.hm_profile.exists():
        out.append(cfg.hm_profile.resolve())
    return out


def scanner_argv(cfg: nix.Config, out_csv: Path) -> list[list[str]]:
    """Acquisition chain, first that works: vulnxscan (live data) before vulnix (feeds retired)."""
    return vulnxscan_argv(cfg, out_csv) + vulnix_argv(cfg)


def vulnix_argv(cfg: nix.Config) -> list[list[str]]:
    tail = ["-c", str(CVE_CACHE), "--json", "--closure"]
    return [
        ["vulnix"] + tail,
        ["nix", "shell", "--inputs-from", str(cfg.flake_dir)] + cfg.nix_args() + ["nixpkgs#vulnix", "-c", "vulnix"] + tail,
        ["nix", "shell", "nixpkgs#vulnix", "-c", "vulnix"] + tail,
    ]


VULNXSCAN_COLUMNS = ("vuln_id", "package", "version_local", "severity")


def vulnxscan_argv(cfg: nix.Config, out_csv: Path) -> list[list[str]]:
    """vulnxscan (sbomnix) queries live OSV/grype data. Preferred over vulnix, whose NVD JSON feeds
    NIST retired: those URLs now answer 401/404, so vulnix cannot build a database at all."""
    tail = ["vulnxscan", "-o", str(out_csv)]
    return [
        tail,
        ["nix", "shell", "--inputs-from", str(cfg.flake_dir)] + cfg.nix_args() + ["nixpkgs#sbomnix", "-c"] + tail,
        ["nix", "shell", "nixpkgs#sbomnix", "-c"] + tail,
    ]


def parse_vulnxscan(csv_text: str) -> tuple[list[dict] | None, str]:
    """Pure. vulnxscan writes one row per (CVE, package); group them into the same per-package shape
    parse_vulnix returns, so everything downstream is identical."""
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    if not rows:
        return None, "vulnxscan produced no rows"
    if not set(VULNXSCAN_COLUMNS) <= set(rows[0].keys()):
        return None, "vulnxscan columns changed: %s" % ", ".join(sorted(rows[0].keys()))[:200]
    by_pkg: dict[tuple, dict] = {}
    for r in rows:
        key = (r.get("package"), r.get("version_local"))
        rec = by_pkg.setdefault(key, {"pname": key[0], "name": "%s-%s" % key if key[1] else key[0],
                                      "derivation": None, "max_cvss": None, "unscored": 0, "cves": []})
        rec["cves"].append(r.get("vuln_id"))
        try:
            score = float(r["severity"])
        except (KeyError, TypeError, ValueError):
            rec["unscored"] += 1                      # no score is UNSCORED, never 0.0
            continue
        rec["max_cvss"] = score if rec["max_cvss"] is None else max(rec["max_cvss"], score)
    out = list(by_pkg.values())
    for rec in out:
        rec["cves"] = rec["cves"][:20]
    out.sort(key=lambda r: (r["max_cvss"] is None, -(r["max_cvss"] or 0), -len(r["cves"])))
    return out, ""


def parse_vulnix(stdout: str, stderr: str, rc: int) -> tuple[list[dict] | None, str]:
    """Pure. A parseable JSON array is a successful scan whatever the exit code; anything else failed."""
    try:
        data = json.loads(stdout)
    except ValueError:
        return None, (stderr.strip() or "vulnix produced no parseable JSON (exit %d)" % rc)[-2000:]
    if not isinstance(data, list):
        return None, ("vulnix produced %s, not a list (exit %d)" % (type(data).__name__, rc))[-2000:]
    out = []
    for rec in data:
        if not isinstance(rec, dict):
            continue
        affected = list(rec.get("affected_by") or [])
        scores = {k: v for k, v in (rec.get("cvssv3_basescore") or {}).items() if k in affected}
        out.append({
            "pname": rec.get("pname"),
            "name": rec.get("name"),
            "derivation": rec.get("derivation"),
            "max_cvss": max(scores.values()) if scores else None,   # a CVE with no score is UNSCORED, never 0.0
            "unscored": len(affected) - len(scores),
            "cves": affected[:20],
        })
    out.sort(key=lambda r: (r["max_cvss"] is None, -(r["max_cvss"] or 0), -len(r["cves"])))
    return out, ""


def deriver_coverage(targets: list[Path]) -> tuple[int, int] | None:
    """How many closure paths still have a deriver. vulnix silently skips the ones that do not, so a
    low ratio means the scan was incomplete."""
    if not targets:
        return None
    try:
        req = subprocess.run(["nix-store", "--query", "--requisites"] + [str(t) for t in targets],
                             capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.SubprocessError):
        return None
    paths = [line for line in req.stdout.splitlines() if line.strip()]
    if req.returncode != 0 or not paths:
        return None
    have = 0
    for i in range(0, len(paths), 500):
        try:
            q = subprocess.run(["nix-store", "--query", "--deriver"] + paths[i:i + 500],
                               capture_output=True, text=True, timeout=300)
        except (OSError, subprocess.SubprocessError):
            return None
        have += sum(1 for out in q.stdout.splitlines() if out.strip() and "unknown-deriver" not in out)
    return have, len(paths)


def cve_scan(cfg: nix.Config, run: Run, targets: list[Path]) -> dict:
    """Runs vulnix over the given store paths. Records the attempt, never a synthesised result."""
    at = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out: dict = {"available": False, "reason": None, "tool": None, "scanned": [str(t) for t in targets],
                 "packages": [], "counts": {"packages": 0, "cves": 0}, "deriver_coverage": None,
                 "limits": cve_limits(), "at": at, "scanner": None}
    if not targets:
        out["reason"] = "nothing to scan: no built system or home-manager path was given"
        return out
    CVE_CACHE.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    (STATE_DIR / "cve-last").write_text(at + "\n")  # on ATTEMPT: a broken network must not become a nightly retry
    reason = "no scanner invocation worked"
    for argv in scanner_argv(cfg, run.dir / "vulnxscan.csv"):
        tool = "vulnxscan" if "vulnxscan" in argv else "vulnix"
        if tool == "vulnxscan":
            # vulnxscan takes ONE target and writes CSV to the -o path; run it per target and merge.
            packages, err = [], ""
            for t in targets:
                csv_path = run.dir / ("vulnxscan-%s.csv" % t.name[:20])
                step = run.step("cve-vulnxscan", [a if a != str(run.dir / "vulnxscan.csv") else str(csv_path) for a in argv] + [str(t)],
                                cwd=cfg.flake_dir, timeout=CVE_TIMEOUT)
                if not csv_path.exists():
                    packages, err = None, (step.tail(20) or "vulnxscan wrote no CSV (exit %d)" % step.exit)[-2000:]
                    break
                part, err = parse_vulnxscan(csv_path.read_text())
                if part is None:
                    packages = None
                    break
                packages += part
        else:
            step = run.step("cve-vulnix", argv + [str(t) for t in targets], cwd=cfg.flake_dir, timeout=CVE_TIMEOUT)
            packages, err = parse_vulnix(step.out, step.err, step.exit)
        if packages is None:
            reason = err
            continue
        packages.sort(key=lambda r: (r["max_cvss"] is None, -(r["max_cvss"] or 0), -len(r["cves"])))
        cov = deriver_coverage(targets)
        out.update({
            "available": True, "reason": None, "tool": argv, "scanner": tool, "limits": cve_limits(tool),
            "packages": packages[:40],
            "counts": {"packages": len(packages), "cves": sum(len(p["cves"]) for p in packages)},
            "deriver_coverage": round(cov[0] / cov[1], 3) if cov and cov[1] else None,
        })
        return out
    out["reason"] = reason
    return out
