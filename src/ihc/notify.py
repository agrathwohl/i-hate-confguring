"""User notifications: desktop (notify-send / osascript) + always a log line."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

from .store import STATE_DIR, ensure_dirs, now_iso

URGENCIES = ("low", "normal", "critical")


def _desktop_env() -> dict:
    env = dict(os.environ)
    uid = os.getuid()
    env.setdefault("XDG_RUNTIME_DIR", "/run/user/%d" % uid)
    env.setdefault("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/%d/bus" % uid)
    return env


def notify(title: str, body: str = "", urgency: str = "normal") -> bool:
    """Send a desktop notification. Returns True when a desktop notifier accepted it."""
    if urgency not in URGENCIES:
        urgency = "normal"
    ensure_dirs()
    with open(STATE_DIR / "notifications.log", "a") as fh:
        fh.write("%s [%s] %s — %s\n" % (now_iso(), urgency, title, body.replace("\n", " / ")))
    print("ihc[%s]: %s — %s" % (urgency, title, body), file=sys.stderr)
    if os.environ.get("IHC_NO_DESKTOP"):
        return False
    if sys.platform == "darwin" and shutil.which("osascript"):
        script = 'display notification %s with title %s' % (_osa(body), _osa("ihc: " + title))
        return subprocess.run(["osascript", "-e", script], capture_output=True).returncode == 0
    if shutil.which("notify-send"):
        argv = ["notify-send", "-a", "ihc", "-u", urgency, "ihc: " + title, body]
        if urgency == "critical":
            argv[3:3] = ["-t", "0"]
        return subprocess.run(argv, env=_desktop_env(), capture_output=True).returncode == 0
    return False


def _osa(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
