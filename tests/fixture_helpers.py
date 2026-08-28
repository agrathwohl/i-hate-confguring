"""Shared fixture setup for ihc tests. Not a test module (no test_ prefix, not collected)."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from ihc.nix import Config

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "example"
NIXOS_FIXTURE = FIXTURES / "nixos"
HM_FIXTURE = (FIXTURES / "hm").resolve()


def make_nixos_tmp() -> Path:
    """Copy the nixos fixture tree into a tempdir with @HM_DIR@ substituted with the
    absolute path of the (unmodified) hm fixture dir. Caller is responsible for cleanup."""
    tmp = Path(tempfile.mkdtemp(prefix="ihc-fixture-"))
    for item in NIXOS_FIXTURE.iterdir():
        dst = tmp / item.name
        if item.is_dir():
            shutil.copytree(item, dst)
        else:
            shutil.copy(item, dst)
    flake = tmp / "flake.nix"
    flake.write_text(flake.read_text().replace("@HM_DIR@", str(HM_FIXTURE)))
    return tmp


def make_config(tmp_nixos: Path) -> Config:
    return Config(
        platform="nixos",
        flake_dir=tmp_nixos,
        host_attr="example",
        hm_attr="alice",
        hm_dir=HM_FIXTURE,
        impure=True,
        impure_reasons=[],
        nix_path_extra=["nixos-config=%s" % (tmp_nixos / "configuration.nix")],
        hostname="example",
        user="alice",
        docs_dir=tmp_nixos,
    )
