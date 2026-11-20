#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux Tunnel Manager — bootstrap launcher.

This single file is what the one-line installer downloads. When executed it
makes sure the full project is present on the machine (cloning or updating it
under /opt), then hands control to the modular `ltm` package.

Install / run:
    curl -fsSL https://raw.githubusercontent.com/amircpuir/Linux-Tunnel-Manager/main/tunnel.py -o tunnel.py \
        && chmod +x tunnel.py && sudo python3 tunnel.py
"""

import os
import sys
import shutil
import subprocess

REPO_URL = "https://github.com/amircpuir/Linux-Tunnel-Manager.git"
INSTALL_DIR = "/opt/Linux-Tunnel-Manager"
RAW_BASE = "https://raw.githubusercontent.com/amircpuir/Linux-Tunnel-Manager/main"


def _is_root() -> bool:
    return os.geteuid() == 0


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _run(cmd: str) -> bool:
    return subprocess.run(cmd, shell=True).returncode == 0


def _ensure_git() -> bool:
    if _have("git"):
        return True
    print("[*] Installing git...")
    if _have("apt-get"):
        _run("DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
             "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git")
    elif _have("dnf"):
        _run("dnf install -y -q git")
    elif _have("yum"):
        _run("yum install -y -q git")
    return _have("git")


def _sync_repo() -> bool:
    """Clone the project on first run, or fast-forward it on later runs."""
    if not _ensure_git():
        print("[!] git is required but could not be installed.")
        return False

    if os.path.isdir(os.path.join(INSTALL_DIR, ".git")):
        print(f"[*] Updating {INSTALL_DIR} ...")
        _run(f"git -C '{INSTALL_DIR}' pull --ff-only --quiet")
    else:
        parent = os.path.dirname(INSTALL_DIR)
        os.makedirs(parent, exist_ok=True)
        if os.path.isdir(INSTALL_DIR):
            shutil.rmtree(INSTALL_DIR, ignore_errors=True)
        print(f"[*] Cloning project into {INSTALL_DIR} ...")
        if not _run(f"git clone --depth 1 --quiet '{REPO_URL}' '{INSTALL_DIR}'"):
            print("[!] Clone failed. Check your network connection and try again.")
            return False
    return True


def _launch(target_dir: str):
    """Replace this process with the package launcher so the menu is interactive."""
    os.chdir(target_dir)
    args = [sys.executable, "-m", "ltm"] + sys.argv[1:]
    os.execvp(sys.executable, args)


def main():
    if not _is_root():
        print("Error: Root privileges required. Run with sudo.")
        sys.exit(1)

    here = os.path.dirname(os.path.abspath(__file__))

    # Already inside a full checkout? Run it directly.
    if os.path.isdir(os.path.join(here, "ltm")):
        _launch(here)
        return

    # Otherwise bootstrap the project, then run it.
    if not _sync_repo():
        sys.exit(1)
    if not os.path.isdir(os.path.join(INSTALL_DIR, "ltm")):
        print("[!] Project layout unexpected after sync.")
        sys.exit(1)
    _launch(INSTALL_DIR)


if __name__ == "__main__":
    main()
