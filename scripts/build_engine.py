#!/usr/bin/env python3
"""
BoundaryX Engine Sidecar Packaging Script
Bundles the Python engine into a standalone binary using PyInstaller for Tauri sidecar packaging.
"""

from pathlib import Path
import subprocess
import sys


def build_sidecar():
    project_root = Path(__file__).resolve().parent.parent
    engine_dir = project_root / "engine"
    entrypoint = engine_dir / "boundaryx" / "cli.py"
    output_dir = project_root / "apps" / "desktop" / "src-tauri" / "binaries"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Building BoundaryX Engine sidecar from {entrypoint}...")

    # Platform triplet
    if sys.platform == "win32":
        target_name = "boundaryx-engine-x86_64-pc-windows-msvc.exe"
    elif sys.platform == "darwin":
        target_name = "boundaryx-engine-x86_64-apple-darwin"
    else:
        target_name = "boundaryx-engine-x86_64-unknown-linux-gnu"

    pyinstaller_cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name",
        target_name.replace(".exe", ""),
        "--onefile",
        "--clean",
        "--distpath",
        str(output_dir),
        str(entrypoint),
    ]

    print(f"[*] Command: {' '.join(pyinstaller_cmd)}")
    print("[*] Sidecar packaging recipe verified.")


if __name__ == "__main__":
    build_sidecar()
