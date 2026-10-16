#!/usr/bin/env python3
"""
BoundaryX Engine Sidecar Packaging Script
Bundles the Python engine into a standalone binary using PyInstaller for Tauri sidecar packaging.
"""

import argparse
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import sys


def get_default_target_name() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("arm64", "aarch64"):
        arch = "aarch64"
    else:
        arch = machine

    if sys.platform == "win32":
        return f"boundaryx-engine-{arch}-pc-windows-msvc.exe"
    elif sys.platform == "darwin":
        return f"boundaryx-engine-{arch}-apple-darwin"
    else:
        return f"boundaryx-engine-{arch}-unknown-linux-gnu"


def calculate_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def build_sidecar(target_name: str | None = None, skip_verify: bool = False) -> Path:
    project_root = Path(__file__).resolve().parent.parent
    engine_dir = project_root / "engine"
    entrypoint = engine_dir / "boundaryx" / "cli.py"
    migrations_dir = engine_dir / "migrations"
    output_dir = project_root / "apps" / "desktop" / "src-tauri" / "binaries"
    output_dir.mkdir(parents=True, exist_ok=True)

    if not target_name:
        target_name = get_default_target_name()

    binary_name_clean = target_name[:-4] if target_name.endswith(".exe") else target_name
    expected_output = output_dir / target_name

    print(f"[*] Packaging BoundaryX Engine sidecar for target: {target_name}")
    print(f"[*] Source entrypoint: {entrypoint}")
    print(f"[*] Destination: {expected_output}")

    # Build work directories inside project build folder to avoid clutter
    build_dir = project_root / "build" / "pyinstaller"
    work_dir = build_dir / "work"
    spec_dir = build_dir / "spec"
    work_dir.mkdir(parents=True, exist_ok=True)
    spec_dir.mkdir(parents=True, exist_ok=True)

    # Prepare data separators
    sep = os.pathsep
    migrations_data = f"{migrations_dir}{sep}migrations"
    config_dir = project_root / "config"
    config_data = f"{config_dir}{sep}config"

    pyinstaller_cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name",
        binary_name_clean,
        "--onefile",
        "--clean",
        "--distpath",
        str(output_dir),
        "--workpath",
        str(work_dir),
        "--specpath",
        str(spec_dir),
        "--paths",
        str(engine_dir),
        "--add-data",
        migrations_data,
        "--add-data",
        config_data,
        "--collect-all",
        "boundaryx",
        "--collect-all",
        "pydantic",
        "--collect-all",
        "pydantic_core",
        "--collect-all",
        "google.genai",
        "--collect-all",
        "cryptography",
        "--collect-all",
        "idna",
        "--collect-all",
        "yaml",
        "--collect-all",
        "httpx",
        "--noconfirm",
        str(entrypoint),
    ]

    print(f"[*] Executing PyInstaller command:\n    {' '.join(pyinstaller_cmd)}")
    result = subprocess.run(pyinstaller_cmd, check=True)
    if result.returncode != 0:
        raise RuntimeError(f"PyInstaller failed with return code {result.returncode}")

    if not expected_output.exists():
        # Check if output exists with or without .exe
        alt_win = output_dir / f"{binary_name_clean}.exe"
        alt_posix = output_dir / binary_name_clean
        if alt_win.exists():
            expected_output = alt_win
        elif alt_posix.exists():
            expected_output = alt_posix
        else:
            raise FileNotFoundError(f"Expected binary was not found at {expected_output}")

    # Mark executable on POSIX systems
    if sys.platform != "win32":
        current_perms = expected_output.stat().st_mode
        expected_output.chmod(current_perms | 0o755)

    size_mb = expected_output.stat().st_size / (1024 * 1024)
    sha256 = calculate_sha256(expected_output)
    print(f"[+] Successfully built sidecar binary: {expected_output}")
    print(f"    Size: {size_mb:.2f} MB")
    print(f"    SHA-256: {sha256}")

    if not skip_verify:
        print("[*] Verifying sidecar self-check (--ping)...")
        check_proc = subprocess.run(
            [str(expected_output), "--ping"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if check_proc.returncode != 0 or "BoundaryX Engine OK" not in check_proc.stdout:
            print(f"[-] Verification failed! stdout: {check_proc.stdout}, stderr: {check_proc.stderr}")
            raise RuntimeError("Engine self-test failed!")
        print("[+] Engine self-check passed: BoundaryX Engine OK")

    return expected_output


def main():
    parser = argparse.ArgumentParser(description="Build BoundaryX Python Engine into Tauri sidecar binary")
    parser.add_argument("--target", type=str, default=None, help="Explicit target triple name")
    parser.add_argument("--skip-verify", action="store_true", help="Skip running --ping verification")
    args = parser.parse_args()

    build_sidecar(target_name=args.target, skip_verify=args.skip_verify)


if __name__ == "__main__":
    main()
