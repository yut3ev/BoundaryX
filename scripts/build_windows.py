#!/usr/bin/env python3
"""Build script to package BoundaryX as a standalone Windows executable using PyInstaller.

Performs prerequisite verification, cleans build caches, executes PyInstaller with
the project specification file, packages portable zip distributions, and computes
SHA-256 integrity checksums.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SPEC_FILE = PROJECT_ROOT / "packaging" / "boundaryx.spec"
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"


def calculate_sha256(file_path: Path) -> str:
    """Calculate the SHA-256 checksum of a file."""
    hasher = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def check_prerequisites() -> None:
    """Verify build tools and dependencies are installed."""
    print("--> Checking build prerequisites...")

    if sys.version_info < (3, 12):  # noqa: UP036
        print(f"Error: Python 3.12 or newer is required. Found: {sys.version}")
        sys.exit(1)

    try:
        import PyInstaller

        print(f"  * PyInstaller: {PyInstaller.__version__}")
    except ImportError:
        print("Error: PyInstaller is not installed. Run: pip install pyinstaller")
        sys.exit(1)

    try:
        import PySide6

        print(f"  * PySide6: {PySide6.__version__}")
    except ImportError:
        print("Error: PySide6 is not installed. Run: pip install PySide6")
        sys.exit(1)

    try:
        import sqlalchemy

        print(f"  * SQLAlchemy: {sqlalchemy.__version__}")
    except ImportError:
        print("Error: SQLAlchemy is not installed.")
        sys.exit(1)

    print("Prerequisites verified successfully.\n")


def clean_build_artifacts() -> None:
    """Remove previous build and distribution directories."""
    print("--> Cleaning build and dist artifacts...")
    for directory in [BUILD_DIR, DIST_DIR]:
        if directory.exists():
            print(f"  Removing {directory}")
            shutil.rmtree(directory, ignore_errors=True)
    print("Clean completed.\n")


def build_executable(clean: bool = True, debug: bool = False) -> Path:
    """Invoke PyInstaller to build the Windows distribution."""
    print(f"--> Building BoundaryX using spec: {SPEC_FILE}")

    if not SPEC_FILE.exists():
        print(f"Error: Specification file not found at {SPEC_FILE}")
        sys.exit(1)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
    ]

    if clean:
        cmd.append("--clean")

    if debug:
        cmd.extend(["--log-level", "DEBUG"])
    else:
        cmd.extend(["--log-level", "INFO"])

    cmd.append(str(SPEC_FILE))

    print(f"Executing: {' '.join(cmd)}")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT / "src")

    result = subprocess.run(cmd, cwd=PROJECT_ROOT, env=env)
    if result.returncode != 0:
        print(f"Error: PyInstaller build failed with exit code {result.returncode}")
        sys.exit(result.returncode)

    output_dir = DIST_DIR / "BoundaryX"
    exe_path = output_dir / "BoundaryX.exe"

    if not exe_path.exists():
        print(f"Error: Expected executable not found at {exe_path}")
        sys.exit(1)

    print(f"\nBuild successful! Executable created at: {exe_path}")
    return output_dir


def create_portable_zip(bundle_dir: Path, version: str = "0.1.0") -> Path:
    """Create a standalone portable ZIP package of the application bundle."""
    print("--> Packaging portable release archive...")
    zip_filename = DIST_DIR / f"BoundaryX-{version}-windows-x64-portable.zip"

    with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(bundle_dir):
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(bundle_dir)
                zipf.write(file_path, arcname=str(Path("BoundaryX") / rel_path))

    checksum = calculate_sha256(zip_filename)
    checksum_file = zip_filename.with_suffix(".zip.sha256")
    checksum_file.write_text(f"{checksum}  {zip_filename.name}\n", encoding="utf-8")

    print(f"Portable archive created: {zip_filename}")
    print(f"SHA-256 Checksum:        {checksum}")
    print(f"Checksum file written:   {checksum_file}\n")
    return zip_filename


def main() -> None:
    """Main CLI entry point for build script."""
    parser = argparse.ArgumentParser(
        description="BoundaryX Windows Packaging Utility",
    )
    parser.add_argument(
        "--no-clean",
        action="store_true",
        help="Do not clean build and dist directories before packaging",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Build with debug logging enabled",
    )
    parser.add_argument(
        "--zip",
        action="store_true",
        default=True,
        help="Generate portable ZIP archive after build (default: True)",
    )
    args = parser.parse_args()

    check_prerequisites()

    if not args.no_clean:
        clean_build_artifacts()

    bundle_dir = build_executable(clean=not args.no_clean, debug=args.debug)

    if args.zip:
        create_portable_zip(bundle_dir)


if __name__ == "__main__":
    main()
