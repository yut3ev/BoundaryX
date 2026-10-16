#!/usr/bin/env python3
"""
BoundaryX SBOM & License Inventory Generator
Generates a dynamic JSON Software Bill of Materials (SBOM) from lockfiles/manifests
and validates release package integrity with SHA-256 verification.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def calculate_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


def get_project_version(project_root: Path) -> str:
    desktop_pkg = project_root / "apps" / "desktop" / "package.json"
    if desktop_pkg.exists():
        try:
            data = json.loads(desktop_pkg.read_text(encoding="utf-8"))
            if "version" in data:
                return str(data["version"])
        except Exception:
            pass
    return "0.1.1"


def extract_python_dependencies(engine_dir: Path) -> list:
    components = []
    # 1. Prefer engine/uv.lock for exact resolved versions
    uv_lock = engine_dir / "uv.lock"
    if uv_lock.exists():
        if tomllib:
            try:
                data = tomllib.loads(uv_lock.read_text(encoding="utf-8"))
                for pkg in data.get("package", []):
                    name = pkg.get("name")
                    ver = pkg.get("version")
                    if name and name != "boundaryx-engine":
                        components.append({
                            "name": name,
                            "version": str(ver),
                            "type": "library",
                            "purl": f"pkg:pypi/{name}@{ver}",
                            "language": "python",
                        })
                if components:
                    return components
            except Exception as e:
                print(f"[!] Warning parsing uv.lock: {e}")
        else:
            current_name = None
            for line in uv_lock.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("name = "):
                    current_name = line.split('"')[1]
                elif line.startswith("version = ") and current_name:
                    ver = line.split('"')[1]
                    if current_name != "boundaryx-engine":
                        components.append({
                            "name": current_name,
                            "version": ver,
                            "type": "library",
                            "purl": f"pkg:pypi/{current_name}@{ver}",
                            "language": "python",
                        })
                    current_name = None
            if components:
                return components

    # 2. Fallback to pyproject.toml
    pyproject_file = engine_dir / "pyproject.toml"
    if pyproject_file.exists():
        content = pyproject_file.read_text(encoding="utf-8")
        in_deps = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("dependencies = ["):
                in_deps = True
                continue
            if in_deps:
                if line.startswith("]"):
                    break
                match = re.search(r'"([a-zA-Z0-9_\-]+)(?:([><=~0-9\., ]+))?"', line)
                if match:
                    pkg_name = match.group(1)
                    ver_spec = (match.group(2) or "").strip()
                    components.append({
                        "name": pkg_name,
                        "version": ver_spec or "latest",
                        "type": "library",
                        "purl": f"pkg:pypi/{pkg_name}",
                        "language": "python",
                    })
    return components


def extract_npm_dependencies(desktop_dir: Path) -> list:
    components = []
    # 1. Prefer package-lock.json for exact resolved versions
    pkg_lock = desktop_dir / "package-lock.json"
    if pkg_lock.exists():
        try:
            data = json.loads(pkg_lock.read_text(encoding="utf-8"))
            packages = data.get("packages", {})
            seen_npm = set()
            for pkg_path, meta in packages.items():
                if not pkg_path or "node_modules/" not in pkg_path:
                    continue
                name = pkg_path.split("node_modules/")[-1]
                ver = meta.get("version")
                if not name or not ver:
                    continue
                key = f"{name}@{ver}"
                if key in seen_npm:
                    continue
                seen_npm.add(key)
                comp = {
                    "name": name,
                    "version": str(ver),
                    "type": "library",
                    "purl": f"pkg:npm/{name}@{ver}",
                    "language": "javascript",
                }
                license_id = meta.get("license")
                if license_id:
                    comp["licenses"] = [{"license": {"id": license_id}}]
                components.append(comp)
            if components:
                return components
        except Exception as e:
            print(f"[!] Warning parsing package-lock.json: {e}")

    # 2. Fallback to package.json
    pkg_json = desktop_dir / "package.json"
    if pkg_json.exists():
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
        for section in ["dependencies", "devDependencies"]:
            for name, ver in data.get(section, {}).items():
                components.append({
                    "name": name,
                    "version": ver.replace("^", "").replace("~", ""),
                    "type": "library",
                    "purl": f"pkg:npm/{name}",
                    "language": "javascript",
                })
    return components


def extract_cargo_dependencies(tauri_dir: Path) -> list:
    components = []
    cargo_lock = tauri_dir / "Cargo.lock"
    if cargo_lock.exists():
        if tomllib:
            try:
                data = tomllib.loads(cargo_lock.read_text(encoding="utf-8"))
                seen_cargo = set()
                for pkg in data.get("package", []):
                    name = pkg.get("name")
                    ver = pkg.get("version")
                    if name and name != "boundaryx-desktop":
                        key = f"{name}@{ver}"
                        if key not in seen_cargo:
                            seen_cargo.add(key)
                            components.append({
                                "name": name,
                                "version": str(ver),
                                "type": "library",
                                "purl": f"pkg:cargo/{name}@{ver}",
                                "language": "rust",
                            })
                if components:
                    return components
            except Exception as e:
                print(f"[!] Warning parsing Cargo.lock with tomllib: {e}")

        # Fallback line-based parsing
        content = cargo_lock.read_text(encoding="utf-8")
        current_name = None
        seen_cargo = set()
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("name = "):
                current_name = line.split('"')[1]
            elif line.startswith("version = ") and current_name:
                ver = line.split('"')[1]
                if current_name != "boundaryx-desktop":
                    key = f"{current_name}@{ver}"
                    if key not in seen_cargo:
                        seen_cargo.add(key)
                        components.append({
                            "name": current_name,
                            "version": ver,
                            "type": "library",
                            "purl": f"pkg:cargo/{current_name}@{ver}",
                            "language": "rust",
                        })
                current_name = None
    return components


def generate_sbom(output_path: Path | None = None) -> Path:
    project_root = Path(__file__).resolve().parent.parent
    engine_dir = project_root / "engine"
    desktop_dir = project_root / "apps" / "desktop"
    tauri_dir = desktop_dir / "src-tauri"

    if output_path is None:
        output_path = project_root / "docs" / "SBOM.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    proj_version = get_project_version(project_root)
    py_comps = extract_python_dependencies(engine_dir)
    npm_comps = extract_npm_dependencies(desktop_dir)
    cargo_comps = extract_cargo_dependencies(tauri_dir)

    all_components = [
        {
            "name": "boundaryx-engine",
            "version": proj_version,
            "type": "application",
            "licenses": [{"license": {"id": "MIT"}}],
            "description": "BoundaryX Security Engine Sidecar",
        },
        {
            "name": "boundaryx-desktop",
            "version": proj_version,
            "type": "application",
            "licenses": [{"license": {"id": "MIT"}}],
            "description": "BoundaryX Desktop UI & Tauri Supervisor",
        },
    ]

    seen = {f"app:boundaryx-engine@{proj_version}", f"app:boundaryx-desktop@{proj_version}"}
    for comp in py_comps + npm_comps + cargo_comps:
        key = f"{comp['language']}:{comp['name']}@{comp['version']}"
        if key not in seen:
            seen.add(key)
            all_components.append(comp)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:boundaryx-{proj_version}-sbom",
        "version": 1,
        "metadata": {
            "component": {
                "name": "boundaryx",
                "version": proj_version,
                "type": "application",
                "licenses": [{"license": {"id": "MIT"}}],
                "description": "Desktop Security Research Workbench for Pentesting & Bug Bounty",
            }
        },
        "components": all_components,
    }

    output_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    print(f"[+] Dynamic SBOM generated at {output_path} with {len(all_components)} components.")
    return output_path


def verify_artifacts(directory: Path):
    print(f"[*] Validating release artifacts in {directory}...")
    if not directory.exists():
        print(f"[-] Directory {directory} does not exist!")
        sys.exit(1)

    # 1. Check for .deb
    debs = [f for f in directory.glob("*.deb") if f.stat().st_size > 0]
    if not debs:
        print("[-] FATAL: No non-empty .deb package found in release artifacts!")
        sys.exit(1)
    for deb in debs:
        print(f"[+] Verified .deb package: {deb.name} ({deb.stat().st_size / (1024*1024):.2f} MB)")

    # 2. Check for .AppImage
    appimages = [f for f in directory.glob("*.AppImage") if f.stat().st_size > 0]
    if not appimages:
        print("[-] FATAL: No non-empty .AppImage package found in release artifacts!")
        sys.exit(1)
    for app in appimages:
        print(f"[+] Verified .AppImage package: {app.name} ({app.stat().st_size / (1024*1024):.2f} MB)")

    # 3. Check for SBOM.json
    sbom_file = directory / "SBOM.json"
    if not sbom_file.exists() or sbom_file.stat().st_size == 0:
        print("[-] FATAL: SBOM.json is missing or empty in release artifacts!")
        sys.exit(1)
    print(f"[+] Verified SBOM.json ({sbom_file.stat().st_size} bytes)")

    # 4. Check for SHA256SUMS.txt
    sums_file = directory / "SHA256SUMS.txt"
    if not sums_file.exists() or sums_file.stat().st_size == 0:
        print("[-] FATAL: SHA256SUMS.txt is missing or empty!")
        sys.exit(1)

    # Verify every hash recorded matches actual file
    sums_content = sums_file.read_text(encoding="utf-8")
    verified_files = set()
    for line in sums_content.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            expected_hash = parts[0]
            filename = parts[1].lstrip("*")
            filepath = directory / filename
            if not filepath.exists():
                print(f"[-] File listed in SHA256SUMS.txt does not exist: {filename}")
                sys.exit(1)
            actual_hash = calculate_sha256(filepath)
            if actual_hash.lower() != expected_hash.lower():
                print(f"[-] Hash mismatch for {filename}!")
                print(f"    Expected: {expected_hash}")
                print(f"    Actual:   {actual_hash}")
                sys.exit(1)
            verified_files.add(filename)

    print(f"[+] Verified {len(verified_files)} file SHA-256 checksums successfully.")
    print("[+] All release artifacts passed verification.")


def main():
    parser = argparse.ArgumentParser(description="BoundaryX SBOM Generator & Release Artifacts Verifier")
    parser.add_argument("--output", type=str, default=None, help="Output path for SBOM.json")
    parser.add_argument("--verify-artifacts", type=str, default=None, help="Directory of artifacts to verify")
    args = parser.parse_args()

    if args.verify_artifacts:
        verify_artifacts(Path(args.verify_artifacts))
    else:
        out = Path(args.output) if args.output else None
        generate_sbom(out)


if __name__ == "__main__":
    main()
