#!/usr/bin/env bash
set -euo pipefail

echo "========================================================"
echo " BoundaryX Linux x86_64 Build & Packaging Pipeline"
echo "========================================================"

# Check prerequisites
command -v node >/dev/null 2>&1 || { echo "[-] Node.js is required but not installed. Aborting."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "[-] npm is required but not installed. Aborting."; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "[-] Rust/Cargo is required but not installed. Aborting."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[-] Python 3 is required but not installed. Aborting."; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist-release"
BINARIES_DIR="$ROOT_DIR/apps/desktop/src-tauri/binaries"
TARGET_TRIPLE="x86_64-unknown-linux-gnu"
SIDECAR_BIN="$BINARIES_DIR/boundaryx-engine-$TARGET_TRIPLE"

mkdir -p "$DIST_DIR" "$BINARIES_DIR"

echo "[1/6] Setting up Python Engine environment & dependencies..."
cd "$ROOT_DIR/engine"
if command -v uv >/dev/null 2>&1; then
    uv pip install -e ".[dev]" || python3 -m pip install -e ".[dev]"
else
    python3 -m pip install -e ".[dev]"
fi

echo "[2/6] Running Engine automated test suite..."
python3 -m pytest tests/ -v --tb=short

echo "[3/6] Compiling standalone Python engine sidecar binary..."
python3 "$ROOT_DIR/scripts/build_engine.py" --target "boundaryx-engine-$TARGET_TRIPLE"
chmod +x "$SIDECAR_BIN"
echo "[+] Sidecar verified at: $SIDECAR_BIN"

echo "[4/6] Building React/TypeScript frontend assets..."
cd "$ROOT_DIR/apps/desktop"
npm install
npm run build

echo "[5/6] Packaging Tauri v2 desktop bundles (.deb and .AppImage)..."
npx @tauri-apps/cli build --bundles deb,appimage

echo "[6/6] Collecting release artifacts, SBOM, and SHA-256 checksums..."
BUNDLE_ROOT="$ROOT_DIR/apps/desktop/src-tauri/target/release/bundle"

# Verify and copy .deb packages
DEB_FOUND=0
for deb in "$BUNDLE_ROOT"/deb/*.deb; do
    if [ -s "$deb" ]; then
        cp "$deb" "$DIST_DIR/"
        DEB_FOUND=1
    fi
done
if [ "$DEB_FOUND" -ne 1 ]; then
    echo "[-] FATAL: No valid non-empty .deb package was produced in $BUNDLE_ROOT/deb!" >&2
    exit 1
fi

# Verify and copy .AppImage packages
APPIMAGE_FOUND=0
for app in "$BUNDLE_ROOT"/appimage/*.AppImage; do
    if [ -s "$app" ]; then
        cp "$app" "$DIST_DIR/"
        APPIMAGE_FOUND=1
    fi
done
if [ "$APPIMAGE_FOUND" -ne 1 ]; then
    echo "[-] FATAL: No valid non-empty .AppImage package was produced in $BUNDLE_ROOT/appimage!" >&2
    exit 1
fi

# Generate dynamic SBOM
python3 "$ROOT_DIR/scripts/generate_sbom.py"
if [ ! -s "$ROOT_DIR/docs/SBOM.json" ]; then
    echo "[-] FATAL: SBOM generation failed or output file is empty!" >&2
    exit 1
fi
cp "$ROOT_DIR/docs/SBOM.json" "$DIST_DIR/"

# Compute SHA-256 checksums
cd "$DIST_DIR"
sha256sum * > SHA256SUMS.txt

# Run integrity verification across all artifacts
python3 "$ROOT_DIR/scripts/generate_sbom.py" --verify-artifacts "$DIST_DIR"

echo "========================================================"
echo " Build & Packaging Successful!"
echo " Release Artifacts in $DIST_DIR:"
echo "--------------------------------------------------------"
cat SHA256SUMS.txt
echo "========================================================"

