#!/usr/bin/env bash
set -euo pipefail

echo "========================================================"
echo " BoundaryX Linux x86_64 Build & Packaging Script"
echo "========================================================"

# Check prerequisites
command -v node >/dev/null 2>&1 || { echo "[-] Node.js is required but not installed. Aborting."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "[-] npm is required but not installed. Aborting."; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "[-] Rust/Cargo is required but not installed. Aborting."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[-] Python 3 is required but not installed. Aborting."; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[1/4] Installing Python engine dependencies via uv..."
cd "$ROOT_DIR/engine"
if command -v uv >/dev/null 2>&1; then
    uv sync
else
    python3 -m pip install -e .
fi

echo "[2/4] Running Engine test suite..."
python3 -m pytest tests/

echo "[3/4] Building Frontend assets..."
cd "$ROOT_DIR/apps/desktop"
npm install
npm run build

echo "[4/4] Packaging Tauri v2 desktop bundle (.deb and AppImage)..."
npm run tauri build -- --bundles deb,appimage

echo "[+] Build complete! Artifacts available in apps/desktop/src-tauri/target/release/bundle/"
