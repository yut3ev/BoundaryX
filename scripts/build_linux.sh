#!/usr/bin/env bash
# ==============================================================================
# BoundaryX Linux Build and Packaging Script
#
# Builds standalone desktop distribution for Linux (x86_64) using PyInstaller,
# bundles Qt libraries, packages tar.gz distribution, and produces SHA-256 digests.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SPEC_FILE="${PROJECT_ROOT}/packaging/boundaryx.spec"
DIST_DIR="${PROJECT_ROOT}/dist"
BUILD_DIR="${PROJECT_ROOT}/build"
VERSION="0.1.0"

echo "=== BoundaryX Linux Packaging Utility v${VERSION} ==="
echo "Project Root: ${PROJECT_ROOT}"

# 1. Prerequisite verification
echo "--> Checking Python and build tools..."
if ! command -v python3 &>/dev/null; then
    echo "Error: python3 is not installed or not in PATH." >&2
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "${PY_VERSION}" | cut -d. -f1)
PY_MINOR=$(echo "${PY_VERSION}" | cut -d. -f2)

if [ "${PY_MAJOR}" -lt 3 ] || [ "${PY_MINOR}" -lt 12 ]; then
    echo "Error: Python 3.12 or newer is required. Found Python ${PY_VERSION}." >&2
    exit 1
fi
echo "  * Python version: ${PY_VERSION} (OK)"

if ! python3 -c "import PyInstaller" &>/dev/null; then
    echo "Error: PyInstaller not found. Install development dependencies:" >&2
    echo "  pip install -e '.[dev]'" >&2
    exit 1
fi
echo "  * PyInstaller: $(python3 -m PyInstaller --version) (OK)"

if ! python3 -c "import PySide6" &>/dev/null; then
    echo "Error: PySide6 is not installed." >&2
    exit 1
fi
echo "  * PySide6: $(python3 -c 'import PySide6; print(PySide6.__version__)') (OK)"

# 2. Clean previous build artifacts
echo "--> Cleaning previous build directories..."
rm -rf "${BUILD_DIR}" "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

# 3. Execute PyInstaller
echo "--> Executing PyInstaller build..."
export PYTHONPATH="${PROJECT_ROOT}/src:${PYTHONPATH:-}"

python3 -m PyInstaller \
    --noconfirm \
    --clean \
    --log-level INFO \
    "${SPEC_FILE}"

BUNDLE_DIR="${DIST_DIR}/BoundaryX"
BINARY_PATH="${BUNDLE_DIR}/BoundaryX"

if [ ! -f "${BINARY_PATH}" ]; then
    echo "Error: Binary was not created at expected location: ${BINARY_PATH}" >&2
    exit 1
fi

chmod +x "${BINARY_PATH}"
echo "Binary successfully created at: ${BINARY_PATH}"

# 4. Package portable tar.gz archive
echo "--> Creating portable release archive..."
TAR_FILE="${DIST_DIR}/BoundaryX-${VERSION}-linux-x64-portable.tar.gz"

cd "${DIST_DIR}"
tar -czf "${TAR_FILE}" BoundaryX/

# 5. Generate SHA-256 Checksum
echo "--> Calculating SHA-256 checksum..."
if command -v sha256sum &>/dev/null; then
    sha256sum "$(basename "${TAR_FILE}")" > "${TAR_FILE}.sha256"
elif command -v shasum &>/dev/null; then
    shasum -a 256 "$(basename "${TAR_FILE}")" > "${TAR_FILE}.sha256"
else
    python3 -c "
import hashlib, sys
p = sys.argv[1]
with open(p, 'rb') as f:
    digest = hashlib.sha256(f.read()).hexdigest()
print(f'{digest}  {p}')
" "$(basename "${TAR_FILE}")" > "${TAR_FILE}.sha256"
fi

CHECKSUM=$(cat "${TAR_FILE}.sha256")
echo "=========================================================="
echo "Build and Packaging Complete!"
echo "Distribution archive: ${TAR_FILE}"
echo "Checksum:             ${CHECKSUM}"
echo "=========================================================="
