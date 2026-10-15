# Packaging & Distribution Guide

BoundaryX can be packaged into standalone, self-contained desktop binaries for **Windows** and **Linux** using **PyInstaller**. This guide details the build process, specification file architecture, hidden import configuration, and portable runtime modes.

---

## 1. Packaging Architecture & Spec File Anatomy

The build configuration is defined in [`packaging/boundaryx.spec`](../packaging/boundaryx.spec).

### 1.1 Data Assets Bundled
- `src/boundaryx/ui/resources/`: Contains application stylesheets (`styles.py`), dark/light themes (`themes.py`), and styling templates.
- `assets/`: Application icons (`icon.ico`, `icon.png`) and branding artwork.
- `examples/`: Sample assessment fixtures (`sample_project.json`, `sample_traffic.har`) embedded for offline demonstration.

### 1.2 Hidden Imports Configuration
Because BoundaryX relies on dynamic imports and modular architectures, the spec file explicitly registers:
- **PySide6**: Qt Core, GUI, Widgets, SVG, Network, and PrintSupport modules.
- **SQLAlchemy 2.x**: Declarative models, `sqlalchemy.orm`, SQLite dialect (`sqlalchemy.dialects.sqlite.pysqlite`), and comparator plugins.
- **HTTPX**: `httpcore`, `h11`, `idna`, `certifi`.
- **Cryptography**: `cryptography.fernet`, OpenSSL backend primitives, PBKDF2 key derivation.
- **NetworkX**: Graph data structures and algorithms.
- **BoundaryX Internal Modules**: All Domain, Security, Infrastructure, Application, and UI modules.

### 1.3 Excluded Modules
To optimize package size and eliminate unnecessary dependencies, non-desktop packages are excluded:
- `tkinter`, `matplotlib`, `scipy`, `numpy`, `IPython`, `notebook`, `pytest`.

---

## 2. Building for Windows

### Prerequisites
1. Python `>= 3.12` (x64) installed and in your `PATH`.
2. Install BoundaryX with development dependencies:
   ```powershell
   python -m pip install --upgrade pip setuptools wheel
   pip install -e ".[dev]"
   ```

### Running the Windows Build Script
Execute the automated packaging script:
```powershell
python scripts/build_windows.py
```

### Build Options
- `--no-clean`: Preserve previous build directories to accelerate incremental compilation.
- `--debug`: Enable verbose PyInstaller diagnostic logging.
- `--zip`: Package the output into a portable ZIP distribution archive (enabled by default).

### Output Artifacts
The build produces:
- `dist/BoundaryX/BoundaryX.exe`: Standalone application launcher.
- `dist/BoundaryX-0.1.0-windows-x64-portable.zip`: Compressed release archive.
- `dist/BoundaryX-0.1.0-windows-x64-portable.zip.sha256`: SHA-256 integrity checksum.

---

## 3. Building for Linux

### Prerequisites
1. Python `>= 3.12` installed with development headers (`python3-dev`).
2. System Qt and OpenGL libraries required for PySide6:
   ```bash
   sudo apt-get update
   sudo apt-get install -y \
     libgl1-mesa-glx \
     libegl1 \
     libxkbcommon-x11-0 \
     libxcb-cursor0 \
     libxcb-icccm4 \
     libxcb-image0 \
     libxcb-keysyms1 \
     libxcb-randr0 \
     libxcb-render-util0 \
     libxcb-shape0 \
     libxcb-xfixes0 \
     libxcb-xinerama0
   ```
3. Install package dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

### Running the Linux Build Script
Execute the shell script:
```bash
chmod +x scripts/build_linux.sh
./scripts/build_linux.sh
```

### Output Artifacts
- `dist/BoundaryX/BoundaryX`: Standalone executable binary.
- `dist/BoundaryX-0.1.0-linux-x64-portable.tar.gz`: Portable compressed archive.
- `dist/BoundaryX-0.1.0-linux-x64-portable.tar.gz.sha256`: SHA-256 integrity checksum.

---

## 4. Portable Mode Runtime

Both Windows and Linux distributions support **Portable Mode**. When running portably:
- The database (`boundaryx.db`) is stored directly in the application folder rather than `%APPDATA%` or `~/.boundaryx/`.
- Application logs (`logs/`) and secret keys (`secrets.json`) remain local to the executable.
- No registry entries or system environment variables are modified.

To run in portable mode:
```bash
# Windows:
BoundaryX.exe --portable

# Linux:
./BoundaryX --portable
```

---

## 5. Troubleshooting PyInstaller Builds

### 1. `qt.qpa.plugin: Could not load the Qt platform plugin "xcb"` (Linux)
- **Cause**: Missing X11 or XCB system shared libraries on minimal Linux installations.
- **Fix**: Install `libxcb-cursor0` and `libxkbcommon-x11-0`:
  ```bash
  sudo apt-get install -y libxcb-cursor0 libxkbcommon-x11-0
  ```

### 2. High-DPI Scaling Artifacts on Windows
- BoundaryX automatically sets `Qt.HighDpiScaleFactorRoundingPolicy.PassThrough` in `app.py`. If fonts appear blurred on multi-monitor setups with mixed DPI scaling, ensure Windows display scaling is set to 100% or 125% uniform scaling.

### 3. Missing Cryptography OpenSSL C-Extensions
- Ensure `cryptography` was installed from a pre-built wheel:
  ```bash
  pip install --force-reinstall cryptography
  ```
