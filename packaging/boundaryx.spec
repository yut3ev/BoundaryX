# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification file for BoundaryX desktop application.

Bundles Python 3.12/3.13 runtime, PySide6 Qt libraries, SQLAlchemy SQLite engine,
HTTPX client, NetworkX graph engine, cryptography primitives, and application resources
into a hardened standalone desktop application distribution.
"""

import sys
from pathlib import Path

block_cipher = None

# Project root and source directory paths
SPEC_DIR = Path(SPECPATH).resolve()
PROJECT_ROOT = SPEC_DIR.parent
SRC_DIR = PROJECT_ROOT / "src"

# Verify source tree is present
if not SRC_DIR.exists():
    raise RuntimeError(f"Source directory not found at {SRC_DIR}")

# Collect data files and assets
datas = []

# Include resources package (stylesheets, templates)
ui_resources_dir = SRC_DIR / "boundaryx" / "ui" / "resources"
if ui_resources_dir.exists():
    datas.append((str(ui_resources_dir), "boundaryx/ui/resources"))

# Include assets (icons, images)
assets_dir = PROJECT_ROOT / "assets"
if assets_dir.exists():
    datas.append((str(assets_dir), "assets"))

# Include example data fixtures for user reference
examples_dir = PROJECT_ROOT / "examples"
if examples_dir.exists():
    datas.append((str(examples_dir), "examples"))

# Explicit hidden imports for dynamic and lazy module loaders
hidden_imports = [
    # PySide6 Qt Core & Widgets
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",
    "PySide6.QtSvg",
    "PySide6.QtNetwork",
    "PySide6.QtPrintSupport",
    # SQLAlchemy ORM and SQLite dialect
    "sqlalchemy",
    "sqlalchemy.sql.default_comparator",
    "sqlalchemy.dialects.sqlite",
    "sqlalchemy.dialects.sqlite.pysqlite",
    "sqlalchemy.orm",
    "sqlalchemy.ext.baked",
    # HTTPX & Network
    "httpx",
    "httpcore",
    "h11",
    "idna",
    "certifi",
    # Pydantic & Pydantic Settings
    "pydantic",
    "pydantic_settings",
    "pydantic.deprecated.decorator",
    # Cryptography
    "cryptography",
    "cryptography.fernet",
    "cryptography.hazmat.primitives.ciphers",
    "cryptography.hazmat.primitives.hashes",
    "cryptography.hazmat.primitives.kdf.pbkdf2",
    "cryptography.hazmat.backends.openssl",
    # Graph Analysis
    "networkx",
    # BoundaryX Internal Layers
    "boundaryx",
    "boundaryx.config",
    "boundaryx.config.settings",
    "boundaryx.domain",
    "boundaryx.domain.identities",
    "boundaryx.domain.identities.models",
    "boundaryx.domain.resources",
    "boundaryx.domain.resources.models",
    "boundaryx.domain.resources.tenant",
    "boundaryx.domain.policies",
    "boundaryx.domain.policies.models",
    "boundaryx.domain.policies.engine",
    "boundaryx.domain.relationships",
    "boundaryx.domain.relationships.models",
    "boundaryx.domain.findings",
    "boundaryx.domain.findings.models",
    "boundaryx.domain.evidence",
    "boundaryx.domain.evidence.models",
    "boundaryx.security",
    "boundaryx.security.scope",
    "boundaryx.security.secrets",
    "boundaryx.security.redaction",
    "boundaryx.security.audit",
    "boundaryx.security.exceptions",
    "boundaryx.infrastructure",
    "boundaryx.infrastructure.database",
    "boundaryx.infrastructure.database.base",
    "boundaryx.infrastructure.database.manager",
    "boundaryx.infrastructure.database.models",
    "boundaryx.infrastructure.database.repositories",
    "boundaryx.infrastructure.http",
    "boundaryx.infrastructure.http.client",
    "boundaryx.infrastructure.imports",
    "boundaryx.infrastructure.imports.har_importer",
    "boundaryx.infrastructure.imports.raw_http_importer",
    "boundaryx.infrastructure.imports.boundaryx_importer",
    "boundaryx.infrastructure.exports",
    "boundaryx.infrastructure.exports.report_exporter",
    "boundaryx.infrastructure.exports.evidence_exporter",
    "boundaryx.infrastructure.exports.project_exporter",
    "boundaryx.infrastructure.logging",
    "boundaryx.infrastructure.logging.logger",
    "boundaryx.application",
    "boundaryx.application.scope",
    "boundaryx.application.scope.service",
    "boundaryx.application.testing",
    "boundaryx.application.testing.models",
    "boundaryx.workers",
    "boundaryx.workers.async_worker",
    "boundaryx.ui",
    "boundaryx.ui.resources",
    "boundaryx.ui.resources.styles",
    "boundaryx.ui.resources.themes",
    "boundaryx.ui.components",
]

# Excluded packages to minimize binary attack surface and bundle size
excluded_modules = [
    "tkinter",
    "matplotlib",
    "scipy",
    "numpy",
    "notebook",
    "IPython",
    "pytest",
    "unittest.test",
    "pdb",
]

a = Analysis(
    [str(SRC_DIR / "boundaryx" / "app.py")],
    pathex=[str(SRC_DIR), str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excluded_modules,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher,
)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="BoundaryX",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(assets_dir / "icon.ico") if (assets_dir / "icon.ico").exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="BoundaryX",
)
