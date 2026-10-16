from pathlib import Path


class PathTraversalError(ValueError):
    pass


def sanitize_filename(filename: str) -> str:
    """Sanitizes a filename, stripping directory traversal elements and illegal characters."""
    clean = Path(filename).name.strip()
    # Strip null bytes and common dangerous characters
    clean = clean.replace("\x00", "").replace("/", "_").replace("\\", "_")
    if not clean or clean in (".", ".."):
        return "unnamed_artifact"
    return clean


def safe_join_path(base_dir: Path, untrusted_relative_path: str) -> Path:
    """
    Safely resolves untrusted relative path against base directory.
    Guarantees that the resulting path is strictly within base_dir.
    """
    base = Path(base_dir).resolve()
    target = (base / untrusted_relative_path).resolve()
    try:
        target.relative_to(base)
    except ValueError as e:
        raise PathTraversalError(f"Path traversal detected: '{untrusted_relative_path}' resolves outside '{base}'") from e
    return target
