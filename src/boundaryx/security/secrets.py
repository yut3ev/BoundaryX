"""Secret management module using authenticated symmetric encryption (Fernet)."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sys
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from boundaryx.security.exceptions import DecryptionError, KeyManagementError, SecurityError

logger = logging.getLogger(__name__)


class SecretManager:
    """Manages application secrets with Fernet encryption and secure file storage.

    Provides encryption, decryption, persistent encrypted storage, and key rotation.
    Never logs secret values. Ensures secure file permissions on key and secrets files.
    """

    def __init__(self, key_path: Path | str, secrets_file: Path | str | None = None) -> None:
        """Initialize SecretManager with a key path and optional secrets store path.

        Args:
            key_path: Path to the encryption key file. Created securely if not present.
            secrets_file: Optional path to JSON secrets storage file. Defaults to
                'secrets.json' in the same directory as key_path.

        Raises:
            SecurityError: If key creation or loading fails, or permissions are insecure.
        """
        self._key_path = Path(key_path).resolve()
        if secrets_file is not None:
            self._secrets_file = Path(secrets_file).resolve()
        else:
            self._secrets_file = self._key_path.parent / "secrets.json"

        self._lock = threading.RLock()
        self._fernet: Fernet = self._initialize_key(self._key_path)

    @property
    def key_path(self) -> Path:
        """Return the path to the encryption key file."""
        return self._key_path

    @property
    def secrets_file(self) -> Path:
        """Return the path to the secrets storage file."""
        return self._secrets_file

    def _initialize_key(self, path: Path) -> Fernet:
        """Load an existing Fernet key or generate and store a new one securely."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._enforce_directory_permissions(path.parent)

            if path.exists():
                self._verify_file_permissions(path)
                with path.open("rb") as f:
                    key = f.read().strip()
                if not key:
                    raise KeyManagementError(f"Key file at {path} is empty")
                return Fernet(key)

            # Generate new key and store securely
            key = Fernet.generate_key()
            self._secure_write_bytes(path, key)
            return Fernet(key)
        except SecurityError:
            raise
        except Exception as exc:
            logger.error("Failed to securely initialize cryptographic key at %s: %s", path, exc)
            raise KeyManagementError(f"Failed to securely initialize key at {path}: {exc}") from exc

    def _enforce_directory_permissions(self, directory: Path) -> None:
        """Ensure the directory containing sensitive data has restricted permissions on POSIX."""
        if sys.platform != "win32":
            try:
                os.chmod(directory, 0o700)
            except OSError as exc:
                raise KeyManagementError(f"Unable to restrict permissions on directory {directory}: {exc}") from exc

    def _verify_file_permissions(self, file_path: Path) -> None:
        """Verify that file permissions are restricted to owner only on POSIX."""
        if sys.platform != "win32":
            try:
                st = file_path.stat()
                # Check if group or others have read/write/execute permissions (0o077)
                if st.st_mode & 0o077:
                    # Attempt to fix permissions
                    os.chmod(file_path, 0o600)
                    st = file_path.stat()
                    if st.st_mode & 0o077:
                        raise KeyManagementError(f"Insecure permissions on key file {file_path}. Must be 0600.")
            except OSError as exc:
                raise KeyManagementError(f"Cannot inspect permissions on {file_path}: {exc}") from exc

    def _secure_write_bytes(self, destination: Path, data: bytes) -> None:
        """Write bytes to destination file securely with restricted permissions."""
        dest_dir = destination.parent
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Create temporary file in same directory for atomic replace
        fd = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            mode = 0o600
            fd = os.open(destination, flags, mode)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            fd = None

            if sys.platform != "win32":
                os.chmod(destination, 0o600)
        except OSError as exc:
            raise KeyManagementError(f"Failed to securely write key file {destination}: {exc}") from exc
        finally:
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext string using Fernet.

        Args:
            plaintext: Raw secret string to encrypt.

        Returns:
            URL-safe base64-encoded ciphertext string.

        Raises:
            SecurityError: If encryption fails.
        """
        if not isinstance(plaintext, str):
            raise SecurityError("Plaintext to encrypt must be a string")
        try:
            encrypted_bytes = self._fernet.encrypt(plaintext.encode("utf-8"))
            return encrypted_bytes.decode("utf-8")
        except Exception as exc:
            raise SecurityError(f"Encryption failed: {exc}") from exc

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a ciphertext string back to plaintext.

        Args:
            ciphertext: URL-safe base64-encoded encrypted token.

        Returns:
            Decrypted plaintext string.

        Raises:
            DecryptionError: If ciphertext is invalid, corrupted, or decryption fails.
        """
        if not isinstance(ciphertext, str):
            raise DecryptionError("Ciphertext must be a string")
        try:
            decrypted_bytes = self._fernet.decrypt(ciphertext.encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except InvalidToken as exc:
            raise DecryptionError("Invalid or corrupted secret ciphertext") from exc
        except Exception as exc:
            raise DecryptionError(f"Decryption failed: {exc}") from exc

    def _read_secrets_file(self) -> dict[str, Any]:
        """Read and parse the secrets JSON file. Must be called with self._lock held."""
        if not self._secrets_file.exists():
            return {}
        try:
            with self._secrets_file.open("r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return {}
                data = json.loads(content)
                if not isinstance(data, dict):
                    raise SecurityError(f"Corrupted secrets file at {self._secrets_file}")
                return data
        except json.JSONDecodeError as exc:
            raise SecurityError(f"Failed to parse secrets JSON at {self._secrets_file}: {exc}") from exc
        except OSError as exc:
            raise SecurityError(f"Error reading secrets file at {self._secrets_file}: {exc}") from exc

    def _write_secrets_file(self, data: dict[str, Any]) -> None:
        """Write the secrets dictionary to file atomically. Must be called with self._lock held."""
        try:
            self._secrets_file.parent.mkdir(parents=True, exist_ok=True)
            self._enforce_directory_permissions(self._secrets_file.parent)

            payload = json.dumps(data, indent=2)
            tmp_fd, tmp_path_str = tempfile.mkstemp(
                dir=str(self._secrets_file.parent),
                prefix="secrets_",
                suffix=".tmp",
            )
            tmp_path = Path(tmp_path_str)

            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                    f.write(payload)
                    f.flush()
                    os.fsync(f.fileno())

                if sys.platform != "win32":
                    os.chmod(tmp_path, 0o600)

                tmp_path.replace(self._secrets_file)
                if sys.platform != "win32":
                    os.chmod(self._secrets_file, 0o600)
            except Exception:
                if tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
                raise
        except OSError as exc:
            raise SecurityError(f"Failed to securely save secrets file {self._secrets_file}: {exc}") from exc

    def store_secret(self, secret_id: str, value: str, metadata: dict[str, Any] | None = None) -> None:
        """Encrypt and store a secret in the JSON secrets file.

        Args:
            secret_id: Unique identifier for the secret.
            value: Secret plaintext value to encrypt and store.
            metadata: Optional dictionary of non-sensitive metadata.

        Raises:
            SecurityError: If encryption or file persistence fails.
        """
        if not secret_id or not isinstance(secret_id, str):
            raise SecurityError("secret_id must be a non-empty string")
        if not isinstance(value, str):
            raise SecurityError("Secret value must be a string")

        encrypted_val = self.encrypt(value)
        record = {
            "encrypted_value": encrypted_val,
            "metadata": metadata or {},
            "updated_at": datetime.now(UTC).isoformat(),
        }

        with self._lock:
            data = self._read_secrets_file()
            data[secret_id] = record
            self._write_secrets_file(data)
            logger.debug("Successfully stored secret ID: %s", secret_id)

    def get_secret(self, secret_id: str) -> str | None:
        """Retrieve and decrypt a stored secret by ID.

        Args:
            secret_id: Unique identifier for the secret.

        Returns:
            Decrypted plaintext secret if found, or None if not found.

        Raises:
            DecryptionError: If the stored ciphertext cannot be decrypted.
            SecurityError: If reading the storage file fails.
        """
        if not secret_id or not isinstance(secret_id, str):
            return None

        with self._lock:
            data = self._read_secrets_file()
            record = data.get(secret_id)
            if record is None:
                return None

            ciphertext = record.get("encrypted_value") if isinstance(record, dict) else str(record)
            if not ciphertext:
                return None

            return self.decrypt(ciphertext)

    def delete_secret(self, secret_id: str) -> bool:
        """Delete a stored secret by ID.

        Args:
            secret_id: Identifier of the secret to delete.

        Returns:
            True if secret existed and was deleted, False if not found.

        Raises:
            SecurityError: If writing the updated secrets store fails.
        """
        if not secret_id or not isinstance(secret_id, str):
            return False

        with self._lock:
            data = self._read_secrets_file()
            if secret_id not in data:
                return False

            del data[secret_id]
            self._write_secrets_file(data)
            logger.debug("Deleted secret ID: %s", secret_id)
            return True

    def list_secret_ids(self) -> list[str]:
        """List all stored secret IDs without revealing any values.

        Returns:
            List of secret ID strings.
        """
        with self._lock:
            data = self._read_secrets_file()
            return sorted(list(data.keys()))

    def rotate_key(self, new_key_path: Path | str) -> None:
        """Re-encrypt all stored secrets with a new encryption key.

        Args:
            new_key_path: Path to the new Fernet key file (created securely if needed).

        Raises:
            SecurityError: If key creation, re-encryption, or persistence fails.
        """
        target_path = Path(new_key_path).resolve()
        with self._lock:
            # Initialize new key securely
            new_fernet = self._initialize_key(target_path)

            data = self._read_secrets_file()
            re_encrypted_data: dict[str, Any] = {}

            # Decrypt with current key and re-encrypt with new key
            for secret_id, record in data.items():
                if isinstance(record, dict) and "encrypted_value" in record:
                    ciphertext = record["encrypted_value"]
                    meta = record.get("metadata", {})
                else:
                    ciphertext = str(record)
                    meta = {}

                plaintext = self.decrypt(ciphertext)
                new_ciphertext = new_fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

                re_encrypted_data[secret_id] = {
                    "encrypted_value": new_ciphertext,
                    "metadata": meta,
                    "updated_at": datetime.now(UTC).isoformat(),
                }

            # Save re-encrypted data
            self._write_secrets_file(re_encrypted_data)

            # Update active key and Fernet instance
            self._key_path = target_path
            self._fernet = new_fernet
            logger.info("Successfully rotated secret encryption key to %s", target_path)
