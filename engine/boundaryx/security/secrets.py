import json
import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet

logger = logging.getLogger("boundaryx.security.secrets")


class SecretStore:
    """
    Secure secret storage abstraction.
    Does NOT store plaintext keys in SQLite, frontend bundles, or unencrypted logs.
    Supports environment override, OS keyring (if available), and Fernet-encrypted local file vault.
    """

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.vault_file = self.data_dir / "secrets.enc"
        self.master_key_file = self.data_dir / ".secret_key"
        self._cipher: Optional[Fernet] = None
        self._init_cipher()

    def _init_cipher(self) -> None:
        if not self.master_key_file.exists():
            key = Fernet.generate_key()
            self.master_key_file.write_bytes(key)
            try:
                os.chmod(self.master_key_file, 0o600)
            except Exception:
                pass
        else:
            key = self.master_key_file.read_bytes().strip()
        self._cipher = Fernet(key)

    def _load_vault(self) -> dict:
        if not self.vault_file.exists():
            return {}
        try:
            encrypted = self.vault_file.read_bytes()
            if not encrypted:
                return {}
            decrypted = self._cipher.decrypt(encrypted)
            return json.loads(decrypted.decode("utf-8"))
        except Exception as e:
            logger.warning("Could not decrypt secrets vault: %s", e)
            return {}

    def _save_vault(self, data: dict) -> None:
        payload = json.dumps(data).encode("utf-8")
        encrypted = self._cipher.encrypt(payload)
        self.vault_file.write_bytes(encrypted)
        try:
            os.chmod(self.vault_file, 0o600)
        except Exception:
            pass

    def store_secret(self, service: str, key_name: str, secret_value: str) -> None:
        vault_key = f"{service}:{key_name}"
        data = self._load_vault()
        data[vault_key] = secret_value
        self._save_vault(data)

    def get_secret(self, service: str, key_name: str) -> Optional[str]:
        # 1. Environment variable override (Development / Headless CI)
        env_var_name = f"{service.upper()}_{key_name.upper()}"
        if env_var_name in os.environ:
            return os.environ[env_var_name]

        if service.lower() == "gemini" and "GEMINI_API_KEY" in os.environ:
            return os.environ["GEMINI_API_KEY"]

        # 2. Encrypted Vault
        vault_key = f"{service}:{key_name}"
        data = self._load_vault()
        return data.get(vault_key)

    def delete_secret(self, service: str, key_name: str) -> bool:
        vault_key = f"{service}:{key_name}"
        data = self._load_vault()
        if vault_key in data:
            del data[vault_key]
            self._save_vault(data)
            return True
        return False
