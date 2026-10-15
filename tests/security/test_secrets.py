"""Tests for SecretManager cryptographic operations and secure storage."""

from pathlib import Path

import pytest

from boundaryx.security.exceptions import DecryptionError, KeyManagementError, SecurityError
from boundaryx.security.secrets import SecretManager


@pytest.fixture
def temp_sec_dir(tmp_path: Path) -> Path:
    sec_dir = tmp_path / "security"
    sec_dir.mkdir(parents=True, exist_ok=True)
    return sec_dir


def test_secret_manager_key_generation(temp_sec_dir: Path) -> None:
    key_file = temp_sec_dir / "secret.key"
    secrets_file = temp_sec_dir / "secrets.json"

    mgr = SecretManager(key_path=key_file, secrets_file=secrets_file)
    assert key_file.exists()
    assert key_file.stat().st_size > 0
    assert mgr.list_secret_ids() == []


def test_secret_manager_encrypt_decrypt(temp_sec_dir: Path) -> None:
    key_file = temp_sec_dir / "secret.key"
    mgr = SecretManager(key_path=key_file)

    secret_text = "super_sensitive_api_key_12345!@#"
    ciphertext = mgr.encrypt(secret_text)

    assert ciphertext != secret_text
    assert secret_text not in ciphertext

    decrypted = mgr.decrypt(ciphertext)
    assert decrypted == secret_text


def test_secret_manager_decrypt_corrupted_data(temp_sec_dir: Path) -> None:
    key_file = temp_sec_dir / "secret.key"
    mgr = SecretManager(key_path=key_file)

    with pytest.raises(DecryptionError):
        mgr.decrypt("not_a_valid_fernet_token")


def test_secret_manager_store_and_get_secret(temp_sec_dir: Path) -> None:
    key_file = temp_sec_dir / "secret.key"
    secrets_file = temp_sec_dir / "secrets.json"
    mgr = SecretManager(key_path=key_file, secrets_file=secrets_file)

    mgr.store_secret("api_token", "secret_value_xyz", metadata={"env": "prod"})

    # Check that secrets file exists and does NOT contain raw secret_value_xyz
    with secrets_file.open("r", encoding="utf-8") as f:
        content = f.read()
        assert "secret_value_xyz" not in content
        assert "api_token" in content

    retrieved = mgr.get_secret("api_token")
    assert retrieved == "secret_value_xyz"

    # Nonexistent secret returns None
    assert mgr.get_secret("unknown_id") is None


def test_secret_manager_delete_secret(temp_sec_dir: Path) -> None:
    key_file = temp_sec_dir / "secret.key"
    mgr = SecretManager(key_path=key_file)

    mgr.store_secret("to_delete", "val123")
    assert "to_delete" in mgr.list_secret_ids()

    deleted = mgr.delete_secret("to_delete")
    assert deleted is True
    assert "to_delete" not in mgr.list_secret_ids()
    assert mgr.get_secret("to_delete") is None

    # Deleting already deleted secret returns False
    assert mgr.delete_secret("to_delete") is False


def test_secret_manager_list_secret_ids(temp_sec_dir: Path) -> None:
    key_file = temp_sec_dir / "secret.key"
    mgr = SecretManager(key_path=key_file)

    mgr.store_secret("secret_b", "val_b")
    mgr.store_secret("secret_a", "val_a")
    mgr.store_secret("secret_c", "val_c")

    ids = mgr.list_secret_ids()
    assert ids == ["secret_a", "secret_b", "secret_c"]


def test_secret_manager_rotate_key(temp_sec_dir: Path) -> None:
    old_key = temp_sec_dir / "old.key"
    new_key = temp_sec_dir / "new.key"
    secrets_file = temp_sec_dir / "secrets.json"

    mgr = SecretManager(key_path=old_key, secrets_file=secrets_file)
    mgr.store_secret("key1", "password_abc")
    mgr.store_secret("key2", "token_xyz")

    mgr.rotate_key(new_key)
    assert new_key.exists()
    assert mgr.key_path == new_key.resolve()

    # Verify secrets can still be retrieved with new key
    assert mgr.get_secret("key1") == "password_abc"
    assert mgr.get_secret("key2") == "token_xyz"

    # Verify a new SecretManager initialized with new_key can decrypt secrets
    new_mgr = SecretManager(key_path=new_key, secrets_file=secrets_file)
    assert new_mgr.get_secret("key1") == "password_abc"
    assert new_mgr.get_secret("key2") == "token_xyz"


def test_empty_key_file_raises_key_management_error(temp_sec_dir: Path) -> None:
    empty_key = temp_sec_dir / "empty.key"
    empty_key.write_text("")

    with pytest.raises(KeyManagementError):
        SecretManager(key_path=empty_key)


def test_invalid_arguments_raise_security_error(temp_sec_dir: Path) -> None:
    key_file = temp_sec_dir / "secret.key"
    mgr = SecretManager(key_path=key_file)

    with pytest.raises(SecurityError):
        mgr.store_secret("", "valid_val")

    with pytest.raises(SecurityError):
        mgr.encrypt(12345)  # type: ignore[arg-type]
