import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class SecretStore:
    """Authenticated encryption wrapper for credentials stored in the database."""

    def __init__(self, key: str, *, allow_ephemeral: bool = False):
        if not key:
            if not allow_ephemeral:
                raise ValueError("SECRET_ENCRYPTION_KEY is required")
            key = base64.urlsafe_b64encode(hashlib.sha256(b"test-only-key").digest()).decode()
        self._fernet = Fernet(key.encode())

    def encrypt(self, value: dict[str, Any]) -> str:
        return self._fernet.encrypt(json.dumps(value).encode()).decode()

    def decrypt(self, value: str) -> dict[str, Any]:
        try:
            decoded = self._fernet.decrypt(value.encode())
        except InvalidToken as exc:
            raise ValueError("credential decryption failed") from exc
        data = json.loads(decoded)
        if not isinstance(data, dict):
            raise ValueError("invalid encrypted credential payload")
        return data


def api_key_matches(configured: str, supplied: str | None) -> bool:
    if not configured:
        return True
    return supplied is not None and hmac.compare_digest(configured, supplied)
