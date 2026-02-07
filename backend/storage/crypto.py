"""
Credential encryption using Fernet (AES-128-CBC + HMAC-SHA256).

The encryption key is derived from a locally generated secret stored
in a keyfile next to the database.  The keyfile is NOT the database —
even if the DB leaks, credentials are unreadable without it.
"""

import base64
import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import DB_PATH

log = logging.getLogger(__name__)

_KEY_FILE = DB_PATH.parent / ".vault_key"
_SALT = b"endpoint_security_tool_v1"  # static salt — the randomness is in the keyfile
_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    """Lazy-load the Fernet instance, generating a key file if needed."""
    global _fernet
    if _fernet is not None:
        return _fernet

    # Generate or read the master secret
    if _KEY_FILE.exists():
        secret = _KEY_FILE.read_bytes()
    else:
        secret = os.urandom(32)
        _KEY_FILE.write_bytes(secret)
        log.info("generated new vault key at %s", _KEY_FILE)

    # Derive a Fernet key from the secret
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=480_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret))
    _fernet = Fernet(key)
    return _fernet


def encrypt(plaintext: str) -> str:
    """Encrypt a string, return base64-encoded ciphertext."""
    if not plaintext:
        return ""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a base64-encoded ciphertext back to plaintext."""
    if not ciphertext:
        return ""
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        log.warning("failed to decrypt credential — key may have changed")
        return "<decryption failed>"
