"""Versioned MFA encryption with a separately held, explicitly managed key.

This protects a database-only disclosure. It does not protect a compromised
application host that can read both the database and its external key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "v1."
BINDING_TEXT = "Westbridge MFA encryption key binding v1"


def default_key_path(data_dir) -> Path:
    directory = Path(os.path.abspath(Path(data_dir).expanduser()))
    return directory.with_name(directory.name + ".secrets") / "mfa.key"


def key_path(data_dir, configured=None) -> Path:
    """Resolve a key outside runtime storage and every enclosing Git tree."""
    from .db import SOURCE_ROOTS

    directory = Path(os.path.abspath(Path(data_dir).expanduser()))
    selected = configured or os.environ.get("BUSINESS_MFA_KEY_FILE") or default_key_path(directory)
    if os.name == "nt":
        reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
        reserved.update(f"{prefix}{n}" for prefix in ("COM", "LPT") for n in "123456789\u00b9\u00b2\u00b3")
        expanded = Path(selected).expanduser()
        for part in expanded.parts[1:] if expanded.anchor else expanded.parts:
            if part in (".", ".."):
                continue
            if ":" in part or part.endswith((".", " ")) or part.split(".")[0].upper() in reserved:
                raise ValueError("Use an ordinary MFA key filename without device names or alternate streams.")
    path = Path(os.path.abspath(Path(selected).expanduser()))
    for candidate in (path, path.resolve()):
        if any(candidate == root or root in candidate.parents for root in (*SOURCE_ROOTS, directory, directory.resolve())):
            raise ValueError("Keep the MFA encryption key outside source and runtime backup directories.")
    for item in (path, *path.parents):
        info = item.lstat() if os.path.lexists(item) else None
        if info and (stat.S_ISLNK(info.st_mode) or
                     getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            raise ValueError("The MFA key path must not use links or junctions.")
        if item.is_dir() and (item / ".git").exists():
            raise ValueError("Keep the MFA encryption key outside Git working trees.")
    return path


def create_key_file(data_dir, configured=None) -> Path:
    """Explicit exclusive creation. Never repair or overwrite an existing key."""
    from .db import create_private_file, validate_data_dir

    path = key_path(data_dir, configured)
    validate_data_dir(path.parent, create=True)
    if os.path.lexists(path):
        raise ValueError("The MFA encryption key already exists; preserve it.")
    create_private_file(path, secrets.token_bytes(32))
    return path


class SecretStore:
    """Authenticated encryption; invalid/missing keys never fall back to plaintext."""

    def __init__(self, data_dir, identity_key: bytes, configured=None):
        from .db import check_private_file, validate_data_dir

        path = key_path(data_dir, configured)
        if not path.parent.is_dir():
            raise ValueError("The external MFA key directory is missing; restore the original key separately from database backups.")
        try:
            validate_data_dir(path.parent)
            check_private_file(path)
            before = path.stat()
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            with os.fdopen(os.open(path, flags), "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not os.path.samestat(before, opened) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                    raise ValueError("The MFA encryption key changed while opening it.")
                material = stream.read(33)
        except OSError:
            raise ValueError("The external MFA encryption key is missing or inaccessible; preserve existing state.") from None
        if len(material) != 32 or hmac.compare_digest(material, identity_key):
            raise ValueError("Use an independent 32-byte MFA encryption key, never the identity key.")
        self.path = path
        self._cipher = AESGCM(material)
        self._binding_id = hashlib.sha256(identity_key).hexdigest()

    def _aad(self, user_id: str, generation: str) -> bytes:
        return json.dumps(["westbridge:mfa:v1", self._binding_id, user_id, generation], ensure_ascii=True, separators=(",", ":")).encode("ascii")

    def encrypt(self, secret: str, user_id: str, generation: str) -> str:
        nonce = secrets.token_bytes(12)
        encrypted = self._cipher.encrypt(nonce, secret.encode("utf-8"), self._aad(user_id, generation))
        return PREFIX + base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")

    def decrypt(self, ciphertext: str, user_id: str, generation: str) -> str:
        try:
            if not isinstance(ciphertext, str) or not ciphertext.startswith(PREFIX) or len(ciphertext) > 512:
                raise ValueError()
            encoded = ciphertext[len(PREFIX):].encode("ascii")
            packed = base64.b64decode(encoded, altchars=b"-_", validate=True)
            if len(packed) < 29 or base64.urlsafe_b64encode(packed) != encoded:
                raise ValueError()
            return self._cipher.decrypt(packed[:12], packed[12:], self._aad(user_id, generation)).decode("utf-8")
        except (InvalidTag, ValueError, UnicodeError, binascii.Error):
            raise ValueError("MFA ciphertext or encryption key is invalid; preserve existing state.") from None

    def create_binding(self) -> str:
        return self.encrypt(BINDING_TEXT, "key-binding", self._binding_id)

    def check_binding(self, ciphertext: str) -> None:
        if not hmac.compare_digest(self.decrypt(ciphertext, "key-binding", self._binding_id), BINDING_TEXT):
            raise ValueError("MFA encryption key does not match this database.")

    def validate_database(self, connection) -> None:
        row = connection.execute("SELECT ciphertext FROM mfa_key_binding WHERE id=1").fetchone()
        if row is None:
            raise ValueError("MFA encryption key binding is missing; preserve existing state.")
        self.check_binding(row[0])
        for row in connection.execute("SELECT * FROM admin_mfa"):
            if (not isinstance(row["generation"], str) or not re.fullmatch(r"[0-9a-f]{32}", row["generation"])
                    or type(row["last_counter"]) is not int or row["last_counter"] < -1):
                raise ValueError("An administrator authenticator is invalid; preserve existing state.")
            secret = self.decrypt(row["secret_ciphertext"], row["user_id"], row["generation"])
            try:
                valid = len(secret) == 32 and len(base64.b32decode(secret, casefold=False)) == 20
            except (binascii.Error, ValueError):
                valid = False
            if not valid:
                raise ValueError("An administrator authenticator is invalid; preserve existing state.")
