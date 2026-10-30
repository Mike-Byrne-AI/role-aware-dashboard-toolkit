"""Offline screening for newly chosen passwords; never applied during sign-in."""

import gzip
from pathlib import Path

MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128
_DATA = Path(__file__).with_name("password_data") / "common-passwords.txt.gz"

# Load once, without network access. A missing or damaged shipped corpus must
# fail startup rather than silently disable screening. SOURCE.txt records its
# version, checksum and limitations; this is not a current breach lookup.
with gzip.open(_DATA, "rt", encoding="utf-8") as _source:
    _COMMON_PASSWORDS = frozenset(line.strip().casefold() for line in _source)
_MAX_COMMON_LENGTH = max(map(len, _COMMON_PASSWORDS))


def _common_or_repeated(candidate: str) -> bool:
    if candidate in _COMMON_PASSWORDS:
        return True
    # A common password repeated two or more times is still predictable. Only
    # consider units covering the whole candidate; unrelated phrases containing
    # a listed word are allowed. At most 33 lookups for the shipped corpus.
    for size in range(1, min(len(candidate) // 2, _MAX_COMMON_LENGTH) + 1):
        if len(candidate) % size:
            continue
        unit = candidate[:size]
        if unit in _COMMON_PASSWORDS and candidate == unit * (len(candidate) // size):
            return True
    return False


def password_policy_error(password: str, *, username: str, name: str) -> str | None:
    """Return safe guidance, without returning or logging the submitted value."""
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        return "Use 15 to 128 characters for your new password."
    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        return "Use valid text for your new password."
    # Normalize only this comparison, never the value that is stored/verified.
    candidate = password.strip().casefold()
    expected = {username.strip().casefold(), name.strip().casefold(),
                "westbridge", "westbridge business group"}
    if not candidate or _common_or_repeated(candidate) or candidate in expected:
        return (
            "Choose a less common password. Try a unique passphrase with several "
            "unrelated words, or use a password manager to generate one."
        )
    return None
