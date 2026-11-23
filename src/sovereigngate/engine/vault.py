import hmac
import re
import unicodedata
from dataclasses import dataclass
from typing import Final

from sovereigngate.engine.detectors import (
    TIER1_ENTITY_TYPES,
    DetectorError,
    canonicalize_candidate,
)

_ENTITY_TYPE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Z][A-Z0-9_]{0,22}\Z")
_TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\[(?P<entity_type>[A-Z][A-Z0-9_]{0,22})_[0-9A-F]{6}\]\Z"
)
_MAX_TOKEN_LENGTH: Final[int] = 32


class VaultError(ValueError):
    """A vault error that never includes source values or token mappings."""


class VaultCollisionError(VaultError):
    """A six-hex token collision within one request vault."""


@dataclass(slots=True)
class _VaultEntry:
    canonical_value: str
    original_value: str


def _derive_suffix(secret: bytes, message: str) -> str:
    return hmac.new(secret, message.encode("utf-8"), "sha256").hexdigest()[:6].upper()


def _canonicalize(entity_type: str, value: str) -> str:
    if entity_type in TIER1_ENTITY_TYPES:
        try:
            return canonicalize_candidate(entity_type, value)
        except (DetectorError, TypeError, ValueError):
            raise VaultError("Unable to canonicalize entity value") from None
    canonical = unicodedata.normalize("NFKC", value).strip()
    if not canonical:
        raise VaultError("Entity value must not be empty")
    return canonical


class SessionVault:
    """Request-scoped HMAC pseudonyms and best-effort in-memory restoration."""

    def __init__(self, hmac_secret: bytes, session_id: str) -> None:
        if len(hmac_secret) < 32:
            raise VaultError("The HMAC secret must contain at least 32 bytes")
        if not session_id:
            raise VaultError("The session identifier must not be empty")
        self._secret = bytes(hmac_secret)
        self._session_id = session_id
        self._entries: dict[str, _VaultEntry] = {}
        self._wiped = False

    def __repr__(self) -> str:
        return "<SessionVault [REDACTED]>"

    __str__ = __repr__

    def tokenize(self, entity_type: str, original_value: str) -> str:
        if self._wiped:
            raise VaultError("The request vault has been wiped")
        if not _ENTITY_TYPE_PATTERN.fullmatch(entity_type):
            raise VaultError("The entity type is invalid")

        canonical_value = _canonicalize(entity_type, original_value)
        message = f"{self._session_id}:{entity_type}:{canonical_value}"
        token = f"[{entity_type}_{_derive_suffix(self._secret, message)}]"
        existing = self._entries.get(token)
        if existing is not None:
            if existing.canonical_value != canonical_value:
                raise VaultCollisionError(f"Token collision for {entity_type}")
            return token

        self._entries[token] = _VaultEntry(canonical_value, original_value)
        return token

    def rehydrate_token(self, token: str) -> str:
        if self._wiped:
            return token
        if not _TOKEN_PATTERN.fullmatch(token):
            return token
        entry = self._entries.get(token)
        return token if entry is None else entry.original_value

    def rehydrate(self, text: str) -> str:
        """Restore only complete placeholders present in this request's vault."""
        return _replace_tokens(text, self)

    def wipe(self) -> None:
        """Overwrite retained values and release request-scoped references."""
        if self._wiped:
            return
        for entry in self._entries.values():
            entry.canonical_value = ""
            entry.original_value = ""
        self._entries.clear()
        self._secret = b""
        self._session_id = ""
        self._wiped = True


def _replace_tokens(text: str, vault: SessionVault) -> str:
    return re.sub(
        r"\[[A-Z][A-Z0-9_]{0,22}_[0-9A-F]{6}\]",
        lambda match: vault.rehydrate_token(match.group()),
        text,
    )


class StreamRehydrator:
    """Rehydrate placeholders split across text chunks with a bounded prefix buffer."""

    def __init__(self, vault: SessionVault) -> None:
        self._vault = vault
        self._pending = ""
        self._finished = False

    def feed(self, chunk: str, *, final: bool = False) -> str:
        if self._finished:
            if chunk:
                raise VaultError("The stream buffer is already finished")
            return ""

        text = self._pending + chunk
        self._pending = ""
        output: list[str] = []
        cursor = 0
        while cursor < len(text):
            opening = text.find("[", cursor)
            if opening < 0:
                output.append(text[cursor:])
                break
            output.append(text[cursor:opening])
            closing = text.find("]", opening + 1)
            next_opening = text.find("[", opening + 1)
            if closing >= 0 and (next_opening < 0 or closing < next_opening):
                candidate = text[opening : closing + 1]
                if len(candidate) <= _MAX_TOKEN_LENGTH and _TOKEN_PATTERN.fullmatch(candidate):
                    output.append(self._vault.rehydrate_token(candidate))
                    cursor = closing + 1
                    continue
                output.append("[")
                cursor = opening + 1
                continue

            partial = text[opening:]
            if not final and _is_token_prefix(partial):
                self._pending = partial
                break
            output.append("[")
            cursor = opening + 1

        if final:
            output.append(self._pending)
            self._pending = ""
            self._finished = True
        return "".join(output)


def _is_token_prefix(value: str) -> bool:
    return (
        value.startswith("[")
        and len(value) < _MAX_TOKEN_LENGTH
        and (len(value) == 1 or "A" <= value[1] <= "Z")
        and all(
            "A" <= character <= "Z"
            or "0" <= character <= "9"
            or character == "_"
            for character in value[1:]
        )
    )
