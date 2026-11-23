import hashlib
import hmac

import pytest

import sovereigngate.engine.vault as vault_module
from sovereigngate.engine.vault import (
    SessionVault,
    StreamRehydrator,
    VaultCollisionError,
    VaultError,
)

_SECRET = bytes(range(32))


def test_vault_uses_required_session_hmac_and_canonical_identifier() -> None:
    vault = SessionVault(_SECRET, "conversation-1")
    formatted = "00 21 01 00 00 4"
    canonical = "00210100004"

    token = vault.tokenize("PL_PESEL", formatted)
    expected_suffix = hmac.new(
        _SECRET,
        f"conversation-1:PL_PESEL:{canonical}".encode(),
        hashlib.sha256,
    ).hexdigest()[:6].upper()

    assert token == f"[PL_PESEL_{expected_suffix}]"
    assert vault.tokenize("PL_PESEL", canonical) == token
    assert vault.rehydrate(token) == formatted


def test_vault_tokens_are_stable_only_for_same_session() -> None:
    first = SessionVault(_SECRET, "conversation-1")
    second = SessionVault(_SECRET, "conversation-2")

    assert first.tokenize("PERSON", "Alice") != second.tokenize("PERSON", "Alice")


def test_vault_detects_collisions_without_exposing_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault_module, "_derive_suffix", lambda _secret, _message: "ABC123")
    vault = SessionVault(_SECRET, "conversation-1")
    first_value = "synthetic-first-value"
    second_value = "synthetic-second-value"
    token = vault.tokenize("PERSON", first_value)

    with pytest.raises(VaultCollisionError) as error:
        vault.tokenize("PERSON", second_value)

    assert token == "[PERSON_ABC123]"
    assert first_value not in str(error.value)
    assert second_value not in str(error.value)
    assert vault.rehydrate(token) == first_value


def test_vault_representation_and_wipe_redact_retained_values() -> None:
    value = "synthetic-private-value"
    vault = SessionVault(_SECRET, "conversation-1")
    token = vault.tokenize("PERSON", value)
    entry = vault._entries[token]

    assert repr(vault) == "<SessionVault [REDACTED]>"
    assert str(vault) == "<SessionVault [REDACTED]>"
    assert value not in repr(vault)

    vault.wipe()
    assert entry.original_value == ""
    assert entry.canonical_value == ""
    assert vault._entries == {}
    assert vault.rehydrate(token) == token
    with pytest.raises(VaultError, match="wiped"):
        vault.tokenize("PERSON", value)


def test_vault_rejects_short_secrets_and_long_entity_tokens() -> None:
    with pytest.raises(VaultError):
        SessionVault(b"short", "conversation-1")

    vault = SessionVault(_SECRET, "conversation-1")
    with pytest.raises(VaultError, match="entity type"):
        vault.tokenize("A" + "B" * 23, "value")


def test_stream_rehydrator_handles_every_token_split() -> None:
    vault = SessionVault(_SECRET, "conversation-1")
    token = vault.tokenize("PL_PESEL", "00210100004")
    for split in range(len(token) + 1):
        stream = StreamRehydrator(vault)
        result = stream.feed("before " + token[:split])
        result += stream.feed(token[split:] + " after", final=True)
        assert result == "before 00210100004 after"


def test_stream_rehydrator_supports_maximum_token_length_and_unknown_tokens() -> None:
    entity_type = "A" + "B" * 22
    vault = SessionVault(_SECRET, "conversation-1")
    token = vault.tokenize(entity_type, "synthetic-value")
    assert len(token) == 32

    stream = StreamRehydrator(vault)
    output = stream.feed(token[:31]) + stream.feed(token[31:], final=True)
    assert output == "synthetic-value"
    assert vault.rehydrate("[UNKNOWN_123ABC]") == "[UNKNOWN_123ABC]"


def test_stream_rehydrator_flushes_non_token_prefix_and_final_partial() -> None:
    stream = StreamRehydrator(SessionVault(_SECRET, "conversation-1"))
    assert stream.feed("ordinary [not a token") == "ordinary [not a token"

    partial_stream = StreamRehydrator(SessionVault(_SECRET, "conversation-1"))
    assert partial_stream.feed("text [PL_PESEL_ABC") == "text "
    assert partial_stream.feed("", final=True) == "[PL_PESEL_ABC"
