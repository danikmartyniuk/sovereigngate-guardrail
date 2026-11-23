import base64
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from sovereigngate.config import (
    EntityAction,
    EntityRule,
    ErrorPolicy,
    OperatingMode,
    PolicyConfig,
    PolicyLoadError,
    load_hmac_secret,
    load_policy,
)


def test_policy_defaults_are_shadow_and_fail_closed() -> None:
    config = PolicyConfig()

    assert config.mode is OperatingMode.SHADOW
    assert config.on_error is ErrorPolicy.FAIL_CLOSED
    assert config.ner.enabled is False


def test_default_policy_file_is_valid() -> None:
    config = load_policy(environ={})

    assert config.mode is OperatingMode.SHADOW
    assert "PL_PESEL" in config.entities
    assert config.ner.enabled is False


def test_policy_rejects_unknown_fields_and_invalid_entity_names() -> None:
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate({"unexpected": True})
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate({"entities": {"bad-name": {}}})


def test_entity_policy_models_are_frozen() -> None:
    rule = EntityRule(action=EntityAction.BLOCK)

    with pytest.raises(ValidationError):
        rule.action = EntityAction.MASK


def test_load_policy_uses_environment_path(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("mode: enforce\non_error: fail_closed\n", encoding="utf-8")

    config = load_policy(environ={"SOVEREIGNGATE_POLICY_PATH": str(policy_path)})

    assert config.mode is OperatingMode.ENFORCE


def test_load_policy_sanitizes_yaml_and_validation_errors(tmp_path: Path) -> None:
    malformed_path = tmp_path / "malformed.yaml"
    malformed_text = "mode: [secret-looking-user-value"
    malformed_path.write_text(malformed_text, encoding="utf-8")

    with pytest.raises(PolicyLoadError) as malformed_error:
        load_policy(malformed_path)
    assert malformed_text not in str(malformed_error.value)

    invalid_path = tmp_path / "invalid.yaml"
    invalid_path.write_text("mode: private-input-value\n", encoding="utf-8")
    with pytest.raises(PolicyLoadError) as validation_error:
        load_policy(invalid_path)
    assert "private-input-value" not in str(validation_error.value)


def test_load_hmac_secret_accepts_hex_and_base64() -> None:
    secret = bytes(range(32))

    assert load_hmac_secret({"SOVEREIGNGATE_HMAC_SECRET": secret.hex()}) == secret
    assert (
        load_hmac_secret({"SOVEREIGNGATE_HMAC_SECRET": base64.b64encode(secret).decode("ascii")})
        == secret
    )


def test_load_hmac_secret_rejects_short_or_invalid_values() -> None:
    with pytest.raises(PolicyLoadError):
        load_hmac_secret({"SOVEREIGNGATE_HMAC_SECRET": "0123"})
    with pytest.raises(PolicyLoadError) as error:
        load_hmac_secret({"SOVEREIGNGATE_HMAC_SECRET": "not-a-valid-secret"})
    assert "not-a-valid-secret" not in str(error.value)


def test_development_secret_is_ephemeral_and_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    environment = {"SOVEREIGNGATE_ENV": "development"}
    with caplog.at_level(logging.WARNING, logger="sovereigngate.config"):
        first = load_hmac_secret(environment)
        second = load_hmac_secret(environment)

    assert len(first) == 32
    assert first != second
    assert "ephemeral HMAC key" in caplog.text
    assert first.hex() not in caplog.text


def test_production_requires_secret() -> None:
    with pytest.raises(PolicyLoadError, match="required outside development"):
        load_hmac_secret({"SOVEREIGNGATE_ENV": "production"})
