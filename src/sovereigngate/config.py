import base64
import binascii
import logging
import os
import re
import secrets
import sysconfig
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)
_MAX_POLICY_BYTES: Final[int] = 1_048_576
_ENTITY_NAME_PATTERN: Final[str] = r"^[A-Z][A-Z0-9_]{0,63}$"
_SHA256_PATTERN: Final[str] = r"^[A-Fa-f0-9]{64}$"

EntityName = Annotated[str, StringConstraints(pattern=_ENTITY_NAME_PATTERN)]


class OperatingMode(StrEnum):
    SHADOW = "shadow"
    ENFORCE = "enforce"


class ErrorPolicy(StrEnum):
    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"


class EntityAction(StrEnum):
    MASK = "mask"
    BLOCK = "block"
    SHADOW_LOG = "shadow_log"
    ALLOW = "allow"


class Sensitivity(StrEnum):
    STANDARD = "standard"
    SPECIAL_CATEGORY = "special_category"


class EncodedContentAction(StrEnum):
    BLOCK = "block"
    SHADOW_LOG = "shadow_log"
    DECODE_UTF8_ONCE = "decode_utf8_once"


class PolicyLoadError(ValueError):
    """A policy loading error with no source document or secret values attached."""


class EntityRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    action: EntityAction = EntityAction.MASK
    sensitivity: Sensitivity = Sensitivity.STANDARD


class NormalizationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    strip_zero_width: bool = True
    collapse_separator_obfuscation: bool = True
    entropy_min_length: int = Field(default=48, ge=48, le=65_536)
    entropy_threshold: float = Field(default=4.5, gt=0.0, le=8.0)
    max_encoded_length: int = Field(default=4096, ge=48, le=1_048_576)
    encoded_content_action: EncodedContentAction = EncodedContentAction.BLOCK


class NerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    model_dir: Path | None = None
    artifact_sha256: Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)] | None = None
    languages: tuple[str, ...] = ()

    @model_validator(mode="after")
    def require_local_model_when_enabled(self) -> Self:
        if self.enabled and (self.model_dir is None or self.artifact_sha256 is None):
            raise ValueError("Enabled NER requires a local model directory and SHA-256 digest")
        return self


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: OperatingMode = OperatingMode.SHADOW
    on_error: ErrorPolicy = ErrorPolicy.FAIL_CLOSED
    normalization: NormalizationConfig = Field(default_factory=NormalizationConfig)
    ner: NerConfig = Field(default_factory=NerConfig)
    entities: dict[EntityName, EntityRule] = Field(default_factory=dict)


def _default_policy_path() -> Path:
    source_tree_path = Path.cwd() / "rules" / "eu_default_v1.yaml"
    if source_tree_path.is_file():
        return source_tree_path
    installed_data_path = Path(sysconfig.get_path("data")) / "share" / "sovereigngate" / "rules"
    installed_data_path /= "eu_default_v1.yaml"
    return installed_data_path


def _validation_field_names(error: ValidationError) -> str:
    paths = {
        ".".join(str(part) for part in item["loc"])
        for item in error.errors(include_input=False)
    }
    return ", ".join(sorted(paths)) or "unknown field"


def load_policy(
    policy_path: str | Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> PolicyConfig:
    """Load a strict policy without exposing YAML contents in error messages."""
    environment = os.environ if environ is None else environ
    if policy_path is not None:
        selected_path = Path(policy_path)
    elif "SOVEREIGNGATE_POLICY_PATH" in environment:
        selected_path = Path(environment["SOVEREIGNGATE_POLICY_PATH"])
    else:
        selected_path = _default_policy_path()

    try:
        policy_bytes = selected_path.read_bytes()
    except OSError:
        raise PolicyLoadError("Unable to read the configured policy file") from None

    if len(policy_bytes) > _MAX_POLICY_BYTES:
        raise PolicyLoadError("The configured policy file exceeds the 1 MiB size limit")

    try:
        policy_data = yaml.safe_load(policy_bytes)
    except (yaml.YAMLError, UnicodeDecodeError):
        raise PolicyLoadError(
            "The configured policy file is malformed YAML or invalid UTF-8"
        ) from None

    try:
        return PolicyConfig.model_validate(policy_data)
    except ValidationError as error:
        fields = _validation_field_names(error)
        raise PolicyLoadError(f"Policy validation failed for fields: {fields}") from None


def _decode_secret(secret_text: str) -> bytes:
    if re.fullmatch(r"(?:[A-Fa-f0-9]{2})+", secret_text):
        try:
            return bytes.fromhex(secret_text)
        except ValueError:
            raise PolicyLoadError("SOVEREIGNGATE_HMAC_SECRET is not valid hex or base64") from None

    try:
        return base64.b64decode(secret_text, validate=True)
    except (binascii.Error, ValueError):
        raise PolicyLoadError("SOVEREIGNGATE_HMAC_SECRET is not valid hex or base64") from None


def load_hmac_secret(environ: Mapping[str, str] | None = None) -> bytes:
    """Load a decoded 32-byte-or-longer secret or create a development-only key."""
    environment = os.environ if environ is None else environ
    secret_text = environment.get("SOVEREIGNGATE_HMAC_SECRET")
    if secret_text is not None:
        secret = _decode_secret(secret_text)
        if len(secret) < 32:
            raise PolicyLoadError("SOVEREIGNGATE_HMAC_SECRET must decode to at least 32 bytes")
        return secret

    if environment.get("SOVEREIGNGATE_ENV", "production").lower() == "development":
        _LOGGER.warning(
            "Using an ephemeral HMAC key for development; "
            "session tokens will not survive process restart"
        )
        return secrets.token_bytes(32)

    raise PolicyLoadError("SOVEREIGNGATE_HMAC_SECRET is required outside development")
