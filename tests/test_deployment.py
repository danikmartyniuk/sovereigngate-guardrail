from pathlib import Path
from typing import Final

import pytest
import yaml
from litellm.proxy.types_utils.utils import get_instance_fn
from litellm.types.guardrails import LitellmParams

from sovereigngate.evidence.audit_log import verify_log

_ROOT: Final[Path] = Path(__file__).resolve().parents[1]


def test_litellm_sample_uses_custom_guardrail_for_pre_and_post_call() -> None:
    config = yaml.safe_load(
        (_ROOT / "deploy" / "litellm_config.yaml").read_text(encoding="utf-8")
    )
    entries = config["litellm_settings"]["guardrails"]
    params = entries[0]["litellm_params"]

    assert entries[0]["guardrail_name"] == "sovereigngate"
    assert params["guardrail"] == (
        "sovereigngate.adapters.litellm_guardrail.SovereignGateGuardrail"
    )
    assert params["mode"] == ["pre_call", "post_call"]
    assert params["default_on"] is True
    assert params["trusted_routes"] == []
    assert params["internal_tools"] == []
    assert "OPENAI_API_KEY" in config["model_list"][0]["litellm_params"]["api_key"]


def test_compose_stack_persists_audit_and_mounts_only_local_ner_assets() -> None:
    compose = yaml.safe_load(
        (_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
    )
    service = compose["services"]["litellm"]
    dockerfile = (_ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")

    assert "audit-data:/var/lib/sovereigngate" in service["volumes"]
    assert "./ner-models:/opt/sovereigngate/ner:ro" in service["volumes"]
    assert service["stop_grace_period"] == "20s"
    assert "litellm[proxy]" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "huggingface" not in dockerfile.lower()


def test_compose_requires_operator_secrets_without_committing_values() -> None:
    compose = (_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
    environment_template = (_ROOT / "deploy" / ".env.example").read_text(encoding="utf-8")

    assert "${LITELLM_MASTER_KEY:?" in compose
    assert "${OPENAI_API_KEY:?" in compose
    assert "${SOVEREIGNGATE_HMAC_SECRET:?" in compose
    assert "LITELLM_MASTER_KEY=\n" in environment_template
    assert "OPENAI_API_KEY=\n" in environment_template
    assert "SOVEREIGNGATE_HMAC_SECRET=\n" in environment_template


def test_litellm_loader_instantiates_guardrail_with_local_policy_and_audit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = _ROOT / "deploy" / "litellm_config.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    entry = config["litellm_settings"]["guardrails"][0]
    params = LitellmParams.model_validate(entry["litellm_params"])
    database_path = tmp_path / "audit.db"
    policy_path = _ROOT / "rules" / "eu_default_v1.yaml"
    monkeypatch.setenv("SOVEREIGNGATE_HMAC_SECRET", "01" * 32)
    monkeypatch.setenv("SOVEREIGNGATE_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("SOVEREIGNGATE_AUDIT_DB", str(database_path))

    guardrail_class = get_instance_fn(params.guardrail, config_file_path=str(config_path))
    extra_params = params.model_dump(exclude_none=True)
    extra_params.pop("guardrail")
    extra_params.pop("mode")
    extra_params.pop("default_on")
    extra_params.pop("stream_scope", None)
    callback = guardrail_class(
        guardrail_name=entry["guardrail_name"],
        event_hook=params.mode,
        default_on=entry["litellm_params"].get("default_on", True),
        **extra_params,
    )

    callback.close()
    assert verify_log(database_path).record_count == 0
