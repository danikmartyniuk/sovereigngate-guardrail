import json
import logging
import traceback
from pathlib import Path

import httpx
import pytest
import structlog.testing
from litellm.exceptions import GuardrailRaisedException

from sovereigngate.adapters.litellm_guardrail import SovereignGateGuardrail
from sovereigngate.config import EntityAction, EntityRule, OperatingMode, PolicyConfig
from sovereigngate.evidence.audit_log import AuditLog, read_records

_SECRET = bytes(range(32))
_SYNTHETIC_IDENTIFIERS: tuple[tuple[str, str], ...] = (
    ("PL_PESEL", "00210100004"),
    ("ES_DNI", "12345678Z"),
    ("FR_NIR", "180010100100162"),
    ("DE_STEUERID", "12234567899"),
    ("IBAN", "DE89370400440532013000"),
)


def _read_database_files(directory: Path) -> bytes:
    return b"".join(path.read_bytes() for path in directory.iterdir() if path.is_file())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("entity_type", "identifier"),
    _SYNTHETIC_IDENTIFIERS,
    ids=[entity_type for entity_type, _ in _SYNTHETIC_IDENTIFIERS],
)
async def test_synthetic_identifiers_never_reach_diagnostics_or_audit(
    entity_type: str,
    identifier: str,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "audit.db"
    policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        entities={entity_type: EntityRule(action=EntityAction.BLOCK)},
    )
    payload = {
        "model": "local/security-test",
        "messages": [{"role": "user", "content": f"Please inspect {identifier}."}],
    }

    with AuditLog(database_path) as audit_log:
        guardrail = SovereignGateGuardrail(policy, _SECRET, audit_log=audit_log)
        with caplog.at_level(logging.DEBUG), structlog.testing.capture_logs() as events:
            with pytest.raises(GuardrailRaisedException) as error:
                await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    error_response = httpx.Response(
        status_code=error.value.status_code,
        json={"detail": str(error.value)},
    )
    records = read_records(database_path)
    assert len(records) == 1
    assert records[0].entities_detected == {entity_type: 1}

    captured_outputs = (
        str(error.value),
        "".join(traceback.format_exception(error.value)),
        error_response.text,
        caplog.text,
        json.dumps(events, ensure_ascii=False, default=str),
        records[0].model_dump_json(),
    )
    for output in captured_outputs:
        assert identifier not in output
    database_bytes = _read_database_files(tmp_path)
    assert identifier.encode() not in database_bytes
    assert error_response.status_code == 403

    for record in caplog.records:
        assert identifier not in record.getMessage()
        assert identifier not in repr(record.msg)
        assert identifier not in repr(record.args)
