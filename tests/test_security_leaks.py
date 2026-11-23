import base64
import json
import logging
import random
import string
import traceback

import pytest
from litellm.exceptions import GuardrailRaisedException

import sovereigngate.engine.pipeline as pipeline_module
from sovereigngate.adapters.litellm_guardrail import SovereignGateGuardrail
from sovereigngate.config import (
    EncodedContentAction,
    EntityAction,
    EntityRule,
    ErrorPolicy,
    NormalizationConfig,
    OperatingMode,
    PolicyConfig,
    Sensitivity,
)

_SECRET = bytes(range(32))
_SYNTHETIC_PII = "00210100004"


def _guardrail(policy: PolicyConfig | None = None) -> SovereignGateGuardrail:
    return SovereignGateGuardrail(
        policy
        or PolicyConfig(
            mode=OperatingMode.ENFORCE,
            entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
        ),
        _SECRET,
    )


def _render_exception(error: BaseException) -> str:
    return "".join(traceback.format_exception(error))


def _render_exception_chain(error: BaseException) -> str:
    rendered: list[str] = []
    pending: list[BaseException] = [error]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        rendered.append(repr(current.args))
        rendered.append(repr(vars(current)))
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return " ".join(rendered)


def _assert_no_leak(value: str, caplog: pytest.LogCaptureFixture, *outputs: str) -> None:
    for output in outputs:
        assert value not in output
    for record in caplog.records:
        assert value not in record.getMessage()
        assert value not in repr(record.msg)
        assert value not in repr(record.args)
        assert record.levelno in {logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR}


@pytest.mark.asyncio
async def test_masking_emits_only_pii_free_metadata_and_no_raw_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    guardrail = _guardrail()
    payload = {"messages": [{"role": "user", "content": f"PESEL {_SYNTHETIC_PII}"}]}

    with caplog.at_level(logging.DEBUG):
        outbound = await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    _assert_no_leak(
        _SYNTHETIC_PII,
        caplog,
        json.dumps(outbound["metadata"]),
        outbound["messages"][0]["content"],
    )
    assert outbound["metadata"]["detected_entity_types"] == ["PL_PESEL"]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_stage", ["normalization", "detector"])
async def test_fail_closed_pipeline_errors_hide_values_in_logs_and_tracebacks(
    failure_stage: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw_error = f"synthetic pipeline failure containing {_SYNTHETIC_PII}"

    def fail_with_raw_detail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(raw_error)

    target = "normalize_text" if failure_stage == "normalization" else "detect_tier1"
    monkeypatch.setattr(pipeline_module, target, fail_with_raw_detail)
    guardrail = _guardrail()
    payload = {"messages": [{"role": "user", "content": _SYNTHETIC_PII}]}

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(GuardrailRaisedException) as error:
            await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    _assert_no_leak(
        _SYNTHETIC_PII,
        caplog,
        str(error.value),
        _render_exception(error.value),
        _render_exception_chain(error.value),
    )
    assert payload["messages"][0]["content"] == _SYNTHETIC_PII
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_fail_closed_encoded_decode_error_has_no_raw_exception_context(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    rng = random.Random(20261123)
    alphabet = string.ascii_letters + string.digits
    noise = " ".join(
        "".join(rng.choice(alphabet) for _ in range(12)) for _ in range(10)
    )
    decoded_text = f"record {_SYNTHETIC_PII} {noise}"
    encoded_blob = base64.b64encode(decoded_text.encode()).decode()
    raw_error = f"decode failure containing {_SYNTHETIC_PII}"
    real_normalize = pipeline_module.normalize_text
    normalize_calls = 0

    def fail_during_decoded_scan(text: str, config: NormalizationConfig):
        nonlocal normalize_calls
        normalize_calls += 1
        if normalize_calls == 2:
            raise RuntimeError(raw_error)
        return real_normalize(text, config)

    monkeypatch.setattr(pipeline_module, "normalize_text", fail_during_decoded_scan)
    policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        normalization=NormalizationConfig(
            encoded_content_action=EncodedContentAction.DECODE_UTF8_ONCE
        ),
        entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
    )
    guardrail = _guardrail(policy)
    payload = {"messages": [{"role": "user", "content": encoded_blob}]}

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(GuardrailRaisedException) as error:
            await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    _assert_no_leak(
        _SYNTHETIC_PII,
        caplog,
        str(error.value),
        _render_exception(error.value),
        _render_exception_chain(error.value),
    )
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_malformed_tool_json_has_no_raw_value_in_exception_or_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    guardrail = _guardrail()
    malformed = f'{{"identifier":{_SYNTHETIC_PII}'
    payload = {
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {"function": {"name": "lookup", "arguments": malformed}}
                ],
            }
        ]
    }

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(GuardrailRaisedException) as error:
            await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    _assert_no_leak(
        _SYNTHETIC_PII,
        caplog,
        str(error.value),
        _render_exception(error.value),
        _render_exception_chain(error.value),
    )
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_policy_block_is_sanitized_at_every_error_surface(
    caplog: pytest.LogCaptureFixture,
) -> None:
    guardrail = _guardrail(
        PolicyConfig(
            mode=OperatingMode.ENFORCE,
            entities={
                "PL_PESEL": EntityRule(
                    action=EntityAction.BLOCK,
                    sensitivity=Sensitivity.SPECIAL_CATEGORY,
                )
            },
        )
    )
    payload = {"messages": [{"role": "user", "content": _SYNTHETIC_PII}]}

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(GuardrailRaisedException) as error:
            await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    _assert_no_leak(
        _SYNTHETIC_PII,
        caplog,
        str(error.value),
        _render_exception(error.value),
        _render_exception_chain(error.value),
    )
    assert "PL_PESEL + special_category" in str(error.value)


@pytest.mark.asyncio
async def test_stream_failure_hides_provider_error_values_and_wipes_vault(
    caplog: pytest.LogCaptureFixture,
) -> None:
    guardrail = _guardrail()
    request = {
        "messages": [{"role": "user", "content": _SYNTHETIC_PII}],
    }
    outbound = await guardrail.async_pre_call_hook(None, None, request, "acompletion")
    raw_error = f"synthetic provider stream failure with {_SYNTHETIC_PII}"

    async def broken_stream():
        raise RuntimeError(raw_error)
        yield {}

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(GuardrailRaisedException) as error:
            async for _ in guardrail.async_post_call_streaming_iterator_hook(
                None, broken_stream(), outbound
            ):
                pass

    _assert_no_leak(
        _SYNTHETIC_PII,
        caplog,
        str(error.value),
        _render_exception(error.value),
        _render_exception_chain(error.value),
    )
    assert error.value.status_code == 502
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_explicit_fail_open_surfaces_only_sanitized_failure_metadata(
    caplog: pytest.LogCaptureFixture,
) -> None:
    guardrail = _guardrail(
        PolicyConfig(
            mode=OperatingMode.ENFORCE,
            on_error=ErrorPolicy.FAIL_OPEN,
            entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
        )
    )
    payload = {
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {"function": {"name": "lookup", "arguments": f'{{"id":{_SYNTHETIC_PII}'}}
                ],
            }
        ]
    }

    with caplog.at_level(logging.DEBUG):
        outbound = await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    _assert_no_leak(_SYNTHETIC_PII, caplog, json.dumps(outbound["metadata"]))
    assert outbound["metadata"]["sovereigngate_processing_error"] == "malformed_tool_arguments"
