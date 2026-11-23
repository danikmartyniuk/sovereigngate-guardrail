import base64
import json
from pathlib import Path

import pytest
from litellm.exceptions import GuardrailRaisedException
from pydantic import BaseModel

from sovereigngate.adapters.litellm_guardrail import SovereignGateGuardrail
from sovereigngate.config import (
    EntityAction,
    EntityRule,
    ErrorPolicy,
    NerConfig,
    OperatingMode,
    PolicyConfig,
    PolicyLoadError,
    Sensitivity,
)
from sovereigngate.engine.detectors import DetectionSpan
from sovereigngate.engine.ner_onnx import NerModelError
from sovereigngate.engine.normalizer import NormalizedText
from sovereigngate.evidence.audit_log import AuditAdmissionError, AuditLog, read_records

_SECRET = bytes(range(32))
_PESEL = "00210100004"


class _TextBlock(BaseModel):
    type: str
    text: str


class _Message(BaseModel):
    role: str
    content: list[_TextBlock]


class _ToolFunction(BaseModel):
    name: str
    arguments: str


class _ToolCall(BaseModel):
    function: _ToolFunction


class _AssistantToolMessage(BaseModel):
    role: str
    tool_calls: list[_ToolCall]


class _ResponseMessage(BaseModel):
    content: list[_TextBlock]
    tool_calls: list[_ToolCall]


class _ResponseChoice(BaseModel):
    message: _ResponseMessage


class _Response(BaseModel):
    choices: list[_ResponseChoice]


class _NoopNER:
    def detect(self, _normalized: NormalizedText) -> tuple[DetectionSpan, ...]:
        return ()


def _guardrail(
    policy: PolicyConfig | None = None,
    *,
    trusted_routes: frozenset[str] = frozenset(),
    internal_tools: frozenset[str] = frozenset(),
) -> SovereignGateGuardrail:
    selected_policy = policy or PolicyConfig(
        mode=OperatingMode.ENFORCE,
        entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
    )
    return SovereignGateGuardrail(
        selected_policy,
        _SECRET,
        trusted_routes=trusted_routes,
        internal_tools=internal_tools,
    )


@pytest.mark.asyncio
async def test_pre_call_copies_and_masks_content_blocks_tool_json_and_tool_outputs() -> None:
    guardrail = _guardrail()
    payload = {
        "model": "provider-model",
        "metadata": {"session_id": "conversation-1"},
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": f"PESEL {_PESEL}"}],
            },
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call-1",
                        "function": {
                            "name": "lookup",
                            "arguments": json.dumps({"id": _PESEL, "count": 3}),
                        },
                    }
                ],
            },
            {"role": "tool", "content": f"Matched {_PESEL}"},
        ],
    }

    outbound = await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    assert payload["messages"][0]["content"][0]["text"] == f"PESEL {_PESEL}"
    assert payload["messages"][1]["tool_calls"][0]["function"]["arguments"] == json.dumps(
        {"id": _PESEL, "count": 3}
    )
    user_text = outbound["messages"][0]["content"][0]["text"]
    tool_arguments = json.loads(outbound["messages"][1]["tool_calls"][0]["function"]["arguments"])
    tool_output = outbound["messages"][2]["content"]
    assert user_text.startswith("PESEL [PL_PESEL_")
    assert tool_arguments["id"] == user_text.removeprefix("PESEL ")
    assert tool_arguments["count"] == 3
    assert tool_output.startswith("Matched [PL_PESEL_")
    assert outbound["metadata"]["detected_entity_types"] == ["PL_PESEL"]
    assert outbound["metadata"]["eu_sensitive"] is False


@pytest.mark.asyncio
async def test_shadow_mode_scans_but_preserves_original_payload() -> None:
    guardrail = _guardrail(
        PolicyConfig(
            mode=OperatingMode.SHADOW,
            entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
        )
    )
    payload = {"messages": [{"role": "user", "content": f"ID {_PESEL}"}]}

    result = await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    assert result["messages"] == payload["messages"]
    assert result["metadata"]["detected_entity_types"] == ["PL_PESEL"]


@pytest.mark.asyncio
async def test_shadow_mode_scans_malformed_tool_arguments_as_text() -> None:
    guardrail = _guardrail(
        PolicyConfig(
            mode=OperatingMode.SHADOW,
            entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
        )
    )
    arguments = f"reference {_PESEL}"
    payload = {
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [{"function": {"name": "lookup", "arguments": arguments}}],
            }
        ]
    }

    result = await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    assert result["messages"][0]["tool_calls"][0]["function"]["arguments"] == arguments
    assert result["metadata"]["detected_entity_types"] == ["PL_PESEL"]
    assert "sovereigngate_processing_error" not in result["metadata"]


@pytest.mark.asyncio
async def test_pre_call_copies_and_masks_pydantic_text_blocks() -> None:
    guardrail = _guardrail()
    message = _Message(role="user", content=[_TextBlock(type="text", text=_PESEL)])
    payload = {"messages": [message]}

    result = await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    assert message.content[0].text == _PESEL
    assert isinstance(result["messages"][0], _Message)
    assert result["messages"][0].content[0].text.startswith("[PL_PESEL_")


@pytest.mark.asyncio
async def test_pre_call_copies_and_masks_pydantic_tool_call_arguments() -> None:
    guardrail = _guardrail()
    message = _AssistantToolMessage(
        role="assistant",
        tool_calls=[
            _ToolCall(
                function=_ToolFunction(
                    name="lookup",
                    arguments=json.dumps({"id": _PESEL}),
                )
            )
        ],
    )

    result = await guardrail.async_pre_call_hook(
        None, None, {"messages": [message]}, "acompletion"
    )

    token_args = json.loads(result["messages"][0].tool_calls[0].function.arguments)
    assert token_args["id"].startswith("[PL_PESEL_")
    assert json.loads(message.tool_calls[0].function.arguments) == {"id": _PESEL}


@pytest.mark.asyncio
async def test_pre_call_masks_text_completion_prompt_without_mutating_input() -> None:
    guardrail = _guardrail()
    payload = {"prompt": f"ID {_PESEL}"}

    result = await guardrail.async_pre_call_hook(None, None, payload, "text_completion")

    assert result["prompt"].startswith("ID [PL_PESEL_")
    assert payload["prompt"] == f"ID {_PESEL}"


@pytest.mark.asyncio
async def test_post_call_restores_only_trusted_text_and_allowlisted_tool_arguments() -> None:
    guardrail = _guardrail(
        trusted_routes=frozenset({"trusted-eu"}),
        internal_tools=frozenset({"internal_lookup"}),
    )
    request = {
        "model": "trusted-eu",
        "metadata": {"session_id": "conversation-1"},
        "messages": [{"role": "user", "content": _PESEL}],
    }
    outbound = await guardrail.async_pre_call_hook(None, None, request, "acompletion")
    token = outbound["messages"][0]["content"]
    response = {
        "choices": [
            {
                "message": {
                    "content": f"Found {token}",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "internal_lookup",
                                "arguments": json.dumps({"id": token}),
                            }
                        }
                    ],
                }
            }
        ]
    }

    restored = await guardrail.async_post_call_success_hook(outbound, None, response)

    assert restored["choices"][0]["message"]["content"] == f"Found {_PESEL}"
    restored_arguments = restored["choices"][0]["message"]["tool_calls"][0]["function"][
        "arguments"
    ]
    assert json.loads(restored_arguments) == {"id": _PESEL}
    assert response["choices"][0]["message"]["content"] == f"Found {token}"
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_post_call_rehydrates_pydantic_text_blocks_and_tool_models() -> None:
    guardrail = _guardrail(
        trusted_routes=frozenset({"trusted-route"}),
        internal_tools=frozenset({"internal_lookup"}),
    )
    request = {
        "model": "trusted-route",
        "metadata": {"session_id": "conversation-1"},
        "messages": [{"role": "user", "content": _PESEL}],
    }
    outbound = await guardrail.async_pre_call_hook(None, None, request, "acompletion")
    token = outbound["messages"][0]["content"]
    response = _Response(
        choices=[
            _ResponseChoice(
                message=_ResponseMessage(
                    content=[_TextBlock(type="text", text=f"Found {token}")],
                    tool_calls=[
                        _ToolCall(
                            function=_ToolFunction(
                                name="internal_lookup",
                                arguments=json.dumps({"id": token}),
                            )
                        )
                    ],
                )
            )
        ]
    )

    restored = await guardrail.async_post_call_success_hook(outbound, None, response)

    assert restored.choices[0].message.content[0].text == f"Found {_PESEL}"
    assert json.loads(restored.choices[0].message.tool_calls[0].function.arguments) == {
        "id": _PESEL
    }
    assert response.choices[0].message.content[0].text == f"Found {token}"


@pytest.mark.asyncio
async def test_retry_reuses_request_vault_and_same_token() -> None:
    guardrail = _guardrail(trusted_routes=frozenset({"trusted-eu"}))
    request = {
        "model": "trusted-eu",
        "metadata": {"session_id": "conversation-1"},
        "messages": [{"role": "user", "content": _PESEL}],
    }
    first_attempt = await guardrail.async_pre_call_hook(None, None, request, "acompletion")
    token = first_attempt["messages"][0]["content"]
    retry_request = {**request, "metadata": first_attempt["metadata"]}

    retry_attempt = await guardrail.async_pre_call_hook(None, None, retry_request, "acompletion")
    response = {"choices": [{"message": {"content": token}}]}
    restored = await guardrail.async_post_call_success_hook(retry_attempt, None, response)

    assert retry_attempt["messages"][0]["content"] == token
    assert restored["choices"][0]["message"]["content"] == _PESEL
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_pre_call_and_response_hooks_use_litellm_metadata_bucket() -> None:
    guardrail = _guardrail(trusted_routes=frozenset({"trusted-route"}))
    request = {
        "model": "trusted-route",
        "litellm_metadata": {"session_id": "conversation-1"},
        "messages": [{"role": "user", "content": _PESEL}],
    }
    outbound = await guardrail.async_pre_call_hook(None, None, request, "acompletion")
    token = outbound["messages"][0]["content"]

    response = await guardrail.async_post_call_success_hook(
        outbound,
        None,
        {"choices": [{"message": {"content": token}}]},
    )

    assert "metadata" not in outbound
    assert outbound["litellm_metadata"]["detected_entity_types"] == ["PL_PESEL"]
    assert response["choices"][0]["message"]["content"] == _PESEL


@pytest.mark.asyncio
async def test_post_call_tool_json_errors_follow_enforce_error_policy() -> None:
    fail_closed = _guardrail(
        PolicyConfig(
            mode=OperatingMode.ENFORCE,
            on_error=ErrorPolicy.FAIL_CLOSED,
            entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
        ),
        internal_tools=frozenset({"internal_lookup"}),
    )
    fail_open = _guardrail(
        PolicyConfig(
            mode=OperatingMode.ENFORCE,
            on_error=ErrorPolicy.FAIL_OPEN,
            entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
        ),
        internal_tools=frozenset({"internal_lookup"}),
    )
    request = {
        "model": "trusted-route",
        "metadata": {"session_id": "conversation-1"},
        "messages": [{"role": "user", "content": _PESEL}],
    }
    response = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "function": {
                                "name": "internal_lookup",
                                "arguments": f"malformed {_PESEL}",
                            }
                        }
                    ]
                }
            }
        ]
    }
    closed_request = await fail_closed.async_pre_call_hook(None, None, request, "acompletion")
    open_request = await fail_open.async_pre_call_hook(None, None, request, "acompletion")

    with pytest.raises(GuardrailRaisedException) as error:
        await fail_closed.async_post_call_success_hook(closed_request, None, response)
    open_response = await fail_open.async_post_call_success_hook(open_request, None, response)

    assert _PESEL not in str(error.value)
    assert open_response == response
    assert (
        open_request["metadata"]["sovereigngate_processing_error"]
        == "response_processing_failure"
    )
    assert fail_closed._contexts == {}
    assert fail_open._contexts == {}


@pytest.mark.asyncio
async def test_fail_open_stream_transform_error_returns_chunk_with_degraded_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guardrail = _guardrail(
        PolicyConfig(
            mode=OperatingMode.ENFORCE,
            on_error=ErrorPolicy.FAIL_OPEN,
            entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
        ),
        trusted_routes=frozenset({"trusted-route"}),
    )
    outbound = await guardrail.async_pre_call_hook(
        None,
        None,
        {
            "model": "trusted-route",
            "metadata": {"session_id": "conversation-1"},
            "messages": [{"role": "user", "content": _PESEL}],
        },
        "acompletion",
    )
    chunk = {"choices": [{"index": 0, "delta": {"content": "safe token text"}}]}

    def fail_transform(_chunk: object, _context: object) -> object:
        raise RuntimeError(f"synthetic failure {_PESEL}")

    monkeypatch.setattr(guardrail, "_transform_stream_chunk", fail_transform)

    async def source():
        yield chunk

    results = [
        result
        async for result in guardrail.async_post_call_streaming_iterator_hook(
            None, source(), outbound
        )
    ]

    assert results == [chunk]
    assert outbound["metadata"]["sovereigngate_processing_error"] == "stream_processing_failure"
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_stream_without_request_context_passes_chunks_through() -> None:
    guardrail = _guardrail()
    chunk = {"choices": [{"delta": {"content": "plain text"}}]}

    async def source():
        yield chunk

    results = [
        result
        async for result in guardrail.async_post_call_streaming_iterator_hook(
            None, source(), {}
        )
    ]

    assert results == [chunk]
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_untrusted_route_keeps_assistant_placeholder_but_restores_allowed_tool() -> None:
    guardrail = _guardrail(internal_tools=frozenset({"internal_lookup"}))
    request = {
        "model": "external-route",
        "metadata": {"session_id": "conversation-1"},
        "messages": [{"role": "user", "content": _PESEL}],
    }
    outbound = await guardrail.async_pre_call_hook(None, None, request, "acompletion")
    token = outbound["messages"][0]["content"]
    response = {
        "choices": [
            {
                "message": {
                    "content": f"Found {token}",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "internal_lookup",
                                "arguments": json.dumps({"id": token}),
                            }
                        }
                    ],
                }
            }
        ]
    }

    restored = await guardrail.async_post_call_success_hook(outbound, None, response)

    assert restored["choices"][0]["message"]["content"] == f"Found {token}"
    arguments = restored["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert json.loads(arguments) == {"id": _PESEL}


@pytest.mark.asyncio
async def test_policy_block_is_a_sanitized_litellm_403() -> None:
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
    payload = {"messages": [{"role": "user", "content": _PESEL}]}

    with pytest.raises(GuardrailRaisedException) as error:
        await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    assert error.value.status_code == 403
    assert error.value.blocked_content is True
    assert "PL_PESEL + special_category" in str(error.value)
    assert _PESEL not in str(error.value)
    assert payload["messages"][0]["content"] == _PESEL
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_encoded_payload_block_uses_sanitized_entity_label() -> None:
    guardrail = _guardrail()
    encoded_blob = base64.b64encode(bytes(range(64))).decode("ascii")
    payload = {"messages": [{"role": "user", "content": encoded_blob}]}

    with pytest.raises(GuardrailRaisedException) as error:
        await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    assert error.value.status_code == 403
    assert "ENCODED_CONTENT" in str(error.value)
    assert encoded_blob not in str(error.value)
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_blocked_pre_call_is_audited_without_persisting_source_text(
    tmp_path: Path,
) -> None:
    policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        entities={"PL_PESEL": EntityRule(action=EntityAction.BLOCK)},
    )
    database_path = tmp_path / "audit.db"
    payload = {"messages": [{"role": "user", "content": _PESEL}]}

    with AuditLog(database_path) as audit_log:
        guardrail = SovereignGateGuardrail(policy, _SECRET, audit_log=audit_log)
        with pytest.raises(GuardrailRaisedException):
            await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    records = read_records(database_path)
    assert records[0].action_taken == "blocked"
    assert records[0].entities_detected == {"PL_PESEL": 1}
    assert _PESEL.encode() not in database_path.read_bytes()


@pytest.mark.asyncio
async def test_litellm_constructor_options_load_policy_and_flush_owned_audit(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "mode: enforce\n"
        "entities:\n"
        "  PL_PESEL: {enabled: true, action: mask, sensitivity: standard}\n",
        encoding="utf-8",
    )
    audit_path = tmp_path / "owned-audit.db"
    guardrail = SovereignGateGuardrail(
        hmac_secret=_SECRET,
        guardrail_name="sovereigngate-test",
        event_hook="pre_call",
        default_on=True,
        policy_path=policy_path,
        audit_db_path=audit_path,
        trusted_routes=["trusted-route"],
        internal_tools=["lookup"],
    )
    result = await guardrail.async_pre_call_hook(
        None,
        None,
        {"model": "test-model", "messages": [{"role": "user", "content": _PESEL}]},
        "acompletion",
    )
    guardrail.close()

    assert guardrail.guardrail_name == "sovereigngate-test"
    assert guardrail.policy.mode is OperatingMode.ENFORCE
    assert result["messages"][0]["content"].startswith("[PL_PESEL_")
    assert read_records(audit_path)[0].action_taken == "masked"


def test_litellm_startup_fails_on_invalid_policy_and_missing_ner_assets(tmp_path: Path) -> None:
    with pytest.raises(PolicyLoadError, match="Unable to read"):
        SovereignGateGuardrail(
            hmac_secret=_SECRET,
            policy_path=tmp_path / "missing-policy.yaml",
        )

    ner_policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        ner=NerConfig(enabled=True, model_dir=tmp_path / "missing-model", manifest_sha256="0" * 64),
        entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
    )
    with pytest.raises(NerModelError):
        SovereignGateGuardrail(ner_policy, _SECRET)


def test_constructor_rejects_invalid_keys_and_duplicate_audit_configuration(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        SovereignGateGuardrail(PolicyConfig(), b"short")

    audit_log = AuditLog(tmp_path / "external.db")
    with pytest.raises(ValueError, match="either an audit writer"):
        SovereignGateGuardrail(
            PolicyConfig(),
            _SECRET,
            audit_log=audit_log,
            audit_db_path=tmp_path / "duplicate.db",
        )
    audit_log.close()


def test_close_does_not_close_an_injected_audit_writer(tmp_path: Path) -> None:
    audit_log = AuditLog(tmp_path / "external.db")
    guardrail = SovereignGateGuardrail(PolicyConfig(), _SECRET, audit_log=audit_log)

    guardrail.close()

    assert audit_log.health.accepting is True
    audit_log.close()


@pytest.mark.asyncio
async def test_adapter_uses_explicit_local_ner_runner() -> None:
    policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        ner=NerConfig(enabled=True, model_dir="/local/model", manifest_sha256="0" * 64),
        entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
    )
    guardrail = SovereignGateGuardrail(policy, _SECRET, ner_runner=_NoopNER())

    outbound = await guardrail.async_pre_call_hook(
        None,
        None,
        {"messages": [{"role": "user", "content": "ordinary text"}]},
        "acompletion",
    )

    assert outbound["messages"][0]["content"] == "ordinary text"
    await guardrail.async_post_call_success_hook(outbound, None, {})


@pytest.mark.asyncio
async def test_malformed_tool_json_fails_closed_without_echoing_payload() -> None:
    guardrail = _guardrail()
    malformed = f'{{"id":{_PESEL}'
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

    with pytest.raises(GuardrailRaisedException) as error:
        await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    assert _PESEL not in str(error.value)
    assert "could not safely process" in str(error.value)
    assert payload["messages"][0]["tool_calls"][0]["function"]["arguments"] == malformed


@pytest.mark.asyncio
async def test_explicit_fail_open_returns_copy_with_sanitized_error_signal() -> None:
    guardrail = _guardrail(
        PolicyConfig(
            mode=OperatingMode.ENFORCE,
            on_error=ErrorPolicy.FAIL_OPEN,
            entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
        )
    )
    malformed = f'{{"id":{_PESEL}'
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

    result = await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    assert result is not payload
    assert result["messages"] == payload["messages"]
    assert result["metadata"]["sovereigngate_processing_error"] == "malformed_tool_arguments"


@pytest.mark.asyncio
async def test_malformed_message_shape_fails_closed_and_fail_open() -> None:
    payload = {"messages": ["synthetic malformed message"]}
    fail_closed = _guardrail()
    with pytest.raises(GuardrailRaisedException) as error:
        await fail_closed.async_pre_call_hook(None, None, payload, "acompletion")
    assert "synthetic malformed message" not in str(error.value)

    fail_open = _guardrail(
        PolicyConfig(
            mode=OperatingMode.ENFORCE,
            on_error=ErrorPolicy.FAIL_OPEN,
            entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
        )
    )
    returned = await fail_open.async_pre_call_hook(None, None, payload, "acompletion")
    assert returned["messages"] == payload["messages"]
    assert returned["metadata"]["sovereigngate_processing_error"] == "malformed_message"


@pytest.mark.asyncio
async def test_post_call_without_request_context_preserves_response() -> None:
    guardrail = _guardrail()
    response = {"choices": [{"message": {"content": "unchanged"}}]}

    result = await guardrail.async_post_call_success_hook({}, None, response)

    assert result is response


@pytest.mark.asyncio
async def test_streaming_hook_rehydrates_split_tokens_and_wipes_context() -> None:
    guardrail = _guardrail(trusted_routes=frozenset({"trusted-eu"}))
    request = {
        "model": "trusted-eu",
        "metadata": {"session_id": "conversation-1"},
        "messages": [{"role": "user", "content": _PESEL}],
    }
    outbound = await guardrail.async_pre_call_hook(None, None, request, "acompletion")
    token = outbound["messages"][0]["content"]

    async def response_stream():
        yield {"choices": [{"index": 0, "delta": {"content": f"Value {token[:6]}"}}]}
        yield {"choices": [{"index": 0, "delta": {"content": token[6:]}}]}
        yield {
            "choices": [
                {"index": 0, "delta": {"content": None}, "finish_reason": "stop"}
            ]
        }

    chunks = [
        chunk
        async for chunk in guardrail.async_post_call_streaming_iterator_hook(
            None, response_stream(), outbound
        )
    ]
    text = "".join(
        chunk["choices"][0]["delta"].get("content") or "" for chunk in chunks
    )

    assert text == f"Value {_PESEL}"
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_streaming_tool_arguments_rehydrate_only_for_allowlisted_tools() -> None:
    guardrail = _guardrail(internal_tools=frozenset({"internal_lookup"}))
    request = {
        "model": "external-route",
        "metadata": {"session_id": "conversation-1"},
        "messages": [{"role": "user", "content": _PESEL}],
    }
    outbound = await guardrail.async_pre_call_hook(None, None, request, "acompletion")
    token = outbound["messages"][0]["content"]

    async def response_stream():
        yield {
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "content": f"Value {token}",
                        "tool_calls": [
                            {
                                "index": 0,
                                "function": {
                                    "name": "internal_lookup",
                                    "arguments": f'{{"id":"{token[:6]}',
                                },
                            }
                        ]
                    },
                }
            ]
        }
        yield {
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "function": {"arguments": token[6:] + '"}'},
                            }
                        ]
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        }

    chunks = [
        chunk
        async for chunk in guardrail.async_post_call_streaming_iterator_hook(
            None, response_stream(), outbound
        )
    ]
    arguments = "".join(
        call["function"].get("arguments", "")
        for chunk in chunks
        for call in chunk["choices"][0]["delta"].get("tool_calls", [])
    )
    streamed_text = "".join(
        chunk["choices"][0]["delta"].get("content") or "" for chunk in chunks
    )

    assert json.loads(arguments) == {"id": _PESEL}
    assert streamed_text == f"Value {token}"
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_stream_close_and_request_failure_release_vault_context() -> None:
    guardrail = _guardrail(trusted_routes=frozenset({"trusted-eu"}))
    request = {
        "model": "trusted-eu",
        "metadata": {"session_id": "conversation-1"},
        "messages": [{"role": "user", "content": _PESEL}],
    }
    outbound = await guardrail.async_pre_call_hook(None, None, request, "acompletion")

    async def response_stream():
        yield {"choices": [{"index": 0, "delta": {"content": "partial"}}]}
        yield {"choices": [{"index": 0, "delta": {"content": "tail"}}]}

    stream = guardrail.async_post_call_streaming_iterator_hook(
        None, response_stream(), outbound
    )
    await anext(stream)
    await stream.aclose()
    assert guardrail._contexts == {}

    retry_data = await guardrail.async_pre_call_hook(None, None, request, "acompletion")
    await guardrail.async_post_call_failure_hook(
        retry_data, RuntimeError("synthetic provider failure"), None
    )
    assert guardrail._contexts == {}


@pytest.mark.asyncio
async def test_audit_queue_admission_failure_obeys_enforce_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def reject_admission(*_args: object, **_kwargs: object) -> bool:
        raise AuditAdmissionError("safe audit admission error")

    fail_closed_log = AuditLog(tmp_path / "closed.db")
    monkeypatch.setattr(fail_closed_log, "enqueue", reject_admission)
    fail_closed = SovereignGateGuardrail(
        PolicyConfig(
            mode=OperatingMode.ENFORCE,
            on_error=ErrorPolicy.FAIL_CLOSED,
            entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
        ),
        _SECRET,
        audit_log=fail_closed_log,
    )
    with pytest.raises(GuardrailRaisedException) as error:
        await fail_closed.async_pre_call_hook(
            None,
            None,
            {"messages": [{"role": "user", "content": _PESEL}]},
            "acompletion",
        )
    assert _PESEL not in str(error.value)
    assert fail_closed._contexts == {}
    fail_closed_log.close()

    fail_open_log = AuditLog(tmp_path / "open.db")
    monkeypatch.setattr(fail_open_log, "enqueue", reject_admission)
    fail_open = SovereignGateGuardrail(
        PolicyConfig(
            mode=OperatingMode.ENFORCE,
            on_error=ErrorPolicy.FAIL_OPEN,
            entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
        ),
        _SECRET,
        audit_log=fail_open_log,
    )
    outbound = await fail_open.async_pre_call_hook(
        None,
        None,
        {"messages": [{"role": "user", "content": _PESEL}]},
        "acompletion",
    )
    assert outbound["metadata"]["sovereigngate_audit_degraded"] is True
    fail_open._release_context(fail_open._context_id(outbound))
    fail_open_log.close()


@pytest.mark.asyncio
async def test_stream_errors_are_sanitized_and_release_request_context() -> None:
    guardrail = _guardrail()
    outbound = await guardrail.async_pre_call_hook(
        None,
        None,
        {"messages": [{"role": "user", "content": _PESEL}]},
        "acompletion",
    )
    raw_error_value = "synthetic-stream-private-value"

    async def broken_stream():
        raise RuntimeError(raw_error_value)
        yield {}

    with pytest.raises(GuardrailRaisedException) as error:
        async for _ in guardrail.async_post_call_streaming_iterator_hook(
            None, broken_stream(), outbound
        ):
            pass

    assert raw_error_value not in str(error.value)
    assert guardrail._contexts == {}
