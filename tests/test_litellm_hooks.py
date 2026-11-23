import json

import pytest
from litellm.exceptions import GuardrailRaisedException
from pydantic import BaseModel

from sovereigngate.adapters.litellm_guardrail import SovereignGateGuardrail
from sovereigngate.config import (
    EntityAction,
    EntityRule,
    ErrorPolicy,
    OperatingMode,
    PolicyConfig,
    Sensitivity,
)

_SECRET = bytes(range(32))
_PESEL = "00210100004"


class _TextBlock(BaseModel):
    type: str
    text: str


class _Message(BaseModel):
    role: str
    content: list[_TextBlock]


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
async def test_pre_call_copies_and_masks_pydantic_text_blocks() -> None:
    guardrail = _guardrail()
    message = _Message(role="user", content=[_TextBlock(type="text", text=_PESEL)])
    payload = {"messages": [message]}

    result = await guardrail.async_pre_call_hook(None, None, payload, "acompletion")

    assert message.content[0].text == _PESEL
    assert isinstance(result["messages"][0], _Message)
    assert result["messages"][0].content[0].text.startswith("[PL_PESEL_")


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
