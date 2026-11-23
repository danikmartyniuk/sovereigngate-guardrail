import copy
import json
import re
import threading
from collections.abc import AsyncGenerator, Mapping
from dataclasses import dataclass, field
from typing import Any, Final
from uuid import uuid4

from litellm.exceptions import GuardrailRaisedException
from litellm.integrations.custom_guardrail import CustomGuardrail
from pydantic import BaseModel

from sovereigngate.config import (
    ErrorPolicy,
    OperatingMode,
    PolicyConfig,
    load_hmac_secret,
)
from sovereigngate.engine.pipeline import (
    NERDetector,
    PipelineError,
    PipelineResult,
    run_pipeline,
)
from sovereigngate.engine.vault import (
    SessionVault,
    StreamRehydrator,
    VaultCollisionError,
)

_CONTEXT_METADATA_KEY: Final[str] = "sovereigngate_request_context"
_CONTEXT_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{32}\Z")


class _AdapterFailure(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _AdapterBlock(Exception):
    def __init__(self, safe_message: str) -> None:
        self.safe_message = safe_message
        super().__init__(safe_message)


@dataclass(slots=True)
class _ScanSummary:
    detected_entity_types: set[str] = field(default_factory=set)
    eu_sensitive: bool = False


@dataclass(slots=True)
class _RequestContext:
    vault: SessionVault
    trusted_route: bool
    stream_buffers: dict[tuple[str, int, int], StreamRehydrator] = field(default_factory=dict)
    stream_tool_names: dict[tuple[int, int], str] = field(default_factory=dict)


class SovereignGateGuardrail(CustomGuardrail):
    """LiteLLM hooks for local masking and request-scoped token restoration."""

    def __init__(
        self,
        policy: PolicyConfig,
        hmac_secret: bytes | None = None,
        *,
        ner_runner: NERDetector | None = None,
        trusted_routes: frozenset[str] = frozenset(),
        internal_tools: frozenset[str] = frozenset(),
    ) -> None:
        super().__init__(guardrail_name="SovereignGate", turn_off_message_logging=True)
        selected_secret = load_hmac_secret() if hmac_secret is None else hmac_secret
        if len(selected_secret) < 32:
            raise ValueError("The HMAC secret must contain at least 32 bytes")
        self.policy = policy
        self._hmac_secret = bytes(selected_secret)
        self._ner_runner = ner_runner
        self._trusted_routes = trusted_routes
        self._internal_tools = internal_tools
        self._contexts: dict[str, _RequestContext] = {}
        self._contexts_lock = threading.Lock()

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict[str, Any],
        call_type: Any,
    ) -> dict[str, Any]:
        del user_api_key_dict, cache, call_type
        original = copy.deepcopy(data)
        working = copy.deepcopy(data)
        metadata_key, metadata = self._metadata_bucket(working)
        context_id, context = self._get_or_create_context(working, metadata)
        metadata[_CONTEXT_METADATA_KEY] = context_id
        summary = _ScanSummary()

        try:
            messages = working.get("messages")
            if messages is not None:
                if not isinstance(messages, list):
                    raise _AdapterFailure("malformed_messages")
                working["messages"] = [
                    self._transform_message(message, context, summary) for message in messages
                ]
            else:
                for text_field in ("prompt", "input"):
                    if text_field in working:
                        working[text_field] = self._transform_text_content(
                            working[text_field], context, summary
                        )
            metadata["eu_sensitive"] = summary.eu_sensitive
            metadata["detected_entity_types"] = sorted(summary.detected_entity_types)
            working[metadata_key] = metadata
            return working
        except _AdapterBlock as error:
            self._release_context(context_id)
            raise self._block_exception(error.safe_message, blocked_content=True) from None
        except VaultCollisionError:
            self._release_context(context_id)
            raise self._block_exception(
                "SovereignGate blocked a request after an in-request token collision",
                blocked_content=True,
            ) from None
        except Exception as error:
            code = error.code if isinstance(error, _AdapterFailure) else "processing_failure"
            self._release_context(context_id)
            if self._fails_closed:
                raise self._block_exception(
                    "SovereignGate could not safely process the request", blocked_content=False
                ) from None
            fallback_key, fallback_metadata = self._metadata_bucket(original)
            fallback_metadata[_CONTEXT_METADATA_KEY] = context_id
            fallback_metadata["eu_sensitive"] = summary.eu_sensitive
            fallback_metadata["detected_entity_types"] = sorted(summary.detected_entity_types)
            fallback_metadata["sovereigngate_processing_error"] = code
            original[fallback_key] = fallback_metadata
            return original

    async def async_post_call_success_hook(
        self,
        data: dict[str, Any],
        user_api_key_dict: Any,
        response: Any,
    ) -> Any:
        del user_api_key_dict
        context_id = self._context_id(data)
        context = self._get_context(context_id)
        if context is None:
            return response
        try:
            return self._rehydrate_response(response, context)
        except Exception:
            if self._fails_closed:
                raise self._block_exception(
                    "SovereignGate could not safely process the response",
                    blocked_content=False,
                    status_code=502,
                ) from None
            self._mark_processing_error(data, "response_processing_failure")
            return response
        finally:
            self._release_context(context_id)

    async def async_post_call_failure_hook(
        self,
        request_data: dict[str, Any],
        original_exception: Exception,
        user_api_key_dict: Any,
        traceback_str: str | None = None,
    ) -> None:
        del original_exception, user_api_key_dict, traceback_str
        self._release_context(self._context_id(request_data))

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: Any,
        response: Any,
        request_data: dict[str, Any],
    ) -> AsyncGenerator[Any, None]:
        del user_api_key_dict
        context_id = self._context_id(request_data)
        context = self._get_context(context_id)
        try:
            async for chunk in response:
                if context is None:
                    yield chunk
                    continue
                try:
                    transformed = self._transform_stream_chunk(chunk, context)
                except Exception:
                    if self._fails_closed:
                        raise _AdapterFailure("stream_processing_failure") from None
                    self._mark_processing_error(request_data, "stream_processing_failure")
                    transformed = copy.deepcopy(chunk)
                yield transformed
        except _AdapterFailure:
            raise self._block_exception(
                "SovereignGate could not safely process a streamed response",
                blocked_content=False,
                status_code=502,
            ) from None
        except Exception:
            raise self._block_exception(
                "SovereignGate stream processing failed",
                blocked_content=False,
                status_code=502,
            ) from None
        finally:
            self._release_context(context_id)

    @property
    def _fails_closed(self) -> bool:
        return (
            self.policy.mode is OperatingMode.ENFORCE
            and self.policy.on_error is ErrorPolicy.FAIL_CLOSED
        )

    @staticmethod
    def _metadata_bucket(data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        for key in ("metadata", "litellm_metadata"):
            value = data.get(key)
            if isinstance(value, dict):
                return key, value
        return "metadata", {}

    @staticmethod
    def _context_id(data: Mapping[str, object]) -> str | None:
        for key in ("metadata", "litellm_metadata"):
            value = data.get(key)
            if isinstance(value, Mapping):
                context_id = value.get(_CONTEXT_METADATA_KEY)
                if isinstance(context_id, str) and _CONTEXT_ID_PATTERN.fullmatch(context_id):
                    return context_id
        return None

    def _get_or_create_context(
        self,
        data: Mapping[str, object],
        metadata: Mapping[str, object],
    ) -> tuple[str, _RequestContext]:
        prior_id = metadata.get(_CONTEXT_METADATA_KEY)
        if isinstance(prior_id, str) and _CONTEXT_ID_PATTERN.fullmatch(prior_id):
            with self._contexts_lock:
                prior_context = self._contexts.get(prior_id)
            if prior_context is not None:
                return prior_id, prior_context

        context_id = uuid4().hex
        session_id_value = metadata.get("session_id")
        session_id = (
            session_id_value
            if isinstance(session_id_value, str) and session_id_value
            else str(uuid4())
        )
        route = metadata.get("route") or metadata.get("model_group") or data.get("model")
        trusted_route = isinstance(route, str) and route in self._trusted_routes
        context = _RequestContext(
            vault=SessionVault(self._hmac_secret, session_id),
            trusted_route=trusted_route,
        )
        with self._contexts_lock:
            self._contexts[context_id] = context
        return context_id, context

    def _get_context(self, context_id: str | None) -> _RequestContext | None:
        if context_id is None:
            return None
        with self._contexts_lock:
            return self._contexts.get(context_id)

    def _release_context(self, context_id: str | None) -> None:
        if context_id is None:
            return
        with self._contexts_lock:
            context = self._contexts.pop(context_id, None)
        if context is None:
            return
        try:
            context.stream_buffers.clear()
            context.stream_tool_names.clear()
        finally:
            context.vault.wipe()

    def _transform_message(
        self,
        message: object,
        context: _RequestContext,
        summary: _ScanSummary,
    ) -> object:
        if isinstance(message, BaseModel):
            content = getattr(message, "content", None)
            tool_calls = getattr(message, "tool_calls", None)
            updates: dict[str, object] = {}
            if content is not None:
                updates["content"] = self._transform_text_content(content, context, summary)
            if isinstance(tool_calls, list):
                updates["tool_calls"] = [
                    self._transform_tool_call(tool_call, context, summary)
                    for tool_call in tool_calls
                ]
            return message.model_copy(update=updates, deep=True)
        if not isinstance(message, dict):
            raise _AdapterFailure("malformed_message")

        transformed = copy.deepcopy(message)
        content = transformed.get("content")
        if content is not None:
            transformed["content"] = self._transform_text_content(content, context, summary)

        tool_calls = transformed.get("tool_calls")
        if isinstance(tool_calls, list):
            transformed["tool_calls"] = [
                self._transform_tool_call(tool_call, context, summary)
                for tool_call in tool_calls
            ]
        return transformed

    def _transform_text_content(
        self,
        value: object,
        context: _RequestContext,
        summary: _ScanSummary,
    ) -> object:
        if isinstance(value, str):
            return self._mask_text(value, context, summary)
        if isinstance(value, list):
            return [self._transform_text_content(item, context, summary) for item in value]
        if isinstance(value, dict):
            result = copy.deepcopy(value)
            for key, item in value.items():
                if key in {"text", "content"}:
                    result[key] = self._transform_text_content(item, context, summary)
            return result
        if isinstance(value, BaseModel):
            updates = {
                name: self._transform_text_content(getattr(value, name), context, summary)
                for name in ("text", "content")
                if self._has_field(value, name)
            }
            return value.model_copy(update=updates, deep=True)
        return copy.deepcopy(value)

    def _transform_tool_call(
        self,
        tool_call: object,
        context: _RequestContext,
        summary: _ScanSummary,
    ) -> object:
        if isinstance(tool_call, BaseModel):
            function = getattr(tool_call, "function", None)
            if isinstance(function, BaseModel) and self._has_field(function, "arguments"):
                arguments = self._get_field(function, "arguments")
                transformed_function = function.model_copy(
                    update={
                        "arguments": self._transform_tool_arguments(
                            arguments, context, summary
                        )
                    },
                    deep=True,
                )
                return tool_call.model_copy(
                    update={"function": transformed_function}, deep=True
                )
            return copy.deepcopy(tool_call)
        if not isinstance(tool_call, dict):
            return copy.deepcopy(tool_call)
        transformed = copy.deepcopy(tool_call)
        function = transformed.get("function")
        if isinstance(function, dict) and "arguments" in function:
            function["arguments"] = self._transform_tool_arguments(
                function["arguments"], context, summary
            )
        return transformed

    def _transform_tool_arguments(
        self,
        arguments: object,
        context: _RequestContext,
        summary: _ScanSummary,
    ) -> object:
        parsed = arguments
        if isinstance(arguments, str):
            try:
                parsed = json.loads(arguments)
            except (json.JSONDecodeError, TypeError):
                if self.policy.mode is OperatingMode.SHADOW:
                    self._mask_text(arguments, context, summary)
                    return arguments
                raise _AdapterFailure("malformed_tool_arguments") from None

        transformed = self._transform_json_values(parsed, context, summary)
        if self.policy.mode is OperatingMode.SHADOW:
            return arguments
        if isinstance(arguments, str):
            return json.dumps(transformed, ensure_ascii=False, separators=(",", ":"))
        return transformed

    def _transform_json_values(
        self,
        value: object,
        context: _RequestContext,
        summary: _ScanSummary,
    ) -> object:
        if isinstance(value, str):
            return self._mask_text(value, context, summary)
        if isinstance(value, list):
            return [self._transform_json_values(item, context, summary) for item in value]
        if isinstance(value, dict):
            return {
                key: self._transform_json_values(item, context, summary)
                for key, item in value.items()
            }
        return copy.deepcopy(value)

    def _mask_text(
        self,
        text: str,
        context: _RequestContext,
        summary: _ScanSummary,
    ) -> str:
        try:
            result = run_pipeline(text, self.policy, self._ner_runner)
        except PipelineError as error:
            raise _AdapterFailure(error.code.value) from None
        summary.detected_entity_types.update(result.detected_entity_types)
        summary.eu_sensitive = summary.eu_sensitive or result.eu_sensitive
        if result.processing_error is not None:
            raise _AdapterFailure(result.processing_error.value)
        if result.blocked:
            raise _AdapterBlock(self._safe_block_message(result))
        if self.policy.mode is OperatingMode.SHADOW:
            return text

        for span in sorted(result.spans_to_mask, key=lambda item: item.start, reverse=True):
            original_value = text[span.start : span.end]
            token = context.vault.tokenize(span.entity_type, original_value)
            text = text[: span.start] + token + text[span.end :]
        return text

    @staticmethod
    def _safe_block_message(result: PipelineResult) -> str:
        sensitivities = {
            decision.span.entity_type: decision.sensitivity.value
            for decision in result.decisions
            if decision.action.value == "block"
        }
        blocked = []
        for entity_type in result.blocked_entity_types:
            safe_type = (
                entity_type
                if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", entity_type)
                else "ENTITY"
            )
            sensitivity = sensitivities.get(safe_type)
            blocked.append(f"{safe_type} + {sensitivity}" if sensitivity else safe_type)
        return f"Blocked by SovereignGate policy: {', '.join(blocked)}"

    def _block_exception(
        self,
        message: str,
        *,
        blocked_content: bool,
        status_code: int = 403,
    ) -> GuardrailRaisedException:
        return self._guardrail_exception(
            message, blocked_content=blocked_content, status_code=status_code
        )

    @staticmethod
    def _guardrail_exception(
        message: str,
        *,
        blocked_content: bool,
        status_code: int,
    ) -> GuardrailRaisedException:
        return GuardrailRaisedException(
            guardrail_name="SovereignGate",
            message=message,
            should_wrap_with_default_message=False,
            status_code=status_code,
            blocked_content=blocked_content,
        )

    @classmethod
    def _mark_processing_error(cls, data: dict[str, Any], code: str) -> None:
        metadata_key, metadata = cls._metadata_bucket(data)
        safe_metadata = copy.deepcopy(metadata)
        safe_metadata["sovereigngate_processing_error"] = code
        data[metadata_key] = safe_metadata

    def _rehydrate_response(self, response: object, context: _RequestContext) -> object:
        if isinstance(response, str):
            return context.vault.rehydrate(response) if context.trusted_route else response
        return self._rehydrate_response_node(response, context)

    def _rehydrate_response_node(
        self,
        value: object,
        context: _RequestContext,
        *,
        field_name: str = "",
        tool_name: str | None = None,
    ) -> object:
        if field_name == "arguments" and tool_name in self._internal_tools:
            return self._rehydrate_tool_arguments(value, context)
        if field_name == "content" and context.trusted_route:
            return self._rehydrate_text_content(value, context)
        if field_name == "text" and context.trusted_route and isinstance(value, str):
            return context.vault.rehydrate(value)

        if isinstance(value, dict):
            child_tool_name = tool_name
            if field_name == "function":
                candidate = value.get("name")
                child_tool_name = candidate if isinstance(candidate, str) else None
            return {
                key: self._rehydrate_response_node(
                    item, context, field_name=key, tool_name=child_tool_name
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._rehydrate_response_node(item, context) for item in value]
        if isinstance(value, BaseModel):
            child_tool_name = tool_name
            if field_name == "function":
                candidate = getattr(value, "name", None)
                child_tool_name = candidate if isinstance(candidate, str) else None
            updates = {
                name: self._rehydrate_response_node(
                    getattr(value, name), context, field_name=name, tool_name=child_tool_name
                )
                for name in type(value).model_fields
            }
            return value.model_copy(update=updates, deep=True)
        return copy.deepcopy(value)

    def _rehydrate_text_content(self, value: object, context: _RequestContext) -> object:
        if isinstance(value, str):
            return context.vault.rehydrate(value)
        if isinstance(value, list):
            return [self._rehydrate_text_content(item, context) for item in value]
        if isinstance(value, dict):
            result = copy.deepcopy(value)
            for key, item in value.items():
                if key in {"text", "content"}:
                    result[key] = self._rehydrate_text_content(item, context)
            return result
        if isinstance(value, BaseModel):
            updates = {
                name: self._rehydrate_text_content(getattr(value, name), context)
                for name in type(value).model_fields
                if name in {"text", "content"}
            }
            return value.model_copy(update=updates, deep=True)
        return copy.deepcopy(value)

    def _rehydrate_tool_arguments(self, value: object, context: _RequestContext) -> object:
        parsed = value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                raise _AdapterFailure("malformed_tool_arguments") from None
        restored = self._rehydrate_json_values(parsed, context)
        if isinstance(value, str):
            return json.dumps(restored, ensure_ascii=False, separators=(",", ":"))
        return restored

    def _rehydrate_json_values(self, value: object, context: _RequestContext) -> object:
        if isinstance(value, str):
            return context.vault.rehydrate(value)
        if isinstance(value, list):
            return [self._rehydrate_json_values(item, context) for item in value]
        if isinstance(value, dict):
            return {key: self._rehydrate_json_values(item, context) for key, item in value.items()}
        return copy.deepcopy(value)

    def _transform_stream_chunk(self, chunk: object, context: _RequestContext) -> object:
        choices = self._get_field(chunk, "choices")
        if not isinstance(choices, list):
            return copy.deepcopy(chunk)
        transformed_choices = [
            self._transform_stream_choice(choice, index, context)
            for index, choice in enumerate(choices)
        ]
        return self._with_updates(chunk, {"choices": transformed_choices})

    def _transform_stream_choice(
        self,
        choice: object,
        fallback_index: int,
        context: _RequestContext,
    ) -> object:
        choice_index_value = self._get_field(choice, "index")
        choice_index = choice_index_value if isinstance(choice_index_value, int) else fallback_index
        final = self._get_field(choice, "finish_reason") is not None
        delta = self._get_field(choice, "delta")
        if delta is None:
            return copy.deepcopy(choice)
        updates: dict[str, object] = {}

        for content_field in ("content", "text"):
            if context.trusted_route and self._has_field(delta, content_field):
                content = self._get_field(delta, content_field)
                if isinstance(content, str) or final:
                    key = ("content", choice_index, -1)
                    buffer = context.stream_buffers.setdefault(key, StreamRehydrator(context.vault))
                    transformed = buffer.feed(
                        content if isinstance(content, str) else "", final=final
                    )
                    if isinstance(content, str) or transformed:
                        updates[content_field] = transformed
                    if final:
                        context.stream_buffers.pop(key, None)

        tool_calls = self._get_field(delta, "tool_calls")
        if isinstance(tool_calls, list):
            transformed_calls = [
                self._transform_stream_tool_call(call, choice_index, index, context, final)
                for index, call in enumerate(tool_calls)
            ]
            updates["tool_calls"] = transformed_calls
        if final:
            for buffer_key in tuple(context.stream_buffers):
                if buffer_key[1] == choice_index:
                    buffer = context.stream_buffers.pop(buffer_key)
                    remainder = buffer.feed("", final=True)
                    if remainder and buffer_key[0] == "content":
                        updates["content"] = f"{updates.get('content', '')}{remainder}"
                    elif remainder:
                        raise _AdapterFailure("incomplete_tool_arguments_stream")
            for tool_key in tuple(context.stream_tool_names):
                if tool_key[0] == choice_index:
                    context.stream_tool_names.pop(tool_key, None)

        return self._with_updates(choice, {"delta": self._with_updates(delta, updates)})

    def _transform_stream_tool_call(
        self,
        tool_call: object,
        choice_index: int,
        fallback_tool_index: int,
        context: _RequestContext,
        final: bool,
    ) -> object:
        tool_index_value = self._get_field(tool_call, "index")
        tool_index = tool_index_value if isinstance(tool_index_value, int) else fallback_tool_index
        function = self._get_field(tool_call, "function")
        if function is None:
            return copy.deepcopy(tool_call)
        name_key = (choice_index, tool_index)
        observed_name = self._get_field(function, "name")
        known_name = context.stream_tool_names.get(name_key, "")
        if isinstance(observed_name, str):
            if observed_name in self._internal_tools:
                known_name = observed_name
            elif known_name not in self._internal_tools:
                known_name += observed_name
            context.stream_tool_names[name_key] = known_name

        function_updates: dict[str, object] = {}
        arguments = self._get_field(function, "arguments")
        buffer_key = ("tool", choice_index, tool_index)
        if known_name in self._internal_tools and (isinstance(arguments, str) or final):
            buffer = context.stream_buffers.setdefault(buffer_key, StreamRehydrator(context.vault))
            restored = buffer.feed(arguments if isinstance(arguments, str) else "", final=final)
            if isinstance(arguments, str) or restored:
                function_updates["arguments"] = restored
            if final:
                context.stream_buffers.pop(buffer_key, None)
        updated_function = self._with_updates(function, function_updates)
        return self._with_updates(tool_call, {"function": updated_function})

    @staticmethod
    def _get_field(value: object, name: str) -> object | None:
        if isinstance(value, Mapping):
            return value.get(name)
        return getattr(value, name, None)

    @staticmethod
    def _has_field(value: object, name: str) -> bool:
        if isinstance(value, Mapping):
            return name in value
        return isinstance(value, BaseModel) and name in type(value).model_fields

    @staticmethod
    def _with_updates(value: object, updates: dict[str, object]) -> object:
        if isinstance(value, dict):
            result = copy.deepcopy(value)
            result.update(updates)
            return result
        if isinstance(value, BaseModel):
            return value.model_copy(update=updates, deep=True)
        return copy.deepcopy(value)
