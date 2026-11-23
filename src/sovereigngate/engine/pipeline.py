from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from sovereigngate.config import (
    EncodedContentAction,
    EntityAction,
    ErrorPolicy,
    OperatingMode,
    PolicyConfig,
    Sensitivity,
)
from sovereigngate.engine.detectors import DetectionSpan, detect_tier1
from sovereigngate.engine.normalizer import EncodedContentSignal, NormalizedText, normalize_text


class PipelineErrorCode(StrEnum):
    NORMALIZATION_FAILURE = "normalization_failure"
    TIER1_FAILURE = "tier1_failure"
    TIER2_FAILURE = "tier2_failure"
    ENCODED_SCAN_UNAVAILABLE = "encoded_scan_unavailable"


class PipelineError(RuntimeError):
    def __init__(self, code: PipelineErrorCode) -> None:
        self.code = code
        super().__init__(f"SovereignGate processing failed closed at {code.value}")


class NERDetector(Protocol):
    def detect(self, normalized: NormalizedText) -> tuple[DetectionSpan, ...]: ...


_PATTERN_ONLY_TYPES: frozenset[str] = frozenset(
    {"EMAIL", "PHONE", "IP_ADDRESS", "API_KEY", "BEARER_TOKEN"}
)


@dataclass(frozen=True, slots=True)
class EntityDecision:
    span: DetectionSpan
    configured_action: EntityAction
    action: EntityAction
    sensitivity: Sensitivity


@dataclass(frozen=True, slots=True)
class PipelineResult:
    decisions: tuple[EntityDecision, ...]
    normalization_signals: tuple[EncodedContentSignal, ...]
    detected_entity_types: tuple[str, ...]
    blocked_entity_types: tuple[str, ...]
    eu_sensitive: bool
    blocked: bool
    processing_error: PipelineErrorCode | None = None

    @property
    def spans_to_mask(self) -> tuple[DetectionSpan, ...]:
        return tuple(
            decision.span for decision in self.decisions if decision.action is EntityAction.MASK
        )


def _overlaps(left: DetectionSpan, right: DetectionSpan) -> bool:
    return left.start < right.end and right.start < left.end


def resolve_spans(spans: Iterable[DetectionSpan]) -> tuple[DetectionSpan, ...]:
    """Resolve overlaps deterministically, with Tier 1 taking precedence over Tier 2."""
    ordered = sorted(
        set(spans),
        key=lambda span: (
            span.tier,
            span.entity_type in _PATTERN_ONLY_TYPES,
            -(span.end - span.start),
            span.start,
            -span.confidence,
            span.entity_type,
        ),
    )
    selected: list[DetectionSpan] = []
    for candidate in ordered:
        if any(_overlaps(candidate, existing) for existing in selected):
            continue
        selected.append(candidate)

    selected.sort(key=lambda span: (span.start, span.end, span.entity_type))
    merged: list[DetectionSpan] = []
    for span in selected:
        if (
            merged
            and merged[-1].end == span.start
            and merged[-1].entity_type == span.entity_type
            and merged[-1].tier == span.tier
        ):
            previous = merged[-1]
            merged[-1] = DetectionSpan(
                start=previous.start,
                end=span.end,
                entity_type=span.entity_type,
                confidence=min(previous.confidence, span.confidence),
                tier=span.tier,
            )
        else:
            merged.append(span)
    return tuple(merged)


def _failure_result(
    policy: PolicyConfig,
    code: PipelineErrorCode,
    signals: tuple[EncodedContentSignal, ...] = (),
) -> PipelineResult:
    if policy.mode is OperatingMode.ENFORCE and policy.on_error is ErrorPolicy.FAIL_CLOSED:
        raise PipelineError(code) from None
    return PipelineResult(
        decisions=(),
        normalization_signals=signals,
        detected_entity_types=(),
        blocked_entity_types=(),
        eu_sensitive=False,
        blocked=False,
        processing_error=code,
    )


def _scan(
    normalized: NormalizedText,
    policy: PolicyConfig,
    ner_runner: NERDetector | None,
) -> tuple[DetectionSpan, ...] | PipelineErrorCode:
    try:
        tier1_spans = detect_tier1(normalized)
    except Exception:
        # Detector exceptions may embed candidates; sanitize at this security boundary.
        return PipelineErrorCode.TIER1_FAILURE

    if not policy.ner.enabled:
        return tier1_spans
    if ner_runner is None:
        return PipelineErrorCode.TIER2_FAILURE
    try:
        tier2_spans = ner_runner.detect(normalized)
    except Exception:
        # Optional runtime exceptions must not escape with source text or model input details.
        return PipelineErrorCode.TIER2_FAILURE
    return (*tier1_spans, *tier2_spans)


def _apply_policy(
    spans: Iterable[DetectionSpan],
    policy: PolicyConfig,
) -> tuple[tuple[EntityDecision, ...], tuple[str, ...], bool]:
    decisions: list[EntityDecision] = []
    blocked_types: set[str] = set()
    eu_sensitive = False
    enabled_rules = {
        entity_type: rule for entity_type, rule in policy.entities.items() if rule.enabled
    }

    configured_spans = (span for span in spans if span.entity_type in enabled_rules)
    for span in resolve_spans(configured_spans):
        rule = enabled_rules[span.entity_type]
        configured_action = rule.action
        if policy.mode is OperatingMode.SHADOW:
            action = (
                EntityAction.ALLOW
                if configured_action is EntityAction.ALLOW
                else EntityAction.SHADOW_LOG
            )
        else:
            action = configured_action
            if action is EntityAction.BLOCK:
                blocked_types.add(span.entity_type)
        eu_sensitive = eu_sensitive or rule.sensitivity is Sensitivity.SPECIAL_CATEGORY
        decisions.append(
            EntityDecision(
                span=span,
                configured_action=configured_action,
                action=action,
                sensitivity=rule.sensitivity,
            )
        )
    return tuple(decisions), tuple(sorted(blocked_types)), eu_sensitive


def run_pipeline(
    text: str,
    policy: PolicyConfig,
    ner_runner: NERDetector | None = None,
) -> PipelineResult:
    """Normalize, detect, resolve spans, and return policy decisions without mutating text."""
    normalized: NormalizedText | None = None
    normalization_failed = False
    try:
        normalized = normalize_text(text, policy.normalization)
    except Exception:
        normalization_failed = True
    if normalization_failed or normalized is None:
        return _failure_result(policy, PipelineErrorCode.NORMALIZATION_FAILURE)

    signals = normalized.encoded_content
    scan_result = _scan(normalized, policy, ner_runner)
    if isinstance(scan_result, PipelineErrorCode):
        return _failure_result(policy, scan_result, signals)
    spans = list(scan_result)

    encoded_action = policy.normalization.encoded_content_action
    encoded_block = bool(
        signals
        and policy.mode is OperatingMode.ENFORCE
        and encoded_action is EncodedContentAction.BLOCK
    )
    if signals and encoded_action is EncodedContentAction.DECODE_UTF8_ONCE:
        decoded_scan: list[DetectionSpan] = []
        one_pass_settings = policy.normalization.model_copy(
            update={"encoded_content_action": EncodedContentAction.SHADOW_LOG}
        )
        for signal in signals:
            if signal.decoded_text is None:
                return _failure_result(
                    policy,
                    PipelineErrorCode.ENCODED_SCAN_UNAVAILABLE,
                    signals,
                )
            decoded: NormalizedText | None = None
            decode_failed = False
            try:
                decoded = normalize_text(signal.decoded_text, one_pass_settings)
            except Exception:
                decode_failed = True
            if decode_failed or decoded is None:
                return _failure_result(
                    policy,
                    PipelineErrorCode.ENCODED_SCAN_UNAVAILABLE,
                    signals,
                )
            if decoded.encoded_content:
                return _failure_result(
                    policy,
                    PipelineErrorCode.ENCODED_SCAN_UNAVAILABLE,
                    signals,
                )
            decoded_result = _scan(decoded, policy, ner_runner)
            if isinstance(decoded_result, PipelineErrorCode):
                return _failure_result(policy, decoded_result, signals)
            decoded_scan.extend(
                DetectionSpan(
                    start=signal.original_start,
                    end=signal.original_end,
                    entity_type=span.entity_type,
                    confidence=span.confidence,
                    tier=span.tier,
                )
                for span in decoded_result
            )
        spans.extend(decoded_scan)

    decisions, blocked_types, eu_sensitive = _apply_policy(spans, policy)
    detected_types = tuple(sorted({decision.span.entity_type for decision in decisions}))
    is_blocked = bool(blocked_types) or encoded_block
    if encoded_block:
        blocked_types = tuple(sorted((*blocked_types, "ENCODED_CONTENT")))

    return PipelineResult(
        decisions=decisions,
        normalization_signals=signals,
        detected_entity_types=detected_types,
        blocked_entity_types=blocked_types,
        eu_sensitive=eu_sensitive,
        blocked=is_blocked,
    )
