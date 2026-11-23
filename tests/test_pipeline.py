import base64
import random
import string
from dataclasses import dataclass

import pytest

from sovereigngate.config import (
    EncodedContentAction,
    EntityAction,
    EntityRule,
    ErrorPolicy,
    NerConfig,
    NormalizationConfig,
    OperatingMode,
    PolicyConfig,
    Sensitivity,
)
from sovereigngate.engine.detectors import DetectionSpan
from sovereigngate.engine.normalizer import NormalizedText
from sovereigngate.engine.pipeline import (
    PipelineError,
    PipelineErrorCode,
    resolve_spans,
    run_pipeline,
)


@dataclass(frozen=True)
class _FakeNER:
    spans: tuple[DetectionSpan, ...]

    def detect(self, normalized: NormalizedText) -> tuple[DetectionSpan, ...]:
        del normalized
        return self.spans


def test_shadow_mode_reports_but_does_not_apply_policy_actions() -> None:
    policy = PolicyConfig(
        mode=OperatingMode.SHADOW,
        entities={"PL_PESEL": EntityRule(action=EntityAction.BLOCK)},
    )

    result = run_pipeline("id 00210100004", policy)

    assert result.blocked is False
    assert result.detected_entity_types == ("PL_PESEL",)
    assert result.decisions[0].configured_action is EntityAction.BLOCK
    assert result.decisions[0].action is EntityAction.SHADOW_LOG
    assert result.spans_to_mask == ()


def test_enforce_mode_returns_mask_decision_and_special_category_metadata() -> None:
    policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        entities={
            "PL_PESEL": EntityRule(action=EntityAction.MASK),
            "HEALTH_TERM": EntityRule(
                action=EntityAction.MASK,
                sensitivity=Sensitivity.SPECIAL_CATEGORY,
            ),
        },
        ner=NerConfig(enabled=True, model_dir="/local/model", manifest_sha256="0" * 64),
    )
    ner_spans = (
        DetectionSpan(start=15, end=28, entity_type="HEALTH_TERM", confidence=0.91, tier=2),
    )

    result = run_pipeline("id 00210100004 contains a condition", policy, _FakeNER(ner_spans))

    assert result.blocked is False
    assert result.eu_sensitive is True
    assert set(result.detected_entity_types) == {"PL_PESEL", "HEALTH_TERM"}
    assert {span.entity_type for span in result.spans_to_mask} == {"PL_PESEL", "HEALTH_TERM"}


def test_disabled_entities_are_not_returned_as_policy_findings() -> None:
    policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        entities={"PL_PESEL": EntityRule(enabled=False)},
    )

    result = run_pipeline("id 00210100004", policy)

    assert result.detected_entity_types == ()
    assert result.decisions == ()


def test_block_action_blocks_only_in_enforce_mode() -> None:
    enforce_policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        entities={"PL_PESEL": EntityRule(action=EntityAction.BLOCK)},
    )
    shadow_policy = enforce_policy.model_copy(update={"mode": OperatingMode.SHADOW})

    assert run_pipeline("id 00210100004", enforce_policy).blocked is True
    assert run_pipeline("id 00210100004", shadow_policy).blocked is False


def test_tier1_wins_over_overlapping_tier2_span() -> None:
    policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        entities={
            "PL_PESEL": EntityRule(action=EntityAction.MASK),
            "PERSON": EntityRule(action=EntityAction.MASK),
        },
    )
    fake_ner = _FakeNER(
        (DetectionSpan(start=3, end=14, entity_type="PERSON", confidence=0.99, tier=2),)
    )

    result = run_pipeline("id 00210100004", policy, fake_ner)

    assert result.detected_entity_types == ("PL_PESEL",)
    assert result.decisions[0].span.tier == 1


def test_overlapping_tier1_validators_do_not_hide_the_configured_entity() -> None:
    policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        entities={"DK_CPR": EntityRule(action=EntityAction.MASK)},
    )

    result = run_pipeline("request 0101800000", policy)

    assert result.detected_entity_types == ("DK_CPR",)
    assert result.spans_to_mask[0].entity_type == "DK_CPR"


def test_span_resolution_prefers_longest_same_tier_and_merges_adjacent_same_type() -> None:
    spans = (
        DetectionSpan(0, 2, "PERSON", 0.9, 2),
        DetectionSpan(0, 4, "PERSON", 0.8, 2),
        DetectionSpan(4, 6, "PERSON", 0.8, 2),
        DetectionSpan(1, 5, "PL_PESEL", 1.0, 1),
    )

    result = resolve_spans(spans)

    assert result == (DetectionSpan(1, 5, "PL_PESEL", 1.0, 1),)
    merged = resolve_spans(
        (DetectionSpan(0, 2, "PERSON", 0.9, 2), DetectionSpan(2, 4, "PERSON", 0.8, 2))
    )
    assert merged == (DetectionSpan(0, 4, "PERSON", 0.8, 2),)


def test_encoded_blob_block_action_respects_shadow_mode() -> None:
    blob = base64.b64encode(bytes(range(64))).decode("ascii")
    enforce_policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        normalization=NormalizationConfig(encoded_content_action=EncodedContentAction.BLOCK),
    )
    shadow_policy = enforce_policy.model_copy(update={"mode": OperatingMode.SHADOW})

    enforce_result = run_pipeline(blob, enforce_policy)
    shadow_result = run_pipeline(blob, shadow_policy)

    assert enforce_result.blocked is True
    assert enforce_result.blocked_entity_types == ("ENCODED_CONTENT",)
    assert len(enforce_result.normalization_signals) == 1
    assert shadow_result.blocked is False
    assert len(shadow_result.normalization_signals) == 1


def test_decode_once_scans_encoded_text_and_maps_a_match_to_blob() -> None:
    random_source = random.Random(20261123)
    alphabet = string.ascii_letters + string.digits
    noise = " ".join(
        "".join(random_source.choice(alphabet) for _ in range(12)) for _ in range(10)
    )
    decoded = f"record 00210100004 {noise}"
    blob = base64.b64encode(decoded.encode("utf-8")).decode("ascii")
    policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        normalization=NormalizationConfig(
            encoded_content_action=EncodedContentAction.DECODE_UTF8_ONCE
        ),
        entities={"PL_PESEL": EntityRule(action=EntityAction.MASK)},
    )

    result = run_pipeline(blob, policy)

    assert result.detected_entity_types == ("PL_PESEL",)
    assert result.spans_to_mask[0].start == 0
    assert result.spans_to_mask[0].end == len(blob)


def test_fail_closed_sanitizes_detector_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    import sovereigngate.engine.pipeline as pipeline_module

    raw_value = "synthetic-sensitive-candidate"

    def fail_detector(_normalized: NormalizedText) -> tuple[DetectionSpan, ...]:
        raise RuntimeError(f"parser failed on {raw_value}")

    monkeypatch.setattr(pipeline_module, "detect_tier1", fail_detector)
    policy = PolicyConfig(mode=OperatingMode.ENFORCE, on_error=ErrorPolicy.FAIL_CLOSED)

    with pytest.raises(PipelineError) as error:
        run_pipeline("safe outer text", policy)
    assert raw_value not in str(error.value)
    assert error.value.code is PipelineErrorCode.TIER1_FAILURE


def test_fail_open_and_shadow_surface_sanitized_processing_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sovereigngate.engine.pipeline as pipeline_module

    def fail_detector(_normalized: NormalizedText) -> tuple[DetectionSpan, ...]:
        raise RuntimeError("synthetic detector exception")

    monkeypatch.setattr(pipeline_module, "detect_tier1", fail_detector)
    policies = (
        PolicyConfig(mode=OperatingMode.ENFORCE, on_error=ErrorPolicy.FAIL_OPEN),
        PolicyConfig(mode=OperatingMode.SHADOW, on_error=ErrorPolicy.FAIL_CLOSED),
    )

    for policy in policies:
        result = run_pipeline("safe text", policy)
        assert result.processing_error is PipelineErrorCode.TIER1_FAILURE
        assert result.blocked is False


def test_missing_ner_runner_fails_closed_when_ner_is_enabled() -> None:
    policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        ner=NerConfig(
            enabled=True,
            model_dir="/local/model",
            manifest_sha256="0" * 64,
        ),
    )

    with pytest.raises(PipelineError) as error:
        run_pipeline("ordinary text", policy)
    assert error.value.code is PipelineErrorCode.TIER2_FAILURE
