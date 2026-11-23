import hashlib
import json
from collections import Counter
from importlib.machinery import ModuleSpec
from pathlib import Path

import pytest

import sovereigngate.benchmark as benchmark_module
from sovereigngate.benchmark import (
    DATASET_ID,
    DATASET_SEED,
    HARD_NEGATIVE_COUNT,
    POSITIVE_COUNT,
    generate_dataset,
    run_benchmark,
    serialize_dataset,
    write_dataset,
)
from sovereigngate.config import PolicyConfig
from sovereigngate.engine.detectors import detect_tier1
from sovereigngate.engine.normalizer import normalize_text
from sovereigngate.engine.pipeline import resolve_spans


def test_generator_matches_frozen_strata_counts_and_offsets() -> None:
    samples = generate_dataset()
    assert samples == generate_dataset()
    assert len(samples) == POSITIVE_COUNT + HARD_NEGATIVE_COUNT == 1000
    assert sum(sample.is_positive for sample in samples) == POSITIVE_COUNT
    assert sum(not sample.is_positive for sample in samples) == HARD_NEGATIVE_COUNT
    assert {sample.sample_id for sample in samples} == {
        f"{DATASET_ID}-{index:04d}" for index in range(1, 1001)
    }

    positive_cells = Counter(
        (sample.country, sample.scenario) for sample in samples if sample.is_positive
    )
    negative_cells = Counter(
        (sample.country, sample.scenario) for sample in samples if not sample.is_positive
    )
    ordered_cells = sorted(positive_cells)
    assert len(ordered_cells) == 18
    assert [positive_cells[cell] for cell in ordered_cells] == [45] * 8 + [44] * 10
    assert [negative_cells[cell] for cell in ordered_cells] == [12] * 2 + [11] * 16

    for sample in samples:
        answer = sample.prompt[sample.span_start : sample.span_end] if sample.is_positive else None
        if sample.is_positive:
            assert sample.entity_type is not None
            assert sample.target_value == answer
            assert sample.span_start is not None and sample.span_end is not None
            resolved = resolve_spans(detect_tier1(normalize_text(sample.prompt)))
            assert any(
                span.entity_type == sample.entity_type
                and span.start == sample.span_start
                and span.end == sample.span_end
                for span in resolved
            )
        else:
            assert sample.entity_type is None
            assert sample.target_value is None
            assert sample.span_start is None and sample.span_end is None


def test_dataset_serialization_is_stable_and_annotated() -> None:
    samples = generate_dataset()
    serialized = serialize_dataset(samples)

    assert serialized == serialize_dataset(generate_dataset(DATASET_SEED))
    assert len(serialized.splitlines()) == 1000
    first = json.loads(serialized.splitlines()[0])
    assert "prompt" in first
    assert first["expected_task_answer"].isdigit()
    assert "production" not in serialized
    assert hashlib.sha256(serialized.encode()).hexdigest()


def test_dataset_writer_creates_only_synthetic_jsonl(tmp_path: Path) -> None:
    output = tmp_path / "dataset" / "eu-synthetic-v1.jsonl"
    samples = generate_dataset()

    write_dataset(output, samples)

    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1000
    assert json.loads(lines[0])["sample_id"].startswith("eu-synthetic-v1-")


def test_benchmark_metrics_are_reproducible_and_report_unmeasured_paths() -> None:
    report = run_benchmark(
        PolicyConfig(),
        measure_latency=False,
        include_presidio=False,
    )

    assert report.seed == DATASET_SEED
    assert report.sample_count == 1000
    expected_digest = hashlib.sha256(serialize_dataset(generate_dataset()).encode()).hexdigest()
    assert report.dataset_sha256 == expected_digest
    assert report.positive_samples == 800
    assert report.hard_negative_samples == 200
    assert report.structured_recall == 1.0
    assert report.hard_negative_fpr == 0.0
    assert report.task_utility_retention == 1.0
    assert report.tier1_observations == 0
    assert report.tier1_p95_ms is None
    assert report.tier2_p95_ms is None
    assert report.thresholds.release_gate_passed is None
    assert report.environment.reference_environment_match is False


def test_presidio_baseline_skips_unprovisioned_model_without_downloading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_find_spec = benchmark_module.importlib.util.find_spec

    def no_model(name: str, package: str | None = None) -> ModuleSpec | None:
        if name == "en_core_web_lg":
            return None
        return original_find_spec(name, package)

    monkeypatch.setattr(benchmark_module.importlib.util, "find_spec", no_model)
    summary = benchmark_module._presidio_baseline(generate_dataset()[:2])

    assert summary.status == "nlp_model_not_provisioned"
    assert all(metric.status == "N/A" for metric in summary.by_language.values())
