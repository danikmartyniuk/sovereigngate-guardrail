import hashlib
import importlib.metadata
import importlib.util
import json
import math
import os
import platform
import random
import re
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from sovereigngate.config import (
    EntityAction,
    EntityRule,
    ErrorPolicy,
    OperatingMode,
    PolicyConfig,
    load_policy,
)
from sovereigngate.engine.detectors import detect_tier1
from sovereigngate.engine.ner_onnx import NerOnnxRunner
from sovereigngate.engine.normalizer import normalize_text
from sovereigngate.engine.pipeline import PipelineResult, resolve_spans, run_pipeline
from sovereigngate.engine.vault import SessionVault

DATASET_ID: Final[str] = "eu-synthetic-v1"
DATASET_SEED: Final[int] = 20261123
POSITIVE_COUNT: Final[int] = 800
HARD_NEGATIVE_COUNT: Final[int] = 200
WARMUP_COUNT: Final[int] = 100
TIMED_PASSES: Final[int] = 10
_BENCHMARK_SECRET: Final[bytes] = hashlib.sha256(b"eu-synthetic-v1-local-benchmark-key").digest()
_PRESIDIO_NLP_MODEL: Final[str] = "en_core_web_lg"
_PRESIDIO_NLP_MODEL_VERSION: Final[str] = "3.8.0"
_PRESIDIO_NLP_MODEL_SHA256: Final[str] = (
    "2c670c29386ea89708bf55e443eb92ab40c9bd05efa94f53703e4db3505c3011"
)
_ENTITY_BY_COUNTRY: Final[dict[str, str]] = {
    "DE": "DE_STEUERID",
    "ES": "ES_DNI",
    "FR": "FR_NIR",
    "IT": "IT_CODICE_FISCALE",
    "NL": "NL_BSN",
    "PL": "PL_PESEL",
}
_LANGUAGE_BY_COUNTRY: Final[dict[str, str]] = {
    "DE": "de",
    "ES": "es",
    "FR": "fr",
    "IT": "it",
    "NL": "nl",
    "PL": "pl",
}
_SCENARIOS: Final[tuple[str, ...]] = ("customer_support", "finance", "hr")
_POSITIVE_CONTEXTS: Final[dict[str, dict[str, str]]] = {
    "de": {
        "customer_support": "Kundenservice: Bitte pruefen Sie die Anfrage mit",
        "finance": "Finanzen: Bitte pruefen Sie die Rechnung mit",
        "hr": "Personalwesen: Bitte pruefen Sie die Unterlagen mit",
    },
    "es": {
        "customer_support": "Atencion al cliente: revise la solicitud con",
        "finance": "Finanzas: revise la factura con",
        "hr": "Recursos humanos: revise el expediente con",
    },
    "fr": {
        "customer_support": "Service client: verifier la demande avec",
        "finance": "Finance: verifier la facture avec",
        "hr": "Ressources humaines: verifier le dossier avec",
    },
    "it": {
        "customer_support": "Assistenza clienti: verificare la richiesta con",
        "finance": "Finanza: verificare la fattura con",
        "hr": "Risorse umane: verificare il fascicolo con",
    },
    "nl": {
        "customer_support": "Klantenservice: controleer het verzoek met",
        "finance": "Financien: controleer de factuur met",
        "hr": "Personeelszaken: controleer het dossier met",
    },
    "pl": {
        "customer_support": "Obsluga klienta: sprawdz zgloszenie z",
        "finance": "Finanse: sprawdz fakture z",
        "hr": "Kadry: sprawdz dokumenty z",
    },
}
_NEGATIVE_CONTEXTS: Final[dict[str, dict[str, str]]] = {
    "de": {
        "customer_support": "Kundenservice Referenz",
        "finance": "Finanzbeleg Referenz",
        "hr": "Personalbericht Referenz",
    },
    "es": {
        "customer_support": "Referencia de atencion al cliente",
        "finance": "Referencia de factura",
        "hr": "Referencia de personal",
    },
    "fr": {
        "customer_support": "Reference du service client",
        "finance": "Reference de facture",
        "hr": "Reference du personnel",
    },
    "it": {
        "customer_support": "Riferimento assistenza clienti",
        "finance": "Riferimento fattura",
        "hr": "Riferimento personale",
    },
    "nl": {
        "customer_support": "Klantenservice referentie",
        "finance": "Factuur referentie",
        "hr": "Personeel referentie",
    },
    "pl": {
        "customer_support": "Numer referencyjny obslugi klienta",
        "finance": "Numer referencyjny faktury",
        "hr": "Numer referencyjny kadr",
    },
}
_TARGET_LABELS: Final[dict[str, str]] = {
    "DE": "Steuer-ID",
    "ES": "DNI",
    "FR": "NIR",
    "IT": "codice fiscale",
    "NL": "BSN",
    "PL": "PESEL",
}
_TASK_ANSWER_PATTERN: Final[re.Pattern[str]] = re.compile(r"\bunits=([0-9]{1,3})\b")
_REFERENCE_DIGEST_PATTERN: Final[re.Pattern[str]] = re.compile(r"sha256:[a-f0-9]{64}\Z")


@dataclass(frozen=True, slots=True)
class BenchmarkSample:
    sample_id: str
    country: str
    language: str
    scenario: str
    is_positive: bool
    prompt: str
    entity_type: str | None
    target_value: str | None
    span_start: int | None
    span_end: int | None
    expected_task_answer: str


class LabelMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    positive_samples: int = Field(ge=0)
    annotated_spans: int = Field(ge=0)
    detected_spans: int = Field(ge=0)
    recall: float | None


class CountryMetrics(LabelMetrics):
    hard_negative_samples: int = Field(ge=0)
    flagged_hard_negative_samples: int = Field(ge=0)
    hard_negative_fpr: float | None


class BaselineLanguageMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str
    positive_samples: int = Field(ge=0)
    detected_positive_samples: int = Field(ge=0)
    hard_negative_samples: int = Field(ge=0)
    flagged_hard_negative_samples: int = Field(ge=0)
    recall: float | None
    hard_negative_fpr: float | None


class PresidioSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_version: str
    actual_version: str | None
    nlp_model_package: str
    nlp_model_version: str | None
    nlp_model_sha256: str | None
    status: str
    by_language: dict[str, BaselineLanguageMetrics]


class BenchmarkEnvironment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operating_system: str
    distribution: str | None
    machine: str
    python_version: str
    cpu_affinity: tuple[int, ...]
    cpu_model: str
    cpu_microcode: str | None
    memory_bytes: int | None
    container_image_digest: str | None
    reference_environment_match: bool


class BenchmarkThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    structured_recall: bool
    hard_negative_fpr: bool
    task_utility_retention: bool
    tier1_latency: bool | None
    tier2_latency: bool | None
    release_gate_passed: bool | None


class BenchmarkReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    benchmark_id: str
    seed: int
    dataset_sha256: str
    sample_count: int
    positive_samples: int
    hard_negative_samples: int
    structured_recall: float
    hard_negative_fpr: float
    flagged_hard_negative_samples: int
    task_utility_retention: float | None
    utility_raw_successes: int
    utility_retained_successes: int
    by_country: dict[str, CountryMetrics]
    by_entity: dict[str, LabelMetrics]
    tier1_observations: int
    tier1_p95_ms: float | None
    tier2_observations: int
    tier2_p95_ms: float | None
    ner_model_load_ms: float | None
    presidio: PresidioSummary
    environment: BenchmarkEnvironment
    thresholds: BenchmarkThresholds


class BenchmarkError(RuntimeError):
    """A sanitized benchmark generation or measurement error."""


def _make_identifier(country: str, rng: random.Random) -> str:
    if country == "DE":
        return "12234567899"
    if country == "ES":
        from stdnum.es import dni

        body = f"{rng.randrange(0, 100_000_000):08d}"
        return body + dni.calc_check_digit(body)
    if country == "FR":
        from stdnum.fr import nir

        body = "180010100" + f"{rng.randrange(0, 10_000):04d}"
        return body + nir.calc_check_digits(body)
    if country == "IT":
        from stdnum.it import codicefiscale

        body = "RSSMRA85M01H501"
        return body + codicefiscale.calc_check_digit(body)
    if country == "NL":
        from stdnum.nl import bsn

        for _ in range(100):
            body = f"{rng.randrange(10_000_000, 100_000_000):08d}"
            for check_digit in range(10):
                candidate = body + str(check_digit)
                if bsn.is_valid(candidate):
                    return candidate
        raise BenchmarkError("Unable to generate a valid synthetic Dutch BSN")
    if country == "PL":
        from stdnum.pl import pesel

        body = "0021010" + f"{rng.randrange(0, 1_000):03d}"
        return body + pesel.calc_check_digit(body)
    raise BenchmarkError("Unsupported synthetic benchmark country")


def _resolves_to_entity(value: str, entity_type: str) -> bool:
    spans = resolve_spans(detect_tier1(normalize_text(value)))
    return len(spans) == 1 and spans[0].entity_type == entity_type


def _positive_prompt(
    country: str,
    scenario: str,
    identifier: str,
    answer: str,
) -> str:
    language = _LANGUAGE_BY_COUNTRY[country]
    prefix = _POSITIVE_CONTEXTS[language][scenario]
    label = _TARGET_LABELS[country]
    return f"{prefix} {label} {identifier}; units={answer}."


def _negative_prompt(
    country: str,
    scenario: str,
    rng: random.Random,
) -> str:
    language = _LANGUAGE_BY_COUNTRY[country]
    prefix = _NEGATIVE_CONTEXTS[language][scenario]
    day = rng.randrange(1, 29)
    reference = rng.randrange(1_000, 10_000)
    units = rng.randrange(1, 51)
    return f"{prefix}: date=2026-11-{day:02d}; reference={reference}; units={units}."


def generate_dataset(seed: int = DATASET_SEED) -> tuple[BenchmarkSample, ...]:
    """Generate the frozen 800-positive/200-hard-negative synthetic benchmark."""
    # The fixed-seed PRNG generates only the synthetic benchmark corpus.
    rng = random.Random(seed)  # nosec B311
    cells = tuple(
        (country, scenario)
        for country in sorted(_ENTITY_BY_COUNTRY)
        for scenario in sorted(_SCENARIOS)
    )
    provisional: list[BenchmarkSample] = []
    for cell_index, (country, scenario) in enumerate(cells):
        positive_count = 45 if cell_index < 8 else 44
        negative_count = 12 if cell_index < 2 else 11
        entity_type = _ENTITY_BY_COUNTRY[country]
        for _ in range(positive_count):
            target = _make_identifier(country, rng)
            for _attempt in range(100):
                if _resolves_to_entity(target, entity_type):
                    break
                target = _make_identifier(country, rng)
            else:
                raise BenchmarkError("Unable to generate an unambiguous synthetic identifier")
            task_answer = str(rng.randrange(1, 51))
            prompt = _positive_prompt(country, scenario, target, task_answer)
            span_start = prompt.index(target)
            provisional.append(
                BenchmarkSample(
                    sample_id="",
                    country=country,
                    language=_LANGUAGE_BY_COUNTRY[country],
                    scenario=scenario,
                    is_positive=True,
                    prompt=prompt,
                    entity_type=entity_type,
                    target_value=target,
                    span_start=span_start,
                    span_end=span_start + len(target),
                    expected_task_answer=task_answer,
                )
            )
        for _ in range(negative_count):
            prompt = _negative_prompt(country, scenario, rng)
            answer = _TASK_ANSWER_PATTERN.search(prompt)
            if answer is None:
                raise BenchmarkError("A generated hard negative is missing its task answer")
            provisional.append(
                BenchmarkSample(
                    sample_id="",
                    country=country,
                    language=_LANGUAGE_BY_COUNTRY[country],
                    scenario=scenario,
                    is_positive=False,
                    prompt=prompt,
                    entity_type=None,
                    target_value=None,
                    span_start=None,
                    span_end=None,
                    expected_task_answer=answer.group(1),
                )
            )

    rng.shuffle(provisional)
    return tuple(
        replace(sample, sample_id=f"{DATASET_ID}-{index:04d}")
        for index, sample in enumerate(provisional, start=1)
    )


def serialize_dataset(samples: tuple[BenchmarkSample, ...]) -> str:
    return "\n".join(
        json.dumps(asdict(sample), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        for sample in samples
    ) + "\n"


def write_dataset(output_path: str | Path, samples: tuple[BenchmarkSample, ...]) -> None:
    path = Path(output_path)
    write_failed = False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(serialize_dataset(samples), encoding="utf-8")
    except OSError:
        write_failed = True
    if write_failed:
        raise BenchmarkError("Unable to write the synthetic benchmark dataset")


def extract_task_answer(text: str) -> str | None:
    match = _TASK_ANSWER_PATTERN.search(text)
    return None if match is None else match.group(1)


def _benchmark_policy(policy: PolicyConfig) -> PolicyConfig:
    entities = {
        name: rule.model_copy(update={"enabled": True, "action": EntityAction.MASK})
        for name, rule in policy.entities.items()
    }
    for entity_type in _ENTITY_BY_COUNTRY.values():
        if entity_type not in entities:
            entities[entity_type] = EntityRule(action=EntityAction.MASK)
    return policy.model_copy(
        update={
            "mode": OperatingMode.ENFORCE,
            "on_error": ErrorPolicy.FAIL_CLOSED,
            "entities": entities,
        }
    )


def _mask_and_rehydrate(
    prompt: str,
    sample_id: str,
    result: PipelineResult,
) -> tuple[str, str]:
    vault = SessionVault(_BENCHMARK_SECRET, f"benchmark:{sample_id}")
    masked = prompt
    try:
        for span in sorted(result.spans_to_mask, key=lambda item: item.start, reverse=True):
            token = vault.tokenize(span.entity_type, prompt[span.start : span.end])
            masked = masked[: span.start] + token + masked[span.end :]
        return masked, vault.rehydrate(masked)
    finally:
        vault.wipe()


def _nearest_rank_p95(observations_ns: list[int]) -> float:
    if not observations_ns:
        raise BenchmarkError("No latency observations were collected")
    ordered = sorted(observations_ns)
    rank = math.ceil(0.95 * len(ordered))
    return ordered[rank - 1] / 1_000_000


def _measure_path(
    samples: tuple[BenchmarkSample, ...],
    policy: PolicyConfig,
    ner_runner: NerOnnxRunner | None,
) -> tuple[int, float]:
    def process(sample: BenchmarkSample) -> None:
        result = run_pipeline(sample.prompt, policy, ner_runner)
        _mask_and_rehydrate(sample.prompt, sample.sample_id, result)

    for sample in samples[:WARMUP_COUNT]:
        process(sample)
    observations: list[int] = []
    for _ in range(TIMED_PASSES):
        for sample in samples:
            started = time.perf_counter_ns()
            process(sample)
            observations.append(time.perf_counter_ns() - started)
    return len(observations), _nearest_rank_p95(observations)


def _memory_bytes() -> int | None:
    try:
        return int(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))
    except (AttributeError, OSError, ValueError):
        return None


def _cpu_facts() -> tuple[str, str | None]:
    cpu_model = platform.processor() or platform.machine()
    cpu_microcode: str | None = None
    cpu_info = Path("/proc/cpuinfo")
    if cpu_info.is_file():
        try:
            for line in cpu_info.read_text(encoding="utf-8").splitlines():
                if line.lower().startswith("model name"):
                    cpu_model = line.partition(":")[2].strip() or cpu_model
                elif line.lower().startswith("microcode"):
                    cpu_microcode = line.partition(":")[2].strip() or None
                if cpu_microcode is not None and cpu_model != platform.machine():
                    break
        except OSError:
            cpu_model = platform.processor() or platform.machine()
            cpu_microcode = None
    return cpu_model, cpu_microcode


def _distribution_name() -> str | None:
    try:
        release = platform.freedesktop_os_release()
    except (AttributeError, OSError):
        return None
    name = release.get("NAME")
    version = release.get("VERSION_ID")
    if isinstance(name, str) and isinstance(version, str):
        return f"{name} {version}"
    return None


def _pin_four_cpus() -> tuple[frozenset[int] | None, tuple[int, ...]]:
    getter = getattr(os, "sched_getaffinity", None)
    setter = getattr(os, "sched_setaffinity", None)
    if getter is None or setter is None:
        return None, ()
    try:
        previous = frozenset(getter(0))
        if len(previous) < 4:
            return previous, tuple(sorted(previous))
        selected = tuple(sorted(previous)[:4])
        setter(0, set(selected))
        return previous, selected
    except OSError:
        return None, ()


def _container_digest(requested_digest: str | None) -> str | None:
    selected = requested_digest or os.environ.get("SOVEREIGNGATE_CONTAINER_IMAGE_DIGEST")
    if isinstance(selected, str) and _REFERENCE_DIGEST_PATTERN.fullmatch(selected):
        return selected
    return None


def _reference_environment(
    cpu_affinity: tuple[int, ...],
    container_image_digest: str | None,
) -> BenchmarkEnvironment:
    distribution = _distribution_name()
    memory = _memory_bytes()
    cpu_model, cpu_microcode = _cpu_facts()
    machine = platform.machine()
    reference_match = bool(
        sys.platform == "linux"
        and distribution == "Ubuntu 24.04"
        and machine in {"x86_64", "amd64"}
        and platform.python_version() == "3.12.16"
        and len(cpu_affinity) == 4
        and memory is not None
        and 8 * 1024**3 <= memory < 9 * 1024**3
        and bool(cpu_model)
        and cpu_microcode is not None
        and container_image_digest is not None
    )
    return BenchmarkEnvironment(
        operating_system=platform.system(),
        distribution=distribution,
        machine=machine,
        python_version=platform.python_version(),
        cpu_affinity=cpu_affinity,
        cpu_model=cpu_model,
        cpu_microcode=cpu_microcode,
        memory_bytes=memory,
        container_image_digest=container_image_digest,
        reference_environment_match=reference_match,
    )


def _metric(
    positive_samples: int,
    detected_samples: int,
    negative_samples: int = 0,
    flagged_negatives: int = 0,
) -> CountryMetrics:
    return CountryMetrics(
        positive_samples=positive_samples,
        annotated_spans=positive_samples,
        detected_spans=detected_samples,
        recall=detected_samples / positive_samples if positive_samples else None,
        hard_negative_samples=negative_samples,
        flagged_hard_negative_samples=flagged_negatives,
        hard_negative_fpr=flagged_negatives / negative_samples if negative_samples else None,
    )


def _presidio_baseline(samples: tuple[BenchmarkSample, ...]) -> PresidioSummary:
    expected_version = "2.2.366"
    empty_languages = {
        language: BaselineLanguageMetrics(
            status="N/A",
            positive_samples=0,
            detected_positive_samples=0,
            hard_negative_samples=0,
            flagged_hard_negative_samples=0,
            recall=None,
            hard_negative_fpr=None,
        )
        for language in sorted(set(_LANGUAGE_BY_COUNTRY.values()))
    }
    try:
        actual_version = importlib.metadata.version("presidio-analyzer")
    except importlib.metadata.PackageNotFoundError:
        return PresidioSummary(
            expected_version=expected_version,
            actual_version=None,
            nlp_model_package=_PRESIDIO_NLP_MODEL,
            nlp_model_version=None,
            nlp_model_sha256=None,
            status="not_installed",
            by_language=empty_languages,
        )
    if actual_version != expected_version:
        return PresidioSummary(
            expected_version=expected_version,
            actual_version=actual_version,
            nlp_model_package=_PRESIDIO_NLP_MODEL,
            nlp_model_version=None,
            nlp_model_sha256=None,
            status="version_mismatch",
            by_language=empty_languages,
        )

    model_version, model_digest = _presidio_model_provenance()
    if model_version is None or model_digest is None:
        return PresidioSummary(
            expected_version=expected_version,
            actual_version=actual_version,
            nlp_model_package=_PRESIDIO_NLP_MODEL,
            nlp_model_version=model_version,
            nlp_model_sha256=model_digest,
            status="nlp_model_not_provisioned",
            by_language=empty_languages,
        )
    if (
        model_version != _PRESIDIO_NLP_MODEL_VERSION
        or model_digest != _PRESIDIO_NLP_MODEL_SHA256
    ):
        return PresidioSummary(
            expected_version=expected_version,
            actual_version=actual_version,
            nlp_model_package=_PRESIDIO_NLP_MODEL,
            nlp_model_version=model_version,
            nlp_model_sha256=model_digest,
            status="nlp_model_mismatch",
            by_language=empty_languages,
        )

    analyzer = None
    initialization_failed = False
    try:
        from presidio_analyzer import AnalyzerEngine

        analyzer = AnalyzerEngine()
    except Exception:
        initialization_failed = True
    if initialization_failed or analyzer is None:
        return PresidioSummary(
            expected_version=expected_version,
            actual_version=actual_version,
            nlp_model_package=_PRESIDIO_NLP_MODEL,
            nlp_model_version=model_version,
            nlp_model_sha256=model_digest,
            status="default_engine_unavailable",
            by_language=empty_languages,
        )

    supported_languages = set(analyzer.supported_languages)
    counts: dict[str, Counter[str]] = {
        language: Counter() for language in empty_languages
    }
    failed_languages: set[str] = set()
    for sample in samples:
        if sample.language not in supported_languages:
            continue
        language_counts = counts[sample.language]
        try:
            results = analyzer.analyze(text=sample.prompt, language=sample.language)
        except Exception:
            failed_languages.add(sample.language)
            continue
        if sample.is_positive:
            language_counts["positives"] += 1
            if any(
                result.start < (sample.span_end or 0)
                and result.end > (sample.span_start or 0)
                for result in results
            ):
                language_counts["detected"] += 1
        else:
            language_counts["negatives"] += 1
            if results:
                language_counts["flagged"] += 1

    by_language: dict[str, BaselineLanguageMetrics] = {}
    for language, values in counts.items():
        positive_count = values["positives"]
        negative_count = values["negatives"]
        if positive_count == 0 and negative_count == 0:
            status = "N/A (unsupported by default registry)"
        elif language in failed_languages:
            status = "unavailable"
        else:
            status = "measured"
        by_language[language] = BaselineLanguageMetrics(
            status=status,
            positive_samples=positive_count,
            detected_positive_samples=values["detected"],
            hard_negative_samples=negative_count,
            flagged_hard_negative_samples=values["flagged"],
            recall=values["detected"] / positive_count if positive_count else None,
            hard_negative_fpr=values["flagged"] / negative_count if negative_count else None,
        )
    measured = any(metric.status == "measured" for metric in by_language.values())
    return PresidioSummary(
        expected_version=expected_version,
        actual_version=actual_version,
        nlp_model_package=_PRESIDIO_NLP_MODEL,
        nlp_model_version=model_version,
        nlp_model_sha256=model_digest,
        status="measured" if measured else "no_supported_languages",
        by_language=by_language,
    )


def _presidio_model_provenance() -> tuple[str | None, str | None]:
    model_spec = None
    try:
        model_spec = importlib.util.find_spec(_PRESIDIO_NLP_MODEL)
        model_version = importlib.metadata.version("en-core-web-lg")
    except (ImportError, ModuleNotFoundError, importlib.metadata.PackageNotFoundError, ValueError):
        return None, None
    if model_spec is None or model_spec.origin is None:
        return None, None

    model_root = Path(model_spec.origin).parent
    digest = hashlib.sha256()
    try:
        for path in sorted(model_root.rglob("*")):
            if not path.is_file() or path.is_symlink() or "__pycache__" in path.parts:
                continue
            digest.update(path.relative_to(model_root).as_posix().encode("utf-8") + b"\0")
            with path.open("rb") as model_file:
                for chunk in iter(lambda: model_file.read(1024 * 1024), b""):
                    digest.update(chunk)
    except OSError:
        return model_version, None
    return model_version, digest.hexdigest()


def run_benchmark(
    policy: PolicyConfig | None = None,
    *,
    ner_runner: NerOnnxRunner | None = None,
    measure_latency: bool = True,
    include_presidio: bool = True,
    container_image_digest: str | None = None,
) -> BenchmarkReport:
    samples = generate_dataset()
    base_policy = load_policy(environ={}) if policy is None else policy
    model_load_ms: float | None = None
    selected_ner = ner_runner
    if base_policy.ner.enabled and selected_ner is None:
        model_started = time.perf_counter_ns()
        selected_ner = NerOnnxRunner.from_policy(base_policy.ner)
        model_load_ms = (time.perf_counter_ns() - model_started) / 1_000_000
    benchmark_policy = _benchmark_policy(base_policy)

    country_values: dict[str, Counter[str]] = {
        country: Counter() for country in _ENTITY_BY_COUNTRY
    }
    entity_values: dict[str, Counter[str]] = {
        entity_type: Counter() for entity_type in _ENTITY_BY_COUNTRY.values()
    }
    flagged_hard_negatives = 0
    utility_raw_successes = 0
    utility_retained_successes = 0

    for sample in samples:
        result = run_pipeline(sample.prompt, benchmark_policy, selected_ner)
        if result.processing_error is not None:
            raise BenchmarkError(f"Pipeline failed: {result.processing_error.value}")
        masked, restored = _mask_and_rehydrate(sample.prompt, sample.sample_id, result)
        raw_answer = extract_task_answer(sample.prompt)
        masked_answer = extract_task_answer(masked)
        if raw_answer == sample.expected_task_answer:
            utility_raw_successes += 1
            if masked_answer == raw_answer and restored == sample.prompt:
                utility_retained_successes += 1
        if sample.is_positive:
            country_values[sample.country]["positives"] += 1
            entity_type = sample.entity_type
            if entity_type is None or sample.span_start is None or sample.span_end is None:
                raise BenchmarkError("A positive benchmark record is missing its span annotation")
            entity_values[entity_type]["positives"] += 1
            detected = any(
                decision.span.entity_type == entity_type
                and decision.span.start == sample.span_start
                and decision.span.end == sample.span_end
                for decision in result.decisions
            )
            if detected:
                country_values[sample.country]["detected"] += 1
                entity_values[entity_type]["detected"] += 1
        else:
            country_values[sample.country]["negatives"] += 1
            if result.decisions or result.blocked:
                country_values[sample.country]["flagged"] += 1
                flagged_hard_negatives += 1

    positive_count = sum(values["positives"] for values in country_values.values())
    hard_negative_count = sum(values["negatives"] for values in country_values.values())
    detected_positive_count = sum(values["detected"] for values in country_values.values())
    structured_recall = detected_positive_count / positive_count
    hard_negative_fpr = flagged_hard_negatives / hard_negative_count
    utility_retention = (
        utility_retained_successes / utility_raw_successes if utility_raw_successes else None
    )

    per_country = {
        country: _metric(
            values["positives"],
            values["detected"],
            values["negatives"],
            values["flagged"],
        )
        for country, values in sorted(country_values.items())
    }
    per_entity = {
        entity_type: LabelMetrics(
            positive_samples=values["positives"],
            annotated_spans=values["positives"],
            detected_spans=values["detected"],
            recall=values["detected"] / values["positives"] if values["positives"] else None,
        )
        for entity_type, values in sorted(entity_values.items())
    }

    cpu_previous: frozenset[int] | None = None
    cpu_affinity: tuple[int, ...] = ()
    tier1_observations = 0
    tier1_p95: float | None = None
    tier2_observations = 0
    tier2_p95: float | None = None
    if measure_latency:
        cpu_previous, cpu_affinity = _pin_four_cpus()
        try:
            tier1_policy = benchmark_policy.model_copy(
                update={"ner": benchmark_policy.ner.model_copy(update={"enabled": False})}
            )
            tier1_observations, tier1_p95 = _measure_path(samples, tier1_policy, None)
            if benchmark_policy.ner.enabled and selected_ner is not None:
                tier2_observations, tier2_p95 = _measure_path(
                    samples, benchmark_policy, selected_ner
                )
        finally:
            if cpu_previous is not None and hasattr(os, "sched_setaffinity"):
                try:
                    os.sched_setaffinity(0, set(cpu_previous))
                except OSError:
                    pass

    image_digest = _container_digest(container_image_digest)
    environment = _reference_environment(cpu_affinity, image_digest)
    presidio_summary = (
        _presidio_baseline(samples)
        if include_presidio
        else PresidioSummary(
            expected_version="2.2.366",
            actual_version=None,
            nlp_model_package=_PRESIDIO_NLP_MODEL,
            nlp_model_version=None,
            nlp_model_sha256=None,
            status="not_run",
            by_language={
                language: BaselineLanguageMetrics(
                    status="N/A",
                    positive_samples=0,
                    detected_positive_samples=0,
                    hard_negative_samples=0,
                    flagged_hard_negative_samples=0,
                    recall=None,
                    hard_negative_fpr=None,
                )
                for language in sorted(set(_LANGUAGE_BY_COUNTRY.values()))
            },
        )
    )
    tier1_pass = None if tier1_p95 is None else tier1_p95 < 2.0
    tier2_pass = None if tier2_p95 is None else tier2_p95 < 65.0
    baseline_measured = presidio_summary.status == "measured"
    gate_values = [
        structured_recall >= 0.99,
        hard_negative_fpr <= 0.01,
        utility_retention is not None and utility_retention >= 0.95,
        tier1_pass is True,
        tier2_pass is True,
        baseline_measured,
    ]
    release_gate = (
        all(gate_values)
        if environment.reference_environment_match
        and all(value is not None for value in gate_values)
        else None
    )

    dataset_digest = hashlib.sha256(serialize_dataset(samples).encode("utf-8")).hexdigest()
    return BenchmarkReport(
        benchmark_id=DATASET_ID,
        seed=DATASET_SEED,
        dataset_sha256=dataset_digest,
        sample_count=len(samples),
        positive_samples=positive_count,
        hard_negative_samples=hard_negative_count,
        structured_recall=structured_recall,
        hard_negative_fpr=hard_negative_fpr,
        flagged_hard_negative_samples=flagged_hard_negatives,
        task_utility_retention=utility_retention,
        utility_raw_successes=utility_raw_successes,
        utility_retained_successes=utility_retained_successes,
        by_country=per_country,
        by_entity=per_entity,
        tier1_observations=tier1_observations,
        tier1_p95_ms=tier1_p95,
        tier2_observations=tier2_observations,
        tier2_p95_ms=tier2_p95,
        ner_model_load_ms=model_load_ms,
        presidio=presidio_summary,
        environment=environment,
        thresholds=BenchmarkThresholds(
            structured_recall=structured_recall >= 0.99,
            hard_negative_fpr=hard_negative_fpr <= 0.01,
            task_utility_retention=(
                utility_retention is not None and utility_retention >= 0.95
            ),
            tier1_latency=tier1_pass,
            tier2_latency=tier2_pass,
            release_gate_passed=release_gate,
        ),
    )
