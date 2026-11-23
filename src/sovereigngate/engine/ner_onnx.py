import hashlib
import importlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Annotated, Any, Final, Literal, Protocol, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from sovereigngate.config import NerConfig
from sovereigngate.engine.detectors import DetectionSpan
from sovereigngate.engine.normalizer import NormalizedText

_MANIFEST_NAME: Final[str] = "model_manifest.json"
_MAX_MANIFEST_BYTES: Final[int] = 65_536
_MAX_MODEL_BYTES: Final[int] = 2_000_000_000
_MAX_TOKENIZER_BYTES: Final[int] = 32_000_000
_ASSET_NAME_PATTERN: Final[str] = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_SHA256_PATTERN: Final[str] = r"^[A-Fa-f0-9]{64}$"
_WORD_PATTERN: Final[re.Pattern[str]] = re.compile(r"\w+(?:[-_]\w+)*|\S", re.UNICODE)
_EXPECTED_LABELS: Final[tuple[tuple[str, str], ...]] = (
    ("person", "PERSON"),
    ("organization", "ORG"),
    ("address", "ADDRESS"),
    ("health_term", "HEALTH_TERM"),
)
_REQUIRED_INPUTS: Final[frozenset[str]] = frozenset(
    {"input_ids", "attention_mask", "words_mask", "text_lengths", "span_idx", "span_mask"}
)

AssetName = Annotated[str, StringConstraints(pattern=_ASSET_NAME_PATTERN)]
Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
NEREntityType = Literal["PERSON", "ORG", "ADDRESS", "HEALTH_TERM"]


class NerModelError(ValueError):
    """A sanitized local NER artifact or inference error."""


class NERModelLabel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt: str
    entity_type: NEREntityType


class NERArtifactManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1]
    model_id: Literal["urchade/gliner_multi-v2.1"]
    source_revision: Literal["443d26d654e0324125a96bebd8e796c14ff2efe6"]
    source_weights_sha256: Literal[
        "2100142f31627531497850659dcb3821c99d5e71c08a8e01a98e4b11ef32a199"
    ]
    exporter_revision: Literal["beb41b3839267952d0f063c04dd6236e9fd93a38"]
    onnx_opset: Literal[19]
    quantization: Literal["dynamic-int8"]
    model_file: AssetName
    model_sha256: Digest
    tokenizer_file: AssetName
    tokenizer_sha256: Digest
    labels: tuple[NERModelLabel, ...]
    ent_token: str = "[ENT]"
    sep_token: str = "[SEP]"
    max_length: int = Field(default=384, ge=16, le=4096)
    max_width: int = Field(default=12, ge=1, le=64)
    output_name: Literal["logits"] = "logits"
    output_layout: Literal["word_width_labels"] = "word_width_labels"

    @model_validator(mode="after")
    def validate_label_contract(self) -> "NERArtifactManifest":
        labels = tuple((label.prompt, label.entity_type) for label in self.labels)
        if labels != _EXPECTED_LABELS:
            raise ValueError("NER manifest must use the fixed SovereignGate entity-label order")
        if self.ent_token == self.sep_token:
            raise ValueError("NER prompt marker tokens must be distinct")
        return self


class _NamedValue(Protocol):
    name: str


class _InferenceSession(Protocol):
    def get_inputs(self) -> Sequence[_NamedValue]: ...

    def get_outputs(self) -> Sequence[_NamedValue]: ...

    def run(
        self,
        output_names: list[str] | None,
        input_feed: Mapping[str, Any],
    ) -> Sequence[Any]: ...


class _Encoding(Protocol):
    ids: Sequence[int]
    attention_mask: Sequence[int]
    word_ids: Sequence[int | None]


class _Tokenizer(Protocol):
    def token_to_id(self, token: str) -> int | None: ...

    def encode(
        self,
        sequence: list[str],
        pair: None = None,
        is_pretokenized: bool = False,
        add_special_tokens: bool = True,
    ) -> _Encoding: ...

    def enable_truncation(self, max_length: int) -> object: ...


SessionFactory = Callable[[Path], _InferenceSession]
TokenizerFactory = Callable[[Path], _Tokenizer]


def _sha256_file(path: Path, *, maximum_size: int) -> str:
    try:
        size = path.stat().st_size
        if size > maximum_size:
            raise NerModelError("A local NER artifact exceeds its size limit")
        digest = hashlib.sha256()
        with path.open("rb") as artifact:
            for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise NerModelError("Unable to read a local NER artifact") from None
    return digest.hexdigest()


def _resolve_asset(model_dir: Path, asset_name: str) -> Path:
    try:
        root = model_dir.resolve(strict=True)
        asset = (root / asset_name).resolve(strict=True)
    except OSError:
        raise NerModelError("A required local NER artifact is missing") from None
    if not root.is_dir() or not asset.is_file() or not asset.is_relative_to(root):
        raise NerModelError(
            "A required local NER artifact is missing or outside its model directory"
        )
    return asset


def _load_manifest(model_dir: Path, expected_sha256: str) -> NERArtifactManifest:
    manifest_path = _resolve_asset(model_dir, _MANIFEST_NAME)
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError:
        raise NerModelError("Unable to read the local NER manifest") from None
    if len(manifest_bytes) > _MAX_MANIFEST_BYTES:
        raise NerModelError("The local NER manifest exceeds its size limit")
    if hashlib.sha256(manifest_bytes).hexdigest() != expected_sha256.lower():
        raise NerModelError("The local NER manifest digest does not match policy")
    try:
        parsed = json.loads(manifest_bytes)
        return NERArtifactManifest.model_validate(parsed)
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError):
        raise NerModelError("The local NER manifest is malformed or unsupported") from None


def _load_session(
    model_path: Path,
) -> tuple[_InferenceSession, tuple[type[BaseException], ...]]:
    try:
        runtime = importlib.import_module("onnxruntime")
    except ImportError:
        raise NerModelError("Tier 2 NER requires the optional 'ner' dependencies") from None
    runtime_state = runtime.capi.onnxruntime_pybind11_state
    runtime_error_types: tuple[type[BaseException], ...] = tuple(
        error_type
        for error_type in vars(runtime_state).values()
        if isinstance(error_type, type)
        and issubclass(error_type, BaseException)
        and error_type.__module__ == runtime_state.__name__
    )

    options = runtime.SessionOptions()
    options.intra_op_num_threads = 4
    options.inter_op_num_threads = 1
    try:
        session = runtime.InferenceSession(
            str(model_path),
            sess_options=options,
            providers=["CPUExecutionProvider"],
        )
    except runtime_error_types:
        raise NerModelError("Unable to initialize the local ONNX NER model") from None
    except (OSError, RuntimeError, ValueError):
        raise NerModelError("Unable to initialize the local ONNX NER model") from None
    return cast(_InferenceSession, session), runtime_error_types


def _load_tokenizer(tokenizer_path: Path, manifest: NERArtifactManifest) -> _Tokenizer:
    try:
        tokenizers = importlib.import_module("tokenizers")
    except ImportError:
        raise NerModelError("Tier 2 NER requires the optional 'ner' dependencies") from None
    try:
        tokenizer = tokenizers.Tokenizer.from_file(str(tokenizer_path))
    except (OSError, ValueError):
        raise NerModelError("Unable to load the local NER tokenizer") from None
    except Exception as error:
        if type(error) is Exception:
            raise NerModelError("Unable to load the local NER tokenizer") from None
        raise
    if (
        tokenizer.token_to_id(manifest.ent_token) is None
        or tokenizer.token_to_id(manifest.sep_token) is None
    ):
        raise NerModelError("The local NER tokenizer is missing required prompt markers")
    tokenizer.enable_truncation(max_length=manifest.max_length)
    return cast(_Tokenizer, tokenizer)


class NerOnnxRunner:
    def __init__(
        self,
        manifest: NERArtifactManifest,
        session: _InferenceSession,
        tokenizer: _Tokenizer,
        numpy: Any,
        threshold: float,
        runtime_error_types: tuple[type[BaseException], ...] = (),
    ) -> None:
        self._manifest = manifest
        self._session = session
        self._tokenizer = tokenizer
        self._numpy = numpy
        self._threshold = threshold
        self._runtime_error_types = runtime_error_types
        input_names = {value.name for value in session.get_inputs()}
        output_names = {value.name for value in session.get_outputs()}
        if input_names != _REQUIRED_INPUTS or manifest.output_name not in output_names:
            raise NerModelError("The local ONNX NER graph does not match its input/output contract")

    def __repr__(self) -> str:
        return "<NerOnnxRunner [LOCAL MODEL] [REDACTED]>"

    __str__ = __repr__

    @classmethod
    def from_policy(
        cls,
        config: NerConfig,
        *,
        session_factory: SessionFactory | None = None,
        tokenizer_factory: TokenizerFactory | None = None,
    ) -> "NerOnnxRunner | None":
        if not config.enabled:
            return None
        if config.model_dir is None or config.manifest_sha256 is None:
            raise NerModelError("Enabled NER requires a local directory and pinned manifest digest")
        return cls.load(
            config.model_dir,
            expected_manifest_sha256=config.manifest_sha256,
            threshold=config.threshold,
            session_factory=session_factory,
            tokenizer_factory=tokenizer_factory,
        )

    @classmethod
    def load(
        cls,
        model_dir: Path,
        *,
        expected_manifest_sha256: str,
        threshold: float = 0.5,
        session_factory: SessionFactory | None = None,
        tokenizer_factory: TokenizerFactory | None = None,
    ) -> "NerOnnxRunner":
        manifest = _load_manifest(model_dir, expected_manifest_sha256)
        model_path = _resolve_asset(model_dir, manifest.model_file)
        tokenizer_path = _resolve_asset(model_dir, manifest.tokenizer_file)
        if (
            _sha256_file(model_path, maximum_size=_MAX_MODEL_BYTES) != manifest.model_sha256.lower()
            or _sha256_file(tokenizer_path, maximum_size=_MAX_TOKENIZER_BYTES)
            != manifest.tokenizer_sha256.lower()
        ):
            raise NerModelError("A local NER artifact digest does not match its manifest")

        if session_factory is None:
            session, runtime_error_types = _load_session(model_path)
        else:
            try:
                session = session_factory(model_path)
            except (OSError, RuntimeError, ValueError):
                raise NerModelError("Unable to initialize the local ONNX NER model") from None
            runtime_error_types = ()
        if tokenizer_factory is None:
            tokenizer = _load_tokenizer(tokenizer_path, manifest)
        else:
            try:
                tokenizer = tokenizer_factory(tokenizer_path)
            except (OSError, RuntimeError, ValueError):
                raise NerModelError("Unable to load the local NER tokenizer") from None
            if (
                tokenizer.token_to_id(manifest.ent_token) is None
                or tokenizer.token_to_id(manifest.sep_token) is None
            ):
                raise NerModelError("The local NER tokenizer is missing required prompt markers")
            tokenizer.enable_truncation(max_length=manifest.max_length)

        try:
            numpy = importlib.import_module("numpy")
        except ImportError:
            raise NerModelError("Tier 2 NER requires the optional 'ner' dependencies") from None
        return cls(manifest, session, tokenizer, numpy, threshold, runtime_error_types)

    def detect(self, normalized: NormalizedText) -> tuple[DetectionSpan, ...]:
        words = [
            (match.group(), match.start(), match.end())
            for match in _WORD_PATTERN.finditer(normalized.text)
        ]
        if not words:
            return ()

        prompt: list[str] = []
        for label in self._manifest.labels:
            prompt.extend((self._manifest.ent_token, label.prompt))
        prompt.append(self._manifest.sep_token)
        prompt_length = len(prompt)
        word_list = [*prompt, *(word for word, _, _ in words)]
        try:
            encoded = self._tokenizer.encode(
                word_list,
                is_pretokenized=True,
                add_special_tokens=True,
            )
        except (TypeError, ValueError):
            raise NerModelError("Unable to tokenize text with the local NER tokenizer") from None

        if len(encoded.ids) != len(encoded.attention_mask) or len(encoded.ids) != len(
            encoded.word_ids
        ):
            raise NerModelError("The local NER tokenizer returned inconsistent sequence metadata")

        words_mask: list[int] = []
        previous_word_id: int | None = None
        visible_text_word_count = 0
        for word_id in encoded.word_ids:
            if word_id is None or word_id < prompt_length:
                words_mask.append(0)
            elif word_id != previous_word_id:
                text_word_id = word_id - prompt_length + 1
                words_mask.append(text_word_id)
                visible_text_word_count = max(visible_text_word_count, text_word_id)
            else:
                words_mask.append(0)
            previous_word_id = word_id

        word_count = min(len(words), visible_text_word_count)
        if word_count == 0:
            return ()
        candidates = [
            (start, start + width)
            for start in range(word_count)
            for width in range(self._manifest.max_width)
        ]
        span_mask = [end < word_count for _, end in candidates]
        inputs: dict[str, Any] = {
            "input_ids": self._numpy.asarray([encoded.ids], dtype=self._numpy.int64),
            "attention_mask": self._numpy.asarray(
                [encoded.attention_mask], dtype=self._numpy.int64
            ),
            "words_mask": self._numpy.asarray([words_mask], dtype=self._numpy.int64),
            "text_lengths": self._numpy.asarray([[word_count]], dtype=self._numpy.int64),
            "span_idx": self._numpy.asarray([candidates], dtype=self._numpy.int64),
            "span_mask": self._numpy.asarray([span_mask], dtype=self._numpy.bool_),
        }
        try:
            outputs = self._session.run([self._manifest.output_name], inputs)
        except self._runtime_error_types:
            raise NerModelError("Local ONNX NER inference failed") from None
        except (RuntimeError, ValueError):
            raise NerModelError("Local ONNX NER inference failed") from None
        if len(outputs) != 1:
            raise NerModelError("The local ONNX NER graph returned an invalid output count")
        logits = self._numpy.asarray(outputs[0])
        expected_shape = (1, word_count, self._manifest.max_width, len(self._manifest.labels))
        if logits.shape != expected_shape:
            raise NerModelError(
                "The local ONNX NER graph returned an incompatible span score tensor"
            )

        spans: list[DetectionSpan] = []
        for start in range(word_count):
            for width in range(self._manifest.max_width):
                end = start + width
                if end >= word_count:
                    continue
                label_index, score = self._best_label(logits[0, start, width])
                if score < self._threshold:
                    continue
                source_span = normalized.original_span(words[start][1], words[end][2])
                spans.append(
                    DetectionSpan(
                        start=source_span.start,
                        end=source_span.end,
                        entity_type=self._manifest.labels[label_index].entity_type,
                        confidence=score,
                        tier=2,
                    )
                )
        return tuple(sorted(spans, key=lambda span: (span.start, span.end, span.entity_type)))

    @staticmethod
    def _best_label(logits: Any) -> tuple[int, float]:
        best_label = 0
        best_score = 0.0
        for index, raw_score in enumerate(logits):
            score = float(raw_score)
            probability = (
                1.0 / (1.0 + math.exp(-score))
                if score >= 0
                else math.exp(score) / (1.0 + math.exp(score))
            )
            if probability > best_score:
                best_label = index
                best_score = probability
        return best_label, best_score
