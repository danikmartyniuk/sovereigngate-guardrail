import hashlib
import json
import socket
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import onnx
import pytest
from onnx import TensorProto, helper, numpy_helper
from tokenizers import Tokenizer, models, pre_tokenizers

import sovereigngate.engine.ner_onnx as ner_module
from sovereigngate.config import NerConfig
from sovereigngate.engine.ner_onnx import NerModelError, NerOnnxRunner
from sovereigngate.engine.normalizer import normalize_text

_INPUT_NAMES = (
    "input_ids",
    "attention_mask",
    "words_mask",
    "text_lengths",
    "span_idx",
    "span_mask",
)


@dataclass(frozen=True)
class _ValueInfo:
    name: str


@dataclass(frozen=True)
class _Encoding:
    ids: Sequence[int]
    attention_mask: Sequence[int]
    word_ids: Sequence[int | None]


class _FakeTokenizer:
    def __init__(self) -> None:
        self.truncation_length: int | None = None
        self.encoded_words: list[str] = []

    def token_to_id(self, token: str) -> int | None:
        return 1 if token in {"[ENT]", "[SEP]"} else None

    def enable_truncation(self, max_length: int) -> None:
        self.truncation_length = max_length

    def encode(
        self,
        sequence: list[str],
        pair: None = None,
        is_pretokenized: bool = False,
        add_special_tokens: bool = True,
    ) -> _Encoding:
        assert pair is None
        assert is_pretokenized
        assert add_special_tokens
        self.encoded_words = sequence
        ids = tuple(range(len(sequence) + 2))
        word_ids = (None, *range(len(sequence)), None)
        return _Encoding(ids, (1,) * len(ids), word_ids)


class _FakeSession:
    def __init__(self, output_shape: tuple[int, ...] | None = None) -> None:
        self.output_shape = output_shape
        self.last_inputs: dict[str, Any] = {}

    def get_inputs(self) -> Sequence[_ValueInfo]:
        return tuple(_ValueInfo(name) for name in _INPUT_NAMES)

    def get_outputs(self) -> Sequence[_ValueInfo]:
        return (_ValueInfo("logits"),)

    def run(
        self,
        output_names: list[str] | None,
        input_feed: dict[str, Any],
    ) -> Sequence[Any]:
        assert output_names == ["logits"]
        self.last_inputs = input_feed
        shape = self.output_shape or (1, 4, 12, 4)
        logits = np.full(shape, -5.0, dtype=np.float32)
        if shape == (1, 4, 12, 4):
            logits[0, 0, 0, 0] = 5.0
            logits[0, 2, 1, 1] = 4.0
        return (logits,)


def _model_bundle(
    model_dir: Path,
    model_bytes: bytes = b"local synthetic onnx test artifact",
    tokenizer_bytes: bytes = b"local synthetic tokenizer test artifact",
) -> bytes:
    (model_dir / "model_int8.onnx").write_bytes(model_bytes)
    (model_dir / "tokenizer.json").write_bytes(tokenizer_bytes)
    manifest: dict[str, Any] = {
        "format_version": 1,
        "model_id": "urchade/gliner_multi-v2.1",
        "source_revision": "443d26d654e0324125a96bebd8e796c14ff2efe6",
        "source_weights_sha256": "2100142f31627531497850659dcb3821c99d5e71c08a8e01a98e4b11ef32a199",
        "exporter_revision": "beb41b3839267952d0f063c04dd6236e9fd93a38",
        "onnx_opset": 19,
        "quantization": "dynamic-int8",
        "model_file": "model_int8.onnx",
        "model_sha256": hashlib.sha256(model_bytes).hexdigest(),
        "tokenizer_file": "tokenizer.json",
        "tokenizer_sha256": hashlib.sha256(tokenizer_bytes).hexdigest(),
        "labels": [
            {"prompt": "person", "entity_type": "PERSON"},
            {"prompt": "organization", "entity_type": "ORG"},
            {"prompt": "address", "entity_type": "ADDRESS"},
            {"prompt": "health_term", "entity_type": "HEALTH_TERM"},
        ],
        "max_length": 384,
        "max_width": 12,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
    (model_dir / "model_manifest.json").write_bytes(manifest_bytes)
    return manifest_bytes


def _runner(
    model_dir: Path,
    manifest_bytes: bytes,
    session: _FakeSession | None = None,
) -> NerOnnxRunner:
    fake_session = _FakeSession() if session is None else session
    return NerOnnxRunner.load(
        model_dir,
        expected_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        session_factory=lambda _: fake_session,
        tokenizer_factory=lambda _: _FakeTokenizer(),
    )


def _write_local_onnx_model(path: Path) -> None:
    input_shapes: dict[str, tuple[int | str, ...]] = {
        "input_ids": (1, "sequence_length"),
        "attention_mask": (1, "sequence_length"),
        "words_mask": (1, "sequence_length"),
        "text_lengths": (1, 1),
        "span_idx": (1, "num_spans", 2),
        "span_mask": (1, "num_spans"),
    }
    input_types = {"span_mask": TensorProto.BOOL}
    input_types.update({name: TensorProto.INT64 for name in input_shapes if name != "span_mask"})
    graph_inputs = [
        helper.make_tensor_value_info(name, input_types[name], list(shape))
        for name, shape in input_shapes.items()
    ]
    logits = np.full((1, 4, 12, 4), -5.0, dtype=np.float32)
    logits[0, 0, 0, 0] = 5.0
    logits[0, 2, 1, 1] = 4.0
    nodes = [
        helper.make_node(
            "Constant",
            inputs=[],
            outputs=["logits"],
            value=numpy_helper.from_array(logits, name="logits_value"),
        )
    ]
    graph_outputs = [helper.make_tensor_value_info("logits", TensorProto.FLOAT, list(logits.shape))]
    for name, shape in input_shapes.items():
        output_name = f"echo_{name}"
        nodes.append(helper.make_node("Identity", inputs=[name], outputs=[output_name]))
        graph_outputs.append(
            helper.make_tensor_value_info(output_name, input_types[name], list(shape))
        )
    graph = helper.make_graph(nodes, "local_ner_test", graph_inputs, graph_outputs)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 19)])
    onnx.checker.check_model(model)
    onnx.save(model, path)


def _write_local_tokenizer(path: Path) -> None:
    vocabulary = {
        "[UNK]": 0,
        "[ENT]": 1,
        "[SEP]": 2,
        "person": 3,
        "organization": 4,
        "address": 5,
        "health_term": 6,
        "Alice": 7,
        "met": 8,
        "Acme": 9,
        "Corp": 10,
    }
    tokenizer = Tokenizer(models.WordLevel(vocab=vocabulary, unk_token="[UNK]"))
    tokenizer.pre_tokenizer = pre_tokenizers.Whitespace()
    tokenizer.add_special_tokens(["[ENT]", "[SEP]"])
    tokenizer.save(str(path))


def test_tier2_is_disabled_without_loading_optional_runtime() -> None:
    assert NerOnnxRunner.from_policy(NerConfig()) is None


def test_ner_model_config_requires_local_directory_and_manifest_digest() -> None:
    with pytest.raises(ValueError, match="local model directory"):
        NerConfig(enabled=True)


def test_local_runner_loads_digest_pinned_manifest_and_returns_source_spans(tmp_path: Path) -> None:
    manifest_bytes = _model_bundle(tmp_path)
    runner = _runner(tmp_path, manifest_bytes)
    original = "Alice met Acme Corp"
    normalized = normalize_text(original)

    spans = runner.detect(normalized)

    entities = {span.entity_type: original[span.start : span.end] for span in spans}
    assert entities == {"PERSON": "Alice", "ORG": "Acme Corp"}
    assert all(span.tier == 2 for span in spans)
    assert all(span.confidence > 0.5 for span in spans)
    assert "Alice" not in repr(runner)


def test_local_onnxruntime_and_tokenizer_load_without_external_model_services(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "model_int8.onnx"
    tokenizer_path = tmp_path / "tokenizer.json"
    _write_local_onnx_model(model_path)
    _write_local_tokenizer(tokenizer_path)
    manifest_bytes = _model_bundle(tmp_path, model_path.read_bytes(), tokenizer_path.read_bytes())

    def fail_network(*args: object, **kwargs: object) -> None:
        pytest.fail("NER runtime attempted a network call")

    monkeypatch.setattr(urllib.request, "urlopen", fail_network)
    monkeypatch.setattr(socket, "create_connection", fail_network)
    config = NerConfig(
        enabled=True,
        model_dir=tmp_path,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
    )
    runner = NerOnnxRunner.from_policy(config)
    assert runner is not None

    spans = runner.detect(normalize_text("Alice met Acme Corp"))
    assert [(span.entity_type, span.start, span.end) for span in spans] == [
        ("PERSON", 0, 5),
        ("ORG", 10, 19),
    ]


def test_local_runner_supplies_bounded_gliner_inputs(tmp_path: Path) -> None:
    manifest_bytes = _model_bundle(tmp_path)
    session = _FakeSession()
    runner = _runner(tmp_path, manifest_bytes, session)

    runner.detect(normalize_text("Alice met Acme Corp"))

    assert set(session.last_inputs) == set(_INPUT_NAMES)
    assert session.last_inputs["input_ids"].ndim == 2
    assert session.last_inputs["span_idx"].shape == (1, 48, 2)
    assert session.last_inputs["span_mask"].shape == (1, 48)
    assert session.last_inputs["text_lengths"].tolist() == [[4]]


def test_runner_fails_closed_on_manifest_hash_mismatch(tmp_path: Path) -> None:
    manifest_bytes = _model_bundle(tmp_path)

    with pytest.raises(NerModelError, match="manifest digest"):
        NerOnnxRunner.load(
            tmp_path,
            expected_manifest_sha256="0" * 64,
            session_factory=lambda _: _FakeSession(),
            tokenizer_factory=lambda _: _FakeTokenizer(),
        )
    assert b"Alice" not in manifest_bytes


def test_runner_rejects_corrupted_model_artifact(tmp_path: Path) -> None:
    manifest_bytes = _model_bundle(tmp_path)
    (tmp_path / "model_int8.onnx").write_bytes(b"changed local artifact")

    with pytest.raises(NerModelError, match="artifact digest"):
        _runner(tmp_path, manifest_bytes)


def test_runner_rejects_missing_model_artifact(tmp_path: Path) -> None:
    manifest_bytes = _model_bundle(tmp_path)
    (tmp_path / "model_int8.onnx").unlink()

    with pytest.raises(NerModelError, match="artifact is missing"):
        _runner(tmp_path, manifest_bytes)


def test_runner_rejects_corrupted_tokenizer_artifact(tmp_path: Path) -> None:
    manifest_bytes = _model_bundle(tmp_path)
    (tmp_path / "tokenizer.json").write_bytes(b"changed local tokenizer")

    with pytest.raises(NerModelError, match="artifact digest"):
        _runner(tmp_path, manifest_bytes)


def test_runner_sanitizes_invalid_tokenizer_errors(tmp_path: Path) -> None:
    manifest_bytes = _model_bundle(tmp_path, tokenizer_bytes=b"malformed tokenizer data")

    with pytest.raises(NerModelError, match="Unable to load the local NER tokenizer") as error:
        NerOnnxRunner.load(
            tmp_path,
            expected_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            session_factory=lambda _: _FakeSession(),
        )
    assert "malformed tokenizer data" not in str(error.value)


def test_runner_sanitizes_invalid_onnx_graph_errors(tmp_path: Path) -> None:
    manifest_bytes = _model_bundle(tmp_path, model_bytes=b"invalid ONNX bytes")

    with pytest.raises(NerModelError, match="Unable to initialize the local ONNX NER model"):
        NerOnnxRunner.load(
            tmp_path,
            expected_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            tokenizer_factory=lambda _: _FakeTokenizer(),
        )


def test_runner_rejects_malformed_manifest_without_echoing_contents(tmp_path: Path) -> None:
    invalid_manifest = b'{"private-looking": "synthetic-value"'
    (tmp_path / "model_manifest.json").write_bytes(invalid_manifest)

    with pytest.raises(NerModelError) as error:
        NerOnnxRunner.load(
            tmp_path,
            expected_manifest_sha256=hashlib.sha256(invalid_manifest).hexdigest(),
            session_factory=lambda _: _FakeSession(),
            tokenizer_factory=lambda _: _FakeTokenizer(),
        )
    assert "synthetic-value" not in str(error.value)


def test_ner_loader_and_inference_do_not_use_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_bytes = _model_bundle(tmp_path)

    def fail_network(*args: object, **kwargs: object) -> None:
        pytest.fail("NER runtime attempted a network call")

    monkeypatch.setattr(urllib.request, "urlopen", fail_network)
    monkeypatch.setattr(socket, "create_connection", fail_network)
    runner = _runner(tmp_path, manifest_bytes)

    assert runner.detect(normalize_text("Alice met Acme Corp"))


def test_runner_rejects_unexpected_onnx_output_shape(tmp_path: Path) -> None:
    manifest_bytes = _model_bundle(tmp_path)
    runner = _runner(tmp_path, manifest_bytes, _FakeSession(output_shape=(1, 4, 3)))

    with pytest.raises(NerModelError, match="incompatible span score tensor"):
        runner.detect(normalize_text("Alice met Acme Corp"))


def test_runner_handles_empty_text_and_invalid_local_asset_paths(tmp_path: Path) -> None:
    manifest_bytes = _model_bundle(tmp_path)
    runner = _runner(tmp_path, manifest_bytes)
    assert runner.detect(normalize_text("")) == ()

    outside_file = tmp_path / "outside.onnx"
    outside_file.write_bytes(b"local test")
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "linked.onnx").symlink_to(outside_file)
    with pytest.raises(NerModelError, match="outside its model directory"):
        ner_module._resolve_asset(model_dir, "linked.onnx")


def test_runner_enforces_local_artifact_size_limit(tmp_path: Path) -> None:
    artifact = tmp_path / "large.bin"
    artifact.write_bytes(b"too large")

    with pytest.raises(NerModelError, match="exceeds its size limit"):
        ner_module._sha256_file(artifact, maximum_size=2)
    with pytest.raises(NerModelError, match="Unable to read"):
        ner_module._sha256_file(tmp_path / "missing.bin", maximum_size=32)


def test_runner_sanitizes_custom_factory_failures(tmp_path: Path) -> None:
    manifest_bytes = _model_bundle(tmp_path)

    def fail_session(_path: Path) -> _FakeSession:
        raise RuntimeError("synthetic local model failure")

    with pytest.raises(NerModelError, match="Unable to initialize") as session_error:
        NerOnnxRunner.load(
            tmp_path,
            expected_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            session_factory=fail_session,
            tokenizer_factory=lambda _: _FakeTokenizer(),
        )
    assert "synthetic local model failure" not in str(session_error.value)

    def fail_tokenizer(_path: Path) -> _FakeTokenizer:
        raise RuntimeError("synthetic local tokenizer failure")

    with pytest.raises(NerModelError, match="Unable to load") as tokenizer_error:
        NerOnnxRunner.load(
            tmp_path,
            expected_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            session_factory=lambda _: _FakeSession(),
            tokenizer_factory=fail_tokenizer,
        )
    assert "synthetic local tokenizer failure" not in str(tokenizer_error.value)
