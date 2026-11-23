import base64
import random
import string

import pytest

from sovereigngate.config import EncodedContentAction, NormalizationConfig
from sovereigngate.engine.normalizer import normalize_text


def test_nfkc_and_zero_width_mapping_preserve_original_span() -> None:
    original = "\uff11\u200b\uff12e\u0301"

    normalized = normalize_text(original)

    assert normalized.text == "12é"
    assert normalized.original_span(0, 2).start == 0
    assert normalized.original_span(0, 2).end == 3
    assert normalized.original_span(2, 3).start == 3
    assert normalized.original_span(2, 3).end == 5


@pytest.mark.parametrize(
    ("original", "expected"),
    [
        ("A-n-n-a", "Anna"),
        ("9 0 0 1 0 1 1 2 3 4 5", "90010112345"),
    ],
)
def test_collapse_single_character_separator_obfuscation(original: str, expected: str) -> None:
    normalized = normalize_text(original)

    assert normalized.text == expected
    assert normalized.original_span(0, len(expected)).start == 0
    assert normalized.original_span(0, len(expected)).end == len(original)


@pytest.mark.parametrize("original", ["A B C D", "I am fine", "12-34-56"])
def test_does_not_collapse_short_or_normal_separated_text(original: str) -> None:
    assert normalize_text(original).text == original


def test_hangul_and_compatibility_characters_are_nfkc_normalized() -> None:
    normalized = normalize_text("\u1100\u1161 \ufb01")

    assert normalized.text == "가 fi"


def test_detect_high_entropy_hex_and_map_to_source() -> None:
    original = bytes(range(64)).hex()
    normalized = normalize_text(original)

    assert len(normalized.encoded_content) == 1
    signal = normalized.encoded_content[0]
    assert signal.kind == "hex"
    assert signal.original_start == 0
    assert signal.original_end == len(original)
    assert signal.entropy_bits_per_byte is not None
    assert signal.entropy_bits_per_byte > 4.5
    assert signal.decoded_text is None


def test_base64_utf8_decode_is_once_and_repr_is_redacted() -> None:
    generator = random.Random(20261123)
    alphabet = string.ascii_letters + string.digits
    decoded = "".join(generator.choice(alphabet) for _ in range(96))
    original = base64.b64encode(decoded.encode("utf-8")).decode("ascii")
    settings = NormalizationConfig(encoded_content_action=EncodedContentAction.DECODE_UTF8_ONCE)

    normalized = normalize_text(original, settings)

    assert len(normalized.encoded_content) == 1
    signal = normalized.encoded_content[0]
    assert signal.kind == "base64"
    assert signal.decoded_text == decoded
    assert original not in repr(normalized)
    assert decoded not in repr(signal)


def test_overlong_encoded_candidates_are_flagged_without_decoding() -> None:
    original = bytes(range(128)).hex()
    settings = NormalizationConfig(max_encoded_length=64)

    normalized = normalize_text(original, settings)

    assert len(normalized.encoded_content) == 1
    assert normalized.encoded_content[0].oversized
    assert normalized.encoded_content[0].decoded_text is None


def test_invalid_spans_and_non_string_input_fail_without_echoing_input() -> None:
    with pytest.raises(ValueError, match="outside the text"):
        normalize_text("safe").original_span(0, 100)
    with pytest.raises(TypeError, match="must be a string"):
        normalize_text(b"not text")  # type: ignore[arg-type]


def test_normalized_text_representation_is_redacted() -> None:
    value = "private-candidate-value"
    normalized = normalize_text(value)

    assert value not in repr(normalized)
    assert "REDACTED" in str(normalized)
