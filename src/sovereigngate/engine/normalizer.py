import base64
import binascii
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from typing import Final, Literal

from sovereigngate.config import EncodedContentAction, NormalizationConfig

_ZERO_WIDTH: Final[frozenset[str]] = frozenset("\u200b\u200c\u200d\ufeff")
_SEPARATORS: Final[frozenset[str]] = frozenset(" \t\r\n-._")
_HEX_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{48,}(?![A-Fa-f0-9])"
)
_BASE64_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/=])"
)


class NormalizationError(ValueError):
    """A text normalization failure without the source text attached."""


@dataclass(frozen=True, slots=True)
class OriginalSpan:
    start: int
    end: int


@dataclass(frozen=True, slots=True, repr=False)
class EncodedContentSignal:
    kind: Literal["base64", "hex"]
    original_start: int
    original_end: int
    entropy_bits_per_byte: float | None
    oversized: bool
    decoded_text: str | None = field(default=None, repr=False, compare=False)

    def __repr__(self) -> str:
        return "<EncodedContentSignal [REDACTED]>"

    __str__ = __repr__


@dataclass(frozen=True, slots=True, repr=False)
class NormalizedText:
    text: str = field(repr=False)
    offsets: tuple[OriginalSpan, ...]
    encoded_content: tuple[EncodedContentSignal, ...]
    original_length: int

    def original_span(self, start: int, end: int) -> OriginalSpan:
        if start < 0 or end <= start or end > len(self.offsets):
            raise ValueError("Normalized span is outside the text")
        return OriginalSpan(self.offsets[start].start, self.offsets[end - 1].end)

    def __repr__(self) -> str:
        return "<NormalizedText [REDACTED]>"

    __str__ = __repr__


def _is_hangul_l(character: str) -> bool:
    codepoint = ord(character)
    return 0x1100 <= codepoint <= 0x115F or 0xA960 <= codepoint <= 0xA97C


def _is_hangul_v(character: str) -> bool:
    codepoint = ord(character)
    return 0x1160 <= codepoint <= 0x11A7 or 0xD7B0 <= codepoint <= 0xD7C6


def _is_hangul_t(character: str) -> bool:
    codepoint = ord(character)
    return 0x11A8 <= codepoint <= 0x11FF or 0xD7CB <= codepoint <= 0xD7FB


def _hangul_composes(segment: list[str], character: str) -> bool:
    if not segment:
        return False
    if _is_hangul_l(segment[-1]) and _is_hangul_v(character):
        return True
    return (
        len(segment) >= 2
        and _is_hangul_l(segment[-2])
        and _is_hangul_v(segment[-1])
        and _is_hangul_t(character)
    )


def _nfkc_units(text: str, strip_zero_width: bool) -> tuple[list[str], list[OriginalSpan]]:
    units = [
        (character, index, index + 1)
        for index, character in enumerate(text)
        if not (strip_zero_width and character in _ZERO_WIDTH)
    ]
    output: list[str] = []
    offsets: list[OriginalSpan] = []
    segment: list[str] = []
    segment_start = 0
    segment_end = 0

    def flush() -> None:
        if not segment:
            return
        normalized = unicodedata.normalize("NFKC", "".join(segment))
        source_span = OriginalSpan(segment_start, segment_end)
        output.extend(normalized)
        offsets.extend(source_span for _ in normalized)
        segment.clear()

    for character, source_start, source_end in units:
        joins_segment = bool(segment) and (
            unicodedata.combining(character) != 0 or _hangul_composes(segment, character)
        )
        if segment and not joins_segment:
            flush()
        if not segment:
            segment_start = source_start
        segment.append(character)
        segment_end = source_end
    flush()
    return output, offsets


def _eligible_obfuscation(characters: list[str], separators: list[str]) -> bool:
    if len(characters) < 4:
        return False
    if all(character.isdigit() for character in characters):
        return len(characters) >= 8
    return all(character.isalpha() for character in characters) and all(
        separator in "-._" for separator in separators
    )


def _collapse_obfuscation(
    characters: list[str], offsets: list[OriginalSpan]
) -> tuple[list[str], list[OriginalSpan]]:
    output: list[str] = []
    output_offsets: list[OriginalSpan] = []
    index = 0

    while index < len(characters):
        if not characters[index].isalnum():
            output.append(characters[index])
            output_offsets.append(offsets[index])
            index += 1
            continue

        positions = [index]
        separators: list[str] = []
        cursor = index
        while (
            cursor + 2 < len(characters)
            and characters[cursor + 1] in _SEPARATORS
            and characters[cursor + 2].isalnum()
        ):
            separators.append(characters[cursor + 1])
            positions.append(cursor + 2)
            cursor += 2

        run = [characters[position] for position in positions]
        if _eligible_obfuscation(run, separators):
            output.extend(run)
            output_offsets.extend(offsets[position] for position in positions)
            index = cursor + 1
        else:
            output.append(characters[index])
            output_offsets.append(offsets[index])
            index += 1

    return output, output_offsets


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _decode_encoded_blob(kind: Literal["base64", "hex"], text: str) -> bytes | None:
    if kind == "hex":
        return bytes.fromhex(text)
    try:
        return base64.b64decode(text, validate=True)
    except binascii.Error:
        return None


def _find_encoded_content(
    text: str,
    offsets: list[OriginalSpan],
    config: NormalizationConfig,
) -> tuple[EncodedContentSignal, ...]:
    signals: list[EncodedContentSignal] = []
    covered: list[tuple[int, int]] = []
    candidates: list[tuple[Literal["base64", "hex"], re.Match[str]]] = []
    candidates.extend(("hex", match) for match in _HEX_PATTERN.finditer(text))
    candidates.extend(("base64", match) for match in _BASE64_PATTERN.finditer(text))

    for kind, match in sorted(candidates, key=lambda candidate: candidate[1].start()):
        start, end = match.span()
        if any(
            start < covered_end and end > covered_start
            for covered_start, covered_end in covered
        ):
            continue
        candidate = match.group()
        original_start = offsets[start].start
        original_end = offsets[end - 1].end
        if len(candidate) > config.max_encoded_length:
            signals.append(
                EncodedContentSignal(kind, original_start, original_end, None, oversized=True)
            )
            covered.append((start, end))
            continue
        if kind == "hex" and len(candidate) % 2 != 0:
            continue
        decoded = _decode_encoded_blob(kind, candidate)
        if decoded is None:
            continue
        entropy = _shannon_entropy(decoded)
        if entropy <= config.entropy_threshold:
            continue

        decoded_text: str | None = None
        if config.encoded_content_action is EncodedContentAction.DECODE_UTF8_ONCE:
            try:
                decoded_text = decoded.decode("utf-8")
            except UnicodeDecodeError:
                decoded_text = None
        signals.append(
            EncodedContentSignal(
                kind,
                original_start,
                original_end,
                entropy,
                oversized=False,
                decoded_text=decoded_text,
            )
        )
        covered.append((start, end))

    return tuple(signals)


def normalize_text(text: str, config: NormalizationConfig | None = None) -> NormalizedText:
    if not isinstance(text, str):
        raise TypeError("Text to normalize must be a string")

    settings = NormalizationConfig() if config is None else config
    characters, offsets = _nfkc_units(text, settings.strip_zero_width)
    nfkc_text = "".join(characters)
    encoded_content = _find_encoded_content(nfkc_text, offsets, settings)

    if settings.collapse_separator_obfuscation:
        characters, offsets = _collapse_obfuscation(characters, offsets)

    return NormalizedText(
        text="".join(characters),
        offsets=tuple(offsets),
        encoded_content=encoded_content,
        original_length=len(text),
    )
