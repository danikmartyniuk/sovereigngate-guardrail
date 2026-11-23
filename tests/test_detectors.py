from collections.abc import Sequence

import pytest

from sovereigngate.engine.detectors import (
    TIER1_ENTITY_TYPES,
    DetectionSpan,
    canonicalize_candidate,
    detect_tier1,
)
from sovereigngate.engine.normalizer import normalize_text

_NATIONAL_ID_FIXTURES: tuple[tuple[str, str, str], ...] = (
    ("AT_VNR", "1237010180", "1230010180"),
    ("BE_NISS", "01018000152", "01018000153"),
    ("BG_EGN", "8001010008", "8001010009"),
    ("BG_PNF", "1234567893", "1234567894"),
    ("HR_OIB", "12345678903", "12345678904"),
    ("CZ_RC", "0001010009", "0001010000"),
    ("DK_CPR", "0101800000", "3213800000"),
    ("EE_IK", "36805280109", "36805280108"),
    ("FI_HETU", "010101-002S", "010101-002T"),
    ("FR_NIR", "180010100100162", "180010100100163"),
    ("DE_STEUERID", "12234567899", "12234567898"),
    ("GR_AMKA", "01018000008", "01018000009"),
    ("HU_ANUM", "12345676", "12345677"),
    ("IE_PPSN", "0000001B", "0000001C"),
    ("IT_CODICE_FISCALE", "RSSMRA85M01H501Q", "RSSMRA85M01H501R"),
    ("LT_ASMENS", "38605220981", "38605220982"),
    ("NL_BSN", "123456782", "123456783"),
    ("PL_PESEL", "00210100004", "00210100005"),
    ("PL_NIP", "0000100003", "0000100004"),
    ("PT_CC", "000000000ZZ4", "000000000ZZ3"),
    ("PT_NIF", "123456789", "123456788"),
    ("RO_CNP", "1960101010010", "1960101010011"),
    ("SK_RC", "0001010009", "0001010008"),
    ("SI_EMSO", "0101006500006", "0101006500007"),
    ("ES_DNI", "12345678Z", "12345678A"),
    ("ES_NIE", "X1234567L", "X1234567M"),
    ("ES_NIF", "A12345674", "A12345675"),
    ("SE_PERSONNUMMER", "8507099805", "8507099804"),
)


def _detected_types(text: str) -> set[str]:
    return {span.entity_type for span in detect_tier1(normalize_text(text))}


@pytest.mark.parametrize(
    ("entity_type", "valid_value", "invalid_value"),
    _NATIONAL_ID_FIXTURES,
    ids=[fixture[0] for fixture in _NATIONAL_ID_FIXTURES],
)
def test_national_identifier_validators_accept_valid_and_reject_invalid(
    entity_type: str,
    valid_value: str,
    invalid_value: str,
) -> None:
    if entity_type not in _detected_types(valid_value):
        pytest.fail(f"Valid synthetic {entity_type} fixture was not detected")
    if entity_type in _detected_types(invalid_value):
        pytest.fail(f"Invalid-checksum {entity_type} hard negative was detected")


def test_tier1_registry_contains_all_23_country_identifier_candidates() -> None:
    expected = {fixture[0] for fixture in _NATIONAL_ID_FIXTURES}

    assert expected <= TIER1_ENTITY_TYPES


@pytest.mark.parametrize(
    ("entity_type", "value", "expected"),
    [
        ("IBAN", "DE89 3704 0044 0532 0130 00", "DE89370400440532013000"),
        ("PAYMENT_CARD", "4111 1111-1111 1111", "4111111111111111"),
        ("BIC", "TESTDEFF", "TESTDEFF"),
        ("EMAIL", "User@Example.TEST", "User@example.test"),
    ],
    ids=["iban", "payment-card", "bic", "email"],
)
def test_structured_validators_detect_and_canonicalize(
    entity_type: str,
    value: str,
    expected: str,
) -> None:
    if entity_type not in _detected_types(value):
        pytest.fail(f"Valid synthetic {entity_type} fixture was not detected")

    assert canonicalize_candidate(entity_type, value) == expected


def test_national_identifier_canonicalization_uses_validator_compact_form() -> None:
    assert canonicalize_candidate("PL_PESEL", "00 21 01 00 00 4") == "00210100004"


def test_iban_requires_valid_mod97_and_eu_country() -> None:
    invalid_checksum = "DE88370400440532013000"
    non_eu_valid_iban = "GB82WEST12345698765432"

    assert "IBAN" not in _detected_types(invalid_checksum)
    assert "IBAN" not in _detected_types(non_eu_valid_iban)


def test_card_candidates_require_luhn_checksum() -> None:
    assert "PAYMENT_CARD" in _detected_types("4111111111111111")
    assert "PAYMENT_CARD" not in _detected_types("4111111111111112")


@pytest.mark.parametrize(
    ("entity_type", "value"),
    [
        ("PHONE", "+1 (202) 555-0123"),
        ("IP_ADDRESS", "192.0.2.1"),
        ("IP_ADDRESS", "2001:db8::1"),
        ("API_KEY", "sk-" + "A" * 24),
        ("API_KEY", "AKIA" + "A" * 16),
        ("BEARER_TOKEN", "Bearer " + "B" * 24),
    ],
    ids=["phone", "ipv4", "ipv6", "api-key", "aws-key", "bearer"],
)
def test_contact_and_secret_patterns(entity_type: str, value: str) -> None:
    if entity_type not in _detected_types(value):
        pytest.fail(f"Synthetic {entity_type} fixture was not detected")


def test_numeric_hard_negatives_are_not_flagged() -> None:
    hard_negatives = (
        "Order 2026-11-23",
        "Invoice 123456789012",
        "Tracking number 0001234567",
    )

    for value in hard_negatives:
        if _detected_types(value):
            pytest.fail("A non-PII numeric hard negative was detected")


def test_obfuscated_identifier_span_maps_back_to_original_text() -> None:
    original = "record: 0 0 2 1 0 1 0 0 0 0 4"
    expected_fragment = "0 0 2 1 0 1 0 0 0 0 4"
    normalized = normalize_text(original)
    spans: Sequence[DetectionSpan] = detect_tier1(normalized)
    pesel_span = next((span for span in spans if span.entity_type == "PL_PESEL"), None)

    if pesel_span is None:
        pytest.fail("Obfuscated synthetic PESEL fixture was not detected")
    assert original[pesel_span.start : pesel_span.end] == expected_fragment
    assert pesel_span.tier == 1
    assert pesel_span.confidence == 1.0
