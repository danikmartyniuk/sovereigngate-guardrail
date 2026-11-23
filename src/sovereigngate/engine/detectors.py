import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Final, Literal, Protocol

from stdnum.at import vnr as at_vnr
from stdnum.be import ssn as be_ssn
from stdnum.bg import egn as bg_egn
from stdnum.bg import pnf as bg_pnf
from stdnum.bic import compact as compact_bic
from stdnum.bic import is_valid as is_valid_bic
from stdnum.cz import rc as cz_rc
from stdnum.de import idnr as de_idnr
from stdnum.dk import cpr as dk_cpr
from stdnum.ee import ik as ee_ik
from stdnum.es import dni as es_dni
from stdnum.es import nie as es_nie
from stdnum.es import nif as es_nif
from stdnum.fi import hetu as fi_hetu
from stdnum.fr import nir as fr_nir
from stdnum.gr import amka as gr_amka
from stdnum.hr import oib as hr_oib
from stdnum.hu import anum as hu_anum
from stdnum.iban import compact as compact_iban
from stdnum.iban import is_valid as is_valid_iban
from stdnum.ie import pps as ie_pps
from stdnum.it import codicefiscale as it_codicefiscale
from stdnum.lt import asmens as lt_asmens
from stdnum.luhn import is_valid as is_valid_luhn
from stdnum.nl import bsn as nl_bsn
from stdnum.pl import nip as pl_nip
from stdnum.pl import pesel as pl_pesel
from stdnum.pt import cc as pt_cc
from stdnum.pt import nif as pt_nif
from stdnum.ro import cnp as ro_cnp
from stdnum.se import personnummer as se_personnummer
from stdnum.si import emso as si_emso
from stdnum.sk import rc as sk_rc

from sovereigngate.engine.normalizer import NormalizedText

EntityTier = Literal[1, 2]
_EU_COUNTRY_CODES: Final[frozenset[str]] = frozenset(
    {
        "AT",
        "BE",
        "BG",
        "CY",
        "CZ",
        "DE",
        "DK",
        "EE",
        "ES",
        "FI",
        "FR",
        "GR",
        "HR",
        "HU",
        "IE",
        "IT",
        "LT",
        "LU",
        "LV",
        "MT",
        "NL",
        "PL",
        "PT",
        "RO",
        "SE",
        "SI",
        "SK",
    }
)


class DetectorError(ValueError):
    """A detector failure that never includes the candidate text."""


@dataclass(frozen=True, slots=True, repr=False)
class DetectionSpan:
    start: int
    end: int
    entity_type: str
    confidence: float
    tier: EntityTier

    def __repr__(self) -> str:
        return f"<DetectionSpan entity_type={self.entity_type!r} span=[{self.start},{self.end})>"


class _ValidatorModule(Protocol):
    def is_valid(self, number: str) -> bool: ...

    def compact(self, number: str) -> str: ...


@dataclass(frozen=True, slots=True)
class _DetectorRule:
    entity_type: str
    pattern: re.Pattern[str]
    is_valid: Callable[[str], bool]
    canonicalize: Callable[[str], str]


def _digit_pattern(lengths: Iterable[int]) -> re.Pattern[str]:
    alternatives = [rf"[0-9](?:[ ./-]?[0-9]){{{length - 1}}}" for length in lengths]
    return re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(alternatives) + r")(?![A-Za-z0-9])")


def _module_rule(
    entity_type: str,
    pattern: re.Pattern[str],
    module: _ValidatorModule,
) -> _DetectorRule:
    return _DetectorRule(entity_type, pattern, module.is_valid, module.compact)


def _is_eu_iban(value: str) -> bool:
    canonical = compact_iban(value)
    return canonical[:2] in _EU_COUNTRY_CODES and is_valid_iban(value)


def _is_bic(value: str) -> bool:
    return value == value.upper() and is_valid_bic(value)


def _is_nl_bsn(value: str) -> bool:
    if re.fullmatch(r"[0-9]{4}[-./][0-9]{2}[-./][0-9]{2}", value):
        return False
    return nl_bsn.is_valid(value)


def _compact_email(value: str) -> str:
    local_part, domain = value.strip().rsplit("@", maxsplit=1)
    return f"{local_part}@{domain.lower()}"


def _is_phone(value: str) -> bool:
    digits = "".join(character for character in value if character.isdigit())
    if value.startswith("+"):
        return 8 <= len(digits) <= 15 and not digits.startswith("0")
    if value.startswith("00"):
        international_digits = digits[2:]
        return 8 <= len(international_digits) <= 15 and not international_digits.startswith("0")
    return value.startswith("0") and 9 <= len(digits) <= 14


def _compact_phone(value: str) -> str:
    digits = "".join(character for character in value if character.isdigit())
    if value.startswith("00"):
        return "+" + digits[2:]
    if value.startswith("+"):
        return "+" + digits
    return digits


def _compact_digits(value: str) -> str:
    return "".join(character for character in value if "0" <= character <= "9")


def _is_payment_card(value: str) -> bool:
    return is_valid_luhn(_compact_digits(value))


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _canonical_ip_address(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        raise DetectorError("Invalid IP_ADDRESS candidate") from None


_NUMBER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])[0-9]+(?:[ ./-][0-9]+)*(?![A-Za-z0-9])"
)
_IBAN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]){11,30}(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_BIC_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_CARD_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])[0-9](?:[ -]?[0-9]){12,18}(?![A-Za-z0-9])"
)
_EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    r"(?![A-Za-z0-9.-])"
)
_PHONE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])\+?[0-9](?:[0-9 .()/-]{6,20}[0-9])?(?![A-Za-z0-9])"
)
_IPV4_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])"
)
_IPV6_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![0-9A-Fa-f:])(?=[0-9A-Fa-f:]*:)[0-9A-Fa-f:]{3,39}(?![0-9A-Fa-f:])"
)
_FI_HETU_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])[0-9]{6}[+\-A][0-9]{3}[0-9A-Y](?![A-Za-z0-9])",
    re.IGNORECASE,
)
_IE_PPSN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])[0-9]{7}[A-W][ABHWTX]?(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_IT_CODICE_FISCALE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])[A-Z0-9]{16}(?![A-Za-z0-9])", re.IGNORECASE
)
_PT_CC_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])[0-9]{9}[A-Z0-9]{2}[0-9](?![A-Za-z0-9])", re.IGNORECASE
)
_ES_DNI_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])[0-9]{8}[A-Z](?![A-Za-z0-9])", re.IGNORECASE
)
_ES_NIE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])[XYZ][0-9]{7}[A-Z](?![A-Za-z0-9])", re.IGNORECASE
)
_ES_NIF_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])[ABCDEFGHJNPQRSUVW][0-9]{7}[0-9A-J](?![A-Za-z0-9])",
    re.IGNORECASE,
)
_API_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}|"
    r"ghp_[A-Za-z0-9]{20,}|"
    r"AKIA[A-Z0-9]{16}"
    r")(?![A-Za-z0-9_-])"
)
_BEARER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?<![A-Za-z0-9])Bearer\s+[A-Za-z0-9._~+/-]{20,}={0,}(?![A-Za-z0-9._~+/-])"
)


_RULES: Final[tuple[_DetectorRule, ...]] = (
    _module_rule("AT_VNR", _digit_pattern((10,)), at_vnr),
    _module_rule("BE_NISS", _digit_pattern((11,)), be_ssn),
    _module_rule("BG_EGN", _digit_pattern((10,)), bg_egn),
    _module_rule("BG_PNF", _digit_pattern((10,)), bg_pnf),
    _module_rule("HR_OIB", _digit_pattern((11,)), hr_oib),
    _module_rule("CZ_RC", _digit_pattern((9, 10)), cz_rc),
    _module_rule("DK_CPR", _digit_pattern((10,)), dk_cpr),
    _module_rule("EE_IK", _digit_pattern((11,)), ee_ik),
    _module_rule("FI_HETU", _FI_HETU_PATTERN, fi_hetu),
    _module_rule("FR_NIR", _digit_pattern((15,)), fr_nir),
    _module_rule("DE_STEUERID", _digit_pattern((11,)), de_idnr),
    _module_rule("GR_AMKA", _digit_pattern((11,)), gr_amka),
    _module_rule(
        "HU_ANUM",
        re.compile(r"(?<![A-Za-z0-9])(?:HU[ -]?)?[0-9]{8}(?![A-Za-z0-9])", re.I),
        hu_anum,
    ),
    _module_rule("IE_PPSN", _IE_PPSN_PATTERN, ie_pps),
    _module_rule("IT_CODICE_FISCALE", _IT_CODICE_FISCALE_PATTERN, it_codicefiscale),
    _module_rule("LT_ASMENS", _digit_pattern((11,)), lt_asmens),
    _DetectorRule("NL_BSN", _digit_pattern((8, 9)), _is_nl_bsn, nl_bsn.compact),
    _module_rule("PL_PESEL", _digit_pattern((11,)), pl_pesel),
    _module_rule("PL_NIP", _digit_pattern((10,)), pl_nip),
    _module_rule("PT_CC", _PT_CC_PATTERN, pt_cc),
    _module_rule("PT_NIF", _digit_pattern((9,)), pt_nif),
    _module_rule("RO_CNP", _digit_pattern((13,)), ro_cnp),
    _module_rule("SK_RC", _digit_pattern((9, 10)), sk_rc),
    _module_rule("SI_EMSO", _digit_pattern((13,)), si_emso),
    _module_rule("ES_DNI", _ES_DNI_PATTERN, es_dni),
    _module_rule("ES_NIE", _ES_NIE_PATTERN, es_nie),
    _module_rule("ES_NIF", _ES_NIF_PATTERN, es_nif),
    _module_rule(
        "SE_PERSONNUMMER",
        re.compile(
            r"(?<![A-Za-z0-9])(?:[0-9]{6}[-+]?[0-9]{4}|[0-9]{8}[-+]?[0-9]{4})(?![A-Za-z0-9])"
        ),
        se_personnummer,
    ),
    _DetectorRule("IBAN", _IBAN_PATTERN, _is_eu_iban, compact_iban),
    _DetectorRule("PAYMENT_CARD", _CARD_PATTERN, _is_payment_card, _compact_digits),
    _DetectorRule("BIC", _BIC_PATTERN, _is_bic, compact_bic),
    _DetectorRule("EMAIL", _EMAIL_PATTERN, lambda value: True, _compact_email),
    _DetectorRule("PHONE", _PHONE_PATTERN, _is_phone, _compact_phone),
    _DetectorRule("IP_ADDRESS", _IPV4_PATTERN, _is_ip_address, _canonical_ip_address),
    _DetectorRule("IP_ADDRESS", _IPV6_PATTERN, _is_ip_address, _canonical_ip_address),
    _DetectorRule("API_KEY", _API_KEY_PATTERN, lambda value: True, str.strip),
    _DetectorRule("BEARER_TOKEN", _BEARER_PATTERN, lambda value: True, str.strip),
)

TIER1_ENTITY_TYPES: Final[frozenset[str]] = frozenset(rule.entity_type for rule in _RULES)


def _validate(rule: _DetectorRule, value: str) -> bool:
    try:
        return rule.is_valid(value)
    except (TypeError, ValueError):
        raise DetectorError(f"Validator failed for {rule.entity_type}") from None


def detect_tier1(normalized: NormalizedText) -> tuple[DetectionSpan, ...]:
    """Detect locally validated Tier 1 entities, returning original-text offsets."""
    detected: set[DetectionSpan] = set()
    for rule in _RULES:
        for match in rule.pattern.finditer(normalized.text):
            candidate = match.group()
            if not _validate(rule, candidate):
                continue
            source_span = normalized.original_span(*match.span())
            detected.add(
                DetectionSpan(
                    start=source_span.start,
                    end=source_span.end,
                    entity_type=rule.entity_type,
                    confidence=1.0,
                    tier=1,
                )
            )
    return tuple(sorted(detected, key=lambda span: (span.start, span.end, span.entity_type)))


def canonicalize_candidate(entity_type: str, value: str) -> str:
    """Return the validator's canonical form without embedding it in an exception."""
    for rule in _RULES:
        if rule.entity_type == entity_type:
            if not _validate(rule, value):
                raise DetectorError(f"Cannot canonicalize invalid {entity_type} candidate")
            return rule.canonicalize(value)
    raise DetectorError("Unsupported entity type")
