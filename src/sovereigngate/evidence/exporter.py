import hashlib
import json
from collections import Counter
from datetime import UTC, date, datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from sovereigngate.config import EntityAction, PolicyConfig, Sensitivity
from sovereigngate.evidence.audit_log import AuditAction, AuditRecord

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
_REPORT_BASIS: Final[str] = (
    "SovereignGate provides configurable data-minimization and technical safeguard controls "
    "(supporting GDPR Art. 5(1)(c) & Art. 32)."
)


class ActiveRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_type: str
    action: EntityAction
    sensitivity: Sensitivity


class RoutingMetadataReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    requests_with_eu_sensitive_metadata: int = Field(ge=0)
    requests_by_model_target: dict[str, int]
    eu_sensitive_by_model_target: dict[str, int]


class SafeguardsReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str
    regulatory_basis: str
    generated_utc: datetime
    period_from: date
    period_to: date
    policy_sha256: str
    active_rules: tuple[ActiveRule, ...]
    records_in_period: int = Field(ge=0)
    actions: dict[str, int]
    total_redactions: int = Field(ge=0)
    redactions_by_entity: dict[str, int]
    redactions_by_eu_country: dict[str, int]
    routing_metadata: RoutingMetadataReport
    chain_head_hash: str
    limitations: tuple[str, ...]

    @field_serializer("generated_utc")
    def serialize_generated_utc(self, value: datetime) -> str:
        return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def policy_sha256(policy: PolicyConfig) -> str:
    serialized = json.dumps(
        policy.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def build_safeguards_report(
    policy: PolicyConfig,
    records: tuple[AuditRecord, ...],
    *,
    period_from: date,
    period_to: date,
    chain_head_hash: str,
) -> SafeguardsReport:
    if period_from > period_to:
        raise ValueError("The report start date must not be after its end date")

    in_period = tuple(
        record
        for record in records
        if period_from <= record.timestamp_utc.astimezone(UTC).date() <= period_to
    )
    actions: Counter[str] = Counter()
    entity_redactions: Counter[str] = Counter()
    country_redactions: Counter[str] = Counter()
    model_targets: Counter[str] = Counter()
    sensitive_model_targets: Counter[str] = Counter()
    sensitive_requests = 0

    for record in in_period:
        actions[record.action_taken.value] += 1
        target = record.model_target or "unspecified"
        model_targets[target] += 1
        if record.eu_sensitive:
            sensitive_requests += 1
            sensitive_model_targets[target] += 1
        if record.action_taken is not AuditAction.MASKED:
            continue
        for entity_type, count in record.entities_detected.items():
            entity_redactions[entity_type] += count
            prefix = entity_type.split("_", maxsplit=1)[0]
            country = prefix if prefix in _EU_COUNTRY_CODES else "OTHER"
            country_redactions[country] += count

    active_rules = tuple(
        ActiveRule(
            entity_type=entity_type,
            action=rule.action,
            sensitivity=rule.sensitivity,
        )
        for entity_type, rule in sorted(policy.entities.items())
        if rule.enabled
    )
    return SafeguardsReport(
        title="GDPR Art. 32 & DPIA Technical Safeguards Evidence Report",
        regulatory_basis=_REPORT_BASIS,
        generated_utc=datetime.now(UTC),
        period_from=period_from,
        period_to=period_to,
        policy_sha256=policy_sha256(policy),
        active_rules=active_rules,
        records_in_period=len(in_period),
        actions=dict(sorted(actions.items())),
        total_redactions=sum(entity_redactions.values()),
        redactions_by_entity=dict(sorted(entity_redactions.items())),
        redactions_by_eu_country=dict(sorted(country_redactions.items())),
        routing_metadata=RoutingMetadataReport(
            requests_with_eu_sensitive_metadata=sensitive_requests,
            requests_by_model_target=dict(sorted(model_targets.items())),
            eu_sensitive_by_model_target=dict(sorted(sensitive_model_targets.items())),
        ),
        chain_head_hash=chain_head_hash,
        limitations=(
            "Routing figures summarize metadata supplied to LiteLLM; "
            "they do not verify provider residency.",
            "The hash chain detects changes to retained records but cannot prove "
            "that the database tail was not removed.",
            "This report is technical evidence, not legal advice or a compliance certification.",
        ),
    )


def render_json(report: SafeguardsReport) -> str:
    return json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=False)


def render_markdown(report: SafeguardsReport) -> str:
    lines = [
        f"# {report.title}",
        "",
        report.regulatory_basis,
        "",
        "This report summarizes configured controls and sanitized local audit metadata. "
        "It does not certify legal compliance.",
        "",
        f"- **Reporting period (UTC):** {report.period_from.isoformat()} "
        f"through {report.period_to.isoformat()}",
        f"- **Generated (UTC):** "
        f"{report.generated_utc.astimezone(UTC).isoformat(timespec='seconds')}",
        f"- **Policy SHA-256:** `{report.policy_sha256}`",
        f"- **Verified audit records in period:** {report.records_in_period}",
        f"- **Latest chain head:** `{report.chain_head_hash}`",
        "",
        "## Active entity rules",
        "",
        "| Entity | Action | Sensitivity |",
        "| --- | --- | --- |",
    ]
    lines.extend(
        f"| {rule.entity_type} | {rule.action.value} | {rule.sensitivity.value} |"
        for rule in report.active_rules
    )
    lines.extend(
        [
            "",
            "## Redactions by entity",
            "",
            "| Entity | Count |",
            "| --- | ---: |",
        ]
    )
    lines.extend(
        f"| {entity_type} | {count} |"
        for entity_type, count in report.redactions_by_entity.items()
    )
    lines.extend(
        [
            "",
            f"**Total redactions:** {report.total_redactions}",
            "",
            "## Redactions by EU country",
            "",
            "| Country code | Count |",
            "| --- | ---: |",
        ]
    )
    lines.extend(
        f"| {country} | {count} |" for country, count in report.redactions_by_eu_country.items()
    )
    lines.extend(
        [
            "",
            "## Routing metadata statistics",
            "",
            "Requests marked EU-sensitive: "
            f"{report.routing_metadata.requests_with_eu_sensitive_metadata}",
            "",
            "| Requested model target | Requests | EU-sensitive requests |",
            "| --- | ---: | ---: |",
        ]
    )
    targets = sorted(
        set(report.routing_metadata.requests_by_model_target)
        | set(report.routing_metadata.eu_sensitive_by_model_target)
    )
    lines.extend(
        f"| {target} | {report.routing_metadata.requests_by_model_target.get(target, 0)} | "
        f"{report.routing_metadata.eu_sensitive_by_model_target.get(target, 0)} |"
        for target in targets
    )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in report.limitations)
    return "\n".join(lines) + "\n"
