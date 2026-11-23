from datetime import UTC, date, datetime
from pathlib import Path

from sovereigngate.config import (
    EntityAction,
    EntityRule,
    ErrorPolicy,
    OperatingMode,
    PolicyConfig,
    Sensitivity,
)
from sovereigngate.evidence.audit_log import AuditAction, AuditEvent, AuditLog, read_records
from sovereigngate.evidence.exporter import (
    build_safeguards_report,
    render_json,
    render_markdown,
)


def _event(
    request_id: str,
    timestamp: datetime,
    *,
    action: AuditAction,
    entity_type: str,
    model_target: str,
    eu_sensitive: bool,
    count: int,
) -> AuditEvent:
    return AuditEvent(
        request_id=request_id,
        timestamp_utc=timestamp,
        mode=OperatingMode.ENFORCE,
        model_target=model_target,
        eu_sensitive=eu_sensitive,
        policy_sha256="a" * 64,
        entities_detected={entity_type: count},
        action_taken=action,
        latency_ms=1.5,
    )


def test_evidence_report_aggregates_sanitized_audit_metadata(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    with AuditLog(database_path) as audit_log:
        audit_log.enqueue(
            _event(
                "1" * 32,
                datetime(2026, 11, 1, tzinfo=UTC),
                action=AuditAction.MASKED,
                entity_type="PL_PESEL",
                model_target="local/test-model",
                eu_sensitive=True,
                count=2,
            ),
            on_error=ErrorPolicy.FAIL_CLOSED,
        )
        audit_log.enqueue(
            _event(
                "2" * 32,
                datetime(2026, 11, 5, tzinfo=UTC),
                action=AuditAction.BLOCKED,
                entity_type="DE_STEUERID",
                model_target="provider/model-a",
                eu_sensitive=False,
                count=1,
            ),
            on_error=ErrorPolicy.FAIL_CLOSED,
        )
        audit_log.enqueue(
            _event(
                "3" * 32,
                datetime(2026, 12, 1, tzinfo=UTC),
                action=AuditAction.MASKED,
                entity_type="FR_NIR",
                model_target="provider/model-b",
                eu_sensitive=True,
                count=1,
            ),
            on_error=ErrorPolicy.FAIL_CLOSED,
        )

    policy = PolicyConfig(
        mode=OperatingMode.ENFORCE,
        entities={
            "PL_PESEL": EntityRule(action=EntityAction.MASK),
            "HEALTH_TERM": EntityRule(
                action=EntityAction.BLOCK,
                sensitivity=Sensitivity.SPECIAL_CATEGORY,
            ),
        },
    )
    records = read_records(database_path)
    report = build_safeguards_report(
        policy,
        records,
        period_from=date(2026, 11, 1),
        period_to=date(2026, 11, 30),
        chain_head_hash=records[-1].record_hash,
    )

    assert report.records_in_period == 2
    assert report.total_redactions == 2
    assert report.redactions_by_entity == {"PL_PESEL": 2}
    assert report.redactions_by_eu_country == {"PL": 2}
    assert report.actions == {"blocked": 1, "masked": 1}
    assert report.routing_metadata.requests_with_eu_sensitive_metadata == 1
    assert report.routing_metadata.eu_sensitive_by_model_target == {"local/test-model": 1}
    assert report.chain_head_hash == records[-1].record_hash

    json_report = render_json(report)
    markdown_report = render_markdown(report)
    assert "configurable data-minimization and technical safeguard controls" in json_report
    assert "configurable data-minimization and technical safeguard controls" in markdown_report
    assert "provider residency" in markdown_report
    assert "automatic GDPR compliance" not in markdown_report
