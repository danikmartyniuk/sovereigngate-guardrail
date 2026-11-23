import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from typer.testing import CliRunner

from sovereigngate.cli import app
from sovereigngate.config import ErrorPolicy, OperatingMode
from sovereigngate.evidence.audit_log import AuditAction, AuditEvent, AuditLog

_PII: Final[str] = "00210100004"


def _write_audit(database_path: Path) -> None:
    event = AuditEvent(
        timestamp_utc=datetime(2026, 11, 23, tzinfo=UTC),
        request_id="1" * 32,
        mode=OperatingMode.ENFORCE,
        model_target="local/test-model",
        eu_sensitive=True,
        policy_sha256="a" * 64,
        entities_detected={"PL_PESEL": 1},
        action_taken=AuditAction.MASKED,
        latency_ms=1.0,
    )
    with AuditLog(database_path) as audit_log:
        audit_log.enqueue(event, on_error=ErrorPolicy.FAIL_CLOSED)


def _write_policy(path: Path) -> None:
    path.write_text(
        "mode: enforce\n"
        "entities:\n"
        "  PL_PESEL: {enabled: true, action: mask, sensitivity: standard}\n",
        encoding="utf-8",
    )


def test_verify_log_command_returns_nonzero_on_corruption(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _write_audit(database_path)
    runner = CliRunner()

    valid = runner.invoke(app, ["verify-log", "--db", str(database_path)])
    assert valid.exit_code == 0
    assert "records=1" in valid.stdout

    connection = sqlite3.connect(database_path)
    connection.execute("UPDATE audit_records SET record_json='{}' WHERE seq=1")
    connection.commit()
    connection.close()
    invalid = runner.invoke(app, ["verify-log", "--db", str(database_path)])
    assert invalid.exit_code == 1
    assert "Audit chain verification failed" in invalid.output
    assert _PII not in invalid.output


def test_export_dpia_command_supports_json_and_markdown(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    policy_path = tmp_path / "policy.yaml"
    _write_audit(database_path)
    _write_policy(policy_path)
    runner = CliRunner()
    common_args = [
        "export-dpia",
        "--from",
        "2026-11-01",
        "--to",
        "2026-11-30",
        "--db",
        str(database_path),
        "--policy",
        str(policy_path),
    ]

    json_result = runner.invoke(app, [*common_args, "--format", "json"])
    assert json_result.exit_code == 0, json_result.output
    parsed = json.loads(json_result.stdout)
    assert parsed["records_in_period"] == 1
    assert parsed["redactions_by_eu_country"] == {"PL": 1}
    assert parsed["routing_metadata"]["requests_with_eu_sensitive_metadata"] == 1
    assert _PII not in json_result.stdout

    markdown_result = runner.invoke(app, [*common_args, "--format", "md"])
    assert markdown_result.exit_code == 0, markdown_result.output
    assert "GDPR Art. 32 & DPIA Technical Safeguards Evidence Report" in markdown_result.stdout
    assert "provider residency" in markdown_result.stdout
    assert _PII not in markdown_result.stdout


def test_export_dpia_returns_nonzero_on_invalid_policy(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    policy_path = tmp_path / "bad-policy.yaml"
    _write_audit(database_path)
    policy_path.write_text("mode: private-sensitive-value\n", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "export-dpia",
            "--from",
            "2026-11-01",
            "--to",
            "2026-11-30",
            "--db",
            str(database_path),
            "--policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 1
    assert "private-sensitive-value" not in result.output


def test_dry_run_scans_jsonl_without_printing_input(tmp_path: Path) -> None:
    input_path = tmp_path / "sample.jsonl"
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path)
    input_path.write_text(
        json.dumps({"messages": [{"role": "user", "content": f"ID {_PII}"}]}) + "\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        ["dry-run", "--file", str(input_path), "--policy", str(policy_path)],
    )

    assert result.exit_code == 0, result.output
    assert '"PL_PESEL":1' in result.stdout
    assert _PII not in result.output


def test_dry_run_malformed_json_is_sanitized_and_nonzero(tmp_path: Path) -> None:
    input_path = tmp_path / "malformed.jsonl"
    input_path.write_text(f'{{"prompt":"{_PII}"\n', encoding="utf-8")

    result = CliRunner().invoke(app, ["dry-run", "--file", str(input_path)])

    assert result.exit_code == 1
    assert "JSONL line 1 must be a JSON object" in result.output
    assert _PII not in result.output


def test_benchmark_command_smoke_reports_fixed_dataset_without_samples() -> None:
    result = CliRunner().invoke(app, ["benchmark", "--skip-presidio", "--skip-latency"])

    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["benchmark_id"] == "eu-synthetic-v1"
    assert report["sample_count"] == 1000
    assert report["positive_samples"] == 800
    assert report["hard_negative_samples"] == 200
    assert report["tier1_p95_ms"] is None
    assert _PII not in result.stdout
