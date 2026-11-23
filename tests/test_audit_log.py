import hashlib
import json
import sqlite3
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from queue import Full

import pytest
from pydantic import ValidationError

from sovereigngate.config import ErrorPolicy, OperatingMode
from sovereigngate.evidence.audit_log import (
    AuditAction,
    AuditAdmissionError,
    AuditEvent,
    AuditFlushError,
    AuditIntegrityError,
    AuditLog,
    canonical_json,
    read_records,
    verify_log,
)

_POLICY_HASH = "a" * 64


def _event(index: int, *, mode: OperatingMode = OperatingMode.ENFORCE) -> AuditEvent:
    return AuditEvent(
        timestamp_utc=datetime(2026, 11, 23, tzinfo=UTC),
        request_id=f"{index:032x}",
        actor_id=f"{index:032x}",
        mode=mode,
        model_target="local/test-model",
        eu_sensitive=True,
        policy_sha256=_POLICY_HASH,
        entities_detected={"PL_PESEL": index + 1},
        action_taken=AuditAction.MASKED,
        latency_ms=1.25,
    )


def _write_three_records(database_path: Path) -> None:
    with AuditLog(database_path) as audit_log:
        for index in range(3):
            assert audit_log.enqueue(_event(index), on_error=ErrorPolicy.FAIL_CLOSED)


def test_sqlite_wal_writer_persists_canonical_hash_chain_and_flushes(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    with AuditLog(database_path) as audit_log:
        assert audit_log.enqueue(_event(0), on_error=ErrorPolicy.FAIL_CLOSED)
        assert audit_log.enqueue(_event(1), on_error=ErrorPolicy.FAIL_CLOSED)
    verification = verify_log(database_path)
    records = read_records(database_path)

    assert verification.record_count == 2
    assert verification.head_hash == records[-1].record_hash
    assert [record.seq for record in records] == [1, 2]
    assert records[0].prev_hash == "0" * 64
    assert records[1].prev_hash == records[0].record_hash
    first_payload = records[0].model_dump(mode="json", exclude={"record_hash"})
    expected_hash = hashlib.sha256(
        canonical_json(first_payload).encode("utf-8")
        + records[0].prev_hash.encode("ascii")
    ).hexdigest()
    assert records[0].record_hash == expected_hash
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)


def test_audit_events_reject_prompt_fields_and_unbounded_values() -> None:
    with pytest.raises(ValidationError) as error:
        AuditEvent.model_validate(
            {
                **_event(0).model_dump(),
                "prompt": "synthetic-private-value",
            }
        )

    assert "synthetic-private-value" not in str(error.value)


@pytest.mark.parametrize("tampering", ["edited", "reordered", "deleted"])
def test_verifier_detects_modified_reordered_or_deleted_interior_records(
    tampering: str,
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "audit.db"
    _write_three_records(database_path)
    connection = sqlite3.connect(database_path)
    if tampering == "edited":
        record_json, = connection.execute(
            "SELECT record_json FROM audit_records WHERE seq=2"
        ).fetchone()
        parsed = json.loads(record_json)
        parsed["action_taken"] = "blocked"
        connection.execute(
            "UPDATE audit_records SET record_json=? WHERE seq=2",
            (canonical_json(parsed),),
        )
    elif tampering == "reordered":
        rows = connection.execute(
            "SELECT seq, record_json, record_hash FROM audit_records "
            "WHERE seq IN (2,3) ORDER BY seq"
        ).fetchall()
        connection.execute(
            "UPDATE audit_records SET record_json=?, record_hash=? WHERE seq=2",
            (rows[1][1], rows[1][2]),
        )
        connection.execute(
            "UPDATE audit_records SET record_json=?, record_hash=? WHERE seq=3",
            (rows[0][1], rows[0][2]),
        )
    else:
        connection.execute("DELETE FROM audit_records WHERE seq=2")
    connection.commit()
    connection.close()

    with pytest.raises(AuditIntegrityError):
        verify_log(database_path)


def test_queue_saturation_applies_mode_and_error_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    audit_log = AuditLog(tmp_path / "audit.db", queue_capacity=1)

    def queue_full(_item: object) -> None:
        raise Full

    monkeypatch.setattr(audit_log._queue, "put_nowait", queue_full)
    assert (
        audit_log.enqueue(_event(0, mode=OperatingMode.SHADOW), on_error=ErrorPolicy.FAIL_CLOSED)
        is False
    )
    with pytest.raises(AuditAdmissionError):
        audit_log.enqueue(_event(1), on_error=ErrorPolicy.FAIL_CLOSED)
    assert audit_log.enqueue(_event(2), on_error=ErrorPolicy.FAIL_OPEN) is False
    assert audit_log.health.degraded is True
    assert audit_log.health.dropped_records == 3
    audit_log.close()


def test_writer_failure_is_counted_and_visible_at_shutdown(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    audit_log = AuditLog(database_path)
    connection = sqlite3.connect(database_path)
    connection.execute("DROP TABLE audit_records")
    connection.commit()
    connection.close()

    assert audit_log.enqueue(_event(0), on_error=ErrorPolicy.FAIL_OPEN)
    deadline = time.monotonic() + 2.0
    while audit_log.health.error_code is None and time.monotonic() < deadline:
        time.sleep(0.01)

    with pytest.raises(AuditFlushError):
        audit_log.close(timeout=2.0)
    assert audit_log.health.healthy is False
    assert audit_log.health.dropped_records >= 1


def test_shutdown_timeout_is_visible_and_can_be_retried(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    audit_log = AuditLog(tmp_path / "audit.db")
    writer_entered = threading.Event()
    release_writer = threading.Event()
    append_event = audit_log._append_event

    def hold_writer(connection: sqlite3.Connection, event: AuditEvent) -> None:
        writer_entered.set()
        release_writer.wait(timeout=2.0)
        append_event(connection, event)

    monkeypatch.setattr(audit_log, "_append_event", hold_writer)
    assert audit_log.enqueue(_event(0), on_error=ErrorPolicy.FAIL_CLOSED)
    assert writer_entered.wait(timeout=1.0)

    with pytest.raises(AuditFlushError, match="deadline"):
        audit_log.close(timeout=0.01)

    release_writer.set()
    audit_log.close(timeout=2.0)
    assert verify_log(tmp_path / "audit.db").record_count == 1
