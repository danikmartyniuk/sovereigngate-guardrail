import hashlib
import json
import re
import sqlite3
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Annotated, Final, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_serializer,
    field_validator,
)

from sovereigngate.config import EntityName, ErrorPolicy, OperatingMode

_ZERO_HASH: Final[str] = "0" * 64
_HASH_PATTERN: Final[str] = r"^[a-f0-9]{64}$"
_REQUEST_ID_PATTERN: Final[str] = r"^(?:[a-f0-9]{32}|req_[a-f0-9]{8,64})$"
_ACTOR_ID_PATTERN: Final[str] = r"^(?:[a-f0-9]{32}|[a-f0-9]{64}|sso_[A-Za-z0-9_-]{8,64})$"
_MODEL_TARGET_PATTERN: Final[str] = (
    r"^[A-Za-z0-9][A-Za-z0-9._:+_-]{0,63}"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._:+_-]{0,63})?$"
)
_MAX_QUEUE_CAPACITY: Final[int] = 10_000
_DEFAULT_DRAIN_TIMEOUT: Final[float] = 10.0
_STOP: Final[object] = object()

Digest = Annotated[str, StringConstraints(pattern=_HASH_PATTERN)]
RequestId = Annotated[str, StringConstraints(pattern=_REQUEST_ID_PATTERN)]
ActorId = Annotated[str, StringConstraints(pattern=_ACTOR_ID_PATTERN)]
ModelTarget = Annotated[str, StringConstraints(pattern=_MODEL_TARGET_PATTERN)]
EntityCount = Annotated[int, Field(strict=True, ge=1, le=1_000_000)]
LatencyMs = Annotated[float, Field(ge=0.0, le=86_400_000.0, allow_inf_nan=False)]


class AuditAction(StrEnum):
    MASKED = "masked"
    BLOCKED = "blocked"
    OBSERVED = "observed"
    ALLOWED = "allowed"
    UNCHANGED = "unchanged"
    PROCESSING_ERROR = "processing_error"


class AuditError(RuntimeError):
    """A sanitized audit subsystem error with no record contents attached."""


class AuditAdmissionError(AuditError):
    """A record could not be admitted to the bounded audit queue."""


class AuditStartupError(AuditError):
    """The local audit writer could not initialize its SQLite store."""


class AuditFlushError(AuditError):
    """The local audit writer did not stop cleanly within its drain deadline."""


class AuditIntegrityError(AuditError):
    """The retained SQLite audit chain failed verification."""


class AuditEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    request_id: RequestId
    actor_id: ActorId | None = None
    mode: OperatingMode
    model_target: ModelTarget | None = None
    eu_sensitive: bool = False
    policy_sha256: Digest
    entities_detected: dict[EntityName, EntityCount] = Field(default_factory=dict, max_length=64)
    action_taken: AuditAction
    latency_ms: LatencyMs

    @field_validator("timestamp_utc")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("Audit timestamps must be timezone-aware UTC values")
        return value.astimezone(UTC)

    @field_serializer("timestamp_utc")
    def serialize_timestamp(self, value: datetime) -> str:
        return value.astimezone(UTC).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )


class AuditRecord(AuditEvent):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    seq: Annotated[int, Field(strict=True, ge=1)]
    prev_hash: Digest
    record_hash: Digest


@dataclass(frozen=True, slots=True)
class AuditVerification:
    record_count: int
    head_hash: str


@dataclass(frozen=True, slots=True)
class AuditHealth:
    healthy: bool
    degraded: bool
    accepting: bool
    queue_depth: int
    dropped_records: int
    persisted_records: int
    error_code: str | None


def canonical_json(value: Mapping[str, object]) -> str:
    """Serialize audit metadata deterministically without emitting non-finite numbers."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def record_hash(record_without_hash: Mapping[str, object]) -> str:
    previous_hash = record_without_hash.get("prev_hash")
    if not isinstance(previous_hash, str) or not re.fullmatch(_HASH_PATTERN, previous_hash):
        raise AuditIntegrityError("An audit record has an invalid previous hash")
    payload = canonical_json(record_without_hash).encode("utf-8")
    return hashlib.sha256(payload + previous_hash.encode("ascii")).hexdigest()


def _decode_record(record_json: object) -> AuditRecord:
    parsed: object | None = None
    invalid = False
    try:
        if not isinstance(record_json, str):
            invalid = True
        else:
            parsed = json.loads(record_json)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        invalid = True
    record: AuditRecord | None = None
    if not invalid:
        try:
            record = AuditRecord.model_validate(parsed)
        except ValidationError:
            invalid = True
    if invalid or record is None:
        raise AuditIntegrityError("An audit record is malformed or violates its schema")
    return record


def _verify_connection(connection: sqlite3.Connection) -> AuditVerification:
    try:
        rows = connection.execute(
            "SELECT seq, record_json, record_hash FROM audit_records ORDER BY seq"
        ).fetchall()
    except sqlite3.Error:
        raise AuditIntegrityError("Unable to read the local audit chain") from None

    expected_seq = 1
    previous_hash = _ZERO_HASH
    for row_seq, record_json, stored_hash in rows:
        record = _decode_record(record_json)
        if not isinstance(row_seq, int) or row_seq != expected_seq or record.seq != expected_seq:
            raise AuditIntegrityError("The local audit chain has a sequence gap or reordering")
        if record.prev_hash != previous_hash or stored_hash != record.record_hash:
            raise AuditIntegrityError("The local audit chain contains a modified record")
        record_without_hash = record.model_dump(mode="json", exclude={"record_hash"})
        expected_hash = record_hash(record_without_hash)
        if expected_hash != record.record_hash:
            raise AuditIntegrityError("The local audit chain contains a modified record")
        if canonical_json(record.model_dump(mode="json")) != record_json:
            raise AuditIntegrityError("An audit record is not in canonical JSON form")
        previous_hash = record.record_hash
        expected_seq += 1
    return AuditVerification(record_count=expected_seq - 1, head_hash=previous_hash)


def verify_log(database_path: str | Path) -> AuditVerification:
    """Verify the full retained chain from sequence 1 and the all-zero genesis hash."""
    path = Path(database_path)
    if not path.is_file():
        raise AuditIntegrityError("The configured audit database does not exist")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path)
        return _verify_connection(connection)
    except sqlite3.Error:
        raise AuditIntegrityError("Unable to verify the local audit database") from None
    finally:
        if connection is not None:
            connection.close()


def read_records(database_path: str | Path) -> tuple[AuditRecord, ...]:
    """Read verified records for offline reporting; never returns unchecked rows."""
    path = Path(database_path)
    if not path.is_file():
        raise AuditIntegrityError("The configured audit database does not exist")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path)
        _verify_connection(connection)
        rows = connection.execute(
            "SELECT record_json FROM audit_records ORDER BY seq"
        ).fetchall()
        return tuple(_decode_record(row[0]) for row in rows)
    except AuditIntegrityError:
        raise
    except sqlite3.Error:
        raise AuditIntegrityError("Unable to read the local audit database") from None
    finally:
        if connection is not None:
            connection.close()


class AuditLog:
    """Bounded non-blocking request admission with a background SQLite WAL writer."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        queue_capacity: int = _MAX_QUEUE_CAPACITY,
        drain_timeout: float = _DEFAULT_DRAIN_TIMEOUT,
    ) -> None:
        if not 1 <= queue_capacity <= _MAX_QUEUE_CAPACITY:
            raise ValueError("Audit queue capacity must be between 1 and 10,000 records")
        if drain_timeout <= 0:
            raise ValueError("Audit drain timeout must be positive")
        self.database_path = Path(database_path)
        self._queue: Queue[AuditEvent | object] = Queue(maxsize=queue_capacity)
        self._drain_timeout = drain_timeout
        self._state_lock = threading.Lock()
        self._ready = threading.Event()
        self._finished = threading.Event()
        self._accepting = True
        self._stop_enqueued = False
        self._closed = False
        self._degraded = False
        self._writer_error: str | None = None
        self._dropped_records = 0
        self._persisted_records = 0
        self._last_sequence = 0
        self._last_hash = _ZERO_HASH
        self._worker = threading.Thread(
            target=self._writer_main,
            name="sovereigngate-audit-writer",
            daemon=True,
        )
        self._worker.start()
        if not self._ready.wait(timeout=drain_timeout):
            self._mark_writer_error("startup_timeout")
            raise AuditStartupError("The local audit writer did not initialize in time")
        with self._state_lock:
            writer_error = self._writer_error
        if writer_error is not None:
            raise AuditStartupError("The local audit writer could not initialize")

    @property
    def health(self) -> AuditHealth:
        with self._state_lock:
            return AuditHealth(
                healthy=self._writer_error is None,
                degraded=self._degraded,
                accepting=self._accepting,
                queue_depth=self._queue.qsize(),
                dropped_records=self._dropped_records,
                persisted_records=self._persisted_records,
                error_code=self._writer_error,
            )

    def enqueue(self, event: AuditEvent, *, on_error: ErrorPolicy) -> bool:
        """Admit an immutable, PII-free event with ``put_nowait``; return false on allowed loss."""
        event_copy = event.model_copy(deep=True)
        with self._state_lock:
            if self._accepting and self._writer_error is None:
                try:
                    self._queue.put_nowait(event_copy)
                except Full:
                    self._dropped_records += 1
                    self._degraded = True
                else:
                    return True
            else:
                self._dropped_records += 1
                self._degraded = True

            fail_closed = (
                event.mode is OperatingMode.ENFORCE and on_error is ErrorPolicy.FAIL_CLOSED
            )
        if fail_closed:
            raise AuditAdmissionError("The sanitized audit event could not be queued")
        return False

    def close(self, timeout: float | None = None) -> None:
        """Stop admissions, drain the queue, and raise visibly on timeout or writer failure."""
        selected_timeout = self._drain_timeout if timeout is None else timeout
        if selected_timeout <= 0:
            raise ValueError("Audit drain timeout must be positive")
        deadline = time.monotonic() + selected_timeout
        with self._state_lock:
            self._accepting = False
            already_closed = self._closed
            stop_enqueued = self._stop_enqueued
        if not already_closed and not self._finished.is_set() and not stop_enqueued:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                self._queue.put(_STOP, timeout=remaining)
            except Full:
                raise AuditFlushError("The audit queue did not drain before shutdown") from None
            with self._state_lock:
                self._stop_enqueued = True

        remaining = max(0.0, deadline - time.monotonic())
        if not self._finished.wait(timeout=remaining):
            raise AuditFlushError("The audit writer did not flush before its shutdown deadline")
        self._worker.join(timeout=max(0.0, deadline - time.monotonic()))
        with self._state_lock:
            self._closed = True
            writer_error = self._writer_error
        if writer_error is not None:
            raise AuditFlushError("The local audit writer stopped with degraded health")

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _mark_writer_error(self, code: str) -> None:
        with self._state_lock:
            if self._writer_error is None:
                self._writer_error = code
            self._degraded = True
            self._accepting = False

    def _count_drop(self) -> None:
        with self._state_lock:
            self._dropped_records += 1
            self._degraded = True

    def _writer_main(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.database_path)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS audit_records "
                "(seq INTEGER PRIMARY KEY, record_json TEXT NOT NULL, record_hash TEXT NOT NULL)"
            )
            connection.commit()
            verification = _verify_connection(connection)
            self._last_sequence = verification.record_count
            self._last_hash = verification.head_hash
            with self._state_lock:
                self._persisted_records = verification.record_count
        except Exception:
            self._mark_writer_error("startup_failure")
            self._ready.set()
            self._finished.set()
            if connection is not None:
                connection.close()
            self._discard_pending()
            return

        self._ready.set()
        try:
            while True:
                item = self._queue.get()
                try:
                    if item is _STOP:
                        break
                    with self._state_lock:
                        writer_unhealthy = self._writer_error is not None
                    if writer_unhealthy:
                        self._count_drop()
                        continue
                    if not isinstance(item, AuditEvent):
                        self._mark_writer_error("invalid_queue_item")
                        self._count_drop()
                        continue
                    try:
                        self._append_event(connection, item)
                    except Exception:
                        try:
                            connection.rollback()
                        except sqlite3.Error:
                            self._mark_writer_error("rollback_failure")
                        self._mark_writer_error("writer_failure")
                        self._count_drop()
                finally:
                    self._queue.task_done()
        except Exception:
            self._mark_writer_error("writer_failure")
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    self._mark_writer_error("close_failure")
            self._discard_pending()
            self._finished.set()

    def _append_event(self, connection: sqlite3.Connection, event: AuditEvent) -> None:
        next_sequence = self._last_sequence + 1
        record_without_hash: dict[str, object] = {
            "seq": next_sequence,
            **event.model_dump(mode="json"),
            "prev_hash": self._last_hash,
        }
        digest = record_hash(record_without_hash)
        record = AuditRecord.model_validate(
            {**record_without_hash, "record_hash": digest}
        )
        serialized = canonical_json(record.model_dump(mode="json"))
        try:
            connection.execute(
                "INSERT INTO audit_records (seq, record_json, record_hash) VALUES (?, ?, ?)",
                (record.seq, serialized, record.record_hash),
            )
            connection.commit()
        except sqlite3.Error:
            raise
        self._last_sequence = next_sequence
        self._last_hash = record.record_hash
        with self._state_lock:
            self._persisted_records += 1

    def _discard_pending(self) -> None:
        while True:
            try:
                item = self._queue.get_nowait()
            except Empty:
                return
            if item is not _STOP:
                self._count_drop()
            self._queue.task_done()
