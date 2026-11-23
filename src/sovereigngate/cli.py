import json
from collections import Counter
from collections.abc import Iterator, Mapping
from datetime import date
from pathlib import Path
from typing import Final, NoReturn

import typer

from sovereigngate import __version__
from sovereigngate.config import PolicyConfig, PolicyLoadError, load_policy
from sovereigngate.engine.ner_onnx import NerModelError, NerOnnxRunner
from sovereigngate.engine.pipeline import PipelineError, run_pipeline
from sovereigngate.evidence.audit_log import AuditIntegrityError, AuditRecord, read_records
from sovereigngate.evidence.audit_log import verify_log as verify_audit_log
from sovereigngate.evidence.exporter import (
    build_safeguards_report,
    render_json,
    render_markdown,
)

_REGULATORY_DESCRIPTION: Final[str] = (
    "configurable data-minimization and technical safeguard controls "
    "(supporting GDPR Art. 5(1)(c) & Art. 32)."
)
_MAX_DRY_RUN_BYTES: Final[int] = 16 * 1024 * 1024
_MAX_JSONL_LINE_BYTES: Final[int] = 1_048_576


class DryRunInputError(ValueError):
    """A sanitized input error for local JSONL evaluation."""


app: typer.Typer = typer.Typer(
    add_completion=False,
    help=f"SovereignGate provides {_REGULATORY_DESCRIPTION}",
    invoke_without_command=True,
    no_args_is_help=True,
)


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", help="Show version and product description."),
) -> None:
    if version:
        typer.echo(f"SovereignGate {__version__}: {_REGULATORY_DESCRIPTION}")
        raise typer.Exit()


def _fail(message: str) -> NoReturn:
    typer.echo(message, err=True)
    raise typer.Exit(code=1)


@app.command("verify-log")
def verify_log_command(
    db: Path = typer.Option(  # noqa: B008
        Path("audit.db"), "--db", help="Local SQLite audit database."
    ),
) -> None:
    verification = None
    failed = False
    try:
        verification = verify_audit_log(db)
    except AuditIntegrityError:
        failed = True
    if failed or verification is None:
        _fail("Audit chain verification failed.")
    typer.echo(
        f"Audit chain verified: records={verification.record_count} "
        f"head_hash={verification.head_hash}"
    )


@app.command("export-dpia")
def export_dpia_command(
    report_from: date = typer.Option(  # noqa: B008
        ..., "--from", help="First included UTC date (YYYY-MM-DD)."
    ),
    report_to: date = typer.Option(  # noqa: B008
        ..., "--to", help="Last included UTC date (YYYY-MM-DD)."
    ),
    output_format: str = typer.Option(  # noqa: B008
        "md", "--format", help="Output format: md or json."
    ),
    db: Path = typer.Option(  # noqa: B008
        Path("audit.db"), "--db", help="Local SQLite audit database."
    ),
    policy_path: Path | None = typer.Option(  # noqa: B008
        None, "--policy", help="Policy YAML file."
    ),
) -> None:
    if report_from > report_to:
        _fail("The report start date must not be after its end date.")
    if output_format not in {"md", "json"}:
        _fail("The report format must be 'md' or 'json'.")

    policy: PolicyConfig | None = None
    records: tuple[AuditRecord, ...] = ()
    error_message: str | None = None
    try:
        policy = load_policy(policy_path)
        records = read_records(db)
    except PolicyLoadError as error:
        error_message = f"Policy loading failed: {error}"
    except AuditIntegrityError:
        error_message = "Audit chain verification failed."
    if error_message is not None or policy is None:
        _fail(error_message or "Unable to load the configured policy.")

    chain_head = records[-1].record_hash if records else "0" * 64
    try:
        report = build_safeguards_report(
            policy,
            records,
            period_from=report_from,
            period_to=report_to,
            chain_head_hash=chain_head,
        )
    except ValueError:
        _fail("Unable to build the technical safeguards report.")
    typer.echo(render_markdown(report) if output_format == "md" else render_json(report))


def _parse_jsonl(path: Path) -> tuple[tuple[int, dict[str, object]], ...]:
    raw_bytes: bytes | None = None
    read_failed = False
    try:
        if path.stat().st_size > _MAX_DRY_RUN_BYTES:
            raise DryRunInputError("The JSONL input exceeds its 16 MiB size limit")
        raw_bytes = path.read_bytes()
    except OSError:
        read_failed = True
    if read_failed or raw_bytes is None:
        raise DryRunInputError("Unable to read the configured JSONL input")

    text: str | None = None
    decode_failed = False
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        decode_failed = True
    if decode_failed or text is None:
        raise DryRunInputError("The JSONL input is not valid UTF-8")

    records: list[tuple[int, dict[str, object]]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(line.encode("utf-8")) > _MAX_JSONL_LINE_BYTES:
            raise DryRunInputError(f"JSONL line {line_number} exceeds its size limit")
        value: object | None = None
        parse_failed = False
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            parse_failed = True
        if parse_failed or not isinstance(value, dict):
            raise DryRunInputError(f"JSONL line {line_number} must be a JSON object")
        records.append((line_number, value))
    return tuple(records)


def _text_values(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _text_values(item)
    elif isinstance(value, Mapping):
        for key in ("text", "content"):
            if key in value:
                yield from _text_values(value[key])


def _json_string_values(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _json_string_values(item)
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _json_string_values(item)


def _tool_argument_texts(arguments: object, line_number: int) -> Iterator[str]:
    if isinstance(arguments, str):
        parsed: object | None = None
        parse_failed = False
        try:
            parsed = json.loads(arguments)
        except (json.JSONDecodeError, TypeError):
            parse_failed = True
        if parse_failed:
            raise DryRunInputError(f"JSONL line {line_number} contains malformed tool arguments")
        yield from _json_string_values(parsed)
    else:
        yield from _json_string_values(arguments)


def _record_texts(record: Mapping[str, object], line_number: int) -> Iterator[str]:
    messages = record.get("messages")
    if messages is not None:
        if not isinstance(messages, list):
            raise DryRunInputError(f"JSONL line {line_number} has malformed messages")
        for message in messages:
            if not isinstance(message, Mapping):
                raise DryRunInputError(f"JSONL line {line_number} has a malformed message")
            yield from _text_values(message.get("content"))
            tool_calls = message.get("tool_calls")
            if tool_calls is None:
                continue
            if not isinstance(tool_calls, list):
                raise DryRunInputError(f"JSONL line {line_number} has malformed tool calls")
            for tool_call in tool_calls:
                function = tool_call.get("function") if isinstance(tool_call, Mapping) else None
                if isinstance(function, Mapping) and "arguments" in function:
                    yield from _tool_argument_texts(function["arguments"], line_number)
        return

    if "prompt" in record or "input" in record:
        for field in ("prompt", "input"):
            if field in record:
                yield from _text_values(record[field])
        return
    raise DryRunInputError(f"JSONL line {line_number} has no supported text fields")


@app.command("dry-run")
def dry_run_command(
    file: Path = typer.Option(  # noqa: B008
        ..., "--file", help="JSONL input file; contents are never printed."
    ),
    policy_path: Path | None = typer.Option(  # noqa: B008
        None, "--policy", help="Policy YAML file."
    ),
) -> None:
    policy: PolicyConfig | None = None
    records: tuple[tuple[int, dict[str, object]], ...] = ()
    error_message: str | None = None
    try:
        policy = load_policy(policy_path)
        records = _parse_jsonl(file)
    except PolicyLoadError as error:
        error_message = f"Policy loading failed: {error}"
    except DryRunInputError as error:
        error_message = str(error)
    if error_message is not None or policy is None:
        _fail(error_message or "Unable to load the configured policy.")

    ner_runner = None
    ner_load_failed = False
    try:
        ner_runner = NerOnnxRunner.from_policy(policy.ner)
    except NerModelError:
        ner_load_failed = True
    if ner_load_failed:
        _fail("Unable to load configured local NER assets.")

    detections: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    flagged_records = 0
    blocked_records = 0
    for line_number, record in records:
        record_flagged = False
        record_blocked = False
        text_values: tuple[str, ...] = ()
        extraction_error: str | None = None
        try:
            text_values = tuple(_record_texts(record, line_number))
        except DryRunInputError as error:
            extraction_error = str(error)
        if extraction_error is not None:
            _fail(extraction_error)
        if not text_values:
            _fail(f"JSONL line {line_number} contains no text values.")
        for text in text_values:
            result = None
            pipeline_error: str | None = None
            try:
                result = run_pipeline(text, policy, ner_runner)
            except PipelineError as error:
                pipeline_error = error.code.value
            if pipeline_error is not None:
                errors[pipeline_error] += 1
                continue
            if result is None:
                errors["processing_failure"] += 1
                continue
            if result.processing_error is not None:
                errors[result.processing_error.value] += 1
            if result.decisions:
                record_flagged = True
            if result.blocked:
                record_blocked = True
            for decision in result.decisions:
                detections[decision.span.entity_type] += 1
        flagged_records += int(record_flagged)
        blocked_records += int(record_blocked)

    summary = {
        "records": len(records),
        "flagged_records": flagged_records,
        "blocked_records": blocked_records,
        "processing_errors": dict(sorted(errors.items())),
        "detected_entity_counts": dict(sorted(detections.items())),
    }
    typer.echo("Dry-run summary: " + json.dumps(summary, sort_keys=True, separators=(",", ":")))
    if errors:
        raise typer.Exit(code=1)
