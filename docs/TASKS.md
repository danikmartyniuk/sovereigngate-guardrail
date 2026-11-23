# V1 Implementation Plan

This is the ordered implementation backlog derived from the product requirements and [`ARCHITECTURE.md`](./ARCHITECTURE.md). Phase 0 items are decision tasks and are checked only when the decision is recorded in the architecture. Implementation tasks are checked only after their acceptance checks, relevant security regressions, lint, and type checks pass. The package scaffold is now installable, but V1 processing features remain incomplete.

SovereignGate provides **configurable data-minimization and technical safeguard controls (supporting GDPR Art. 5(1)(c) & Art. 32)**; it does not certify compliance.

## Phase 0 — Product decisions

The four Phase 0 decisions are recorded below. T01's cross-request token-collision risk remains an explicit external-pilot gate; completing the decision does not accept that risk on behalf of an operator.

- [x] **T01 — Resolve token collision and lifecycle policy.** Keep the mandated six-hex format; detect different canonical values mapping to the same token within a request vault and fail closed in enforce mode before provider dispatch, never overwriting. One vault belongs to a logical LiteLLM request and is shared across its retries/stream; clear it on every terminal path. Restore tool arguments only for allowlisted internal tools and assistant text only on explicitly trusted routes; otherwise leave placeholders. The unpreventable cross-request collision risk is a documented pilot gate requiring written owner acceptance. See [T01 decision](./ARCHITECTURE.md#t01--token-collision-and-request-lifecycle-resolved).
- [x] **T02 — Define audit writer failure policy.** Use a bounded 10,000-record queue and non-blocking pre-dispatch admission. On saturation/writer failure, shadow records degraded health and continues; enforce follows `on_error` (fail-closed rejects before dispatch, explicit fail-open proceeds with a sanitized loss signal). Writer failure after dispatch is counted; shutdown drains for 10 seconds then fails visibly. See [T02 decision](./ARCHITECTURE.md#t02--audit-queue-and-writer-failure-policy-resolved).
- [x] **T03 — Fix supported identifier and NER artifact matrix.** Baseline validator is `python-stdnum==2.2`: explicit modules cover 23 EU member states; CY, LV, LU, and MT have no personal-ID module in this baseline and are not claimed supported. Canonicalize only through each module's accepted compact/validate behavior, preserve significant characters/leading zeroes, and require valid, invalid-checksum, hard-negative, and offset fixtures. Select Apache-2.0 `urchade/gliner_multi-v2.1`, pin its model revision and source-weight SHA-256, export/quantize offline, and verify the generated ONNX digest from a local manifest. See [T03 decision](./ARCHITECTURE.md#t03--identifier-matrix-and-local-ner-artifact-resolved).
- [x] **T04 — Freeze measurable benchmark protocol.** Fix `eu-synthetic-v1` (seed `20261123`, 1,000 samples, 800 positives/200 hard negatives), stratification, span annotations, and a non-PII task-utility proxy. Pin Presidio Analyzer `2.2.366` with its default registry/no custom recognizers, and a Linux x86_64/CPython 3.12.16, 4-vCPU/8-GiB reference; use 100 warm-ups and 10,000 timed runs. Keep absolute thresholds separate from baseline results. See [T04 decision](./ARCHITECTURE.md#t04--benchmark-protocol-resolved).

## Phase 1 — Package, policy, and local processing

- [x] **T05 — Create package and quality baseline.** Added the `src/sovereigngate/` package and `pyproject.toml` for Python `>=3.12` with runtime/optional/dev extras, pytest/ruff/mypy configuration, CI quality workflow, and a `--version` CLI/import smoke test. CI tests do not download model artifacts or make request-path network calls.
  - Depends on: T01, T02, T03, T04.
- [x] **T06 — Implement strict configuration and default policy.** Added frozen Pydantic v2 schemas with forbidden extra fields, safe YAML/environment-path loading, per-entity actions/sensitivity, `shadow`/`fail_closed` defaults, normalization and optional NER settings, plus a default policy pack. HMAC secrets are decoded/validated as at least 32 bytes; only explicit development mode may create an ephemeral key, with a sanitized warning. Unknown and malformed settings fail with field-only diagnostics. See [`config.py`](../src/sovereigngate/config.py) and [`eu_default_v1.yaml`](../rules/eu_default_v1.yaml).
  - Depends on: T05.
- [x] **T07 — Implement normalization and offset mapping.** Added NFKC and zero-width normalization with source spans, conservative single-character obfuscation collapse, and bounded Base64/hex entropy signals (decoded-byte Shannon entropy, 48-character minimum, 4 KiB cap). Optional one-time UTF-8 decode is explicit in policy; result representations redact text. See [`normalizer.py`](../src/sovereigngate/engine/normalizer.py) and focused source-offset/entropy tests.
  - Depends on: T06.
- [x] **T08 — Implement Tier 1 detector registry.** Added validators for the 23 T03 country candidates, EU IBAN, Luhn card numbers, BIC, email, phone, IP, and selected API/bearer tokens. Numeric candidates require the corresponding `python-stdnum` validator; EU IBANs are country-restricted. Added valid/invalid checksum and hard-negative fixtures for all national-ID types plus offset/canonicalization tests. See [`detectors.py`](../src/sovereigngate/engine/detectors.py) and [`test_detectors.py`](../tests/test_detectors.py).
  - Depends on: T03, T07.
- [x] **T09 — Implement optional offline ONNX NER.** Added a CPU-only `onnxruntime` runner with a digest-pinned local manifest/model/tokenizer, fixed GLiNER span-score ABI, and `PERSON`, `ORG`, `ADDRESS`, and `HEALTH_TERM` spans. Runtime imports neither PyTorch nor GLiNER and makes no network calls. Tests cover disabled mode, hash/config corruption, missing assets, synthetic local ONNX inference, source offsets, and network-call guards. No model weights are bundled; language enablement still requires benchmark evidence. See [`ner_onnx.py`](../src/sovereigngate/engine/ner_onnx.py).
  - Depends on: T03, T05, T07.
- [x] **T10 — Implement span resolution and policy pipeline.** Added the engine pipeline for normalization, Tier 1 and opt-in Tier 2 scans, original-offset spans, Tier 1 precedence, deterministic nested/overlap resolution, same-type adjacency merging, and per-entity `shadow`/`enforce` decisions. Enforce-mode blocks are reported before outbound dispatch; `fail_closed` sanitizes unexpected stage errors while fail-open/shadow results carry explicit error codes. The pipeline returns decisions/spans; request mutation and HMAC masking are Phase 2. See [`pipeline.py`](../src/sovereigngate/engine/pipeline.py) and [`test_pipeline.py`](../tests/test_pipeline.py).
  - Depends on: T06, T07, T08; T09 is optional for the Tier 1-only path.

## Phase 2 — Pseudonymization and LiteLLM integration

- [x] **T11 — Implement HMAC token vault and streaming buffer.** Added canonicalized per-session HMAC tokens, collision rejection without overwriting, redacted vault representations, explicit best-effort wipe, and bounded buffering for split/unknown SSE placeholders up to 32 characters. Focused coverage verifies exact HMAC derivation, same-session stability, collisions, wiping, all token split points, and prompt flushing of non-token text. See [`vault.py`](../src/sovereigngate/engine/vault.py) and [`test_vault_and_stream.py`](../tests/test_vault_and_stream.py).
  - Depends on: T01, T06.
- [ ] **T12 — Implement LiteLLM lifecycle adapter.** Subclass the supported LiteLLM `CustomGuardrail`; implement pre-call, post-call, and streaming hooks; copy caller payloads; traverse content/text blocks, tool-call JSON arguments, and tool outputs; attach only non-PII routing metadata; sanitize block/error messages; ensure request context and vault cleanup on success, exception, cancellation, retry, and stream termination.
  - Depends on: T06, T10, T11.
- [ ] **T13 — Add security leak regression suite.** Use synthetic PII fixtures and `caplog` to verify no raw values appear in DEBUG/INFO/WARNING/ERROR logs, exceptions, audit records, or rendered vaults across malformed JSON, decoding/detector failures, block paths, and streaming errors. Verify enforce `fail_closed` never forwards unmasked payloads.
  - Depends on: T06–T12.

## Phase 3 — Evidence, CLI, and release readiness

- [ ] **T14 — Implement PII-free asynchronous hash-chain audit.** Add strict audit-record schema, canonical JSON hashing, SQLite WAL writer and verifier, non-blocking enqueue, graceful flush, and the explicit queue/writer-failure behavior from T02. Add adversarial tests for edited, reordered, and deleted interior records. Do not log or persist message contents.
  - Depends on: T02, T05, T06, T12.
- [ ] **T15 — Implement offline CLI and evidence exporter.** Provide `verify-log`, `export-dpia` (Markdown/JSON), and `dry-run`; generate reports from sanitized policy/audit metadata only and use bounded regulatory terminology. Return non-zero on verification/configuration failures.
  - Depends on: T06, T10, T14.
- [ ] **T16 — Implement reproducible synthetic benchmark.** Generate `eu-synthetic-v1` exactly per T04 (seed, 800/200 split, 18 strata, annotated original offsets); compare with Presidio Analyzer `2.2.366`, report recall/FPR and per-country/entity results, the non-PII utility proxy, and Tier 1/Tier 2 p95. Enforce the absolute thresholds on the T04 reference VM; provision all models before the offline run.
  - Depends on: T04, T08, T10.
- [ ] **T17 — Add LiteLLM pilot deployment and end-to-end tests.** Provide sample LiteLLM config and slim local Docker Compose stack; verify shadow/enforce, streaming, tool calls, startup failure behavior, offline NER provisioning, shutdown flush, and no raw-PII logs end to end.
  - Depends on: T12, T13, T14, T15.
- [ ] **T18 — Complete V1 release gate.** Run full `pytest -v`, `ruff check src tests`, `mypy src`, dependency audit, coverage threshold (at least 90% over engine/adapters/evidence), and benchmark on the reference environment. Review licensing, data-flow documentation, and the open risks in `ARCHITECTURE.md`; resolve or explicitly accept pilot blockers.
  - Depends on: T13–T17.

## Per-task verification

For each implementation task, add focused tests alongside the code, including relevant zero-leakage regressions. Run the narrowest relevant checks while iterating; before the V1 release gate run the complete commands above. Do not mark unfinished work complete based on documentation or a passing smoke test alone.