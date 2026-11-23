# V1 Implementation Plan

This is the ordered implementation backlog derived from the product requirements and [`ARCHITECTURE.md`](./ARCHITECTURE.md). **All implementation tasks are currently open**; this repository currently contains product documentation, not a runnable package. Phase 0 items are decision tasks and are checked only when the decision is recorded in the architecture. Implementation tasks are checked only after their acceptance checks, relevant security regressions, lint, and type checks pass.

SovereignGate provides **configurable data-minimization and technical safeguard controls (supporting GDPR Art. 5(1)(c) & Art. 32)**; it does not certify compliance.

## Phase 0 — Resolve pilot-critical decisions

- [x] **T01 — Resolve token collision and lifecycle policy.** Keep the mandated six-hex format; detect different canonical values mapping to the same token within a request vault and fail closed in enforce mode before provider dispatch, never overwriting. One vault belongs to a logical LiteLLM request and is shared across its retries/stream; clear it on every terminal path. The unpreventable cross-request collision risk is a documented pilot gate requiring written owner acceptance. See [T01 decision](./ARCHITECTURE.md#t01--token-collision-and-request-lifecycle-resolved).
- [x] **T02 — Define audit writer failure policy.** Use a bounded 10,000-record queue and non-blocking pre-dispatch admission. On saturation/writer failure, shadow records degraded health and continues; enforce follows `on_error` (fail-closed rejects before dispatch, explicit fail-open proceeds with a sanitized loss signal). Writer failure after dispatch is counted; shutdown drains for 10 seconds then fails visibly. See [T02 decision](./ARCHITECTURE.md#t02--audit-queue-and-writer-failure-policy-resolved).
- [x] **T03 — Fix supported identifier and NER artifact matrix.** Baseline validator is `python-stdnum==2.2`: explicit modules cover 23 EU member states; CY, LV, LU, and MT have no personal-ID module in this baseline and are not claimed supported. Select Apache-2.0 `urchade/gliner_multi-v2.1`, pin its model revision and source-weight SHA-256, export/quantize offline, and verify the generated ONNX digest from a local manifest. See [T03 decision](./ARCHITECTURE.md#t03--identifier-matrix-and-local-ner-artifact-resolved).
- [ ] **T04 — Freeze measurable benchmark protocol.** Fix dataset seed and generation rules, ground truth, task-utility scoring, Presidio version, and reference 4-vCPU environment. Separate absolute NFR thresholds from baseline comparisons.

## Phase 1 — Package, policy, and local processing

- [ ] **T05 — Create package and quality baseline.** Establish the `src/sovereigngate/` package, `pyproject.toml` with Python `>=3.12`, runtime/optional/dev extras, test/lint/type-check configuration, and offline CI. Add a minimal import/CLI smoke test. No model or telemetry downloads in CI's request hot path.
  - Depends on: T01, T02, T03, T04.
- [ ] **T06 — Implement strict configuration and default policy.** Add frozen Pydantic v2 schemas, YAML/environment loading, `shadow` default, entity actions/sensitivity, `on_error`, secret validation, and a reviewed `rules/eu_default_v1.yaml`. Reject unknown or invalid settings explicitly.
  - Depends on: T05.
- [ ] **T07 — Implement normalization and offset mapping.** Add NFKC, specified zero-width removal, separator-obfuscation handling, original-index span mapping, and bounded high-entropy/encoded-content handling. Define clear failure results that let enforce mode fail closed.
  - Depends on: T06.
- [ ] **T08 — Implement Tier 1 detector registry.** Add supported EU identifier, IBAN, payment-card, contact, and credential detectors using structural boundaries plus check-digit validation where applicable. Build the country/entity support matrix from T03; every checksum detector needs valid fixtures and invalid-checksum/hard-negative tests.
  - Depends on: T03, T07.
- [ ] **T09 — Implement optional offline ONNX NER.** Load only the locally provisioned, digest-pinned model; expose `PERSON`, `ORG`, `ADDRESS`, and `HEALTH_TERM` spans for supported languages. Test disabled-by-default behavior, missing/corrupt artifacts, and absence of network access.
  - Depends on: T03, T05, T07.
- [ ] **T10 — Implement span resolution and policy pipeline.** Orchestrate normalization, Tier 1 and optional Tier 2, source-offset restoration, overlap precedence (Tier 1 wins), adjacent/nested span resolution, immutable spans, and `shadow`/`enforce` actions.
  - Depends on: T06, T07, T08; T09 is optional for the Tier 1-only path.

## Phase 2 — Pseudonymization and LiteLLM integration

- [ ] **T11 — Implement HMAC token vault and streaming buffer.** Canonicalize values, derive required per-session HMAC tokens, detect token/vault collisions per T01, redact vault `repr`/`str`, implement explicit wipe, and test stable same-session tokens plus split SSE token handling up to 32 characters.
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
- [ ] **T16 — Implement reproducible synthetic benchmark.** Generate the specified 1,000-prompt dataset with 20% hard negatives, compare with pinned Presidio, report recall/FPR/utility and latency, and enforce the absolute NFR-1 release thresholds. Avoid real personal data in fixtures and outputs.
  - Depends on: T04, T08, T10.
- [ ] **T17 — Add LiteLLM pilot deployment and end-to-end tests.** Provide sample LiteLLM config and slim local Docker Compose stack; verify shadow/enforce, streaming, tool calls, startup failure behavior, offline NER provisioning, shutdown flush, and no raw-PII logs end to end.
  - Depends on: T12, T13, T14, T15.
- [ ] **T18 — Complete V1 release gate.** Run full `pytest -v`, `ruff check src tests`, `mypy src`, dependency audit, coverage threshold (at least 90% over engine/adapters/evidence), and benchmark on the reference environment. Review licensing, data-flow documentation, and the open risks in `ARCHITECTURE.md`; resolve or explicitly accept pilot blockers.
  - Depends on: T13–T17.

## Per-task verification

For each implementation task, add focused tests alongside the code, including relevant zero-leakage regressions. Run the narrowest relevant checks while iterating; before the V1 release gate run the complete commands above. Do not mark unfinished work complete based on documentation or a passing smoke test alone.