# SovereignGate Guardrail

**Local text redaction and pseudonymization for LiteLLM-based AI gateways.**

SovereignGate is an open-source Python library and LiteLLM custom guardrail for detecting configured European identifiers and selected personal or sensitive data in text, replacing detected values before a model request, and selectively restoring values at trusted response or tool boundaries. Its local audit writer records sanitized policy metadata in a tamper-evident chain without storing prompt contents.

SovereignGate provides **configurable data-minimization and technical safeguard controls (supporting GDPR Art. 5(1)(c) & Art. 32)**. It is not a compliance product or legal advice.

> **Project status:** Implementation is underway. The installable Python package, policy loader, normalizer, Tier 1 detectors, local ONNX NER runner, span/policy decision pipeline, HMAC vault, bounded streaming placeholder buffer, LiteLLM lifecycle adapter, SQLite WAL audit writer/verifier, offline `verify-log`/`export-dpia`/`dry-run` commands, and zero-leak regressions are implemented. The adapter copies and masks supported request text, restores only at configured trusted boundaries, enqueues PII-free pre-call records, and wipes request vaults on terminal paths. The reproducible benchmark and pilot deployment remain in progress. NER weights are not bundled, and language support is not claimed until benchmarked. See the [V1 task plan](./docs/TASKS.md) for implementation status.

## Why it exists

Applications often send user text through an AI gateway to a model provider. That text can contain identifiers and other sensitive values that the application does not want to disclose to the provider. A gateway guardrail can reduce the data sent by replacing selected values with stable, opaque placeholders while preserving enough context for the model to do its work.

SovereignGate is designed to run inside the customer's existing LiteLLM deployment. Its detection, pseudonymization, and audit components are intended to run locally; it does not add a hosted SaaS dependency or make network calls from the engine/evidence hot path. LiteLLM still makes its normal request to whichever model provider the customer has configured.

## What V1 is designed to do

- **Detect structured identifiers locally.** Use structural boundaries and check-digit validation for supported EU national identifiers, IBANs, payment cards, and related categories. The initial country priority includes Poland, Spain, France, Germany, Italy, the Netherlands, Sweden, and Belgium, followed by identifiers supported by verified validators. The exact supported matrix must be documented; “EU-27 target” does not imply every national identifier is already supported.
- **Detect common contact and secret patterns.** The planned Tier 1 set includes emails, phone numbers, IP addresses, and selected API-key/bearer-token formats.
- **Normalize obfuscated text before scanning.** Apply Unicode NFKC normalization, remove specified zero-width characters, and handle separator obfuscation while keeping offsets so detections can be replaced in the original text.
- **Optionally detect unstructured entities.** An opt-in CPU-based ONNX runner for person, organization, address, and health-related spans is implemented. It requires a locally provisioned, hash-verified model/tokenizer bundle, is disabled by default, and has no runtime model downloads or PyTorch dependency. Target languages remain unvalidated until the benchmark gates pass.
- **Pseudonymize consistently within a session.** Use HMAC-derived placeholders such as `[PL_PESEL_9F2A1C]` so repeated canonical values in the same session can map to the same token. The lookup needed to restore a value is kept only in a request-scoped in-memory vault.
- **Integrate with LiteLLM request/response paths.** Inspect supported message text, tool-call argument JSON, and tool outputs; handle streaming placeholders split across chunks; attach non-PII entity/routing metadata; and apply configured actions.
- **Support observe-first operation.** `shadow` mode is intended to report findings without changing or blocking a request. `enforce` mode is intended to apply per-entity `mask`, `block`, `shadow_log`, or `allow` policy actions.
- **Create local evidence.** A background writer persists sanitized event metadata in a local SQLite hash chain. The `verify-log`, `dry-run`, and `export-dpia` commands verify, evaluate, and export sanitized evidence offline.

## How a request is intended to flow

1. LiteLLM invokes the SovereignGate pre-call hook.
2. The adapter copies the request structure and scans supported text fields. It does not inspect image pixels or arbitrary binary data.
3. Text is normalized and scanned by deterministic validators. Optional local NER can add probabilistic spans.
4. The policy engine resolves overlaps (Tier 1 checksum-validated matches take precedence) and decides which configured entities to mask, block, log in shadow, or allow.
5. In enforce mode, masked text and per-session HMAC placeholders are passed to the configured model provider. The original values remain in the request's in-memory vault for permitted restoration.
6. Post-call or streaming hooks can restore only placeholders mapped in that request's vault. Restoration should be limited to a boundary trusted to receive the original value, such as an authorized internal tool. Rehydrating assistant output can expose the original value to the calling application.
7. Sanitized audit metadata is queued for local persistence. The vault is wiped/released on success, failure, stream completion, and cancellation.

Undetected entities and unsupported payload types may still reach the configured provider. Detection is a data-minimization control, not a guarantee that a prompt contains no personal data.

## LiteLLM adapter and restoration boundaries

`SovereignGateGuardrail` is implemented in [`litellm_guardrail.py`](./src/sovereigngate/adapters/litellm_guardrail.py). It subclasses LiteLLM's `CustomGuardrail`, copies incoming payloads, and implements native pre-call, post-call-success, failure, and streaming-iterator hooks. It scans message content and text blocks, JSON tool-call argument values, tool outputs, and text `prompt`/`input` fields. Malformed tool-call JSON is rejected with a sanitized guardrail error in fail-closed enforce mode; explicit fail-open emits a sanitized processing-error metadata signal.

Restoration is opt-in at construction: `trusted_routes` names routes allowed to receive restored assistant text, and `internal_tools` names tools allowed to receive restored tool-call arguments. The route name is matched against request metadata (`route` or `model_group`) or the model name. If a route or tool is not allowlisted, its output retains placeholders. Provide a stable `SOVEREIGNGATE_HMAC_SECRET` in production; an explicit bytes secret may also be passed when constructing the adapter. Request-context metadata contains only a random identifier and sanitized entity/routing tags.

## Operating modes and failure behavior

| Mode | Intended behavior |
| --- | --- |
| `shadow` | Detect and report policy findings without changing payloads or blocking because of those findings. |
| `enforce` | Apply configured entity actions before the provider request and restore values only at configured trusted boundaries. |

The default is `shadow`. `on_error` supports `fail_closed` and `fail_open`; in enforce mode, fail-closed behavior stops an outbound request if parsing, normalization, detection, or audit admission fails unexpectedly. Operational failures are explicit and sanitized. The bounded audit queue follows the overflow and writer-failure policy recorded in [T02](./docs/ARCHITECTURE.md#t02--audit-queue-and-writer-failure-policy-resolved).

## Privacy and security model

- **Local processing:** Detection, normalization, pseudonymization, and evidence writing remain local and offline. The configured model provider still receives requests through the existing LiteLLM path.
- **No raw PII in diagnostics:** Prompts, message bodies, tool arguments, matched values, and vault contents never appear in logs, exposed exception messages, or validated audit records.
- **Request-scoped restoration map:** Raw values are not persisted in the audit database. The in-memory vault is request-scoped, redacts its string representation, and is wiped/released in lifecycle cleanup. Python cannot guarantee physical erasure of immutable string allocations; this is best-effort memory hygiene, not cryptographic erasure.
- **Pseudonyms remain sensitive:** HMAC placeholders are reversible within the request vault and stable tokens can remain linkable across requests in a session. They are pseudonyms, not anonymized data. Protect the HMAC secret as a production secret; an ephemeral development secret will not produce stable tokens after process restart.
- **Audit-chain limits:** A hash chain can reveal modification of a retained chain, but by itself cannot prove that an entire database or its latest tail was not deleted. Restrict local database access and protect backups.
- **NER model control:** Any ONNX model must be selected, licensed, provisioned, and versioned by the operator. Runtime downloads are not part of the design.
- **Regulatory responsibility:** The consuming organization remains responsible for lawful processing, data retention, access control, provider choice, DPIA decisions, and any user-facing AI disclosure. SovereignGate does not provide automatic GDPR or EU AI Act compliance.

## Performance and evaluation targets

The benchmark protocol uses 1,000 generated prompts (`eu-synthetic-v1`, fixed seed `20261123`) across DE, ES, FR, IT, NL, and PL support, HR, and finance scenarios; 800 contain positive synthetic examples and 200 are hard negatives. The baseline is pinned to [Presidio Analyzer 2.2.366](https://pypi.org/project/presidio-analyzer/2.2.366/).

| Measure | Target |
| --- | ---: |
| Structured identifier recall on benchmarked countries | At least 99.0% |
| False positive rate on hard negatives | At most 1.0% |
| Offline non-PII task-utility retention proxy | At least 95.0% |
| Tier 1 latency, p95 on a 4-vCPU reference VM | Under 2.0 ms |
| Optional Tier 2 CPU NER latency, p95 | Under 65.0 ms |

The utility figure is a deterministic proxy: compare whether a task answer derived from non-sensitive prompt context remains unchanged after masking. It is not an LLM quality score. These are targets to measure, not results already achieved. Benchmark reports should include the generated dataset annotations, environment, and baseline configuration; comparisons must not promise to beat Presidio on every metric. See the [benchmark protocol](./docs/ARCHITECTURE.md#t04--benchmark-protocol-resolved).

## CLI interface and configuration

The implementation plan includes a Python `>=3.12` package, a Pydantic v2 YAML/environment policy loader, and a `sovereigngate` CLI. Planned environment settings include `SOVEREIGNGATE_POLICY_PATH` and `SOVEREIGNGATE_HMAC_SECRET`. Production deployments should provision a stable secret of at least 32 bytes rather than rely on a development-only ephemeral key.

Implemented offline commands:

- `sovereigngate verify-log --db audit.db` — verify the local SQLite hash chain and return a failing exit status on integrity errors.
- `sovereigngate export-dpia --from YYYY-MM-DD --to YYYY-MM-DD --format md|json` — export a report of configured controls and sanitized audit aggregates.
- `sovereigngate dry-run --file sample_prompts.jsonl` — evaluate local sample input against a policy without calling a model provider.
- `sovereigngate benchmark` — run the synthetic benchmark and report measured accuracy and latency.

The `benchmark` command and reference-environment benchmark run remain release work. The implemented commands above run locally and do not call model providers. For architecture boundaries and remaining decisions, read the [architecture](./docs/ARCHITECTURE.md); for implementation ordering and acceptance criteria, read the [task plan](./docs/TASKS.md).

## Out of scope for V1

- A standalone reverse-proxy server replacing LiteLLM.
- Image OCR or pixel/bounding-box redaction.
- A hosted dashboard, SaaS control plane, SSO/billing service, or external model API for detection.
- A claim that all identifiers in every EU member state are covered before each detector has validated fixtures and release evidence.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).