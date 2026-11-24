# SovereignGate Guardrail — Technical Guide

This guide covers installation, configuration, runtime behavior, integration patterns, commands, and operational limits for SovereignGate Guardrail `0.1.0`.

SovereignGate provides **configurable data-minimization and technical safeguard controls (supporting GDPR Art. 5(1)(c) & Art. 32)**. It is not a compliance certification. Masked values are pseudonyms, not anonymized data.

- Package: [sovereigngate-guardrail on PyPI](https://pypi.org/project/sovereigngate-guardrail/)
- User-oriented overview: [../README.md](../README.md)
- Architecture and coverage decisions: [ARCHITECTURE.md](./ARCHITECTURE.md)
- Implementation and release gates: [TASKS.md](./TASKS.md)
- Example local deployment: [../deploy/README.md](../deploy/README.md)

## 1. What the package does

The package is an in-process LiteLLM custom guardrail, not an HTTP proxy or standalone sidecar server. The adapter copies supported request structures, scans configured text locally, and applies the policy before LiteLLM sends the request to its configured model provider. It can selectively restore request-scoped placeholders in configured trusted response and tool boundaries.

The processing pipeline is:

1. Read and validate a YAML policy.
2. Copy supported text fields from the LiteLLM request.
3. Normalize Unicode and selected separator/zero-width obfuscations while tracking offsets back to the original text.
4. Detect Tier 1 structured entities with local format and checksum validation; optionally run local CPU ONNX NER (Tier 2).
5. Resolve spans and apply per-entity policy actions.
6. In `enforce` mode, replace configured matches with HMAC-derived placeholders and retain their originals only in a request-scoped in-memory vault.
7. Optionally enqueue a sanitized audit event to a background SQLite WAL writer.
8. Rehydrate only when the configured route or internal tool is trusted, then wipe the request context on the terminal lifecycle path.

The `engine/` and `evidence/` paths perform no provider or SaaS calls. LiteLLM continues to make its ordinary request to the model provider configured by the application.

## 2. Install

Python 3.12 or newer is required. The initial package release is available from PyPI:

```bash
python -m pip install sovereigngate-guardrail
```

Install the optional LiteLLM dependency to use the adapter:

```bash
python -m pip install "sovereigngate-guardrail[litellm]"
```

Optional dependency groups:

| Extra | Installs | Notes |
| --- | --- | --- |
| `litellm` | LiteLLM | Required to import and run `SovereignGateGuardrail`. |
| `ner` | ONNX Runtime and Tokenizers | Enables optional local Tier 2 inference; it does not install model weights. |
| `sidecar` | FastAPI and Uvicorn | Dependency group only; V1 does not include a standalone sidecar service. |
| `all` | `litellm`, `sidecar`, and `ner` | Installs all optional extras; the sidecar extra provides dependencies only. |

For example, install the adapter and local NER runtime with:

```bash
python -m pip install "sovereigngate-guardrail[litellm,ner]"
```

Verify the installed CLI and version:

```bash
sovereigngate --version
```

For development from a checkout, use an editable install. The `[dev]`, `[test]`, `[typecheck]`, `[security]`, and `[benchmark]` extras are for maintainers and CI, not needed in production.

## 3. Configure secrets and policy

### HMAC key

The adapter requires `SOVEREIGNGATE_HMAC_SECRET` outside explicit development mode. It accepts hexadecimal or base64 text that decodes to at least 32 bytes. Generate a random 32-byte hexadecimal key for a local shell, then store production keys in a secret manager:

```bash
export SOVEREIGNGATE_HMAC_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

Do not commit the key or print it in production logs. Stable keys are needed for deterministic tokens across process restarts. The command above creates a new key each time; do not use it as a replacement production key on every startup. If `SOVEREIGNGATE_ENV=development` and no key is configured, the loader creates an ephemeral key and emits a warning; tokens will not be stable across process restarts. Do not use this fallback for production.

### Policy path

Set `SOVEREIGNGATE_POLICY_PATH` to choose a policy file. If unset, the loader checks `rules/eu_default_v1.yaml` in the current working directory, then the installed `share/sovereigngate/rules/eu_default_v1.yaml` data path.

```bash
export SOVEREIGNGATE_POLICY_PATH="$PWD/rules/eu_default_v1.yaml"
```

Policies are strict Pydantic-validated YAML: unknown keys and invalid values fail loading rather than silently becoming defaults. The top-level settings are:

```yaml
mode: shadow
on_error: fail_closed

normalization:
  strip_zero_width: true
  collapse_separator_obfuscation: true
  entropy_min_length: 48
  entropy_threshold: 4.5
  max_encoded_length: 4096
  encoded_content_action: block

ner:
  enabled: false
  languages: [de, fr, es, pl, it, nl, en]

entities:
  PL_PESEL:
    enabled: true
    action: mask
    sensitivity: standard
```

Entity names must be uppercase identifiers. Each entity rule has:

| Field | Values | Meaning |
| --- | --- | --- |
| `enabled` | `true` / `false` | Whether the finding participates in policy decisions. |
| `action` | `mask`, `block`, `shadow_log`, `allow` | Mask in enforce mode, block the request, observe without masking, or allow. |
| `sensitivity` | `standard`, `special_category` | Adds sensitivity classification to sanitized decision metadata and blocking diagnostics. |

`shadow` is the safe starting mode: it scans and reports configured findings but leaves request text unchanged. In `enforce`, `mask` redacts, `block` stops the request, `shadow_log` observes without changing text, and `allow` records an allowed finding. An encoded-content `block` signal is enforced only in enforce mode. `decode_utf8_once` performs one bounded decode-and-scan attempt; it is not recursive decoding.

The default `eu_default_v1.yaml` enables many entity categories with `mask`, but the policy's default mode is `shadow`. Review and explicitly select an enforce policy before relying on masking.

To enable Tier 2, an operator must provision the exact locally exported model bundle and its `model_manifest.json`, then configure both the model directory and SHA-256 of the manifest. The manifest independently pins the ONNX model and tokenizer digests and must satisfy the fixed model/export/label contract validated by this package. For example:

```yaml
ner:
  enabled: true
  model_dir: /opt/sovereigngate/ner
  manifest_sha256: <64-character SHA-256 of model_manifest.json>
  threshold: 0.5
  languages: [de, fr, es, pl, it, nl, en]
```

Replace the digest placeholder with the actual manifest digest. Model conversion and provisioning are offline operator tasks; the runtime does not fetch model files.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `SOVEREIGNGATE_HMAC_SECRET` | Hex or base64 secret, minimum 32 decoded bytes; required outside explicit development mode. |
| `SOVEREIGNGATE_ENV` | Set to `development` only to enable an ephemeral development key fallback. |
| `SOVEREIGNGATE_POLICY_PATH` | Policy YAML path; otherwise source-tree or installed default policy is used. |
| `SOVEREIGNGATE_AUDIT_DB` | SQLite audit file path used when the adapter creates its own audit writer. |

## 4. Run a local scan

The engine API returns decisions and original-input spans; it does not itself mutate text or tokenize it. For policy-only checks and offline examples:

```python
from sovereigngate.config import load_policy
from sovereigngate.engine.pipeline import run_pipeline

policy = load_policy()
result = run_pipeline("Synthetic PESEL: 00210100004", policy)

print(result.detected_entity_types)
print([(item.span.entity_type, item.action.value) for item in result.decisions])
```

The default policy is in `shadow`, so this example reports a configured finding without masking it. `PipelineResult.spans_to_mask` contains original-text offsets selected for masking in `enforce` mode; use the adapter for request copying, tokenization, lifecycle state, and rehydration.

### Core Python API reference

| API | Purpose |
| --- | --- |
| `load_policy(path=None)` | Load and validate a YAML policy; uses `SOVEREIGNGATE_POLICY_PATH` or the packaged default when no path is supplied. |
| `normalize_text(text, config=None)` | Return normalized text, source-offset mappings, and encoded-content signals. The result representation is redacted. |
| `detect_tier1(normalized)` | Return immutable Tier 1 spans with offsets into the original input. |
| `run_pipeline(text, policy, ner_runner=None)` | Return policy decisions, entity categories, block status, and maskable original spans. It does not replace the source string. |
| `SessionVault(secret, session_id)` | Create request-local tokens and retain originals only for that request's restoration window. |
| `StreamRehydrator(vault)` | Reassemble and restore known tokens split across text chunks; call `feed(..., final=True)` at stream end. |
| `AuditLog(path)` | Start the optional background SQLite WAL writer; use `enqueue(event, on_error=...)`, inspect `.health`, then call `.close()` at shutdown. |
| `verify_log(path)` / `read_records(path)` | Verify the retained hash chain; `read_records` returns records only after verification. |

### Token format and scope

Tokens have the form `[ENTITY_XXXXXX]`. The six-character uppercase hexadecimal suffix is the first six hex digits of HMAC-SHA256 over `session_id:entity_type:canonical_value`, keyed with `SOVEREIGNGATE_HMAC_SECRET`. Tier 1 values use the validator's compact canonical form after normalization. Repeated canonical values with the same session ID therefore produce the same token. The lookup from token back to original text is not persistent: each LiteLLM request has its own vault. This allows deterministic placeholders but does not support rehydrating a previous request's token in a later request.

The suffix is 24 bits, so collisions across requests remain possible. Different values colliding within one vault are detected and rejected without overwriting the first mapping. This residual collision risk is a documented risk-owner acceptance gate before an external pilot.

When using `SessionVault` directly, always wipe it in a `finally` block. For example, using synthetic test content:

```python
from sovereigngate.config import load_hmac_secret
from sovereigngate.engine.vault import SessionVault

vault = SessionVault(load_hmac_secret(), session_id="example-session")
try:
    token = vault.tokenize("PERSON", "Synthetic Person")
    restored = vault.rehydrate(f"Hello, {token}")
finally:
    vault.wipe()
```

## 5. Integrate with LiteLLM

### LiteLLM proxy configuration

The repository's [V2 LiteLLM configuration](../deploy/litellm_config.yaml) is a starting point:

```yaml
model_list:
  - model_name: demo
    litellm_params:
      model: openai/gpt-4o-mini
      api_key: os.environ/OPENAI_API_KEY

litellm_settings:
  guardrails:
    - guardrail_name: sovereigngate
      litellm_params:
        guardrail: sovereigngate.adapters.litellm_guardrail.SovereignGateGuardrail
        mode: [pre_call, post_call]
        default_on: true
        trusted_routes: []
        internal_tools: []
```

Use a stable HMAC secret and a reviewed policy in the proxy environment. The sample deliberately leaves trusted routes and tools empty. This means response text and tool arguments remain tokenized; no automatic restoration is enabled.

The adapter constructor accepts a `PolicyConfig` and bytes key for embedding, or may load its policy/key from the environment when those values are omitted. Other supported constructor options include `policy_path`, `audit_db_path`, `trusted_routes`, `internal_tools`, and an injected `AuditLog` writer. Do not pass both `audit_db_path` and `audit_log`. If an audit writer is injected, the caller owns closing it; if the adapter creates it, call `close()` during orderly shutdown (an exit hook is also registered for an adapter-owned writer).

### Request and response behavior

The adapter copies input payloads; it does not mutate the caller's dictionaries. It scans these text-bearing locations:

- `messages[].content` strings and nested text/content blocks;
- string values nested in `messages[].tool_calls[].function.arguments` JSON;
- tool-role message content;
- text `prompt` and `input` request fields when `messages` is absent.

Non-string JSON fields are preserved. Tool-call JSON strings are parsed and serialized compactly in enforce mode. Malformed tool JSON fails closed by default in enforce mode, with a sanitized error that does not include the contents. Shadow mode observes malformed JSON as text and leaves the original payload unchanged.

The adapter adds sanitized metadata including `eu_sensitive` and `detected_entity_types`. It also adds an opaque request-context ID used to find the in-memory vault across LiteLLM retries and hooks. The HMAC session ID is read from request metadata when available; otherwise a random per-request ID is used.

### Trusted restoration boundaries

Configure `trusted_routes` only for routes authorized to receive original assistant response text. Route matching checks request metadata `route` or `model_group`, then the model name. Configure `internal_tools` only for internal tools authorized to receive original tool arguments. Tool names must match the allowlist exactly.

Rehydration is request-scoped. Only a complete placeholder present in the current request vault can be restored; unknown placeholder-shaped strings remain unchanged. Tool results that return to the model pass through pre-call scanning again. Restoration exposes originals to the configured recipient, so treat allowlists as data access controls rather than convenience options.

### Streaming

For trusted routes and allowlisted tools, the streaming hook buffers partial placeholder prefixes across chunks, up to the 32-character token limit. It restores known placeholders and flushes incomplete text when the stream finishes. Untrusted assistant text and non-allowlisted tool arguments remain tokenized. Stream completion, failure, and cancellation release the request context and wipe the vault.

### Direct Python construction

If the host application constructs the adapter itself rather than using LiteLLM's config loader:

```python
from sovereigngate.adapters.litellm_guardrail import SovereignGateGuardrail

guardrail = SovereignGateGuardrail(
    policy_path="/etc/sovereigngate/policy.yaml",
    trusted_routes=("internal-eu-route",),
    internal_tools=("customer_record_lookup",),
    audit_db_path="/var/lib/sovereigngate/audit.db",
)
```

This reads `SOVEREIGNGATE_HMAC_SECRET` from the process environment and uses the supplied policy path. Integrate the instance through the supported LiteLLM guardrail lifecycle; do not call only the pre-call hook in production because request vault cleanup depends on response, failure, and stream hooks.

## 6. Detection coverage and boundaries

Tier 1 checks structured candidates locally using boundaries and validator/checksum logic. The tested personal identifier candidate matrix covers these entity types:

| Country | Entity types |
| --- | --- |
| Austria | `AT_VNR` |
| Belgium | `BE_NISS` |
| Bulgaria | `BG_EGN`, `BG_PNF` |
| Croatia | `HR_OIB` |
| Czechia | `CZ_RC` |
| Denmark | `DK_CPR` |
| Estonia | `EE_IK` |
| Finland | `FI_HETU` |
| France | `FR_NIR` |
| Germany | `DE_STEUERID` |
| Greece | `GR_AMKA` |
| Hungary | `HU_ANUM` |
| Ireland | `IE_PPSN` |
| Italy | `IT_CODICE_FISCALE` |
| Lithuania | `LT_ASMENS` |
| Netherlands | `NL_BSN` |
| Poland | `PL_PESEL`, `PL_NIP` |
| Portugal | `PT_CC`, `PT_NIF` |
| Romania | `RO_CNP` |
| Slovakia | `SK_RC` |
| Slovenia | `SI_EMSO` |
| Spain | `ES_DNI`, `ES_NIE`, `ES_NIF` |
| Sweden | `SE_PERSONNUMMER` |

The policy also includes `IBAN`, `PAYMENT_CARD`, `BIC`, `EMAIL`, `PHONE`, `IP_ADDRESS`, `API_KEY`, and `BEARER_TOKEN`. Personal-ID support is not implemented for Cyprus, Latvia, Luxembourg, or Malta using the pinned baseline. This is not complete EU-27 national-ID coverage; see the [architecture matrix](./ARCHITECTURE.md#t03--identifier-matrix-and-local-ner-artifact-resolved) and run the detectors against synthetic, country-specific cases.

Tier 2 labels are `PERSON`, `ORG`, `ADDRESS`, and `HEALTH_TERM`. It is disabled by default and requires an operator-provisioned, hash-verified local ONNX model/tokenizer bundle. The model files are not included in the package and are not downloaded at runtime. Setting `ner.languages` does not by itself prove language accuracy; target languages remain unvalidated until benchmarked.

The detector does not inspect images, OCR, arbitrary binary content, or every possible form of personal data. Unsupported and undetected text may reach the configured provider.

## 7. Normalization and encoded content

The normalizer applies Unicode NFKC, removes the configured zero-width characters, collapses supported separator obfuscations, and maintains source offsets. Detected spans refer to the original string so the adapter can replace original text accurately.

Long Base64/hex-like candidates are checked against the configured entropy threshold and maximum encoded length. The default policy sets `encoded_content_action: block`. In enforce mode, a qualifying encoded-content signal blocks before dispatch; in shadow mode it is observed without changing or blocking the request. `decode_utf8_once` performs a single bounded UTF-8 decode-and-scan and fails according to `on_error` if the scan cannot safely complete.

## 8. Error handling

| Condition | Default behavior |
| --- | --- |
| Policy missing, malformed, or invalid | Startup or CLI configuration error with sanitized field/path diagnostics; no silent fallback policy. |
| Configured entity action is `block` in enforce mode | Sanitized LiteLLM guardrail exception (HTTP 403); reports entity category/sensitivity, not matched text. |
| Unexpected request processing error in enforce + `fail_closed` | Reject before provider dispatch. |
| Unexpected request processing error in enforce + `fail_open` | Return the original copied payload with a sanitized `sovereigngate_processing_error` metadata code. This is an explicit permissive mode. |
| Response or stream processing error in enforce + `fail_closed` | Sanitized response/stream processing error (HTTP 502); context is released. |
| Audit queue unavailable in enforce + `fail_closed` | Reject before provider dispatch rather than silently losing the required record. |

The adapter never includes prompt text, matched values, tool arguments, or vault contents in its user-facing errors. Applications should still avoid logging request/response bodies around the guardrail.

## 9. Audit logging and evidence

Set `SOVEREIGNGATE_AUDIT_DB` to enable an adapter-owned SQLite audit log, or pass an `AuditLog` instance when constructing the adapter. Audit events contain validated metadata such as a request ID, mode, model target, policy digest, entity counts, action, and latency; they do not contain prompt/response bodies or matched values.

The writer admits events to a bounded queue without waiting for SQLite I/O on the request path. It stores a SHA-256 hash chain in SQLite WAL mode. Queue capacity is at most 10,000 records. Shadow mode records degraded/drop health and continues if events cannot be admitted; enforce mode follows `on_error`. Shutdown drains for up to 10 seconds by default and reports a visible failure if the writer does not flush. The chain detects edits and interior changes in the retained database; it cannot detect deletion of the entire database or prove that its newest tail was not removed.

Useful commands:

```bash
sovereigngate verify-log --db /var/lib/sovereigngate/audit.db
sovereigngate export-dpia \
  --from 2026-11-01 \
  --to 2026-11-30 \
  --format md \
  --db /var/lib/sovereigngate/audit.db \
  --policy /etc/sovereigngate/policy.yaml
```

The export summarizes policy configuration and sanitized audit aggregates. It is supporting technical evidence, not a legal determination, complete DPIA, or compliance certificate.

## 10. Offline CLI patterns

### Dry-run JSONL

Create newline-delimited JSON with one request object per line. Supported record shapes include `messages` with user content and tool-call arguments, or text `prompt`/`input` fields. Example using a synthetic test value:

```json
{"messages":[{"role":"user","content":"Check synthetic PESEL 00210100004."}]}
```

Run the input against the selected policy:

```bash
sovereigngate dry-run --file sample_prompts.jsonl --policy rules/eu_default_v1.yaml
```

The dry-run command is offline: it does not call a provider or print input contents. It reports record, flagged, and blocked counts, entity counts, and processing error codes. It does not replace text or create pseudonym tokens. Input is bounded to 16 MiB total and 1 MiB per JSONL line.

### Benchmark

The benchmark uses only deterministic synthetic prompts. A smoke invocation may skip latency and Presidio, but is not release evidence:

```bash
sovereigngate benchmark --skip-presidio --skip-latency
```

The reference benchmark uses 1,000 synthetic prompts, 100 warm-ups, and 10,000 timed observations. Presidio comparisons may be `N/A` for unsupported default-registry language cells. Tier 2 measurements require the operator-provisioned model bundle. See the [frozen protocol](./ARCHITECTURE.md#t04--benchmark-protocol-resolved).

## 11. Local LiteLLM deployment

The sample Compose deployment is useful for evaluation, not a claim of production readiness or EU data residency. It requires a LiteLLM master key, provider API key, and stable HMAC key.

```bash
cp deploy/.env.example .env
# Edit .env with locally managed credentials; do not commit it.
docker compose -f deploy/docker-compose.yml config --quiet
docker compose -f deploy/docker-compose.yml up --build
```

The sample starts in shadow mode, uses OpenAI as its configured provider, persists audit data in a local volume, and mounts an empty read-only directory for optional NER artifacts. A live completion requires valid provider credentials. Shadow mode leaves request text unchanged and may send original data to that provider. Review [deploy/README.md](../deploy/README.md) before using the stack.

## 12. Security and operational notes

- Treat original prompt text and restored values as sensitive while they exist in process memory.
- Use a stable HMAC secret, restrict access to it, and rotate it according to your organization's secret-management policy.
- Keep `trusted_routes` and `internal_tools` minimal. Rehydration deliberately releases original values to those recipients.
- The request vault is wiped on normal lifecycle termination, but Python cannot guarantee physical erasure of immutable string allocations.
- Six hexadecimal token characters provide only a 24-bit suffix. In-request collisions are detected and fail closed; cross-request collisions cannot be prevented by the request-scoped vault. This remains a documented risk-owner acceptance gate before an external pilot.
- Audit files and backups need appropriate access controls. Hash chaining does not make the database undeletable or provide external anchoring.
- Validate customer policies, entity coverage, provider retention, data residency, and operational failure behavior for your deployment. The product is not a substitute for these controls.

For responsible vulnerability reporting, see [../SECURITY.md](../SECURITY.md). For code changes and release procedures, see the [repository README](../README.md) and [task plan](./TASKS.md).

## 13. Common usage patterns

| Goal | Recommended pattern |
| --- | --- |
| Inspect findings before changing provider payloads | Start with `mode: shadow`; use `sovereigngate dry-run` on synthetic or approved local samples. |
| Redact configured matches before provider dispatch | Use `mode: enforce` with `action: mask`, stable key material, and `on_error: fail_closed`; verify policy and detector coverage before enabling traffic. |
| Block selected entity categories | Set the relevant enabled entity's `action: block`; the adapter emits sanitized 403 diagnostics in enforce mode. |
| Use detected text in an internal tool | Add only that tool's exact name to `internal_tools`; review its access and downstream logs. |
| Restore assistant output | Add only the exact trusted route/model name to `trusted_routes`; leave it unset for ordinary user-facing model routes. |
| Add NER | Install `[ner]`, provision a compatible local bundle, pin its manifest digest in policy, and validate the target language before use. |
| Keep audit evidence | Set `SOVEREIGNGATE_AUDIT_DB`, monitor writer health/degradation, and verify/export the local chain during operations. |

Before production use, run the security and quality checks described in the [repository README](../README.md), validate your own policies with synthetic data, and plan for the still-open reference benchmark, live gateway E2E, license review, and token-collision risk acceptance.
