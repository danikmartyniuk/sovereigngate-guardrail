# SovereignGate Guardrail

**Local text redaction and pseudonymization for LiteLLM-based AI gateways.**

SovereignGate is an open-source Python library and LiteLLM custom guardrail for detecting configured European identifiers and selected personal or sensitive data in text, replacing detected values before a model request, and selectively restoring values at trusted response or tool boundaries. Its local audit writer records sanitized policy metadata in a tamper-evident chain without storing prompt contents.

SovereignGate provides **configurable data-minimization and technical safeguard controls (supporting GDPR Art. 5(1)(c) & Art. 32)**. It is not a compliance product or legal advice.

> **Project status:** Version `0.1.0` is published on [PyPI](https://pypi.org/project/sovereigngate-guardrail/). The package includes the policy loader, normalizer, Tier 1 detectors, local ONNX NER runner, span/policy decision pipeline, HMAC vault, bounded streaming placeholder buffer, LiteLLM lifecycle adapter, SQLite WAL audit writer/verifier, offline CLI, synthetic benchmark harness, and security regressions. The reference-environment benchmark and live pilot deployment remain unverified. NER weights are not bundled, and language support is not claimed until benchmarked. See the [V1 task plan](./docs/TASKS.md) for remaining gates.

## Why it exists

Applications often send user text through an AI gateway to a model provider. That text can contain identifiers and other sensitive values that the application does not want to disclose to the provider. A gateway guardrail can reduce the data sent by replacing selected values with stable, opaque placeholders while preserving enough context for the model to do its work.

SovereignGate runs inside the customer's existing LiteLLM deployment. Its detection, pseudonymization, and audit components run locally; it does not add a hosted SaaS dependency or make network calls from the engine/evidence hot path. LiteLLM still makes its normal request to whichever model provider the customer has configured.

## Installation and first run

Use Python 3.12 or newer.

### Install from PyPI

Version `0.1.0` is available. Install the base package or the optional integrations you need:

```bash
pip install sovereigngate-guardrail
pip install "sovereigngate-guardrail[litellm]"
pip install "sovereigngate-guardrail[sidecar]"
```

The `litellm` extra installs the LiteLLM adapter dependency. The `sidecar` extra installs FastAPI and Uvicorn dependencies for optional sidecar integrations; a standalone proxy is not part of V1. The `ner` extra enables the local ONNX runtime but does not download model weights. Install all three optional integration groups with `pip install "sovereigngate-guardrail[all]"`.

### Install from a source checkout (development)

For development or unreleased changes, install an editable checkout:

```bash
git clone https://github.com/danikmartyniuk/sovereigngate-guardrail.git
cd sovereigngate-guardrail
python3.12 -m venv .venv
```

Activate the environment (`source .venv/bin/activate` on macOS/Linux, or `.venv\Scripts\activate` in Windows PowerShell), then install:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[litellm]"
sovereigngate --version
```

For local development and the full test/toolchain set:

```bash
python -m pip install -e ".[dev,test,typecheck,security,benchmark,litellm,ner]"
```

The Presidio benchmark baseline requires a pre-provisioned local `en_core_web_lg==3.8.0` model matching the pinned digest in [T04](./docs/ARCHITECTURE.md#t04--benchmark-protocol-resolved); the benchmark runner never downloads it.

To run the local quality checks from the source checkout:

```bash
pytest -v
ruff check src tests benchmarks deploy
mypy src
pip-audit
python -m build
twine check dist/*
```

The [GitHub Actions workflow](./.github/workflows/ci.yml) runs the deterministic 100-case, user-style adversarial request suite as a dedicated step, then runs the full regression suite with coverage reporting, Ruff, mypy, and dependency auditing. The full-suite run also includes the adversarial cases. The [security workflow](./.github/workflows/security.yml) adds full-history secret scanning, strict dependency/license checks, CodeQL, Bandit, and zero-leakage regressions on pushes, pull requests, and a weekly schedule. Local hooks are available with `python -m pip install -e ".[dev,security]"`, followed by `pre-commit install`; see [.pre-commit-config.yaml](./.pre-commit-config.yaml) and the [security policy](./SECURITY.md). The [PyPI publishing workflow](./.github/workflows/publish-pypi.yml) runs tests and builds on manual dispatch but skips publishing; pushing a `v*.*.*` tag triggers the trusted OIDC publish job only after security checks pass. The reference-environment benchmark and full release coverage gate are separate release checks.

## Configuration

Production requires a stable `SOVEREIGNGATE_HMAC_SECRET` of at least 32 bytes, represented as hex or base64. Generate a development secret with:

```bash
python -c 'import secrets; print(secrets.token_hex(32))'
```

Store the result in your secret manager or local `.env`; do not commit it. The development-only `SOVEREIGNGATE_ENV=development` fallback creates an ephemeral key and is not appropriate for stable production tokens. `SOVEREIGNGATE_POLICY_PATH` selects the YAML policy (default: `rules/eu_default_v1.yaml` from the source tree), and `SOVEREIGNGATE_AUDIT_DB` selects the local SQLite audit path when the adapter creates its own writer.

The default policy is `shadow`: findings are observed and audited without changing payloads. Shadow mode may still send original content to the configured provider. To test enforcement, create a policy file and point `SOVEREIGNGATE_POLICY_PATH` to it; for example, this deliberately narrow test policy masks only valid PESEL values:

```yaml
mode: enforce
on_error: fail_closed
entities:
  PL_PESEL:
    enabled: true
    action: mask
    sensitivity: standard
```

Only configured, enabled entities receive the listed action. Unsupported, disabled, or undetected data may still reach the provider.

## LiteLLM proxy usage

The V2 custom-guardrail configuration is in [`deploy/litellm_config.yaml`](./deploy/litellm_config.yaml). It loads `SovereignGateGuardrail` for pre-call and post-call hooks, enables PII-free audit admission, and leaves `trusted_routes` and `internal_tools` empty. Consequently, assistant text and tool arguments are not rehydrated by default. Add allowlists only for routes/tools explicitly trusted to receive original values.

For the local Compose stack, follow [`deploy/README.md`](./deploy/README.md). It requires operator-provided LiteLLM master, provider, and HMAC secrets. The stack starts in shadow mode. To exercise `enforce`, mount or copy an operator-reviewed enforcement policy into the image and set `SOVEREIGNGATE_POLICY_PATH` to its container path. The sample model points to OpenAI; this is an ordinary provider request and does not establish EU data residency.

## What V1 currently supports

- **Detect structured identifiers locally.** Tier 1 uses structural boundaries and check-digit validation for configured EU national identifiers, EU IBANs, payment cards, and related categories. The tested candidate matrix covers 23 national-ID modules; CY, LV, LU, and MT personal-ID formats remain unsupported by the pinned `python-stdnum` baseline. See the [country matrix](./docs/ARCHITECTURE.md#t03--identifier-matrix-and-local-ner-artifact-resolved). “EU-27 target” does not mean every national identifier is supported.
- **Detect common contact and secret patterns.** Tier 1 includes email, phone, IP address, and selected API-key/bearer-token detection.
- **Normalize obfuscated text before scanning.** Apply Unicode NFKC normalization, remove specified zero-width characters, and handle separator obfuscation while keeping offsets so detections can be replaced in the original text.
- **Optionally detect unstructured entities.** An opt-in CPU-based ONNX runner for person, organization, address, and health-related spans is implemented. It requires a locally provisioned, hash-verified model/tokenizer bundle, is disabled by default, and has no runtime model downloads or PyTorch dependency. Target languages remain unvalidated until the benchmark gates pass.
- **Pseudonymize consistently within a session.** Use HMAC-derived placeholders such as `[PL_PESEL_9F2A1C]` so repeated canonical values in the same session can map to the same token. The lookup needed to restore a value is kept only in a request-scoped in-memory vault.
- **Integrate with LiteLLM request/response paths.** The adapter scans supported message text, text blocks, tool-call JSON argument values, tool outputs, and text `prompt`/`input` fields; it handles split streaming placeholders and adds non-PII routing metadata.
- **Support observe-first operation.** `shadow` mode reports findings without changing or blocking on policy results. `enforce` mode applies per-entity `mask`, `block`, `shadow_log`, or `allow` actions and follows the configured error policy.
- **Create local evidence.** A bounded background writer persists validated, sanitized event metadata in a local SQLite hash chain. The `verify-log`, `dry-run`, and `export-dpia` commands verify, evaluate, and export evidence offline.

## How a request flows

1. LiteLLM invokes the SovereignGate pre-call hook.
2. The adapter copies the request structure and scans supported text fields. It does not inspect image pixels or arbitrary binary data.
3. Text is normalized and scanned by deterministic validators. Optional local NER can add probabilistic spans.
4. The policy engine resolves overlaps (Tier 1 checksum-validated matches take precedence) and decides which configured entities to mask, block, log in shadow, or allow.
5. In enforce mode, masked text and per-session HMAC placeholders are passed to the configured model provider. The original values remain in the request's in-memory vault for permitted restoration.
6. Post-call or streaming hooks can restore only placeholders mapped in that request's vault. Restoration should be limited to a boundary trusted to receive the original value, such as an authorized internal tool. Rehydrating assistant output can expose the original value to the calling application.
7. A sanitized pre-call audit event is admitted non-blockingly to the local writer when auditing is configured. The vault is wiped/released on success, failure, stream completion, and cancellation.

Undetected entities and unsupported payload types may still reach the configured provider. Detection is a data-minimization control, not a guarantee that a prompt contains no personal data.

## LiteLLM adapter and restoration boundaries

`SovereignGateGuardrail` is implemented in [`litellm_guardrail.py`](./src/sovereigngate/adapters/litellm_guardrail.py). It subclasses LiteLLM's `CustomGuardrail`, copies incoming payloads, and implements native pre-call, post-call-success, failure, and streaming-iterator hooks. It scans message content and text blocks, JSON tool-call argument values, tool outputs, and text `prompt`/`input` fields. Malformed tool-call JSON is rejected with a sanitized guardrail error in fail-closed enforce mode; explicit fail-open emits a sanitized processing-error metadata signal.

Restoration is opt-in at construction: `trusted_routes` names routes allowed to receive restored assistant text, and `internal_tools` names tools allowed to receive restored tool-call arguments. The route name is matched against request metadata (`route` or `model_group`) or the model name. If a route or tool is not allowlisted, its output retains placeholders. Provide a stable `SOVEREIGNGATE_HMAC_SECRET` in production; an explicit bytes secret may also be passed when constructing the adapter. Request-context metadata contains only a random identifier and sanitized entity/routing tags.

## Operating modes and failure behavior

| Mode | Intended behavior |
| --- | --- |
| `shadow` | Detect and report findings without changing payload text or blocking on policy results. |
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

The benchmark protocol uses 1,000 generated prompts (`eu-synthetic-v1`, fixed seed `20261123`) across DE, ES, FR, IT, NL, and PL support, HR, and finance scenarios; 800 contain positive synthetic examples and 200 are hard negatives. The baseline is pinned to [Presidio Analyzer 2.2.366](https://pypi.org/project/presidio-analyzer/2.2.366/) with the default `en_core_web_lg==3.8.0` package tree pinned by SHA-256. Reports mark languages unsupported by the default registry as `N/A`.

| Measure | Target |
| --- | ---: |
| Structured identifier recall on benchmarked countries | At least 99.0% |
| False positive rate on hard negatives | At most 1.0% |
| Offline non-PII task-utility retention proxy | At least 95.0% |
| Tier 1 latency, p95 on a 4-vCPU reference VM | Under 2.0 ms |
| Optional Tier 2 CPU NER latency, p95 | Under 65.0 ms |

The utility figure is a deterministic proxy: compare whether a task answer derived from non-sensitive prompt context remains unchanged after masking. It is not an LLM quality score. The local macOS arm64 diagnostic measured 100% recall, 0% hard-negative FPR, 100% utility retention, and Tier 1 p95 of 0.202458 ms over 10,000 observations; these are not release results. The T04 Ubuntu reference run and optional Tier 2 model evaluation remain pending. Presidio comparisons are `N/A` for the six languages under its default registry. Benchmark reports include the generated dataset annotations, environment, and baseline configuration; comparisons must not promise to beat Presidio on every metric. See the [benchmark protocol](./docs/ARCHITECTURE.md#t04--benchmark-protocol-resolved).

## CLI commands

Implemented offline commands:

- `sovereigngate verify-log --db audit.db` — verify the local SQLite hash chain and return a failing exit status on integrity errors.
- `sovereigngate export-dpia --from YYYY-MM-DD --to YYYY-MM-DD --format md|json` — export a report of configured controls and sanitized audit aggregates.
- `sovereigngate dry-run --file sample_prompts.jsonl` — evaluate local sample input against a policy without calling a model provider.
- `sovereigngate benchmark` — run the synthetic benchmark and report accuracy, baseline availability, and measured latency. Use `--skip-latency` only for smoke checks; it is not release evidence. `--output report.json` writes a sanitized JSON summary.

`dry-run` accepts one JSON object per line. For example:

```json
{"messages":[{"role":"user","content":"Please check order 42."}]}
```

It prints only aggregate entity/action counts and processing errors, never the input text.

The commands run locally and do not call model providers. The reference-environment benchmark and Tier 2 measurement remain release work. For architecture boundaries and remaining decisions, read the [architecture](./docs/ARCHITECTURE.md); for implementation ordering and acceptance criteria, read the [task plan](./docs/TASKS.md).

## Pilot deployment

A sample LiteLLM configuration and Docker Compose stack are provided in [`deploy/`](./deploy/README.md). To start it:

```bash
cp deploy/.env.example .env
# Edit .env with a LiteLLM master key, provider API key, and stable 64-hex HMAC secret.
docker compose -f deploy/docker-compose.yml config --quiet
docker compose -f deploy/docker-compose.yml up --build
```

The stack listens on port 4000, persists audit data in a local volume, and mounts NER artifacts read-only. The bundled policy starts in `shadow` mode. Shadow mode does not mask or block based on findings and may pass original text to the configured provider; use synthetic examples unless you deliberately select an operator-reviewed `enforce` policy.

For a local request using only a synthetic PESEL test value:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"Check synthetic PESEL 00210100004."}]}'
```

Compose syntax and custom-guardrail class loading are tested; a live stack run has not been verified here because the Docker daemon is unavailable. A live completion also needs provider credentials. See [deploy/README.md](./deploy/README.md) for the audit volume, local NER mount, and shutdown notes.

## Out of scope for V1

- A standalone reverse-proxy server replacing LiteLLM.
- Image OCR or pixel/bounding-box redaction.
- A hosted dashboard, SaaS control plane, SSO/billing service, or external model API for detection.
- A claim that all identifiers in every EU member state are covered before each detector has validated fixtures and release evidence.

## Maintainer release checklist

1. Configure PyPI Trusted Publishing for this repository, workflow `.github/workflows/publish-pypi.yml`, and GitHub environment `pypi`. No PyPI API token is stored in GitHub secrets.
2. Confirm the release commit passes CI and verify the distributions locally with `python -m build` and `twine check dist/*`.
3. Choose the next unused semantic version and create and push its `vX.Y.Z` tag. Version `0.1.0` is already released; never reuse a published version or tag. The tag is the package version source, so do not edit a version constant in `pyproject.toml`. For example, if `0.1.1` is the intended next version:

   ```bash
   git tag v0.1.1 && git push origin v0.1.1
   ```

4. Confirm the tag workflow's test and build jobs pass and the `pypi` environment publishes the artifact. A manual `workflow_dispatch` run is a dry run: it validates and builds but does not publish.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).