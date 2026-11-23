# Local LiteLLM pilot stack

This development stack runs LiteLLM with the SovereignGate `CustomGuardrail`, mounts a local audit volume, and exposes the configured model provider through LiteLLM. It does not claim that the configured model is EU-hosted; provider selection and residency must be verified by the operator.

1. Copy `deploy/.env.example` to `.env` at the repository root and set `LITELLM_MASTER_KEY`, `OPENAI_API_KEY`, and a stable `SOVEREIGNGATE_HMAC_SECRET` containing at least 32 bytes encoded as hex or base64.
2. Run `docker compose -f deploy/docker-compose.yml up --build`.
3. Use LiteLLM's `/v1/chat/completions` endpoint on port 4000 with model `demo`.

The bundled policy is `shadow`, so it reports findings but does not mask or block because of them. Set `SOVEREIGNGATE_POLICY_PATH` to an operator-reviewed `enforce` policy before evaluating masking behavior; shadow mode can still send the original text to the configured provider. The custom guardrail uses both pre-call and post-call hooks. Assistant responses and tool arguments are not rehydrated because the allowlists are empty by default.

The named `audit-data` volume stores the local SQLite WAL audit chain. The adapter registers an orderly process-exit flush and the Compose stop grace period allows the 10-second writer drain. The `ner-models` bind mount is read-only and intentionally contains no model weights. To enable Tier 2, provision the verified local model bundle there and point an operator policy at `/opt/sovereigngate/ner`; no model is downloaded at startup or in the request path.

For a zero-data local configuration check, run `docker compose -f deploy/docker-compose.yml config` after setting the required environment values. A live completion still requires valid provider credentials.
