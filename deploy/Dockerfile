FROM python:3.12.16-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SOVEREIGNGATE_ENV=production \
    SOVEREIGNGATE_POLICY_PATH=/app/rules/eu_default_v1.yaml \
    SOVEREIGNGATE_AUDIT_DB=/var/lib/sovereigngate/audit.db

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY rules ./rules
COPY deploy/litellm_config.yaml ./deploy/litellm_config.yaml

RUN python -m pip install --no-cache-dir ".[ner]" "litellm[proxy]>=1.50.0" \
    && apt-get update \
    && apt-get install --yes --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 sovereigngate \
    && useradd --uid 10001 --gid 10001 --home-dir /home/sovereigngate --create-home sovereigngate \
    && mkdir -p /var/lib/sovereigngate /opt/sovereigngate/ner \
    && chown -R 10001:10001 /var/lib/sovereigngate /opt/sovereigngate/ner

USER 10001:10001

EXPOSE 4000

ENTRYPOINT ["litellm"]
CMD ["--config", "/app/deploy/litellm_config.yaml", "--host", "0.0.0.0", "--port", "4000"]
