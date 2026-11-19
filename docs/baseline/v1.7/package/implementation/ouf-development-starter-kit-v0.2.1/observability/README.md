# Observability baseline

Use OpenTelemetry-compatible tracing and structured JSON logs. `correlationId` is the primary OUF cross-module application correlation key; trace/span identifiers complement it.

Never log bearer tokens, secret material or full protected/sensitive payloads. Module PETs remain authoritative for domain-specific metrics and SLOs.
