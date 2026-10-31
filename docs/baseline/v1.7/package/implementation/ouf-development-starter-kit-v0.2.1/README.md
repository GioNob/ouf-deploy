# OUF Common Development Starter Kit — v0.2.1

Purpose: give independent OUF implementation teams a common, development-ready baseline without reopening module PETs or inventing platform decisions.

Normative contract baseline: `contracts/ouf-contracts-v1.0.0-rc3-coherence/`.

## What this kit freezes

- Java toolchain: 21.
- Spring Boot product line: 3.x, exact patch/minor supplied by the platform BOM at implementation time.
- PostgreSQL/Flyway category baseline for stateful Java modules.
- OpenAPI/JSON Schema contracts versioned with code and validated in CI.
- OUF cross-module contract repository as the only canonical machine-readable contract source.
- Scenario-neutral M2M identity integration: applications consume normalized PrincipalContext semantics and environment bindings; no code branches on IAM scenario A/B/C.
- OpenTelemetry-compatible trace/metric correlation and structured JSON logging.
- Kubernetes/Helm/GitOps deployment conventions.
- Common blocking CI stages and release evidence expectations.

## What this kit deliberately does NOT decide

- IAM scenario A/B/C.
- Real issuer/JWKS/audience/claim names.
- Real client IDs, secrets, certificates or rotation process.
- Exact Spring Boot/Flyway/Testcontainers patch versions before platform BOM approval.
- Environment hostnames, routes, database endpoints, storage endpoints or RPO/RTO.
- Module-specific domain logic, schemas, migrations, capabilities or operational limits.
- New broker, graph DB, vector DB, analytics engine, workflow engine or service mesh.

## Quick start

1. Copy `templates/service-java21-springboot/` into the module repository.
2. Bind platform versions in `platform/platform-version-bindings.yaml`.
3. Point the module CI to the vendored/frozen contract baseline or an approved immutable artifact carrying the same freeze manifest.
4. Implement module-specific OpenAPI/schema/migrations without copying or redefining shared OUF contracts.
5. Run:
   - `python ci/scripts/validate_contracts.py`
   - `python ci/scripts/check_identity_neutrality.py`
   - `python ci/scripts/check_repository_layout.py`
6. Translate `ci/pipeline-contract.yaml` to the organization's CI engine without dropping blocking stages.
7. Render/adapt the Helm chart using environment bindings; never embed secrets.

## Repository shape

```text
ouf-development-starter-kit/
├── contracts/
├── build/
├── ci/
├── platform/
├── templates/
├── helm/
├── observability/
├── testing/
├── docs/
└── sbom/
```

The kit is implementation scaffolding, not a new OUF runtime module.

## v0.2.1 coherence patch
Current adoption instructions are pinned consistently to `ouf-contracts-v1.0.0-rc3-coherence`. CI includes a stale-baseline guard for starter-kit documentation outside vendored contract history.
