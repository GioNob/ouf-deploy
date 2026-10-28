# Common release evidence package

Each module release candidate should provide, as applicable:

- build/unit/static-analysis report;
- OpenAPI/JSON Schema lint and example-validation report;
- shared-contract compatibility report;
- Flyway migrate/validate from zero and N->N+1/upgrade evidence;
- integration test report with dependency stubs/Testcontainers;
- security scans: dependency, container, secrets, SAST;
- E2E report mapped to approved scenarios;
- capacity/backpressure/performance results;
- OCI image digest;
- rendered Helm manifests;
- SBOM;
- artifact checksums/provenance;
- deployment/readiness evidence from staging;
- runbook version;
- unresolved issue list with zero BLOCKER/HIGH for acceptance.
