# Module adoption checklist

A module may declare starter-kit adoption when:

- [ ] Java 21 toolchain is enforced where the module is Java.
- [ ] Platform BOM is consumed; no conflicting Spring Boot 3.x patch line is pinned locally.
- [ ] `ouf-contracts-v1.0.0-rc3-coherence` freeze manifest is referenced immutably.
- [ ] Shared OUF schemas are not copied into divergent local definitions.
- [ ] Module-specific OpenAPI/JSON Schema examples validate in CI.
- [ ] Scenario A/B/C is absent from application branching.
- [ ] Identity is normalized to `PrincipalContext`.
- [ ] Secrets/credentials appear only as references.
- [ ] Gateway boundary and backend fine-grained authorization ownership are preserved.
- [ ] ProblemDetails uses canonical `code` and `correlationId`.
- [ ] OpenTelemetry/correlation propagation is implemented.
- [ ] Flyway zero-to-current and upgrade tests exist if persistent.
- [ ] Helm render, NetworkPolicy and probe checks pass.
- [ ] Contract, integration, security, E2E, performance and package gates are mapped.
- [ ] Runbook and acceptance evidence locations exist.
