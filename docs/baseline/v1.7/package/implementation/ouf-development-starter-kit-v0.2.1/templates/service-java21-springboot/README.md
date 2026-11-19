# Java 21 / Spring Boot service template

This is intentionally a skeleton, not a runnable OUF domain service.

Required module additions:
- domain/application/adapters/boot package boundaries;
- module OpenAPI and local JSON Schemas;
- Flyway migrations if persistent;
- contract tests against shared `ouf-contracts`;
- authorization integration using normalized PrincipalContext;
- module-specific readiness and dependency diagnostics;
- runbook and acceptance evidence.

Do not copy shared contract schemas into a divergent local form. Vendor/reference the approved contract artifact instead.
