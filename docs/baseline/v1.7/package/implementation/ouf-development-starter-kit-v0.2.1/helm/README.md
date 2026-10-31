# Helm conventions

The chart is intentionally restrictive:
- ClusterIP only by default; external exposure is through the Urban API Gateway.
- default-deny NetworkPolicy skeleton;
- liveness is process/JVM oriented;
- readiness may include required local/platform dependencies but should not depend on an arbitrary single external source;
- PDB baseline is enabled for replicated workloads;
- secrets are references/bindings, never chart values containing credential material.

Module teams must add only the egress and environment bindings required by their PET.
