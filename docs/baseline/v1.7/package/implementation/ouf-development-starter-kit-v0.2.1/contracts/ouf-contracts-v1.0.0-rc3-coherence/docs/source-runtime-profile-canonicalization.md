# SourceRuntimeProfile canonicalization — v1.0 RC1

The uncataloged artifact `onboarding/source-runtime-profile-v1.json` has been removed before the v1.0 candidate.

The canonical machine-readable runtime contract is `gateway/source-runtime-profile-v1.json`.

Ownership is unchanged:
- Source Onboarding / Configuration owns the complete source configuration and publishes the runtime projection.
- Urban API Gateway consumes/materializes the technical runtime projection.

This cleanup changes no contract field semantics and introduces no new responsibility.
