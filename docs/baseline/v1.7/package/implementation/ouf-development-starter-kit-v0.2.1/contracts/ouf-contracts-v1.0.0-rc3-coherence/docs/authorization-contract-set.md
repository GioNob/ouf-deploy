# OUF Authorization Common Contracts + Consistency Check — v0.7

## Result

**PASS**

Materialized contracts: **9**  
Cross-contract invariants: **18**

## Contracts

- PrincipalContext
- ResourceContext
- CapabilityDescriptor
- PolicyGrant
- OrganizationScope
- AssuranceRequirement
- AuthorizationPolicyBundle
- AuthorizationDecision
- PolicyEvaluationEvidence

## Checked invariants

The check verifies actor separation, HUMAN_REQUIRED enforcement, default deny, deny-overrides,
stable capability identity, immutable single-request policy snapshot, policyVersion/contentHash consistency,
decision/evidence consistency and the separation between authorization and downstream domain/runtime guards.

Negative fixtures deliberately test:
- SERVICE_IDENTITY attempting a human-required capability;
- unknown capability incorrectly returning ALLOW;
- decision built with a different policyVersion than the active snapshot;
- ALLOW returned when an applicable explicit DENY exists.

## External gates deliberately not resolved

- M2M scenario A/B/C;
- actual issuer/JWKS/audience;
- real IAM claim names and role/org identifiers;
- service identity provisioning/rotation lifecycle.

These remain platform integration decisions and do not change the logical Authorization contracts.
