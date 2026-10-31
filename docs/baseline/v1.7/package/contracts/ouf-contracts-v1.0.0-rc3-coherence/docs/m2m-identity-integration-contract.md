# OUF M2M Identity Integration Contract — scenario-neutral

## Result

**PASS**

The contract deliberately does **not** select IAM scenario A, B or C.

It freezes only what application modules are allowed to depend on:
- trusted issuer/JWKS/audience bindings;
- signed-token validation;
- provider-specific claim mapping into normalized `PrincipalContext`;
- actor type derivation from validated identity context;
- technical service-identity policy;
- explicit exclusion of credential material.

Two materially different mock IAM profiles validate against the same contract and normalize to the same provider-neutral principal semantics.

## External gate retained

The following remain unresolved external integration decisions:
issuer ownership, actual issuer/JWKS URLs, actual claim names, client provisioning,
secret/certificate rotation, realm/perimeter topology and scenario A/B/C.

No application code may branch on A/B/C.
