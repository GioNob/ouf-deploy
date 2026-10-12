# Retained V11 renewable authorization token — source-contract review, 12 October 2026

## Verified scope and limits

The [operator-reported source usage](../evidence/retained-v11-source-usage-target-20261012.json) identifies retained mount0 through OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE and mount1 through OUF_SEMANTIC_DELEGATION_KEY_FILE. Prior metadata diagnosis found one root0/group10001/mode0440 member replaced in the0750 directory; the standalone10001:10001/mode0400 key source is unchanged. No source credential bytes were read or private baseline changed by these diagnoses.

The EXACT original V11 source3ec99277b8383e496913b9fd3bb05c877825abf5 [ActiveBundleRefresher](https://github.com/GioNob/ouf-semantic-registry/blob/3ec99277b8383e496913b9fd3bb05c877825abf5/vendor/authorization-sdk/src/main/java/it/comune/trieste/ouf/authorization/ActiveBundleRefresher.java) executes Files.readString(tokenFile).strip() on EACH policy refresh before its bounded HTTPS GET. Thus it can consume a replaced token without restart; it does not issue or write that token. AuthorizationAutoConfiguration binds the registry-token-file property. This verifies consumer behavior, not writer identity, current JWT validity or lawful rotation.

The metadata preparer incorrectly modeled BOTH original sources as immutable historical file identities. That assumption must be corrected for the authorization token through an explicit independently approved renewable-credential contract, not by simply dropping inode/time checks or updating the old snapshot. The original key remains static until an explicit owner-governed key rotation contract exists.

## Required renewable-source contract (DESIGN ONLY; not implemented/accepted)

Preserve exact readonly directory source/target, root identity and0750/root0/group10001 custody, exact member name,0440/root0/group10001 regular-single-link custody, no symlink/subordinate mount/extra-member shadowing and bounded file handling. The credential remains private: no raw JWT, claims containing principal data, source path or low-entropy digest in public output.

An authorized installed token owner must be identified independently: service/unit, source/entrypoint custody, configuration, issuer/client/audience/scopes, installation authority and bounded renewal/failure/revocation policy. An atomic inode replacement is allowed only under that contract. The observed metadata change alone never proves it.

Use fresh, stable FD/named-path/mounted-view identity during EACH observation, with before/after generation checks and owner-authenticated current credential validity. Historical member inode/time/byte digest cannot serve as the forever identity of an expiring token. A concurrent replacement produces explicit pause/reconciliation under the finite owner policy; no automatic promotion of the new token, old activation-claim replay or budget reset.

Issuer/signature/audience/expiry/revocation enforcement must be attributed to the existing IAM/owner/Gateway controls, with no new authority or token issuer invented. The LLM, source-usage report and SDK file reread do not approve a JWT. Do not send a new token-grant request merely to diagnose the writer.

The static delegation-key source retains its exact approved custody/content binding. Full six-mount policy, independent signed acceptance, authenticated transport, retained-budget distinct worker, readiness and the real Teatri CSV/ACK/object/search chain remain pending. This review grants no runtime HUMAN/THS authority.

## Next installed-owner evidence

Read only installed service/timer NAME and STATE metadata to locate the existing credential-renewal component. This inventory prints neither ExecStart arguments nor Environment/EnvironmentFile contents and does not read token/key files or invoke service start/stop/restart. Candidate names alone are not writer proof; absence from the name filter is not proof no writer exists. Then inspect only the selected candidate's source-bound owner configuration under protected routing before implementing/admitting the renewable-source contract.

R12's lease journal uses0600/root-private custody in the inspected source; the observed0440 token is not attributed to R12. No ad hoc R12 stop or token rotation is authorized by this review.

## Installed-source evidence reconciliation

The root-controlled selected config/code observation now reports output directory/member/GID matching historical mount0, root0750/0440 publication and client/scope configured. [Receipt](../evidence/semantic-token-private-output-correspondence-target-20261012.json). Source root ancestry through /opt/ouf remains unproven, and HTTPS/client/scope presence is not approved issuer/audience/grant authority.

Legacy systemctl dict parsing discarded repeated properties. [Correction](SEMANTIC_TOKEN_PROPERTY_MULTIPLICITY_CORRECTION_20261012.md) requires explicit sole-file/single-command cardinality and all timer rows before concluding effective configuration/renewal cadence. Missing expiry is still accepted by observed code; durable finite failure budget and actual owner-enforced validity/revocation remain unproven. The renewable contract remains DESIGN ONLY with no relaxation of historical key custody or six-mount acceptance.
