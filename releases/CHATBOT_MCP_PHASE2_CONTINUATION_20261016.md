# Phase 2: continue the existing MCP migration container

**Consumed on target:** the approved execution passed MCP migrations/cleanup, UDP and Onboarding in the execution flow, then paused at Gateway publication with `GATEWAY_WRITE_OUTCOME_UNPROVEN_NO_REPLAY`. Do not rerun this launcher. Follow the current [roadmap](../docs/CHATBOT_CSV_ROADMAP.md) and phase-5 readback. The remainder is historical release documentation.

## Target boundary and roadmap

The 16 October target readback proves technical phase 1 complete. All four
archives are COMPLETE, hash-verified and retained. MCP is 250874 bytes with
SHA-256 `b050f7706b650199a09115e24828858de509179f26896c92072cab6ae9946dc4`.
No new database dump is permitted by this continuation. Copying and verifying
these same archives does not repeat phase 1. Follow
[the stable roadmap](../docs/CHATBOT_CSV_ROADMAP.md): target phase **2/8 paused**,
functional milestones **0/6**. Phase 2 closes only after target migration and
privilege-cleanup evidence, not publication or CI success.

The retained migration container is
`e502ee4e5ebd13ca6cbc8857756d895668a06bd9ca4a44a0b27ed1b0232a12c6`,
created and never started. The database still has exactly the nine original
migrations. The audit role was bootstrapped; its temporary SET membership,
CREATE schema and TRIGGER grant remain present at the target readback. Table
OID, owner and pre-existing ACL match. Six cumulative grants and ten completed
Registry effects are retained. Later cohort journals have zero effects.

## Correction and bounded continuation

The failed check compared Docker Env and Labels to the request alone. Docker
adds image defaults. The replacement checks the exact merge of the verified
original image defaults and original request, rejects duplicate environment
names and unexplained additions, and preserves image, command, user, mounts,
network and host restrictions. The full configuration is bound in the review.
The Docker null-to-false OomKillDisable representation is the only explicitly
normalized host field; other changes remain blocks.

A fresh complete HUMAN review binds the changed source and one new finite
worker session. It does not reuse old authority or erase six prior grants:
the next new grant is the seventh cumulative. Maximum 128 attempts and 3600
seconds apply to the new session, within the overall 3600-second action;
there is no automatic renewal. The original first grant is not repeated.

Before review and before execution, fresh readback checks the exact retained
files, stopped predecessor process, cancelled worker, Registry generation,
created migration container and database baseline. The new database journal
copies four existing archives and the original migration/audit checkpoints.
It neither dumps databases nor creates another migration container nor
bootstraps the audit role again. A persistent one-start claim is saved before
starting the exact existing container; ambiguous results cannot replay start.
The owner then verifies all twelve packaged migrations and revokes/verifies
the temporary privileges, preserving the incident table's existing owner and
ACL. The original history remains unchanged. Subsequent phases 3–8 are covered
by the complete review, including their existing admission and verification
requirements. No Registry start, signal, attestation or completed effect is
replayed; no database restore is permitted.

## Qualification

Runtime source: `70af66b26d9a8dfdd7151c55f44eb5795fcc84a8`.
Native qualification source: `9306c6bb5bc81016e596f6cf8d0e461d8b3b583d`;
the only difference is disposable CI database fixture setup, outside the
runtime capsule.

[Native run 38839051380](https://github.com/GioNob/ouf-deploy/actions/runs/38839051380)
passed on Docker 29.8.1/containerd and PostgreSQL 17 using the exact original
MCP artifact. Its original binary applied migrations 10–12 to a nine-migration
fixture with a database user lacking SUPERUSER and CREATEROLE. Exit code was 0,
all twelve checksums matched, the two audit functions had the expected owner,
and cleanup left membership 0, schema CREATE false and temporary TRIGGER 0,
with original table owner/OID/ACL preserved. It used one fixture create and
one start; target continuation uses zero creates. Artifact `12020760097` has
SHA-256 `456355b91f07df256c0efa73698a5722b9916e1ed6c3226201f1a6003be624e5`.
The native fixture drives Docker and SQL directly; it does not claim signed
aggregate end-to-end execution or target acceptance.

The initial native run failed while building historical migrations 1–9,
which themselves require role creation. The corrected fixture grants its
setup user administration only for that historical setup, then explicitly
removes SUPERUSER and CREATEROLE before testing the three pending migrations.
This is solely disposable CI setup, not a change to target application roles.

Thirteen local tests pass for strict image identity, signed archive adoption,
no duplicate start after ambiguity, exact retained Registry effects,
revocation and the production migrate/cleanup/reconcile path with synthetic
native effects. Twelve of these are in the runtime-source full CI; the added
thirteenth exercises the production migration owner twice and confirms one
start and CLEAN checkpoint. The separate actual Docker/PostgreSQL test above
covers real packaged SQL and privilege behavior.

[Backup run 38838880431](https://github.com/GioNob/ouf-deploy/actions/runs/38838880431)
passed 79 tests across seven suites on the exact runtime source. Overlapping
suites must not be counted twice when reporting total coverage.

[Full delivery run 38838880289](https://github.com/GioNob/ouf-deploy/actions/runs/38838880289)
passed **435 tests across 58 suites**, with zero failures, errors or skips,
on the exact runtime source. This includes the actual seventh TLS grant with
six predecessors retained, mounted admission, complete v6 review compilation,
revocation before grant, duplicate installation denial, signed migration
continuation, native service fencing, real four-database archives and
owner-observed commit/NOOP checks. Qualification details and limits are in
`evidence/chatbot-mcp-phase2-continuation-qualification-20261016.json`.

## Pinned delivery

Preparation capsule SHA-256:
`f7682c9433bfa6aa90d348f58e7e428a868be78171b209efef47fc85cae57182`.
Delivery script SHA-256:
`37701cf02614616052cce699280c055d826a0064342f2af064c63a0ca872fe94`.
Launcher `scripts/launch-chatbot-mcp-phase2-continuation-20261016.sh` SHA-256:
`2c48df480b21a252e49aae268450a3cf301b662a0ae823fcfdcbb3a11409365c`.

Use this new launcher once, after its release commit and hash are verified.
It checks the retained portable GitHub client before sudo, reuses the original
package, prepares a private new source capsule and performs current readback.
The complete private review precedes `APPROVO <review-hash>`.
AGENTS.md and resilience policy v3 require that fresh exact HUMAN decision
for changed source and a new finite session; development authorization does
not supply it. Preserve the complete log on any stop. Do not relaunch the
consumed previous running-backup launcher.

No CI run contacts the VPS or issues target runtime authority. The finite
review and successful technical execution alone would not prove the six CSV
functional milestones or permanent runtime acceptance.
