## 2026-10-16 — Actual role preflight and private update candidate preparation

User target log /home/oufadmin/ouf-semantic-mcp-reprocessing-preflight-read.YZ0cQW57/read.log confirms the exact old generation and all 12 source checksums. The application has schema CREATE, migration INSERT, REFERENCES and immutable trigger EXECUTE, but has neither SET nor inherited access to ouf_mcp_retention_owner. The retention role owns the existing function, has NOLOGIN, no superuser and zero memberships. Function definition hash is pinned in evidence/chatbot-semantic-mcp-role-target-20261016.json. These are observations, not authorization to grant membership.

The proposed least-privilege sequence must hold MCP stopped while a single temporary membership permits the native packaged migration 13, then prove the original zero-membership state before application start. No permanent superuser/CREATEROLE/owner change is proposed. The previous claim and all cumulative history remain unchanged.

Private preparation source e055287fbe1842512434f7a3b553f52fc962ceb2 passed CI run 38936636346: 19 reader tests, 5 preparation tests against the actual candidate archive (both tagless archive profiles), and actual native image import on the ephemeral overlay2 runner. This run does not prove native containerd import. The same ref passed a separate native PostgreSQL preflight workflow after making observation reusable without public emission of its private context.

Next user action: the separately pinned launch-chatbot-semantic-mcp-update-review-20261016.sh downloads artifact 12059844351, checks ZIP/source hashes, creates a new root-private candidate, verifies current role/claim/runtime bindings, copies only approved MCP configuration into its private review and derives the tagless archive for the observed Engine store. It performs no image import, lifecycle action, DB write, grant, token call, signature or runtime authority issuance. It stops on changed generation/roles/history. At most 180 seconds, five Engine reads and one read-only SQL session. The root result is not ready for execution: pending executor qualification, current authenticated exact review, fresh owner receipt absence, separate finite reprocessing consent, existing role signatures, final runtime profile/metadata mounts and current authorization/owner policy remain explicit. No approval is requested by the preparer.

# MCP semantic reprocessing: target binding and unsigned package

Status: technical 8/8, functional 0/6. No proposal, semantic approval, release acceptance, runtime permit, migration or cutover is performed by this preparation.

## Proven target

Readback /home/oufadmin/ouf-semantic-mcp-binding-read.wkknNUge/read.log confirms source f249b3dcc58c2a96742092d90fa09fd90b705bd0, reviewed image and stable native generation. Exact retained HUMAN claim is FAILED/ACKNOWLEDGED, lock version 2, one reconciled owner call, expected semantic capability denial proven by retained audit, workload ouf-chatgpt and current manifest pinned in evidence/chatbot-semantic-mcp-binding-target-20261016.json. The original claim is not rearmed or deleted.

## Qualified unsigned delivery

Source PR: https://github.com/GioNob/ouf-mcp-server/pull/70 (draft, target cohort lineage, not main). Exact package source 1cbc496e1632ec3b1f2f0d9bf1e1f59a308278ef. Package run https://github.com/GioNob/ouf-deploy/actions/runs/38934847558 and artifact 12059844351. It contains one MCP Docker-save image, extracted binary, source archive/inventory, pinned base-image resolution, image-bound vulnerability scan and SHA256SUMS. Native and independent local checks confirm unchanged migrations 1..12 plus migration 13, no HIGH/CRITICAL/UNKNOWN vulnerability including unfixed, non-root 10005:10005 image. This is an unsigned candidate and does not authorize target import. Exact hashes in evidence/chatbot-semantic-mcp-reprocessing-package-20261016.json.

## Next bounded preflight

Use the separately pinned migration-role reader. It verifies this exact MCP generation, old migration checksums and a single read-only SQL session; role capabilities and function definition hash are metadata only. It does not grant roles, run SQL migrations, read private keys/tokens or call MCP. A missing privilege is evidence for the concrete proposed least-privilege plan; it must not trigger an automatic grant. Synthetic PostgreSQL qualification and target observation are separate.

## Remaining installation work

After actual role facts: prepare a fresh one-component MCP backup and signed finite import/migration/cutover review. Preserve existing network/storage/identity/deployment binding from approved configuration, use packaged native migration code and verify temporary role cleanup before application start. Do not replay previous four-component delivery or restore historical snapshots over live writes. Migration outcome ambiguity requires reading the existing migration history before continuation.

Runtime reprocessing permit is a separate finite infrastructure decision: use existing authorized installer key and distinct DEPLOYMENT_INTENT/FINAL_DEPLOYMENT_APPROVAL role signatures in the existing wire format. Do not involve creation attestor or invent keys. Bind exact HUMAN/tenant/workload/current manifest/original key/hash/predecessor version/reason and a fresh receipt-absence read, one extra call and cumulative two. Current authorization and current owner policy still gate the call. Lost response preserves UNKNOWN and consumes the one-use session; only owner reconciliation may establish the result. HUMAN semantic approval remains in THS.

The token worker authority deadline 18:47:18 Europe/Rome has elapsed. User reports expiration; terminal final receipt/cumulative publication count is not yet observed. No automatic renewal/restart, budget reset or inference of current token expiry is allowed. Technical/functional results above survive that deadline; future token sessions require exact finite review retaining history.
