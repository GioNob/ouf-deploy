## 2026-10-16 — Exact MCP claim observed; release binding required before deployment

Target readback /home/oufadmin/ouf-semantic-mcp-claim-read.zuAdwY5t/read.log proves one retained claim: attempt 9d676b80-8f5f-4160-ac9e-57f0935f78be, requestHash b8bc4ccb0f8fe48764ecf87340fd2ff209520c0b5b947a3ee6a1e461fc57a112, FAILED / ACKNOWLEDGED, lockVersion 2, reservation RECONCILED, actualToolCalls=1, reservedToolCalls=1. Database OID 21560 and role matched. No claim rearm/deletion or database mutation occurred. Owner receipt remained absent for the exact same HUMAN/key; the authorized reprocessing call returned SEMANTIC_RECEIPT_READ_REQUIRED and did not dispatch a new owner proposal.

Development source is on GioNob/ouf-mcp-server branch fix/semantic-governed-reprocessing-20261016, based on the cohort lineage f249b3dcc58c2a96742092d90fa09fd90b705bd0, not main. Existing two role signatures reuse the existing installer key and exact trust-policy/frame formats; attestor remains excluded. No new keys, runtime permit or deployment has been issued. Signed sessions preserve old history and owner command key, add at most one call (1+1=2), enforce current authorization, expiry, capacity and UNKNOWN blocking. See source branch docs/SEMANTIC_GOVERNED_REPROCESSING.md. This remains development evidence, not target readiness.

Next user action: run scripts/launch-chatbot-semantic-mcp-binding-readback-20261016.sh from this delivery. Source pinned at 2ec7baf4bbd79e22f832df892d5614116e2c964f; SHA256 08559a2bcec0b7ec29ab6adabd3253d5ae2f1d1bb18ac9d05fa1d89d2d97d01c. CI GitHub Actions run 38934302504 passed 12 reader tests; target observation is still pending. The bounded reader uses up to four Engine reads and one read-only SQL session, no credential files/grants/MCP calls/service writes. It projects exact source/image/generation, current manifest/workload/HUMAN and whether retained audit proves the expected denial; drift stops the read. It does not rearm any claim or deploy a correction.

The token owner session's original deadline remains 2026-10-16 18:47:18 Europe/Rome. No automatic renewal, restart or budget reset is authorized. Technical phases remain 8/8; functional milestones 0/6. Deployment requires exact target lineage, role/migration preflight, a pinned package and a concrete finite backup/migration/cutover review; token-only authority does not authorize it. Semantic approval remains in THS.

# Teatri semantic DRAFT reprocessing review — 2026-10-16

Status: EXPLICIT_ONE_ATTEMPT_AUTHORIZED; MCP_RETURNED_SEMANTIC_RECEIPT_READ_REQUIRED. One tool invocation returned the admission replay marker; subsequent owner receipt read404. No DRAFT creation is confirmed. Preserve original claim/key and obtain read-only target claim metadata before recovery design.

One new attempt to submit the existing ontology as DRAFT via the native semantic.propose owner contract. The prior create request was denied403; the renewed-token diagnostic now returns policy40/HTTP200 and one owner receipt read returns404 PROPOSAL_RECEIPT_NOT_FOUND. The new attempt is a deliberate operator decision after reconciliation, not an automatic retry of a permanent denial.

Exact payload: [teatri-reuse-semantic-proposal-20261014.json](teatri-reuse-semantic-proposal-20261014.json), importCommand only.

- Full review canonical SHA256 (excluding proposalHash): `be74308e098aa3a65396f3df739dd8f2837e9f8e27b6e49deb0e49d04506cb1a`.
- Import command canonical SHA256: `f7d2b21a0d80bcd1ab268288a091720a71973b2a3482a25cec0c229ec6540db4`.
- Exact Turtle SHA256: `6e4668ea42cf1c75b822e17a8ca9cb71fb2c4d8f500eed628282fa6039a6dbaa`.
- Same commandKey: `teatri-semantic-draft-be74308e098aa3a6-20261016`. Do not invent another key to bypass reconciliation.
- Same authenticated actor: ouf-admin, subject b93d8cf6-cd14-4ee6-91d7-84cd76c4f500, connector link_6aafef96b4148191b767e9af7b756a07.
- Proposed artifact: TeatriOntology, type ONTOLOGY, semantic version1.0.0. Preserve exact ownerRef/authorityRef/IRIs/labels/Turtle from the retained file; these values do not grant runtime authority.
- Rationale: describe theatre venues using schema:PerformingArtsTheater, name/additionalType and qualified source properties. No equivalence with Cinema; preserve lexical CAP, coordinate provenance/precision, seasonal scope and notes qualifying seat capacity.
- One create request, no automatic retries. On ambiguous transport result, stop mutation and read same owner receipt; on403/permanent/unknown failure, stop and diagnose.
- The owner retains enforcement and idempotency. A DRAFT receipt is not approval/publication or source activation. Validation and any trusted challenge must use actual returned revision/row version and their native guarded contracts; no assumed IDs.
- Semantic HUMAN decision remains exclusively in the authenticated THS. No direct approval, publication, source activation, ingestion, grant changes, token-session renewal or account switch is authorized by this review.
- Original CSV is not reread or changed by this DRAFT creation. File/source/onboarding/ingestion/UDP/query milestones remain unproven until separately exercised and read back.

The currently signed token-worker mandate grants only the finite token-policy operation. It is not the instruction to execute this semantic reprocessing review.
