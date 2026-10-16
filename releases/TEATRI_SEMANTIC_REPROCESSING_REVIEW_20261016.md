# Teatri semantic DRAFT reprocessing review — 2026-10-16

Status: PREPARED_AWAITING_EXPLICIT_OPERATOR_INSTRUCTION. No new semantic mutation executed.

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
