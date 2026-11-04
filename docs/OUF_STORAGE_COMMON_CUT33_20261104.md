# Generation33: quiesced PostgreSQL/S3 common recovery cut

This step qualifies a disposable fixture against the exact generation33 image and
cohort. It does not operate on MinIO, the VPS, OUF writers or real objects.

The fixture durably reserves two intents in PostgreSQL 17.11 before issuing their
S3 PUTs. One is ACKED; the second simulates an interrupted publication after the
external effect. A compare-and-set transition to DRAINING rejects late claims
and publication, and the unresolved intent prevents FROZEN.

All four original SeaweedFS processes are stopped cleanly. The only S3 identity
is restarted with Read/List permissions, without Admin/Write. New PUT, overwrite
and DELETE must return HTTP 403 with AccessDenied; LIST, complete GET bodies,
HEAD, MIME, hashes and generation metadata must remain correct. This is a
stop/restart fence of one fixture identity, not an online target-wide fence.

The ambiguous body is reconciled from actual S3 readback without resending PUT.
Only then may the ledger become FROZEN. While S3 is stopped and the catalog is
frozen, a custom PostgreSQL dump and a cold copy of all storage roles plus config
are bound in one manifest. The original PostgreSQL cluster is stopped and the
original storage directory withheld. Restoration uses a distinct, initially
empty PostgreSQL cluster and independent storage roots. Original ACKs, events,
control epoch/version, object bodies and metadata must match. Both restored
interfaces must still deny late writes. Schema-only fixture roles/grants are
installed explicitly; no production IAM or complete cluster-backup claim.

Local validation: 11 common-cut tests, 7 existing fence tests and 4 existing
logical-restore tests PASS (22 total). Negative cases cover pending intents,
rewritten ACK/history, stale epochs, incomplete/duplicate/extra LIST results,
same-length corrupt bodies, changed metadata and a non-AccessDenied response.
The original cohort archive is independently rebound by an offline test.
Workflow YAML parses and every shell block passes bash -n.

Native qualification is PENDING until the dedicated Actions run and original
artifact are read back. Its workflow pins the producer/cohort hashes, verifies
the cohort publisher, builds pinned PostgreSQL, retains failures and checksums,
and attests successful evidence. A local PASS is not a native restore result.

MiniPET remains **18.3/46 = 39.78%, approximately 40% ±10**; no extra credit.
**0/8 gates, 0/21 acceptance tests, 0/120 real objects copied.** Physical PITR at
a common cut, crash/reboot, representative RPO/RTO, durable custody, complete
maintenance/licence review, all target writer bindings and lateral isolation
remain open. Existing PITR/TLS and generation32 evidence remains historical and
unchanged. No target authority, replay, reset, grant, merge or deployment.

Authority: MiniPET sections 6–8, Matrix1.7 sections 1/4/5, UDP1.3 sections
109.4–109.5 and resilience policy v3 rules 4–7/15: durable intents, no blind
resend after ambiguity, short database transactions, explicit generations and
separation of fixture proof from acceptance.
