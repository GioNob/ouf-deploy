# Generation33: real worker death after PUT, before catalog ACK

This bounded step extends the previously qualified quiesced common-cut fixture.
The first object is ACKED normally. The second has a durable PostgreSQL intent;
a distinct Python worker sends exactly one S3 PUT, records the successful
post-PUT/pre-catalog-ACK boundary in an exclusively created fsynced diagnostic
file, and kills itself with SIGKILL. Its supervisor requires signal return code
-9, empty stdout/stderr and the exact marker. Ordinary failure, timeout, missing
marker, different intent or an unexpected signal cannot qualify the crash.

The catalog must retain the original ACK and the second PENDING intent.
PostgreSQL is then restarted with pg_ctl's immediate mode, exercising abrupt
shutdown/recovery rather than a clean database restart. Full ledger snapshots
before/after must match, including control, epoch, intents and event history.
Re-reserving the identical idempotency key must return EXISTING_PENDING and
leave the ledger unchanged: it grants no second PUT. Recovery follows the
existing drain/fence, actual S3 readback and reconciliation, followed by the
quiesced common cut and independent PostgreSQL/S3 restore. The diagnostic marker
is evidence of injection timing, not permission to resolve the pending intent;
only actual S3 bytes/hash/metadata readback supports reconciliation.

The workflow runs both the original no-crash path and the crash path on the
same pinned OCI33/cohort and PostgreSQL17.11 build, in separate fresh roots.
It retains their separate evidence trees and a complete checksum manifest.
The restored PostgreSQL diagnostic call counter is now reused, preserving both
the restored ledger query and the later reservation-denial SQL output; historical
archives remain unchanged.

Local validation: 22 common-cut/crash tests, including a real child SIGKILL and
negative evidence tests; 7 existing fence and 4 logical-restore tests. Native
Docker/PostgreSQL qualification is PENDING until the original CI archive has
been read back. No target operation or real object is involved.

Scope limits: death after a completed single PUT, not an in-flight streaming or
multipart kill, lost HTTP response, host power loss or SeaweedFS component crash.
The fixture bucket is unversioned. Two exact keys and no recovery PUT demonstrate
no repeated effect in this bounded path; this is not a general exactly-once or
versioned-bucket deduplication claim. Target-wide writer fencing, coordinated
physical PITR, production RPO/RTO, custody and acceptance remain OPEN.

MiniPET stays **18.3/46 = 39.78%, approximately 40% ±10**; no extra credit.
**0/8 gates, 0/21 AT, 0/120 real objects copied.** Authority remains the storage
MiniPET, original PET/Matrix and resilience policy v3 (durable intent, no blind
resend after ambiguity, restart preserving state and finite failure handling).

## First native attempt retained; sequence validation corrected

Run 41803868175 on `7e6d80a3f003aa6c245edca39deedcb658749296` failed
before the crash-path dump/restore. The ordinary path passed. Worker SIGKILL,
immediate PostgreSQL restart, pending-intent preservation, no-resend decision,
S3 fencing and reconciliation completed. The verifier then rejected the valid
event IDs `[1,2,3,34,35,36]` because it incorrectly required `[1,2,3,4,5,6]`.

The original failed archive is retained at
`evidence/artifacts/storage-common-cut33-failed-41803868175.zip`; independent
readback verified 225 members, 224 checksums and 23 source hashes. The three
committed events survive unchanged, and all six expected payloads remain in
order. [Failed readback](../evidence/storage-crash33-failed-readback-20261104.json).

[PostgreSQL17 sequence documentation](https://www.postgresql.org/docs/17/functions-sequence.html)
explicitly permits gaps after crashes. Validation now requires six exact event
payloads and strictly increasing positive bigint identifiers. A separate exact
prefix comparison prohibits renumbering or rewriting committed history; the
final restored ledger must still equal the source ledger byte-semantically.
Three regressions cover the original failed archive, invalid/duplicate/reversed
IDs and rewriting an otherwise ordered prefix. **33 local tests total PASS**.
The failed native run remains failed; fresh qualification is required.
