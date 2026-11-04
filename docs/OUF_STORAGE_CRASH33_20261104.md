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

Local validation: 19 common-cut/crash tests, including a real child SIGKILL and
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
