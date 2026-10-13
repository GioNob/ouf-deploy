# Governed migration root custody component — 2026-10-13

This component creates only the absent root paths retained by host-input hash
`93fa9bc8fe4d90fe445bb310363f11966f9ed89df74d169ad925cda0a157acc4`.
It is not a full installer, runtime authority, or target execution command.
The prior design approval remains recorded; it is not reused as an execution mandate.

`migration_root_custody.py` requires the same native dual-role authority and live
HUMAN mandate as the migration, plus an explicit signed `policyTokenRootCustody`
scope. The scope binds host/source/logical owner, exact retained ancestor device
and inode identities, missing path segments, permissions and finite limits.
Only these three roots and their missing ancestors are eligible:

- `/usr/local/libexec/ouf-policy-token`
- `/etc/ouf/policy-token/credentials/semantic`
- `/var/lib/ouf/policy-token/semantic`

Every new directory is root-owned mode 0700. Existing directories are not
adopted, changed, repaired, removed or replaced. Traversal uses directory file
descriptors and rejects symlinks and changed ancestors. A persistent exclusive
fence and atomic evidence ledger bind progress to the same logical operation.

Before each mkdir, the ledger records the pending path and consumes an attempt.
After creation and parent fsync, it records the new identity. A process crash
before mkdir can resume only while the same path is still absent and authority,
boot, ancestors and budget remain valid. If the directory exists without an
identity checkpoint, its origin remains unproven: automatic adoption/replay is
blocked for explicit reconciliation. A checkpointed directory that disappears
or changes is never recreated. All final identities are checked before success.
Revocation after creation preserves the pending evidence without claiming success.

The finite scope is at most twice the number of missing directories (maximum
24 mkdir reservations), within 300 elapsed seconds from the original ledger.
The boot-bound monotonic deadline and consumed count persist across restarts;
new decisions, processes and source versions do not silently reset the ledger.
There is no automatic retry scheduler or rollback in this component. A caller
must classify transient failures under the resilience policy before retrying;
an ambiguous existing directory always requires reconciliation.

Local isolated tests use actual root directories, native signatures and forked
process crashes. Twelve tests cover creation/restart identities, unknown existing
directories, missing signed scope/revocation, both crash windows, missing
checkpointed directories, concurrent fences, symlinks/parent drift and durable
deadline expiry, retained attempt exhaustion and creation without service-retirement permission. Three isolated-memory tests pass with the expanded exact
29-module closure. Hosted qualification is recorded separately after completion.

Remaining integration: bind the resulting private custody receipt into the
credential/grant scopes, generate the complete current IAM/consumer/TLS review,
and qualify the full installer and its signing/delivery path. This component
does not stop services, rotate credentials, create a grant session, request a
token, reconcile unknown accounting, start renewal, or confer release acceptance.
No new VPS mutation was performed while developing or testing this component.
