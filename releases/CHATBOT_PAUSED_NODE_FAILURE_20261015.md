# Paused Registry successor — 2026-10-15

The operator ran the pinned source0525c4186a5613000905ba4dfae6766827ad9f06,
accepted review892cc1048a526d0e4705a58ce91a9b5a3f6712796d64fb98b619d8ad397bfc8f
and received authorityfa7bdc08f0c0ea048b064774648176cf54ce51279118ce1df0ff296fc8616d3b.
It stopped with ValueError in file_only_node_owner.resolve line154, inside
PausedNodeObservation.observe. The public diagnostic excludes those deeper
modules, so it does not identify the underlying failing condition.

The exact executing source proves an ordered advance beyond the earlier
CreationDenied boundary: CREATE_REPLACEMENT was reconciled and
STAGE_PAUSED_REPLACEMENT completed before ATTEST_NEW_OCI_PEER was invoked.
That is progress after creation, beyond permissions/approval. It is not proof
of migration, application readiness, source acceptance or end-to-end delivery.
Current native state and new worker grant counters need readback.

## Qualification gap

The six CI checks were green on the exact source. Docker lifecycle tests
exercise real native operations but substitute non-Docker attestation/admission
boundaries. The signed successor test uses fixture phase adapters. No existing
check proves the full FileOnlyNodeOwner.resolve path against this VPS frame.
The read-bound fix is not invalidated by this later failure; the complete
runtime qualification remained insufficient. Do not interpret test totals as
successful target acceptance or as an estimate of remaining work.

## Next operator action

Run only scripts/read-chatbot-paused-node-20261015.py from this checkpoint.
It is pinned to the failed context, review, source, authority and container.
It requires only sudo read access; no IAM login, device authorization or terminal
APPROVO is needed. Do not rerun the delivery wrapper or reset/remove its claim.

The reader checks stopped delivery, the global reservation, worker counters,
transition phases, later ledgers, current paused Engine/runc generation, exact
retained OCI comparison, four mount metadata bindings and real link observations.
It runs the independently hash-pinned pure network compiler functions against
those observations. Known static compiler failure text is exposed only if it
is an exact string literal in the verified source; arbitrary messages and
policy values are suppressed. Selected functions confer no acceptance.

No installer, grant, IAM/DB call, token or credential read, signature, service
mutation, journal initialization or file write is invoked. Rootfs sealing and
private frame-content hashing are not rerun. PASS for the selected network
probe does not prove complete attestation. The complete current native trace
may still be unavailable; do not invent a root cause if this probe passes.

Seven local tests passed with zero skips: actual frozen pure compiler pass,
static ValueError privacy, source tamper, changing native links, arbitrary error
privacy, real bounded private-file/symlink/hardlink custody, safe ledger projection.
The target reader has not been executed from this workspace. No new runtime
continuation is supplied until the retained effects and new worker accounting
have been reconciled without resetting history or replaying consumed operations.

## Operator readback and corrected reader

The first readback (operator output at18:29 Europe/Rome) confirms transition
v13, nextPhase6: first6 phases APPLIED, ATTEST_NEW_OCI_PEER IN_FLIGHT. The
new worker is CANCELLED with1 attempt and1 publication; cumulative attempts2.
Admission is BLOCKEDv3. The Registry is running/paused, PID3484588, restart0.
The retained expected OCI differs from the current OCI; no issuance claim exists.
The actual pure native network policy check passes. These are target facts,
not merely consequences inferred from test execution.

The reader failed twice due to its own output emitter: mount readOnly collided
with the readOnly protocol flag, then END budgetReset collided with the protocol
flag. Both TypeErrors are locally reproduced. The mount field is now named
mountReadOnly; the redundant END field is removed and reserved fields are
explicitly guarded. Safe code locations accompany unknown reader errors.

The corrected reader adds the source-hash-verified original full-OCI predicate
and a bounded structural diff. Only static OCI field names, list indexes,
types and lengths are returned; dynamic map keys and private values/hashes
are suppressed. Approved public mount-option enums and boolean hardening flags
may be shown. It does not copy current OCI into expected policy or authorize it.
Network PASS does not repair the OCI mismatch. No runtime patch is yet proposed.

Eleven local tests now pass, zero skips. Two run the entire main entrypoint
through END against actual sealed disposable records and source/view inodes,
with native command/process observations explicitly simulated: both equal and
unequal OCI cases complete with4 mount metadata rows. The unequal case reports
PAUSED_NODE_FULL_OCI_DRIFT with redacted locations. This closes the emitter
coverage gap; it is not a native VPS/Docker acceptance test.

Use the replacement reader at this checkpoint. It needs only sudo and performs
no grant, IAM/DB or lifecycle operation. The new target output is needed to
identify the actual differing OCI fields before constructing a recovery plan.
See evidence/chatbot-paused-node-partial-readback-20261015.json. The cumulative
2 grant attempts, old journals, claims and paused generation must be retained.
