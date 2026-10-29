# OUF — historical Registry predicate STOP

The owner supplied one receipt from `/home/oufadmin/ouf-semantic-transport.UIPPICGG/operator.log`:
`STOP_RECONCILE`, reason `HISTORICAL_REGISTRY_NOT_RUNNING`, readOnlytrue,
runtimeEffectsDispatched0, activationResubmittedfalse, automaticReplayAllowedfalse.
No target execution timestamp/duration or precise lifecycle metadata was supplied.

## Preserved state and meaning

The source and case are pinned at4a6a7befd33345a92798abacb9f43db7b15c62f1.
The completed12-stage patch context and historical RegistryID remain those in that case.
The stopped reader's combined identity/running/unpaused/not-restarting predicate failed
after two exact inspect calls in its source sequence and before the log call; that call
count is source-derived, not an independently reported target counter. Gateway generation
passed its initial check only. Neither same-line correlation nor the Registry's current
service identity/address nor root cause has been established. Do not reinterpret a stopped
container's released allocation as a live endpoint, rerun old readers or use a name fallback.

Retained status: infrastructure patch12/12; technical8/8; functional4/6; G3OPEN;
native profile publication and release acceptance unproven. OAuth304/304 exhausted.
Previous source activation attempts and24hour deadline remain historical observations,
not authority to retry now. All claims, private contexts, caches and logs stay intact.

## One new read-only observation

`tools/semantic_stopped_registry_observation` is a separate diagnostic. It observes
the exact historical container's lifecycle metadata even if stopped, and independently
checks whether the semantic GET and NO_ROUTE_TO_HOST occur on the same Gateway log line
in the already-selected13:12–13:15Z window (15:12–15:15 Europe/Rome,22October2026).

Five GET maximum,35second deadline,2MiB/reply,tail4000/followfalse. Both process/lifecycle,
configuration and network snapshots and retained review/journal must remain unchanged.
404/drift produces STOP. No substitute/discovery/list/probe, raw log/error/IP/URL output,
route-admin call, credential read, OAuth/provider/DB call, write or service mutation.
Successful completion is `BOUNDED_HISTORICAL_OBSERVATION_ONLY`; it is not reconciliation
of a mutation, root-cause proof, a current route map or permission for runtime changes.
Any current service/route binding remains a separate required reconciliation.

The versioned case is the installation binding. Fetch only the reader and case from the
new published commit through the existing authenticated portable GitHub client, verify
both SHA256 pins, then run exactly once with `sudo python3 -I -B -S`. Preserve the new
directory/operator.log and paste its public JSON. Do not rerun after STOP or trigger the
source activation. A pinned concrete command is delivered alongside the commit.

## Qualification and limits

Python3.12.14:13new tests PASS,0skips;5unchanged predecessor regressions PASS,0skips.
The new full-path fixture covers five reads for stopped and running metadata, lifecycle/
configuration/network/context drift, same-line/exact-path matching, timestamp/window and
nanoseconds, closed GET paths/budget, frames, duplicates, private-file custody and redaction.
The actual stdlib HTTP client/parser receives a simulated byte-stream404 and makes no
fallback. Socket path/inode/mode validation is fixture-covered. This sandbox rejects real
AF_UNIX socket creation with PermissionError; there is no native Docker/host/Unix-network
qualification or execution of this new reader on the target. No CI claim is made.

Normative references reread: original Matrix1.7 §§1,4,6; Gateway PET1.5 T33.7/§34;
Mini-PET1.1 §§12–14; resiliencev3. No PET archive/full text is published. No owner boundary,
contract, migration, grant or HUMAN/THS decision is changed. No source activation or fresh
authentication is requested by this diagnostic.
