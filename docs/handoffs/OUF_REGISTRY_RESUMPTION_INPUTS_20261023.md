# Registry resumption after successful JVM directory cleanup

The user-pasted target result from `/home/oufadmin/ouf-jvm-cleanup.dkFC6YI3/operator.log` confirms all six directory removals and exact equality to the unchanged independent rootfs seal. The Registry remains paused. HTTP 502 is not yet resolved; original SERVICE GET 200 and durable renewal remain unproven.

## Why the existing launcher cannot continue

- `core.validate_current`: the expired signed window is rejected; all claimed/applied effect records are bound to that old authority.
- `authorization.AuthorityScope.guard`: a new authority cannot retrospectively authorize the old journal creation time.
- `read_budget.ReadBudget`: native reads have their own authority binding and consumed counts, which must be preserved.
- `bootstrap.install`: existing recovery roots cannot be initialized again.
- `semantic_registry_postboot_owner.contract.compile_scope`: accepts previous-boot governed owner lineage and legacy fence, while the actual latest cancelled owner is the current-boot postboot session with a postboot fence and cumulative count 320.

An explicit successor protocol is required. It must preserve START and PAUSE evidence, the exact paused PID generation, all consumed grants/reads, first-grant history, and old immutable authorizations. It must serialize with both existing invocation locks and a one-use globally fenced successor claim. Imported effects must retain their original provenance rather than be labelled as newly executed. A new finite window and any new token allowance require complete fresh scoped review; no automatic renewal of the exhausted/expired scope. Fresh native application admission remains mandatory after the snapshot.

## Immediate command being prepared

`capture-registry-resumption-inputs-20261023.py` captures the exact retained checkpoint and completed cleanup receipts under the two existing protocol locks. It performs no Engine, OAuth, database, Gateway, application or rootfs-content operations. Every input is rehashed before private publication; no existing artifact is changed. The private capture stores full current session metadata and input hashes necessary to construct and review the successor. This capture does not authorize or implement successor execution.

Bounded to 96 aggregate metadata reads, 32 MiB and 30 seconds; each original Reader phase remains bounded to 20 reads/16 MiB. All6claims+receipts and exact closed maintenance file set are required. New private snapshot root0700, canonical file0400, stable identity, no replay. Five local tests exercise actual filesystem/flocks with explicit native lifecycle fixture responses; no target successor qualification claimed.

## Next implementation requirements

1. Bind reviewed successor inputs to this snapshot hash and completed maintenance result hash, preserving 320 and native DB1/Admin6/Semantic0/readAttempts5.
2. Implement explicit native journal epoch/authority handoff with signed provenance for imported prefix and unchanged effects, no START/PAUSE redispatch or journal reinitialization.
3. Implement current-boot postboot-owner successor contract/fence handoff, retaining original first grant and latest cancelled row, not fabricating previous-boot lineage.
4. Qualify concurrency, crash points before/after each durable claim, expiry, changed PID/boot/OCI, stale fences, and exactly-once native effects before runtime delivery.
5. Fresh native seal/mount/token/database admission, unpause and release only in new reviewed scope, then original SERVICE GET 200. Establish durable renewal separately; finite success alone is insufficient.

Addresses, ports, URLs, resolvers and runtime storage locations continue to come from the exact retained configuration; kernel API paths and exact evidence references are not deployment endpoint defaults. Do not replay cleanup, relax seal equality, or duplicate Kubernetes responsibilities.
