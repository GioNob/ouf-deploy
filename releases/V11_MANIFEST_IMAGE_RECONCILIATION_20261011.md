# V11 image import: exact native manifest reconciliation — 11 October 2026

> **Target step completed:** the operator confirmed VERIFIED/version2 at22:04 Europe/Rome, cumulative import attempt1 and zero new imports. [Target receipt](../evidence/v11-manifest-reconciliation-target-20261011.json). No repeat of this operation is needed. Continue with [new native V11 private plan](NATIVE_V11_PLAN_20261011.md).

The operator attempted the tagless import once and received IMPORT_ABSENCE_DOES_NOT_PROVE_NO_EFFECT. Preserve that consumed journal; do not rerun the old import launcher, reset/remove the journal or repeat Docker load. [Operator receipt](../evidence/v11-image-import-target-ambiguous-20261011.json).

## Cause and target evidence

Read-only VPS jobs [38169014372](https://github.com/GioNob/ouf-deploy/actions/runs/38169014372) and [38169090706](https://github.com/GioNob/ouf-deploy/actions/runs/38169090706) prove Docker29.8.1/API1.56. CLI, API1.44 and API1.56 cannot resolve the original config digest. A tagless native image exists with the same source, ten layer diff IDs and execution-config projection. API1.56 identifies it by its schema2 manifest descriptor. [Safe target reads](../evidence/v11-image-manifest-target-read-20261011.json).

| Identity | Exact digest |
|---|---|
| Original authenticated config digest | sha256:83635be46d1fe61dea08597ea4488980b4349e5f6e0ed8bbd3ab6f5e2686370e |
| Derived native schema2 manifest,1845 bytes | sha256:bd48ab35db0441b1f4f48422e7190adaff176a61cddde5f981d93e496ad4b24a |
| Original ZIP | b6ae1051cee4ec9fb1b28f532622ecd39e038ec2e6a384d50565cbf92f2a0def |
| Original Docker archive | e0e51617f847494f3bf8a746277da02761aeb81b37d1483ec26dc8e4e35fbd00 |
| Derived tagless archive | 52baabdfd39189c598a9ded3aeec08367d20ae2fccbf14330481c98f1ad7783f |

The old root reader assumed config digest equals native Engine ID. That assumption worked with the tested classic image store and failed with the VPS manifest store. The stdin transport itself is qualified by the exact root-style anonymous file, empty CLI config and explicit local Docker host. Hosted qualification38169276055 derives the exact1845-byte native manifest from the original signed config and every authenticated archive layer; it matches the VPS descriptor. No source label alone is accepted as byte proof.

The derivation follows [containerd archive importer](https://github.com/containerd/containerd/blob/v2.2.0/core/images/archive/importer.go): schema2 config/layer descriptors and their original verified blob sizes/digests. It does not accept changed/compressed substitute blobs or arbitrary same-source images. Native RootFS and all execution fields remain exact requirements.

## Completed implementation and scope

[Reconciler](../scripts/reconcile-v11-manifest-image.py), source7e81b2db2c83f0297f3199a7bd1e1127a44d9df4, SHA256628dd79524e45f9d2ed19a38fcc119303be31ff8b0bafc373100cd9bf90c1859. [Launcher](reconcile-v11-manifest-image-20261011.sh), source213fc71cb5d6f94feacf67c03540611b1a454b23, SHA25647ee7478dff556ff39515cd7b5e7dabb6b2aa6a2a67e95daedd1aa2e9d22db91.

All eight immutable source files are checked before sudo and rechecked before any root execution. All eight original publisher subjects are freshly verified. The isolated root entry revalidates original declaration/request/config/command/socket custody and original ZIP/layer bytes. It reconstructs the ORIGINAL import context, requires the existing journal and an already consumed single attempt, acquires its invocation fence and compares two full native API1.56 reads against the byte-derived manifest descriptor, exact platform/config/rootfs and zero tags. Only then may one expected-version CAS move IN_FLIGHT1 to VERIFIED2. Original intent, authority binding, context and attempt count are retained. VERIFIED2 requires the same native evidence and performs no second journal write.

The entry contains no image-load callback, journal initialization, application/container/DB/provider/firewall/R12 effect or new budget. It records both configImageId and nativeEngineImageId explicitly. Old HUMAN approval is read solely to recover command custody, never to confer a new application transition grant. A missing/changed native image, descriptor, private plan, config or journal remains blocked without replay.

Native [qualification38169559656](https://github.com/GioNob/ouf-deploy/actions/runs/38169559656) passed for the classic store and a separate actual containerd snapshotter daemon on hosted runners. Each fixture verifies eight publisher subjects and all original byte hashes, performs one tagless import, actually exits the child after the effect, reopens the fsynced journal and reconciles without another import. The containerd case reproduces the config-ID absence and exact manifest identity. Fixture authority checkpoints are synthetic; target root journal/entry acceptance is pending the operator receipt. No target root execution is implied by these hosted tests.

## Operator operation completed

The exact existing-import reconciliation was executed successfully. Its immutable launcher remains retained in GitHub; the active operator command is now [native V11 private plan preparation](NATIVE_V11_PLAN_20261011.md). Image custody is established; application/transport/full OCI/CSV acceptance remain OPEN.

## Final delivery qualification

[CI38169611271](https://github.com/GioNob/ouf-deploy/actions/runs/38169611271), classic job114559269863 and containerd job114559269727 both SUCCESS:41 tests on each job and the actual archive/publisher/native import/process-death/reconciliation proof. Tests deny all16 download/tamper positions, all8 publisher failures, all8 root bootstrap tamper positions and all7 sealed-module tamper positions before execution; they cover consumed-intent preservation, READY rejection, stable reads, drift/absence/revocation and repeated verification without another write. All eight immutable remote sources and launcher bytes were independently compared to hash-qualified local files. [Qualification projection](../evidence/v11-manifest-reconciliation-qualified-20261011.json).
