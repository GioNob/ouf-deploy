# V11 offline image custody and import reconciliation — historical qualification

> **Superseded current action:** the target import was attempted once and the classic config-ID assumption failed on the native manifest store. Do not repeat this import operation or reset its journal. [Current exact manifest reconciliation](V11_MANIFEST_IMAGE_RECONCILIATION_20261011.md) supersedes the operator command below; original source and historical qualification evidence remain retained.

The private V11 plan is already prepared. This step addresses exact image byte custody; it does not apply that creation request, migrate data, create/start/stop a container, change R12, install transport, issue signatures or grant application/domain permissions.

## Qualified concrete behavior

[Byte custody CI38167052718](https://github.com/GioNob/ouf-deploy/actions/runs/38167052718) verifies all eight original publisher subjects, the original ZIP/member hashes, image config identity, source label/platform and every actual rootfs layer byte; actual hosted Engine inspection matches the expected configuration and ten layer diff IDs.

[Crash reconciliation CI38167316672](https://github.com/GioNob/ouf-deploy/actions/runs/38167316672) actually terminates the importing process after its Docker effect. The fsynced owner journal remains IN_FLIGHT; a newly opened Journal verifies two stable native image reads and moves to VERIFIED without another load. A missing image after an ambiguous attempt is not proof of no effect and does not permit replay. Concurrent invocation, changed authority, wrong identity/config/layers and timeout paths are denied or remain ambiguous. The authentication checkpoints of the hosted fixture are synthetic; they do not grant target execution or application authority.

The original archive contains one repository tag. [Tagless CI38167487486](https://github.com/GioNob/ouf-deploy/actions/runs/38167487486) re-envelopes only the exact authenticated config and layer bytes with RepoTags=null and no unrelated repository/index descriptors. It reaudits the derived archive, imports it into actual hosted Docker and repeats actual process-death/reconciliation. No image rebuild or new publisher signature occurs; original signatures continue to authenticate the original source bytes, while the source-bound transformation and derived hash are explicit. Tagless envelope contains zero repository tags and matches the same expected image ID, native configuration projection and ten rootfs layers.

| Binding | SHA256 |
|---|---|
| Original signed ZIP | b6ae1051cee4ec9fb1b28f532622ecd39e038ec2e6a384d50565cbf92f2a0def |
| Original image archive | e0e51617f847494f3bf8a746277da02761aeb81b37d1483ec26dc8e4e35fbd00 |
| Qualified derived tagless archive | 52baabdfd39189c598a9ded3aeec08367d20ae2fccbf14330481c98f1ad7783f |
| Original config image digest (classic Engine ID) | 83635be46d1fe61dea08597ea4488980b4349e5f6e0ed8bbd3ab6f5e2686370e |
| Native execution-config projection | 52d4e0beabafa92afc603a5cd1fc9e226a367b5d0cc139db1fb27bb75880cd6b |
| Native rootfs projection | 11ef2e90fcd021cdcd0a06bf3ab5b0fb3d645b8f575d71affef3f5fb1960d775 |

## Operator delivery: exact image only

[Root entry](../scripts/import-verified-v11-image.py), source commit `cbee055c1d6c8cf115a21246f88eb104c0b74629`, SHA256 `34e96bdd52bca79f25a4ef75d34b667f0f6693c5607e4a9b9551769dcaf4d3ed`.
[Launcher](verified-v11-image-import-20261011.sh), commit `3f1854d903a2542f4f119a9e473371de4eff26c0`, SHA256 `cf45c48d768dbad6b7aae00ed6c54b2f63047424bb6a527dda70e4bb3c8c4bc7`.

The shell checks all six immutable sources and freshly verifies all eight existing publisher subjects before sudo; isolated root rechecks all source hashes before execution. It requires the exact root-owned V11 declaration/request hashes, a retained hash-bound Docker executable and a root-owned bound local Engine socket. The old approval file is used solely to recover existing executable metadata; it is not new runtime authority.

The root image-only invocation copies the original ZIP into an anonymous bounded file, verifies original ZIP/archive digests and all layer bytes, derives/reaudits the exact qualified tagless envelope, and retains a 10GiB disk control reserve. The loaded Engine image must match ID/platform/config and all rootfs layers. No repository tag is assigned or overwritten.

A distinct private journal is stored at `/etc/ouf/deploy-snapshots/semantic-v11-image-import-ffc02da66a08`. It binds the current private declaration/request, original and derived archive hashes, and the complete source closure to an operator-root offline-image-only invocation. This hash binds the scope; it is not a HUMAN/THS domain approval or an application transition signature. Short CAS transactions surround durable intent/evidence; a separate invocation fence excludes concurrent launches. No common lease lock is taken or wait/retry loop installed. Partial initialization is not automatically reset. IN_FLIGHT is reconciled, never resubmitted; VERIFIED is freshly checked, never reimported. Missing/mismatched native evidence remains blocked.

This operation may import one exact image and creates a new private import journal. All container/DB/firewall/R12/provider/signature effects remain zero. It creates no application transition claim and grants no complete container OCI, peer or transport closure. Root/image file custody on the target remains pending until the operator receipt; hosted Engine success is not target proof.

Local28 tests cover archive/config/layer checks, raw/gzip bytes, bounded copies/metadata, tagless transformation, actual local process death and fsynced journal restart, concurrency/ambiguity/revocation paths, all five sealed module hash failures, all12 download/tamper positions, all6 root-bootstrap tamper positions, all8 signature-failure positions, retained portable gh and exact failure propagation. Root plan tests and authentication callbacks are fixtures; the complete target root entry has not yet executed. Hosted final delivery qualification is linked below after completion.

## Historical operator action retired

The original import launcher was executed once on the target and reported an ambiguous outcome. Its original immutable source remains retained. Use only the [current existing-import reconciliation](V11_MANIFEST_IMAGE_RECONCILIATION_20261011.md); the old import command has been removed from this active document. This preserves the consumed operation and avoids an incorrect second import.

## Final qualification completed

[CI38168097869](https://github.com/GioNob/ouf-deploy/actions/runs/38168097869), job114554772062 SUCCESS:28 tests and the exact signed V11 archive/tagless image/Docker process-death/reopened-journal proof. [Qualification projection](../evidence/v11-offline-image-import-qualified-20261011.json). All six immutable remote source files and the launcher digest were independently checked through the GitHub connector. The operator command above is the concrete next image-only action; no target execution or CSV end-to-end acceptance is inferred.
