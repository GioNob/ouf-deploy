# Generation32 image pipeline

This pipeline qualifies the combined source32 candidate after the exact frozen31-patch prefix. It does not promote the candidate or inherit image, vulnerability, licence/cohort or runtime outcomes from generation31.

Source32 is independently retained in `evidence/seaweedfs-source32-integrated-local-20261103.json`. The new patch is `patches/seaweedfs/4.52-maintained-profiles-mongodb-v2-generation32.patch` with SHA256 `f1b2fa148663e8206415d957954241d37f66294ef1fd9aa8a7c217ec20b18bf9`. Exact source tree: `d58d388bd4b791ffbc41814cc670af44af20f47c`. Exact binary SHA256: `33c54c173912884a5e38779d0bdbfd7cbce3a3955b8aa4434535bba99bcf7511`. The actual CGO-disabled closure contains1,533 packages and215 dependency modules; versions and checksum inventory are pinned by the new build manifest.

The new enginev3 preserves immutable enginesv1/v2, runtime_image and readbackv1. Producer and independent readback32 require the exact manifest, source set, patch prefix, build settings, root/nested locks, compiled package graph, binary module rows, raw Trivy0.70.0 inventory and complete SPDX inventory. Fresh HIGH, CRITICAL or UNKNOWN findings prevent qualification. No older VEX or applicability dispositions are transferred. All action/tool pins are retained explicitly; publisher attestation verification and independent byte readback remain separate checks.

## Observed and required tests

| Profile | Actual local outcome | Hosted requirement |
| --- | --- | --- |
| Main,50 packages |6,656 test/subtest PASS,12 skip;41 packages PASS,9 without tests|Same exact terminal identities/outcomes; Azure and integration skips remain explicit limitations|
| Complete server |982 PASS,2 TLS skips due sandbox netlink denial|All fixed identities; both named TLS upload/downgrade cases must PASS|
| Storage focused |54 PASS,2 environment skips|Same fixed identities; the two exact conditional parents/children may run and must PASS if available|
| Race, httpdown/raftstore/filersink |185 PASS,3 packages PASS|Same exact identities under CGO-enabled race detector|
| Complete shell |296 PASS,10 failing events in5 test families; baseline31 parity due denied AF_UNIX sockets|306 exact terminal identities, all PASS; no skip/failure accepted|

Main and server observations are derived from the retained complete combined run plus a separate invocation for missing main packages. The manifest records their raw origins and hashes. The complete failed shell stream remains retained; it has never been converted into a local PASS. Hosted shell proof is a distinct `REQUIRED_HOSTED_PASS_NOT_LOCALLY_OBSERVED` contract. The new producer must generate its real successful receipt, and packaging/readback revalidate that receipt. Likewise, the two actual local TLS skips cannot satisfy the hosted source qualification.

Local pipeline validation passed43 boundary/packaging/readback tests plus12 immutable runtime tests. Five additional preliminary boundary tests passed. Actual source32 logs were reprocessed by the verifier: all four local profiles matched their identities, and the actual failed shell log was rejected as required. YAML,18 shell blocks, Python sources and13 pinned action references were checked. Tests explicitly use synthetic unit fixtures for package/readback round trips; those fixtures are not image32 evidence. No qualified local OCI, fresh image scan or SPDX has been produced for the real binary, because the necessary successful hosted shell/TLS results do not yet exist.

## Lifecycle and authority limits

The compiled profile forbids AWS SDKv1/deprecated S3 manager, old Bolt/raft-boltdb/mapstructure/Sarama/metrics/clock/stats dependencies, OpenCensus, the deprecated Google detector, PGV, colorstring and Mongo driver v1. Maintained Mongo driver/v2 is a separate allowed module. This is a compiled-profile closure assertion: the full optional/test module graph still contains legacy edges, and YAML lifecycle review remains OPEN. There is no claim that every remaining dependency is maintained.

Google GCS/PubSub integration remains explicitly excluded from this standard profile, as do previously excluded optional integrations. Target feature binding remains OPEN; a target needing those features cannot use this candidate without separate qualification. Licence/cohort, durable custody and cold recovery/MIME/identity/egress must be freshly bound to the resulting image before any promotion. Release admission and runtime authority remain false. Target operations performed:0.
