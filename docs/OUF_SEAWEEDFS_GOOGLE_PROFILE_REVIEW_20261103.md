# OUF standard storage profile: explicit Google integration exclusion

Status: local source/build qualification for a future candidate. This document does not change the currently qualified image or issue target authority. The patch applies after the exact generation31 source sequence; it must be integrated and requalified with any other future changes.

## Contract

The standard candidate rejects native GCS remote storage, GCS replication sink, Google PubSub notifications and Google PubSub replication input. Registrations remain recognizable and all work-bearing methods return the explicit `OUF_STANDARD_PROFILE_GOOGLE_UNSUPPORTED` error. Disabled integrations do not change the S3/filer/master/volume roles. S3-compatible and Azure implementation files are unchanged.

The profile rejects enabled configuration before filer options/TLS/stores, before replication input/sink/source initialization, before backup checkpoint/retry effects, before credential-file reads/cache callbacks, and before the `allowUntrusted` remote opt-out. GCS `remote.configure` creation/update is denied before persistence; inspection/deletion remains available to recover old configuration. A GCS configuration encountered during remote-map reload aborts the new publication, preserving the previous map and persistent bytes. On initial load this rejects the whole remote configuration set until corrected; it does not silently drop the unsupported record or activate partial mappings.

Build tags `gcs`, `google_pub_sub` and `googlecloud` cannot enable the removed integrations and fail compilation with an explicit separately-qualified-candidate message. Historical upstream scaffold sections are not a support claim for this OUF candidate. If the target requires any excluded feature, this profile cannot be admitted; target feature binding stays OPEN.

## Evidence

See `evidence/seaweedfs-google-profile-20261103/receipt.json` and the retained bounded raw test terminals/failure output, graph, full module graph and build-info. Full raw test logs are hash-bound by the receipt; retained terminal subsets are explicitly not full stdout.

- Patch `2809f72e392571ef8fdd3f97a6ea229a39bf7b837b6d20c401531c22faa48990`: 31 changed source/module/test files; full replay equals all 4563 files, with no missing or unexpected files.
- Patched source tree `65f0ae9fbbdd2bba6e54c84fe767f838bea2ae44`.
- Local binary SHA256 `aa1ff7497f7a770abe84cbd23b792f3af299846839c1c628ef75dd366def9da2` (193141948 bytes), Go1.27.3, CGO disabled, trimpath, original upstream VCS revision with modified=true.
- Actual compiled closure: **1,534 packages, 219 dependency modules**, down from1,740 and234 in generation31. Zero compiled OpenCensus, deprecated GoogleCloudPlatform detector, and PGV. Every retained compiled module keeps its exact version.
- Focused final: **52 test/subtest PASS in14 packages**, including file/environment startup preflight, direct factories and operations, ACK denial, cache builder denial, shell-before-filer denial, reload preservation and unchanged S3/Azure SSRF regressions. All three forbidden tag checks failed as required; tidy-diff passed.
- Broad run: **1,764 test/subtest PASS,7 skip,10 failed events in5 shell test families**. This is not a full PASS. The same10 failures occur on unmodified generation31 under the same sandbox: AF_UNIX socket creation is not permitted. Both negative outputs are retained; hosted execution remains necessary. Restoring the pure parser/shared-error tests was followed by the final focused run.

## Limitations and next qualification

The root module graph still contains transitive OpenCensus/PGV/old-detector edges through modules such as gocloud, Iceberg and gRPC, although those packages are absent from this binary. Root go.mod removes11 now-unneeded requires and changes no retained version. PubSub module requirements can remain indirect through other upstream module/test graphs. This patch does not claim repository-wide eradication or that every remaining module is maintained.

The old GCS SDK-backed implementation tests are intentionally replaced by profile-denial tests. Pure `ParseInlineCredentials` and shared not-found sentinel tests are preserved. The helper parser remains available for unchanged low-level credential validation tests; it does not enable GCS client construction.

Before a candidate promotion, run the combined full suite on hosted CI, rebuild the exact merged source, generate fresh scan/SPDX, validate licence/cohort/custody bindings, and repeat cold recovery/MIME/identity/egress checks against the new image. No previous generation image, vulnerability dispositions or runtime proof transfers. Runtime authority and release admission remain false; target operations performed:0.
