# SeaweedFS source32 — integrated maintained profiles

Status: local source qualification only; no hosted image, cohort admission, target deployment, live MongoDB qualification, or miniPET completion is asserted. Base is the frozen generation 31 source. Candidate generations already published remain immutable.

The incremental patch integrates three reviewed deltas: a local synchronized progress reporter replacing progressbar/colorstring; official MongoDB Go driver v2.9.2; and the explicit standard Google feature profile excluding legacy GCS remote storage/replication and Google Pub/Sub while preserving the separate GCP KMS implementation. Explicit unsupported feature tags fail compilation. Configuration preflights reject excluded providers before the corresponding initialization/effects; a deployment requiring these features needs a separately qualified profile. No OUF target binding is inferred from source tests.

The change is exactly 38 files, including go.mod/go.sum. Sixteen root requirements are removed, MongoDB/v2@v2.9.2 is the sole added requirement, and no retained module version or retained h1 changes. No YAML/vendor migration is included. Production closure is 1533 packages and 215 dependency modules. The compiled MongoDBv1, archived progress/color dependencies and Google legacy stacks are absent. The root transitive module graph still contains uncompiled legacy edges; legacy gopkg.in/yaml.v3@v3.0.1 remains compiled and lifecycle qualification is OPEN.

MongoDB preserves the existing retryWrites/session/transaction-number policy. Adaptive retries introduced in v2 are explicitly 0; unsupported adaptive opt-in and removed nonzero timeout options fail before Connect. Unacknowledged w=0 is rejected before Connect and mutations verify Acknowledged. Initialization publishes the client only after index creation succeeds, closes failed setup clients with a bounded context, and preserves real server/write/cursor errors rather than reporting success/not-found. Existing empty-KV and no-op transaction semantics are unchanged. The component's real-driver synthetic wire tests cover commands, BSON and error behavior; they do not establish replica-set deduplication, live-server compatibility, durability, PITR or target eligibility. MongoDB server >= 4.4 is required by the official driver.

## Actual local checks

| Profile | PASS events | Skip events | Result |
| --- | ---: | ---: | --- |
| Main |6656|12|Observed PASS, integration skip limits retained |
| Server (whole package) |982|2|Observed PASS, TLS cases require hosted PASS |
| Storage focused |54|2|Observed PASS, environment cases require hosted PASS |
| Race (httpdown, raftstore, filersink) |185|0|Observed PASS with race detector |
| Shell local observation |296|0|10 FAIL events in 5 AF_UNIX-restricted test families; hosted PASS REQUIRED |

Counts are per profile and are not a sum of unique tests: race intentionally overlaps main. Subtests are included. Raw commands/stdout/stderr, skips, terminal identities and source hashes are retained.

The initial broad command exited 1: 7650 PASS, 14 skips and 10 shell failures. The exact failed identities match the pre-existing Google baseline; the local socket errors are not converted into successes. The main log is explicitly derived from that raw log excluding the complete shell and server package streams, then appending a successful disjoint supplemental-package invocation. Server retains its entire raw observed stream separately. `observed-profiles.json` records this derivation and hashes. The hosted image workflow must execute the whole shell package and require all declared cases to PASS. It must also require the 2 server TLS and 2 storage conditional tests to PASS under their declared environment normalization. Main Azure/external integration skips remain unqualified.

Both nested modules, test/kafka and test/s3/iam, passed actual `go mod tidy -diff` with empty output against root 32, and compile-only `go test -run '^$' ./...`; their locks remain byte-identical to31. This is compile qualification only, not service integration.

Two independent build paths (integrated source and fresh 31 plus the incremental patch) used `-trimpath -buildvcs=true`; all 4567 source files, Git tree and binary bytes match. Binary SHA256: `33c54c173912884a5e38779d0bdbfd7cbce3a3955b8aa4434535bba99bcf7511` (193113064 bytes). Source tree: `d58d388bd4b791ffbc41814cc670af44af20f47c`. VCS retains upstream revision `984eac6a790be89e2a11de175a7413e1e3e32dd3`, modified=true. Source32 is not assigned a fabricated upstream commit.

The initial offline complete-root-module listing failed because metadata for 2 uncompiled transitive modules was absent. The failed attempt is retained; querying the official Go proxy supplied metadata and the complete 781-module listing passed. Production graph resolution was already successful offline. No dependency download failure is silently interpreted as absence.

The broad test used the historical shared Go temporary location. No missing compiler files or new non-shell failures occurred. Subsequent commands used an exclusive generation32 work directory. Only compiler work owned by completed generation32 builds was removed, with receipts; no shared cache/work directory was deleted by this qualification.

## Boundaries

No GitHub mutation or target operation was performed by this source integration. HUMAN/THS authorities, consumed scopes, Teatri/Farmacie evidence and miniPET admission gates are unchanged. The original PET/Matrix and resilience constraints still apply; HTTP retry budgets, restoration results and actual S3 migration are not inferred from dependency removal. Hosted source/image qualification and existing lifecycle/functional gates must complete before this source can replace an admitted cohort. YAML remains the next explicitly separate dependency front.
