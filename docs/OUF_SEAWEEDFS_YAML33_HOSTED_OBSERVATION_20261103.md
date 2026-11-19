# YAML33 hosted source observation — not qualification

This optional workflow produces the missing full SeaweedFS vendor observations on a hosted runner. It leaves the generation 32 image pipeline unchanged. It does not publish a candidate image, release, binary, full vendor tree, runtime authority or admission. Parent publication is still required before it can run; local observer tests are not hosted results.

The observation starts from the exact upstream commit `984eac6a790be89e2a11de175a7413e1e3e32dd3` and the 32 ordered patches authenticated by generation 32 manifest SHA256 `5289372fe7577936376497adba277fb329bb2a625652eacad47c854735937144`. Two independent clean clones must reconstruct source tree `80632ef3a54debb04531c1913860d2f94d2b418d` and the original frozen lockfile hashes. The initial upstream checkout is not patched. Go is exactly 1.27.3, linux/amd64, production CGO disabled, explicit vendor mode, trimpath and VCS metadata enabled. The job has a 45-minute cap; the observer has a 35-minute total command budget, individual deadlines and process-group termination on timeout.

## Evidence sequence

1. Reconstruct source 32, prove tidy fixed point, capture the root module graph, generate a complete vendor tree from the original dependencies. Downloads populate a fresh runner-only cache; no cached source is patched. Recheck root locks.
2. Enumerate all headers in `vendor/modules.txt`, not merely compiled modules. Download records for those exact versions are authenticated against frozen go.sum. Independently recompute every ZIP h1 and go.mod h1, retain byte hashes and metadata, run `go mod verify`, and compare every actual baseline vendor file against its original ZIP member. `modules.txt` is separately identified as Go-generated metadata. Any unexplained file or source difference fails the observation.
3. Save complete before/after file-hash inventories. Apply the existing reviewed Iceberg config import patch and explicit downstream notice, preserving LICENSE/NOTICE and checking the one-file delta. Vendor tree hashes are observed from real files at runtime, not supplied as invented pre-pins. The materializer uses this observed baseline plus the separately pinned single-file transformation; that is an observation, not independent admission of its vendor tree.
4. Reuse the exact eight materializer tests and the remaining 33 source-profile/origin/CLI tests in small fixtures cut from the actual vendor inputs. Run actual production dependency listing and build the full SeaweedFS executable. Legacy YAML must be absent from compiled packages and binary module inventory, with canonical Iceberg and maintained YAML identities retained. Vendor build-info h1 fields stay empty.
5. Capture the compiled module origin inventory separately; it must be a subset of the authenticated complete vendor origins. Run actual Iceberg worker tests, source-profile guards, original upstream config tests against a copy of the actual patched config, race-check those config tests, and compare 17 legacy/maintained YAML parsing cases. Config tests retain the upstream test-file hash. Legacy YAML is intentionally permitted in the comparator's test-only imports; it remains prohibited in the production graph and binary.
6. Verify eight excluded profile tags fail for the expected OUF diagnostic. Reconstruct the second clean source path, independently regenerate vendor, compare its full baseline inventory, apply the same reviewed delta and build with the same flags. The two binary byte hashes and build metadata must match. Recheck all vendor files, lockfiles, module-cache integrity and original input checksums after tests/builds.

## Artifact contract

The artifact is `seaweedfs-yaml33-source-observation-<run_id>`, retention 90 days. It contains diagnostics, command vectors/deadlines/exit codes, original-input inventories, complete vendor path-to-hash maps, source and binary metadata, test output and a SHA256SUMS inventory. Neither binary bytes nor full vendor source are included in this bounded diagnostic artifact. No raw scanner output is rewritten or transferred from generation 32; fresh scanner/SPDX and complete image qualification remain future work.

Key files:

| File | Scope |
| --- | --- |
| `base32-manifest.json`, `observation-inputs.json` | Exact source and tool inputs, all reused helper/test hashes |
| `vendor-before-files.json`, `vendor-after-files.json` | Pure maps of vendor-relative path to SHA256; one changed file only |
| `baseline-vendor-module-enumeration.txt` | All vendor module headers, explicitly not binary build-info |
| `baseline-vendor-origins.json` | Authenticated original ZIP/go.mod records for every vendored module header |
| `baseline-vendor-file-origins.json` | Complete baseline vendor-file verification against original ZIP members |
| `first-build-info.stdout`, `second-build-info.stdout` | Untouched Go binary metadata |
| `compiled-module-origins.json` | Original inputs for actual compiled binary dependencies only |
| `production-graph.stdout`, `production-packages.json` | Actual production graph under explicit vendor mode |
| `commands.json`, test stdout/stderr, summaries | Actual execution and diagnostic evidence, including failures |
| `observation.json`, `SHA256SUMS` | Honest PASS/FAIL observation status and artifact byte hashes |

The original-module collector schema is reused without pretending a vendor-header enumeration is binary metadata: its `buildInfoSha256` binds the explicit enumeration text for baseline origins and the actual raw binary build-info for compiled origins. Consumers must retain that distinction. A future vendor-aware engine must bind all observed materials, one source patch set of 32 and one dependency patch, the exact one-file delta, original checksums versus modified bytes, and fresh scan/SPDX identities. It must not relax generations 31/32 or infer that an upstream h1 describes patched source.

If a command fails, the observer saves failure details and command evidence, marks `OBSERVATION_FAIL_NOT_RELEASE_QUALIFIED`, hashes the evidence and exits nonzero. The workflow's always step additionally emits a failure record when execution never started, then uploads whatever diagnostics exist. A runner crash or hard cancellation can still prevent upload; successful diagnostic collection is not assumed without the hosted artifact.

Downstream ownership stays OPEN. The result never closes maintenance, legal, image, recovery, custody, target-binding or HUMAN/THS gates. No target operations are performed and previous scope consumption, Teatri and Farmacie results remain unchanged.
