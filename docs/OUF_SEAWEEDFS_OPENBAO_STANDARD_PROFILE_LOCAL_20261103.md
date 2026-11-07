# OUF standard candidate: OpenBao/Vault exclusion, local qualification

Status: **LOCAL_PASS_NOT_ADMITTED**. This is an isolated candidate30 development patch on generation29 plus the separately frozen LDAP mapstructure-v2 patch. It does not change admitted/current qualification, the immutable generation29 image, MinIO operation, consumed scopes, or Teatri/Farmacie results. HUMAN/THS target authorities remain unchanged.

The maintained OpenBao SDK alone would retain the old mapstructure module through parseutil; the primary-source investigation is recorded separately in `OUF_OPENBAO_SDK_MAPSTRUCTURE_REVIEW_20261103.md`. The conditional OUF standard profile therefore removes the OpenBao/Vault KMS implementation and its root-module SDK integration test. It **must not be selected for a consumer requiring either KMS provider**. The target dependency gate is OPEN: the historical 120-object public baseline with no encrypted objects is insufficient to establish absence across all writers, consumers, or restore data.

## Behavior and state boundaries

* Explicit OpenBao/Vault declarations are rejected before KMS factories, cached provider reuse, closing retained providers, health probes, default/bucket rebinding, or IAM publication. All providers are checked before iterating any supported provider. The actual provider type is checked, including case/whitespace normalization; an instance named `vault` with a supported type is permitted.
* The real S3 constructor reads and validates the selected config before credential-store initialization or filer work. It passes those same validated bytes into IAM startup. A later reload acquires the existing reload mutex before reading the file and preserves the lock through publication. Denied file/byte reloads retain identity and credential pointers, static markers, persisted credential configuration, KMS provider instances and bindings.
* Replication validates before input/source/sink initialization, even when the SSE singleton was previously initialized. Backup validates before checkpoint reads and the retry loop. The real CLI commands reject the profile without reaching the otherwise missing input/sink. Unrelated pre-existing SSE initialization warnings/fallback behavior remains intact.
* Explicit `openbao`, `vault`, or combined feature tags fail compilation with `OUF_STANDARD_PROFILE_DOES_NOT_SUPPORT_OPENBAO_OR_VAULT`. This patch neither supplies a custom HTTP KMS replacement nor silently aliases an unmaintained library to another module.
* Normal KMS providers, LDAP coercion tests, MQ/SQL source files and normal S3 API behavior remain within the test/build scope below. This is not a proof for arbitrary concurrent external configuration mutation or every optional feature combination.

## Actual local results

| Check | Result |
|---|---|
| Focused profile cases within the final broad run | 33 PASS: 10 top-level, 23 subtests; 5 packages |
| Broader KMS/S3/IAM/replication/command run | 7,650 PASS: 2,859 top-level, 4,791 subtests; 11 skipped tests; 42 packages PASS; 10 packages have no executed tests |
| RED control on generation29 + LDAP, without profile patch | All six exclusion cases fail because the old loader returns nil; the positive no-KMS case passes |
| Full `./weed` build, Go1.27.3, Linux/amd64, CGO=0, trimpath | PASS; SHA256 `0eb485af73e59767600dfe9b9d85963d385a5a4690963d3e8b7490b9c339d037` |
| Production dependency graph | 1,811 → 1,791 packages; 20 removed, zero added |
| Successful offline `go mod tidy` | 11 root requirements removed; zero added modules or changed retained versions; maintained mapstructure/v2 becomes direct |
| `openbao`, `vault`, `openbao,vault` builds | Expected compile rejection with the profile diagnostic |
| Actual `filer.replicate` and `filer.backup` CLI | Exit 2 with explicit profile denial, bounded local fixtures, no configured input/sink |
| Patch replay | All 21 resulting changed/deleted files match qualified source exactly |

The actual production package graph and linked binary contain no `github.com/hashicorp/vault/api`, `github.com/hashicorp/go-secure-stdlib/parseutil`, or `github.com/mitchellh/mapstructure`. The retained decoder is `github.com/go-viper/mapstructure/v2 v2.5.0`. This closes those arcs in this conditional production profile, not the entire maintenance audit of the future combined candidate.

The 11 skipped tests are six Azure integration tests and five existing S3 integration tests; their exact names are in the test summary. Raw test output contains one log event with an unescaped line break; its bytes are retained unchanged. A JSON stream decoder permitting that control character reads all 36,914 events, including all terminal test/package records. The initial focused run is retained as preliminary evidence; final qualification uses the broad run after source freeze. The first CLI attempt also encountered the sandbox's missing `/tmp` logging path; corrected runs use `-logtostderr=true` and have no logging failure.

`go list -m -json all` with `GOPROXY=off` could not enumerate uncached module metadata. Its failure is preserved and is not reported as a passing check. The narrower actual production `go list -deps -json ./weed`, tidy, and binary build/readback passed. Some historic checksum-only entries may remain in go.sum through other module metadata; the production absence claim comes from actual imports and linked modules.

## Integration and remaining qualification

Apply `patches/seaweedfs/4.52-ouf-standard-openbao-profile.patch` **after** the separate LDAP patch. Its 21-file delta is based on generation29 plus LDAP; it does not duplicate the LDAP source/test change. Of the 21 files, 19 are non-module changes and two are go.mod/go.sum. When composing other candidate30 changes (Kafka/metrics/Bolt), integrate the 19 source/test changes and perform one final tidy; do not overwrite a newer combined module manifest with this isolated manifest.

The exact receipt and per-file evidence hashes are in `evidence/seaweedfs-452-openbao-standard-profile-local-20261103.json`. The raw larger outputs are losslessly gzip-compressed. A second reviewer reran the 33 focused cases and individual OpenBao/Vault negative tags and found no remaining blocker.

No combined candidate30 seal, hosted OCI image, vulnerability/lifecycle/SBOM/license cohort, new runtime laboratory, target binding qualification, or cutover is claimed. This patch earns no additional admitted miniPET gate or AT. Any OpenBao/Vault dependency discovered during the target inventory invalidates this standard profile for that target and requires a separately maintained, qualified capability before proceeding.
