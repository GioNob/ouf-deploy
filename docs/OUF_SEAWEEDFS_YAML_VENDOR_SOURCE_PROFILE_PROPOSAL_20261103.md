# Generation 33 YAML vendor source profile — proposal, not admission

This is a separate implementation proposal beyond immutable generation 32. It does not modify generation 31/32 sources, their qualification engines, published records, raw scanners, SBOMs, module caches or target systems. The base source 32 was frozen at Git tree `80632ef3a54debb04531c1913860d2f94d2b418d`; the generation 32 qualified manifest must additionally be bound when available. No full SeaweedFS vendor or generation 33 binary has yet been produced by this proposal.

## Exact change and provenance

The only permitted dependency source edit is `github.com/apache/iceberg-go/config/config.go` from Iceberg `v0.7.0`, commit `89a9104ec3639d38ab07e4461721cb5270e95571`: change the YAML import from `gopkg.in/yaml.v3` to the already selected `go.yaml.in/yaml/v3 v3.0.5`, with a conspicuous downstream modification comment. Iceberg's canonical module name/version and Apache LICENSE/NOTICE remain intact. The file stays in the vendor copy of the actual Iceberg module; Iceberg table/config behavior is preserved rather than substituted by an unrelated local configuration API. No feature is removed.

The reviewed patch SHA-256 is `001459c5254303378cb30dafaceec1777cbb143957fa6afb5e2e7eb8cbb46eef`. Original Iceberg ZIP SHA-256 is `a042ec87708c376362859041b1741213dc4e05400cad7ad0220ea4361a250d55`, h1 `h1:bTD6Pb4uM4sWcMfIx0/cV1haHMc84r+CvPieUqYzD4I=`. These are checksums of original upstream input only. They do not certify modified vendor bytes. The original config SHA is `30ec8eebf86cd2f5df0c8d6bbf8661c0bf72d10fc8c025d6943c9565ae13a604`; the modified config SHA is `9983e5e82a9372e9f47db6ccc5a55d9b747fd503caaedb5619e4b37e95c75ab4`.

## Implemented companions

- `prepare_iceberg_vendor_patch.py` preserves the previous eight materializer tests. It authenticates original ZIP and vendor input tree, checks licensing and exact bytes, predicts the complete resulting tree, then makes the single allowed source edit. It is used only on an owned vendor copy.
- `vendor_yaml_source.py` binds the frozen parent manifest/source, root lockfiles, entire base source tree, complete before/after vendor trees, patch and materializer. Reconstructing the original vendor tree by replacing the single config hash rejects additional vendor changes even if someone updates the claimed modified-tree hash.
- `vendor_module_origins.py` reads existing cache records without downloads or mutations. It independently recomputes the Go ZIP h1 and go.mod h1, authenticates them against frozen root go.sum, hashes the actual ZIP/go.mod bytes and preserves available origin metadata. Every binary dependency needs one record. Unknown origin metadata stays null rather than inventing an upstream commit.
- `verify_iceberg_vendor_source_profile.py` emits only a separate provenance supplement. It rejects output paths that alias raw evidence or fall under the source tree. The raw scanner and SPDX inputs are verified unchanged.
- The draft JSON intentionally fails the guard. Unknown full-vendor, origins and qualified-parent bindings remain null.

## Required future qualification engine integration

A new, separately reviewed vendor-aware engine is required; do not relax the existing generation 31/32 engine. In particular, the existing `binary_modules` assumption that each build-info dependency contains an h1 cannot be reused unchanged. Actual Go vendor build-info omits these checksums. The new engine must retain the raw build-info unchanged and select its input policy explicitly from the bound source profile.

| Evidence | Meaning | Guard obligation |
| --- | --- | --- |
| Raw binary module identity | Canonical upstream module name/version | Reject replacements, duplicate module paths, and legacy YAML; all vendor dependency h1 fields remain empty |
| Complete original-input inventory | Original ZIP/go.mod h1 and byte hashes for every compiled module | Exact one-to-one identity match with binary inventory; recompute actual cached input checksums and compare frozen go.sum |
| Base vendor tree | Exact unmodified dependency sources materialized before patch | Bind complete sorted file-hash inventory and modules.txt |
| Patched vendor tree | Actual dependency source bytes used by the build | Only the reviewed config delta; retain Apache license and notice |
| Raw Trivy and SPDX | Unmodified scanner output and canonical CVE identity | Preserve Iceberg canonical name/version/PURL; no fork rename, CVE suppression or fake upstream h1 |
| Separate source supplement | Explicit relationship from upstream input through patch to binary | Bind raw artifact hashes and SPDX node IDs; record DESCENDANT_OF, PATCH_FOR, PATCH_APPLIED, GENERATED_FROM |

The supplement is not a standalone SPDX document and is not a release admission. It provides additional source provenance without rewriting the scanner's canonical package representation. The upstream Iceberg advisory stream remains applicable; a source patch is not evidence that its other vulnerabilities are fixed. Downstream patch vulnerability and compatibility review remain separate obligations.

All root Go build, production graph, regression, race and excluded-profile commands must explicitly use `-mod=vendor`, with effective `GOFLAGS` empty and `GOWORK=off`; overlay and alternate module-mode flags are rejected. Nested independent modules need their existing separate qualification, not a false assertion that they use the root vendor tree. `go mod tidy` and module maintenance do not use vendor source: record their results and any legacy module-graph residue separately. Do not claim legacy YAML was removed from every root graph simply because it is absent from the compiled binary.

The existing publisher, VCS identity, image/executable relationship, legal inventory, complete module inventory, vulnerability decision, lifecycle and runtime authority checks remain necessary. Contract tests with synthetic records do not establish command execution authenticity, binary/package correspondence or release identity; those are supplied and verified by the generation qualification pipeline. Commands must have real exit codes and hashes in that pipeline. No `-buildvcs=false` prototype is a release identity.

## Ownership and scope limits

Downstream maintenance status is explicitly `OPEN`, with no invented technical owner. Review cadence is each candidate and weekly while the patch remains active. The review must cover upstream Iceberg changes/security notices, maintained YAML changes, ongoing necessity of the patch, patch applicability and scanner findings. Missed review or unassigned ownership leaves the gate open. One downstream commit does not establish a maintained fork.

The source supplement always states `releaseAdmitted=false`, `runtimeAuthorityIssued=false`, `allDependenciesMaintained=false`, and `targetOperations=0`. Existing PET/HUMAN/THS authority requirements and consumed scopes are unchanged. Teatri/Farmacie evidence remains intact. Full source, binary, legal, scanner and image qualification, maintainer assignment and any required target-specific binding are outstanding. No human action is requested by this code preparation.

## Sequencing and space

Generation 32 source/build freeze was received before this proposal considered full vendoring. A read-only budget observed about 2.14 GB free; selected cached module trees sum to 1.68 GB, a conservative estimate rather than actual vendor output. Full vendor/build is deferred until adequate space is available without competing with parent qualification. No existing evidence or other agent's files may be deleted to make room without ownership review.

After space is available: copy the frozen source 32 into an isolated owned stage; generate the whole vendor tree once; authenticate and record it; apply the single locked patch; bind the complete module-origin inventory to the actual vendor binary; run the full explicit vendor-mode graph/tests/race/exclusion builds; reproduce from a second independent path; perform canonical raw Trivy/SPDX scanning and separate provenance; integrate the new engine and legal/readback paths. Promotion requires the complete applicable gates, not merely the source supplement.
