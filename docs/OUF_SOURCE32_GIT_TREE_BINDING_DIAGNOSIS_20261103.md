# Source32 Git-tree binding diagnosis and canonical replay

The hosted source32 build correctly rejected the local expected tree. Its tree is `80632ef3a54debb04531c1913860d2f94d2b418d` (4567 entries); the local frozen receipt incorrectly recorded `d58d388bd4b791ffbc41814cc670af44af20f47c` (4543 entries).

The local tree calculation created a new alternate index and ran `git add -A` without first loading the upstream tree. That omitted 24 files which were tracked upstream but matched ignore rules: 23 Rust vendor files and `weed/images/sample1.jpg`. All 24 files are present in the frozen source working tree and in its full SHA256 file manifest, with bytes equal to the correct Git blobs. Every common entry has identical blob ID and mode. There is no working-source byte difference demonstrated by this tree discrepancy.

This cause is reproduced in an isolated diagnostic Git database:

- Starting from an empty index and scanning the actual working tree reproduces the incorrect `d58d388b…` tree.
- Loading upstream `984eac6a790be89e2a11de175a7413e1e3e32dd3` before the same working-tree scan produces the correct `80632ef3…` tree.
- Independently loading that upstream tree and applying all 32 exact, hash-verified patches using `git apply --cached` also produces `80632ef3…`, matching hosted output.

The original source32 receipt `3bda090e8b62cd0e5cc0fcf18b1e26d1bdec6b3f10cb2e51c9d7bd34891952f0`, source patch, binary and failed hosted expectation are preserved unchanged. This delivery documents and prevents the provenance-calculation error; it does not silently rewrite historical evidence or claim that the failed hosted run passed. The parent qualification workflow controls any explicit corrective receipt/manifest and new hosted execution.

## Reusable computation

`scripts/replay-seaweedfs-source-tree.py` accepts a repository containing the upstream Git objects, a manifest with `upstreamCommit` and ordered `{path,sha256}` patch records, and the patch root. `--base` optionally accepts an explicit parent commit/tree instead of the manifest upstream.

```sh
python scripts/replay-seaweedfs-source-tree.py \
  --repository /path/to/seaweedfs-source \
  --manifest releases/seaweedfs-452-generation32-build-manifest-20261103.json \
  --patch-root . \
  --output /path/to/owned-evidence/canonical-tree.json \
  --entries-output /path/to/owned-evidence/canonical-tree.ls-tree.z
```

It loads the base tree into a private index, applies verified patch bytes with `git apply --cached`, and writes all new Git objects into a temporary private bare repository. The source object store is only an alternate read source; the caller index, refs, objects and working tree are untouched. The private directory is removed after success or failure. This preserves tracked ignored files and Git file modes, avoids working-tree filters, and prevents patch-path traversal or post-verification patch replacement. A mismatch or unapplicable patch fails explicitly.

The eight regression tests cover tracked ignored files, executable and symlink modes, the original empty-index failure, caller metadata isolation, commit/tree base equivalence, exact patch ordering, hash mismatch, path escape and unapplicable-patch cleanup. The real 32-patch replay passed independently and reproduced the hosted tree. No new application build, runtime qualification or target operation was performed.

Raw NUL-delimited `git ls-tree` outputs are retained as gzip with original/compressed hashes in the helper receipt. The diagnostic JSON lists all 24 missing entries, their ignore rules and byte comparisons. These records distinguish an erroneous tree expectation from a change to the source payload.
