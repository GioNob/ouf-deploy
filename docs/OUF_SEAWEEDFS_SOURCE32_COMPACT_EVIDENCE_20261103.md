# Source32 compact publication

This is a lossless representation of the frozen 117-file local qualification delivery. It changes no source, qualification result, skip, failure or evidence hash. The original receipt remains byte-identical, SHA256 `3bda090e8b62cd0e5cc0fcf18b1e26d1bdec6b3f10cb2e51c9d7bd34891952f0`.

The publication stores 11 large raw payloads as deterministic gzip files. Documentation, patch, complete observed-profile and source manifests, build information and the frozen qualification receipt remain directly readable. The 117 original inputs occupy 34,768,100 bytes before compression and 4,762,787 bytes in their published representations; the mapping, verifier and this explanation add a small amount.

**Paths in the original frozen receipt are logical evidence identifiers.** An uncompressed logical path is not asserted to exist in this compact checkout. Resolve it using `evidence/seaweedfs-source32-compact-publication-20261103.json`: each entry names its actual `publishedPath`, encoding, original/published byte lengths and SHA256 hashes. The original 117-file delivery manifest is preserved separately as `evidence/seaweedfs-source32-original-delivery-files-20261103.json`.

Verify every published payload and every decoded original from the repository root:

```sh
python scripts/verify-seaweedfs-source32-compact-evidence.py --root .
```

To reconstruct all original paths in a new directory, with the same verification:

```sh
python scripts/verify-seaweedfs-source32-compact-evidence.py --root . --materialize /tmp/ouf-source32-original-evidence
```

The materialization directory must not already exist. A single gzip payload can also be read using `gzip -dc path/to/payload.gz`; use the mapping's original hash to verify the decoded bytes.

All 117 original inputs were verified against the frozen delivery manifest before publication and each gzip payload was decompressed and compared byte for byte with its original. The publication verifier rechecks all physical and original hashes. The original raw delivery remains preserved unchanged. This publication representation adds no test execution, hosted qualification or admission credit.
