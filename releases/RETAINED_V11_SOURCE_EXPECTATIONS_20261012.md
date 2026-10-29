# Retained V11 source expectations — 12 October 2026

## Selected target input

The [operator-reported gated preparation](../evidence/gated-v11-private-plan-prepared-target-20261012.json) published intake `005f6a7afad7d493a52d9b183816fa0346f1bb1a4de5ab4b63c8b0b39f3fb092` and creation request `37b517eda22f5997504687222679d458c9478ee66ba5ef2377cf5588ef3f0a9d`. Its two retained scopes are one directory/one file. The initial preparation read metadata only; no source-byte expectation or full six-mount acceptance was produced.

## Source-bound preparation

[Program](../scripts/prepare-retained-v11-source-expectations.py), pinned source commit `3167d10b89daa9f34f32776b25ad8a5edb630751`, SHA256 `d6b3fc0f277d83e5c93b2fc78fe26fa84a8d36e780487b1665ff6dd481939e31`. [Launcher](retained-v11-source-expectations-20261012.sh), SHA256 `83c2ec2ba30a2b4a26864f4b4f7b84b9ccdac94a46ea7f8b35545e13dc53cd07`. Original atomic publisher is retained byte-exact at bdcf4594d152ea12d6b9b39b51e0d2533d83b7ef.

This finite no-apply operation verifies the exact selected intake, all four private file hashes, six-mount request hash and both operator-reported source metadata seals. It follows no symlink, traverses source ancestors using directory FDs and requires root-protected ancestors. It rejects stale metadata, extra directory members, special files, hardlinks, source substitution and changed metadata/content. Each of the two files is bounded to1MiB, hashed twice per observation and observed again before publication. Overall deadline120seconds; no shared lease lock or automatic retry.

Unlike the previous metadata-only preparation, this operation **reads both retained file contents into a streaming hash**. It does not parse/classify private keys and cannot claim zero private-key reads. It prints no contents, source paths or individual byte hashes, and spools no source bytes. Hashes, exact bindings and member custody are recorded only in a new private expectation file. The safe report exposes counts, custody and aggregate publication hashes. Original private intakes are unchanged.

The root entry is isolated (`python3 -I -B`); both downloaded sources are checked before sudo and rechecked as stable regular single-link files before execution. Unknown exception text is redacted; an interrupted private publication explicitly requires reconciliation. Publication uses the existing atomic no-replace publisher: two files plus manifest, identical rerun verifies the same publication without rewriting it. Changed intent needs explicit reprocessing; no automatic budget reset, runtime operation, signature or authority is issued.

## Validation and limits

Nine local source/publication tests and four delivery tests pass. Native10001 UID/GID custody is checked by the [dedicated workflow](../.github/workflows/retained-v11-source-expectations.yml) on a disposable root-owned fixture; local UID ownership restrictions are not represented as a native10001 qualification.

Target execution of this new preparer is still pending. The resulting historical byte expectations must feed an independently approved six-mount compiler/observer and fresh source-bound HUMAN/signature authority; they are not accepted runtime policy, OCI acceptance, authenticated transport, worker admission, readiness or CSV evidence. This operation neither invokes Docker/nft/systemd/SQL/provider/DNS nor changes R12, cumulative recovery history or one-use claims.
