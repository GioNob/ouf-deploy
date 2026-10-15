# Snapshot reader correction — 2026-10-15

The target attempt at 17:45 Europe/Rome stopped before IAM, terminal approval
and runtime authority, with PRIVATE_SNAPSHOT_CUSTODY_UNPROVEN.

The cohort retained-history reader accepted an explicit 8MiB bound but called
the independent IAM snapshot reader, whose protocol caps files at 512KiB. The
complete source bundle exceeded that smaller bound. The actual complete bundle
regression reproduces the same error with root/root, 0600, single-link custody
before this change and passes after it. The earlier qualification missed this
compiler-to-reader boundary. No target permissions need to be relaxed.

The cohort reader now honors its caller bound, capped at 8MiB, retaining regular
file/root/root/0600/single-link checks, protected parent, no-follow opens, stable
inode and metadata, two identical bounded reads, SHA256 binding and strict JSON.
The separate IAM snapshot reader and its 512KiB limit remain unchanged. Seven
reader regressions and the complete-bundle assembly regression were added.
Intake failures now expose bounded code locations without messages, paths or
local values. No credential rotation, grant, image import, database or service
mutation is added. All previous histories and consumed claims remain intact.

Local evidence: complete-bundle 1, reader 7, predecessor 14 and entry 10 tests PASS.
The published source 0525c4186a5613000905ba4dfae6766827ad9f06 passed all six
same-source CI qualifications, including 319 native cohort tests in 42 suites
with 0 skips. The published operator command pins that source and launcher.
Actual target current state and CSV E2E remain unproven. No runtime authority
was issued by this workspace.
