# Registry rootfs mount-profile mismatch — 2026-10-15

The complete target entry readback finishes without unavailable checks. Against
the original independent package baseline it reports exactly eight differences:
three missing CI mount placeholders, four new reviewed mount placeholders, and
one directory link-count change. No content/xattr/ownership/mode drift of shared
image entries is reported. There is no image rebuild or application execution.

The package qualifier mounted delegation/proposal/DB/token at
`/run/ouf/delegation.key`, `/run/ouf/proposal.key`, `/run/ouf/database`,
`/run/ouf/policy`. The reviewed retained request instead uses
`/run/secrets/semantic-read-owner.key`, `/run/ouf/proposal.key`,
`/run/ouf-semantic-db`, `/run/ouf-semantic-auth`.
Docker creates the corresponding underlying empty targets and ancestors.
Therefore the original generic CI seal cannot equal this realized image view.
The complete expected OCI defect and this distinct seal-profile defect are both
preparation defects; no user typing or IAM approval can correct them.

Native run38784418792 at sourcea535e987b52f66d75b805541d89012b883a8864b
uses the exact retained original semantic artifact, Docker29.8.1/containerd,
the same four reviewed mount targets, synthetic private inputs and the same
nonroot shell gate. It never starts Java. Two independent unchanged v1 seals
match:9302entries,1719645735bytes,
`a73d7520737345d67030baaa2405478b3784fc84060f6ec6ccc6109f98ac2f11`.
The independently captured complete CI entry difference reproduces all eight
target public difference projections. Original qualified seal
`510f56436da3e36b700b244e5e2476db9d4984216866e412b0484f951bfdb8a2`
remains unchanged. No exclusion, directory normalization or adopted target hash.

The new read-only proposal reader embeds this full independent CI entry stream.
It binds both the original package seal and new retained-mount seal, requires
the exact four readonly reviewed request/policy targets, and compares every
target image entry and the full unchanged v1 seal with the independent CI.
The earlier exact OCI proposal check is also repeated. Only in-memory proposal
data is used; it never overwrites the old recipe, journal or frame policy.
It reports `RETAINED_MOUNT_PROPOSAL`, complete differences and END. A passing
readback proves these proposed expectations, not a signature or application E2E.

Preserve the same paused Registry PID3484588/restart0 and six APPLIED phases.
The unsigned old ATTEST remains IN_FLIGHT. All old claims and the cancelled
worker with cumulative2 grants remain untouched. A later governed recovery must
explicitly bind changed OCI/rootfs recipe intent in a new finite approved scope,
preserve all six effects, avoid CREATE/STAGE/SIGUSR1 replay, preserve DB fence
and backup, and issue/account any new worker grant after cumulative2. Current
postgrant-created-v1 launcher does not implement this boundary and must not run.

Full private frame byte checks, fresh token admission, peer attestation,
migrations/start/readiness and actual chatbot CSV end-to-end remain unproven.
