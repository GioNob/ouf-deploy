# Fresh dependency evidence and pre-key recovery review — 2026-10-09 R2

State: PENDING_HUMAN_ACCEPTANCE. No new target authority or start is granted by these documents or CI.

Parent human sign/start approval remains OUF_PROVIDER_V2_SIGN_START_HUMAN_APPROVAL_20261009_075624, recorded at a355a4f738ed1d5a713b911f33f7f63a4952aa6a. The original complete-frame/image acceptance remains valid for its exact scope. This addendum replaces only two dependencyEvidence input hashes, because the old database validity ended 2026-10-09T06:31:48Z.

## Concrete differences

Database v6.1.10 built 2026-10-08T06:33:47Z; SHA256 3b5bd894077ef069b123399de782d5df1e513c1917255a14f2d086226350d5f4. Validity ends 2026-10-10T06:33:47Z (10 October 08:33:47 Europe/Rome). The whole 240-second authority window must fit inside this validity; it is not extended.

| Role | Critical / High / Unknown | Medium old → new | Low old → new | Negligible |
| --- | --- | --- | --- | --- |
| adapter | 0 / 0 / 0 | 5 → 5 | 0 → 0 | 0 |
| southbound | 0 / 0 / 0 | 142 → 141 | 18 → 19 | 4 |

No ignored matches or package alerts. Both complete extended SBOM byte hashes are unchanged: adapter 19be04f4c6bef442fb3273cb8b68d4b78203e53e4c897c7841a8e7a3990a938f; southbound c8d0560ec09175e4f47202ec19d9b9b9210d0cefb9bbb350a1014c22800e6781.

Adapter dependency input: old 3e66cfb38a24923e1880cd1c28e53abdbd39d09fdca2f2cdfd105115f16b193b → new e5b31a2117b2f5abfb5e305b62a04d8861341501c626ab1cd50459e2b07b248d.
Southbound dependency input: old 5c60aa4def36d5ea09cb01f0b2a76ac93640b9df2878b5cdd5b83232b7db53c9 → new 17ae54703ac8b29c4d554b9832f2a2f9d6d0067d421ee8cffc8ed89e96da8168.

Full proposed input scope: evidence/provider-v2-fresh-dependency-review-20261009/controlled-execution-review.json. Fourteen existing files, both CIDs, accepted image manifests/configs, original v1 rootfs seals, full OCI hashes, transactions, network declarations and 39-file runtime/observer closure are retained. No original input file is overwritten or recopied: the fourteen bindings remain at the existing draft; only the two new dependency documents will be written to a new private operator context after approval.

## Actual evidence and failures retained

Fresh scan/source producer: GioNob/ouf-semantic-registry, commit ab1667d08f80737d63a9be2715036d505cb702c6, run 37894554849, artifact 11599718815, ZIP SHA256 113ab1bce6031e2700ce2eeeefe61fd24140956c42a2923a66ae50e6771a3b7a. Scan and public Sigstore attestation succeeded (11 subjects); parent job concluded failure when root-owned output blocked bundle copy. It is not described as a green producer run.

Independent readback: ouf-deploy run 37894929681 / job 113704024082 PASS. Six actual subjects cryptographically verified against the exact public producer workflow, commit and ref. The shared actual Sigstore bundle was recovered from the verified records, without repeating scans. Artifact 11599489979, ZIP SHA256 acd592af6d96bcb716ca2f49573fd91d33114b96579b9d2f9ae33ad8af605c72. Downloaded ZIP, six subject bytes and bundle hash were independently matched here. Bundle SHA256 68407fa1d1b3cceaa5f6ec0445b6847e93e3ab728704775a93b1ca6b3245c333.

Earlier ouf-deploy fresh scan run 37894061727 succeeded in scanning but failed attestation persistence because user-owned private repositories do not support that feature. Its unsigned reports are not the proposed acceptance subjects. Public producer workflow ownership was fixed at 12e3a132105f56c988962660984888eda1160605 without triggering another scan.

## Bounded pre-key recovery

Operator readback at 08:24:16 reports execution-claim, issued-signatures and role-authority absent, operator-context-claim present, zero private-key reads/lifecycle and runtime unchanged. Prior context xatlxkf6 and denial remain evidence. Cloud did not independently acquire VPS state.

The reviewed bridge consumes only that exact failure. It checks root custody, exact retained context/approval, absent key/lifecycle outputs and original empty wrapper. It preserves old claim/denial in the existing failed context, records an exclusive recovery claim, and uses the corrected intake entry in SHA256-pinned memory, retaining the installed original entry and unchanged runtime source closure. Fixed intake SHA256 69e2ef61a7ee3f598286b50d9460a44ceb51acfe016413a9f23cf52bd076b26a.

Preflight uses a separate root-private empty verifier directory that is removed on success/denial. Actual signature directory, execution claim and private-key reads remain after both role mandates pass. Safe denial retains errorType/errno and public symbolic reasons without raw private data.

Nine local checks pass, including one connected cold sequence: absent future signature directory → both real issuer preflights → eight actual disposable CI signatures → actual authenticated profile publication. These CI keys/fixtures confer no target authority. Target signing, guard switch and controlled cohort admission have not been performed.

After human acceptance is recorded, the existing local authority keys issue two bounded role mandates and the previously approved guarded two-CID transaction may proceed. Mandatory live OCI/rootfs/NIC/peer/generation/guard checks, no automatic retry/rollback, no provider lease grant, no general sudo, no daemon restart, no Teatri job and no release acceptance remain unchanged. Approval cannot suppress a failed target check.

No target command is issued while this review is pending. The prepared bridge explicitly rejects pending human dependency acceptance before recovery mutation.
