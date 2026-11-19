# SeaweedFS 4.52 — final root-module IAM/S3 test importers migrated

Patch 26 migrates `test/s3/policy/policy_test.go` and `test/s3/normal/iam_test.go` to AWS SDK Go v2. The policy test uses the bounded S3 client from patch 22, SDK v2 multipart models and wrapped Smithy errors. Both IAM clients preserve custom endpoints, fixture credentials and their explicit regions (`us-east-1` for policy; `us-west-2` for normal), while adding test contexts, one SDK attempt and a 30-second HTTP timeout. The multipart exercise retains admin fixture credentials and therefore does not prove enforcement of the created user's policy.

The new test-only requirement `github.com/aws/aws-sdk-go-v2/service/iam v1.64.6` comes from official tag commit `c350990c95a551ec1bb7b30a76d25bce33ecd389`. Its module/archive checksums were obtained through the normal Go proxy and checksum database, not inferred. It requires the already pinned core v1.47.5, configsources v1.5.8, endpoints/v2 v2.8.8 and Smithy v1.28.7; no existing dependency version is changed.

## Verified local scope

- Both packages compile with exact published pins and `-mod=readonly`.
- Eight new top-level tests and five subcases pass. They cover IAM Query form bytes, custom-endpoint SigV4 scopes, XML models, NoSuchEntity/DeleteConflict errors, a single attempt on server failure, and cancellation before network transmission.
- Combined with patch 22/23 regressions: 16 top-level tests and eight subcases pass across two packages.
- The merged `normal`/`policy` test graph contains 1,803 packages and zero SDK v1 packages.
- Direct source importers fall from 11 to nine: zero in the root module, nine in the separate IAM module.
- Six changed files reapply byte-for-byte after patches 1–25.
- The production graph is byte-identical to the qualified 15-patch cohort: 1,811 packages, SHA256 `cb2536b10d73bc04e587c257a75a622c6b3cf855f1d232f26dba246b43b03f4a`.
- Rebuilt production binary is also byte-identical: SHA256 `85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033`.

The workflow reapplies all 26 patches, verifies the remaining importers, repeats compilation and deterministic tests, and checks the exact production graph and binary hashes before attesting the bounded evidence. Hosted qualification is **PENDING** until the actual workflow result is read back.

These are in-memory transport fixtures and source/build proofs, not live authorization, target acceptance or release admission. The root module still contains optional `elastic`/`rclone` dependency edges requiring separate treatment; zero direct source importers does not establish eradication from the complete module graph. The exact 15-patch OCI candidate remains unchanged. Licence/custody gates remain open.

MiniPET remains approximately 35% ±10: 0/8 gates, 0/21 AT, 0/120 real objects. MinIO remains active. Scope17/52 Engine GET, Teatri/M1 and Farmacie are preserved. No target operation, replay/reset/grant, release, merge or deploy was performed.

[Local evidence](../evidence/seaweedfs-root-iam-tests-sdk-v2-local-20261103.json). Patch SHA256: `f3fc1c0c20b04c4885efd0ce747fad2d52822116510379e0c337a5ba73d6b883`.
