# SeaweedFS 4.52 — bucket-policy tests on AWS SDK v2

The twenty-second patch migrates `test/s3/policy/bucket_policy_idempotency_test.go` to maintained AWS SDK Go v2. It preserves the three integration scenarios (policy roundtrip, idempotent PUT and delete/recreate), fixture credentials, HTTP loopback endpoint, region `us-east-1` and path-style addressing. Requests carry the test context; the client has a 30-second HTTP timeout and one SDK attempt. Wrapped `NoSuchBucketPolicy` errors are inspected through `smithy.APIError`.

Four deterministic regressions validate client configuration, signed request and response handling through an in-memory HTTP transport, no retry after a 503 and no request after context cancellation. They are transport fixtures, not live policy-authorization evidence.

Local qualification uses exact source `984eac6a790be89e2a11de175a7413e1e3e32dd3` with the previous 21 patches applied in order. The package compiles with `-mod=readonly`, all four regressions pass and the two changed files reapply byte-for-byte. No dependency pins are modified. The workflow repeats patch application, compilation and the four regressions, then attests the bounded evidence manifest. Hosted outcome is **PENDING** until its actual run is verified.

Direct SDK v1 importers fall from 20 to 19 (12 in `test/s3/iam`, seven elsewhere). The `policy` package still resolves 51 SDK v1 packages in a 1,850-package test graph because `policy_test.go` retains its IAM/S3 clients. This patch does **not** claim closure of that package or the repository-wide module graph.

The exact 15-patch OCI candidate, production binary, release admission and runtime authority are unchanged. MiniPET remains approximately 35% ±10, with 0/8 gates, 0/21 AT and 0/120 real objects copied. Scope17/52 Engine GET, Teatri/M1 and Farmacie are preserved; MinIO remains active. No target operation, replay, reset, grant, release, merge or deploy is performed.

Local evidence: [JSON](../evidence/seaweedfs-bucket-policy-tests-sdk-v2-local-20261103.json). Patch SHA256: `d97a3360ff974525d4e080f2fe7ec8344113cd2f9c27453289034d292a5a4e19`.
