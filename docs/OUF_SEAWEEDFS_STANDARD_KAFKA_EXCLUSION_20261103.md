# OUF standard candidate: Kafka notification/replication exclusion proposal

Status: **LOCAL QUALIFIED PATCH PROPOSAL, NOT AN ADMITTED OR DEPLOYED GENERATION**.
Base: exact ordered generation29 source. The qualified generation29 image, source lock, scopes and target evidence remain unchanged. Integration with the other lifecycle patches requires a new ordered generation and the full miniPET image/SBOM/scanner/qualification pipeline.

## Decision and compatibility gate

The standard candidate excludes external Kafka as a filer notification provider and replication input. This removes the compiled legacy Shopify Sarama client and its archived rcrowley metrics dependency. The separately preserved IBM Sarama migration proposal is not selected: IBM v1.61.1 still compiles rcrowley, so changing the module namespace alone does not close the lifecycle gap.

**If an actual OUF target requires these external Kafka integrations, this standard profile is not admissible for that target.** Actual target feature binding remains OPEN; this proposal does not infer non-use. A separately qualified maintained client end-to-end would be required. No HUMAN/THS scope is consumed or reactivated. Teatri/Farmacie results are unchanged.

Native SeaweedFS Kafka MQ/protocol code and native SQL/query code remain byte-identical to generation29. Other notification and replication providers remain registered. No target event is silently dropped or acknowledged.

## Behavior

- Kafka remains recognizable under its original provider name; `Initialize`, `SendMessage` and replication `ReceiveMessage` return the explicit `OUF_STANDARD_PROFILE_KAFKA_INTEGRATION_UNSUPPORTED` error. Receive returns no message and no ACK callbacks.
- Filer startup rejects enabled Kafka before caller-option mutation, certificate provider construction, goroutines, DNS refresh, master connections, filesystem/store initialization or another queue initialization. Filer and notification files are read once in their original merge order. Original JWT, CORS, exposed-directory and effective TLS inputs are captured before those merges to preserve prior precedence. The TLS snapshot reads all15 string keys currently consumed by the four existing TLS loaders, including automatic environment overrides and per-target allowlists; certificate providers are constructed only after the guard. This explicit key set must track future `security/tls.go` changes.
- Replication rejects enabled Kafka in its existing input validation/initialization path before constructing its sink. Mixed enabled providers fail existing exclusivity validation before any provider initialization.
- A `kafka` build tag deliberately fails compilation. It cannot reactivate excluded code. Existing elastic/rclone exclusion guards remain unchanged.

## Local qualification

The receipt `evidence/seaweedfs-standard-kafka-exclusion-local-20261103.json` binds exact patch bytes and all retained evidence.

- Focused notification/replication suite:88 test/subtest PASS events plus4 package PASS, zero skips/failures. Includes subprocess rejection of Kafka-only/mixed configurations, direct publish/receive rejection and positive non-Kafka provider selection.
- Filer preflight/snapshot suite:6 test/subtest PASS plus1 package PASS. Four fresh-process cases cover notification file, filer file, merge with a second queue, and environment override. Nil options or nil master discovery, nonexistent store paths and invalid TLS certificate paths prove rejection before construction/effects. Effective TLS snapshots remain unchanged after subsequent config/environment changes.
- Negative control removing only the early guard fails as expected. This is an isolated Go overlay; the frozen proposal source remains unchanged.
- Existing security suite:39 test/subtest PASS plus1 package PASS, including real local TLS health checks.
- Whole `weed` compile PASS; root `go mod tidy -diff` empty; exact indexed patch replay against generation29 PASS.
- Production package closure with CGO disabled:1811→1765 packages,46 removed,0 added. No Shopify Sarama or rcrowley package remains in this selected production graph.

The local developer build and module manifest are evidence for this isolated proposal only, not the hosted generation30 artifact or miniPET runtime qualification. No full replacement image, scanner completion, target migration, disaster recovery pass or all-maintained certification is claimed.

## Root graph limitation

Natural `go mod tidy` removes12 root requirements and changes SCRAM from direct to indirect; it does not upgrade any retained module. Historical module/checksum graph entries remain: Jaeger v1.47.0 requires Shopify Sarama v1.33.0 and rcrowley, and Zipkin v0.4.3 requires rcrowley. These3 edges are absent from the selected production package closure. Jaeger/Zipkin are reachable in the root source graph through the native SQL parser tracing chain. Removing the native SQL/query feature is not authorized by this patch, so the root graph is **not** claimed free of every legacy reference.

The broader candidate29 lifecycle inventory has additional open findings. This patch closes one bounded compiled dependency chain only; it does not close the entire miniPET maintenance requirement.
