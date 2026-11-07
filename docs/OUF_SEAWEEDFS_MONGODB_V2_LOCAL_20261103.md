# MongoDB driver v2: isolated local migration prototype

**LOCAL_PASS_NOT_ADMITTED — future lot32, unsealed.** The historical working directory is `mongodb31-stage`; the patch is based on the frozen `maintained30-stage/source`. It does not alter generation30, any hosted image/cohort, the current miniPET gates, MinIO, consumed scopes, Teatri/Farmacie, or HUMAN/THS authorities. No target or GitHub operation was performed for this lot.

The filer MongoDB backend remains compiled and registered. Its two production importers move from `go.mongodb.org/mongo-driver v1.17.9` to the official `go.mongodb.org/mongo-driver/v2 v2.9.2`, tag commit `df261dcb3f58dcedb9464bd8e7cd79f4e6657579`. The Go proxy archive, module checksum and signed sumdb lookup are retained by reference/hash. No alternative driver, custom database client, alias, or MongoDB exclusion is introduced.

Lifecycle wording is deliberately precise: upstream formally deprecated v1 at 1.17.8, but still released security fix 1.17.10 in September2026. Thus this work does not claim that every form of v1 maintenance ceased. The old pin predates that correction; neither an exploitable GridFS path in the filer nor a completed vulnerability qualification is claimed. v2.9.2 is the selected maintained major-version patch, with exact pins.

## Behavior preserved and intentional changes

The `mongodb` store name, `filemeta` collection, directory/name compound unique index, BSON field names and binary `meta` representation are unchanged. Entry protobuf encoding/gzip paths, upsert filters, directory/name matching, KV key splitting, prefix regex quoting, listing ordering/limits and callback behavior remain in the same adapter. Normal URI topology, authentication source/mechanism, credentials, pool override, read/write concern, compression and retryWrites/retryReads settings are preserved within the tested cases. Client TLS certificate/CA loading and the explicit historical insecure option are retained; the latter is not a target security approval.

The v2 API changes require `Connect` without its previously unused context, separate UpdateOne options and option builders. Removed index MaxTime becomes a 10-second context covering the actual index operation, including server selection/network work. A failed index initialization disconnects the new client with an independent bounded cleanup context and does not publish it. This does not establish atomic arbitrary live reconfiguration: existing Initialize field ordering and successful reinitialization lifecycle are outside this prototype's contract proof.

Unacknowledged writes change materially in v2: instead of the old sentinel error, callers must inspect `Acknowledged`. The adapter rejects `w=0` before Connect and checks acknowledgement after all five mutation paths. It also preserves wrapped errors instead of converting FindEntry server/cancellation failures to not-found, and checks cursor errors instead of returning a falsely complete listing. Empty-metadata and empty-KV-value legacy not-found behavior is not redesigned; transactions remain the existing no-op adapter methods, not new multi-document ACID support.

Nonzero legacy `socketTimeoutMS` and `wTimeoutMS` are rejected explicitly, because v2 no longer applies their old options. A consumer must select an explicit `timeoutMS`/context migration with its own budget semantics; the adapter does not silently equate these different limits. Invalid URI and TLS settings remain errors before dependent operations.

The minimum supported server is now **MongoDB4.4**, as required by v2.9.2; Go1.25 is its minimum and the local toolchain is Go1.27.3. An older target requires a separate compatibility decision before adopting this candidate. The real driver rejects a synthetic wire-version8 handshake before sending index DDL. This verifies the denial boundary, not compatibility with every MongoDB4.4+ release.

## Retry distinction

Existing retryWrites/read URI values and driver defaults are not disabled or replaced. Supported MongoDB retryable writes use sessions/txnNumber and server protocol; this is different from replaying arbitrary application mutations. Both selected v1 and v2 sources can retry until the deadline under CSOT, so an unconditional “one retry” statement would be wrong.

v2 introduces adaptive overload retries, default2, for the newer Atlas9+ feature. This profile explicitly sets **maxAdaptiveRetries=0** to preserve the v1 feature boundary. An explicit positive value or `enableOverloadRetargeting=true` is rejected before Connect, rather than ignored. The new feature can be qualified separately. A bounded TCP fixture proves one attempted write and preservation of overload16500 with labels; removing the explicit zero makes the real v2 driver retry into the fixture's canned success, and the same regression test fails. A preliminary code50 experiment did not distinguish the control and is retained as such, not counted as a successful RED proof.

There is no claim of replica-set/sharded failover, server deduplication, durable owner budgets, exactly-once delivery, long-outage recovery, or PITR. The synthetic fixture advertises a standalone server and does not pretend to be a functioning replica set. Most command-contract cases explicitly disable retries to isolate the serializer and responses; the overload case preserves the ordinary driver defaults.

## Qualification obtained

| Evidence | Observed result |
|---|---|
| Final MongoDB contract suite | 31 PASS =13 top-level +18 subtests, zero skip/fail |
| Filer + S3 regressions | 4,846 PASS =1,629 top-level +3,217 subtests; five existing S3 integration skips |
| v1.17.9 comparison using the same common TCP/BSON contracts | Five positive top-level contracts PASS; five known failure-behavior subtests fail, plus their containing test |
| v2 control with acknowledgement checks removed | All five mutation cases fail because the operation returns nil |
| v2 control with adaptive zero removed | The overload regression fails because the operation is retried into success |
| Full final `./weed` link, CGO=0/Linux/amd64/Go1.27.3 | PASS with `-mod=readonly -trimpath -o /dev/null`; no new binary identity or image claimed |
| Final production package graph | 1,740→1,742; 47 removed, 49 added; zero v1 packages, 49 v2 packages |
| Module manifest | v1.17.9 and montanaflynn/stats0.7.1 removed; only v2.9.2 added; all retained module versions unchanged |
| Exact patch replay | All six changed/added files match qualified source bytes |

The tests exercise the real driver over local TCP OP_QUERY/OP_MSG: index definition, entry/KV commands, BSON binary data and metadata roundtrip, missing results, prefix/range/limit queries, callback errors, server/cursor/cancellation errors, acknowledgement handling, SCRAM denial, TLS failure without plaintext fallback and server-version rejection. Authentication success, actual MongoDB query execution/index enforcement, persistent data, compression negotiation, TLS rotation, DNS/SRV, cloud/LDAP/Kerberos/OIDC auth, read/write concern durability and failover remain unproved. A TLS options unit test or canned server response is not a live database qualification.

The regression suite predates only the final adaptive-policy restriction, which was then exercised by the final complete MongoDB suite, new negative control and full final link. Earlier fixture mistakes (BSON length and RawArray API) and the unsuccessful SCRAM fixture setup remain in the work evidence; they are not reported as product failures or final PASS. The auth URI without credentials before explicit overrides is rejected identically by both drivers in a separate comparison.

## Integration and remaining work

Apply `patches/seaweedfs/4.52-mongodb-driver-v2.patch` after the frozen generation30 source. It contains two production files, two test files and go.mod/go.sum. If another future lot already changes module manifests, integrate source/test changes and compose the module delta with one final tidy. The exact receipt, commands, compressed raw outputs, negative-control sources and normative input hashes are in `evidence/seaweedfs-452-mongodb-v2-local-20261103.json` and its evidence directory.

Before admission: reconcile actual MongoDB versions/configuration/consumers; run live supported-server and replica-set tests with successful auth/TLS, index uniqueness, read/write concerns, ambiguous-write reconciliation, restart/restore and session dedup; qualify the final combined source/binary/OCI, dependency scan, SBOM/licenses/provenance and runtime laboratory. A target using legacy timeouts, unacknowledged writes, adaptive opt-in, or an older server requires an explicit compatible profile. No target action is requested by this development receipt, and no miniPET gate/AT is closed by it.

Primary upstream references: [v1 deprecation](https://www.mongodb.com/docs/drivers/go/v1.x/whats-new/), [v2 upgrade changes](https://www.mongodb.com/docs/drivers/go/current/reference/upgrade/), [release notes](https://www.mongodb.com/docs/drivers/go/current/reference/release-notes/), [exact v2.9.2 release](https://github.com/mongodb/mongo-go-driver/releases/tag/v2.9.2), [pinned migration guide](https://github.com/mongodb/mongo-go-driver/blob/v2.9.2/docs/migration-2.0.md). The exact downloaded README, migration guide, go.mod, license and relevant retry source are retained with hashes.
