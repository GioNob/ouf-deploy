# Provider v2 admission: next target step — 8 October 2026

## Target state

The operator completed stopped creation in `/etc/ouf/deploy-snapshots/semantic-provider-v2-stopped-resume-k5mmsudx`, source SHA256 `2a9fc3d2861faa2e15370c70979b171cb63b2e09a2dfef1e2895ca27fa663861`. The full receipt is `evidence/discovery-provider-v2-stopped-creation-target-20261008.json`.

- Adapter CID: `f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67`; Docker manifest/image ID `sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc`; verified config `sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320`.
- Southbound CID: `1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916`; Docker manifest/image ID `sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366`; verified config `sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04`.

Both candidates were never started. Mounts, startup and configured addresses were verified. All 96 pre-existing container states were preserved. One image was imported during recovery. No daemon restart, firewall write, provider call, authority-key read or runtime-allowlist update occurred. Configured address metadata does not prove live namespace allocation. No start or release acceptance was granted.

Do not repeat stopped creation or run Docker start. The runtime allowlist is still empty.

## Required implementation

Creation-only intent issuance and the runtime broker already exist in reviewed Gateway source `ace683b1019f79adaace86796b67e463b93ec12e`. The existing authority profile is `/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json`, hash `7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18`.

The target transaction-specific provisioner/orchestrator is not yet implemented. It must assemble per-CID creation mandate, verified frame policy, node-attestor v4 observer binding, final-approval producer, broker/preparer profiles and durable journals, then complete reviewed actual-OCI and namespace/guard/lease admission. It must preserve independent image/config digest bindings and existing source/authority custody. CI or locally generated booleans cannot replace signed complete authorization.

The operator has now installed and verified the source package at `/etc/ouf/deploy-snapshots/semantic-provider-v2-producers-Vj1CmjRH`. Apply and verify both returned PASS. This package contains the 26 reviewed Gateway sources and the reviewed frame observer. The raw operator output is retained at `evidence/discovery-provider-v2-producers-target-20261008.txt`; it is operator evidence, not an independently fetched target receipt. Some printed source hashes have missing characters, so do not reconstruct an authoritative root receipt from that pasted output. Use the sealed package manifest for canonical source hashes.

The source-only receipt explicitly leaves broker, preparer, node attestor, installer approval, runtime adapter, trust-policy consumption and startup authorization uninstalled/unconfigured. The previously registered runtime remains separate and has an empty candidate allowlist. No further filename listing or repeated source installation is required.

### Concrete integration defect

Gateway runtime v4 normalizes Docker's generated OCI rootfs and network namespace paths, hashes that document, and sends only the hash to broker `authorize-create` before creating the runc process. Node attestor v4 later requires the observer policy hash to equal the creation intent's artifact hash. The owner OCI reviewer requires byte-canonical equality between the entire actual OCI document and `expectedOci` in that immutable policy. No transaction-specific compiler for that independently prepared, complete target OCI policy is present in the reviewed source closure. The native test fixture supplies its OCI document directly and is not a target Docker policy compiler.

Consequently the remaining work is code integration, not another operator diagnostic. The implementation must resolve the binding of runtime-generated paths and exact OCI acceptance without copying observed values into an authority claim, weakening the complete-policy check, granting default-runtime starts, or treating source custody/CI success as deployment acceptance. It also needs the signed live-acceptance authorization and final-approval issuance paths, not just configuration JSON.

A valid completion proof must exercise the actual Docker/containerd create/start path against the controlled runtime, prove that application code stays blocked until admission, reject mismatched policy/rootfs/namespace facts, and leave existing containers untouched. No target start command is ready.

## Completion goal

After provider admission, activate the reviewed Semantic/MCP configuration and necessary discovery grants. Use the existing Teatri asset (`6609b245-86ed-4315-8ce0-73f2a8555bf3`) for national discovery, chatbot semantic mapping/review, human approval, onboarding, ingestion and UDP readback. Product operations must use the MCP-compatible chatbot, not SSH. No Teatri reupload, local fallback or repeat of completed tests. Continue beyond milestones and update the user at least once per minute; stop only for genuinely required user intervention. Infrastructure sudo remains operator-only.
