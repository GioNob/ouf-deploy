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

Before writing a target provisioner, locate the already staged observer and source manifests in the exact existing package `/etc/ouf/deploy-snapshots/semantic-admission-package-20261004-055825`. Prior preflight reported source-package receipt SHA256 `080c9f710024e392a84a8f5104f8c6edf56b90eaf3e2488a924e084a2f2c65c0`, but did not expose package file routing. The current root action needed is only a bounded filename listing of that package, no private-key/config-value read or mutation. Do not download, install or fabricate a different observer without checking the existing one.

## Completion goal

After provider admission, activate the reviewed Semantic/MCP configuration and necessary discovery grants. Use the existing Teatri asset (`6609b245-86ed-4315-8ce0-73f2a8555bf3`) for national discovery, chatbot semantic mapping/review, human approval, onboarding, ingestion and UDP readback. Product operations must use the MCP-compatible chatbot, not SSH. No Teatri reupload, local fallback or repeat of completed tests. Continue beyond milestones and update the user at least once per minute; stop only for genuinely required user intervention. Infrastructure sudo remains operator-only.
