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

### Compiler and current integration boundary

The pure compiler at `tools/semantic_frame_compiler/compile_creation_frame_policy.py` now resolves seven closed Docker path/identity slots from separate template, launch and context inputs. It does not consume observed OCI. All other fields stay exact, and the owner full-document comparison remains unchanged.

CI [37741307729](https://github.com/GioNob/ouf-deploy/actions/runs/37741307729) passed 12 unit tests and one real isolated Docker test per backend (classic vfs and containerd overlayfs). A second fixture policy was sealed before its OCI existed and subsequently matched the complete generated document. The runtime refused create before runc; no candidate application ran. The fixture template is synthetic, not an independently approved target template. This proves path compilation in those fixtures, not deployment acceptance or the full controlled runtime create/start path. Evidence: `evidence/discovery-provider-v2-frame-compiler-ci-20261008.json`.

The self-hosted read at [37734793698](https://github.com/GioNob/ouf-deploy/actions/runs/37734793698) independently confirms both exact target candidates remain never started, Docker data root is `/var/lib/docker`, and storage driver is `overlayfs`. It did not read private configuration/environment, authenticate a complete context, or prove rootfs admission. Evidence: `evidence/discovery-provider-v2-frame-context-target-20261008.json`.

The operator has completed private launch preparation, frame-policy compilation and the bounded admission-manifest read. The manifest is retained in `evidence/provider-v2-admission-input-manifest-target-20261008.json`. It reports hash-bound inputs, not authenticated context, rootfs acceptance, signed transaction configuration or startup authorization. No repeat of these operator steps is needed.

The stopped-network handover is complete: only five endpoint declarations moved from the two never-started legacy candidates to the exact v2 candidates. Existing container states were preserved. This is metadata preparation, not live kernel address allocation; do not repeat the handover.

### Current code blocker: sibling peer interfaces

The southbound-to-adapter flow requires the actual sibling host-veth index, which does not exist while both candidates remain stopped. A numeric guess would invalidate the admission model. `tools/semantic_peer_bindings/semantic_provider_peer_bindings.py` therefore embeds the peer's complete OCI hash and all approved NIC identities in the immutable transport declaration and resolves the kernel index only after independently observing real runc state and reciprocal links.

Six unit tests pass. Hosted native CI [37760409623](https://github.com/GioNob/ouf-deploy/actions/runs/37760409623) passed with a real runc-created process held before application start; wrong MAC, OCI and extra interfaces were rejected. That run tested the initial declaration representation. The updated embedded-declaration representation needs its own native run. Neither result proves target integration or grants target startup authorization.

The resolver is not yet integrated into broker/preparer/node observation and the final release recheck. The coordinated two-candidate creation path and independently verified complete image/rootfs acceptance remain to be implemented and tested. The next work is source integration; no new operator command is currently required.

Remaining code integration: independently approve the complete per-role target OCI template, authenticate target context, bind compiled policy to creation-only intent and broker/preparer profiles, issue and verify complete signed live acceptance and final approval, and test the actual controlled Docker create/start path and rejection cases. A new runtime version is not presumed necessary solely for generated paths. No target start command is ready.

## Completion goal

After provider admission, activate the reviewed Semantic/MCP configuration and necessary discovery grants. Use the existing Teatri asset (`6609b245-86ed-4315-8ce0-73f2a8555bf3`) for national discovery, chatbot semantic mapping/review, human approval, onboarding, ingestion and UDP readback. Product operations must use the MCP-compatible chatbot, not SSH. No Teatri reupload, local fallback or repeat of completed tests. Continue beyond milestones and update the user at least once per minute; stop only for genuinely required user intervention. Infrastructure sudo remains operator-only.
