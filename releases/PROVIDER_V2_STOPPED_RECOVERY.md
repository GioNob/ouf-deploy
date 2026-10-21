# Provider v2 stopped recovery — 8 October 2026

This recovery supersedes the suspended stopped-creation bootstrap. Do not repeat the original apply.

The operator proved that the imported adapter image ID `sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc` is an OCI manifest whose config digest is the byte-qualified `sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320`. Docker rootfs and startup readback matched. The earlier expected-config-ID absence probe did not establish that no image had been imported. The original creation code could import successfully and then fail while inspecting an unsupported config-digest reference on the containerd image store.

The recovery uses the frozen archives in `/etc/ouf/deploy-snapshots/semantic-provider-v2-stopped-create-a2kbzv6l`, checks that no creation receipts or target candidate names exist, verifies all archive bytes/layers/accounts again, and derives the OCI manifest/config relationship from the archives. It also recognizes a uniquely selected linux/amd64 OCI index. It uses the actual Docker image ID while retaining the original config digest as a separate verified binding. It reuses an already present, matching image and loads only a missing image. Docker load stdout/stderr are retained privately on failure.

All original registration, authority, trust, input, network and empty-allowlist requirements remain. A new recovery snapshot holds the transaction claim and per-container IDs. Old snapshots and candidates are preserved. New containers remain stopped, with no published ports or start authority. There is no Docker restart, firewall change, provider call or automatic cleanup/replay.

## Validation

Final source commit: `900c2e0607e67788be44ed2d99af415838128387`.
Source SHA256: `2a9fc3d2861faa2e15370c70979b171cb63b2e09a2dfef1e2895ca27fa663861`.
Real isolated Docker CI [37729973288](https://github.com/GioNob/ouf-deploy/actions/runs/37729973288) passed on both classic and containerd image stores. It exercised actual image export/import, OCI config/manifest/index resolution, full stopped-container readback, duplicate planned IP metadata, preservation of an existing running fixture, and refusal of start by the sealed empty runtime. Host guard custody is simulated in CI; target release/admission remains unproven.

Next target result expected: `CREATED_STOPPED_AND_READBACK_VERIFIED`, with actual container IDs and separate config/manifest/image identities. Those IDs are required for the subsequent signed admission transaction. Product completion still requires national discovery and the semantic/onboarding/ingestion/UDP path through MCP with human approval.
