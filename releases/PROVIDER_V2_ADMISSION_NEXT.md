# Provider v2: target state and next action — 8 October 2026

## Completion goal
Use the existing Teatri asset through the MCP chatbot: national semantic discovery, mapping, human approval, onboarding, ingestion and UDP readback. The complete product flow has not yet been demonstrated. No Teatri reupload is required.

## Completed target work
Both exact v2 candidates remain never started. Verified images, startup configuration, TLS inputs, private launch files and private frame policies are prepared. The frame policy receipt is retained in evidence/discovery-provider-v2-frame-policies-target-20261008.json. These policies are drafts; their receipt does not grant creation acceptance or start authorization.

The independent Docker 29.8.1 fixture passes complete OCI comparison with two adapter networks and three southbound networks. Run 37753252302, source f39f8ad980a8912f4c5eb4794c5cbab05bd048f8. It proves the tested compiler/Engine behavior, not actual target admission.

The target network handover passed in run 37755104626, source 66f389b82aae1981e934cdb9c001b08d5a9aa940. Five exact declarations were released from the two never-started predecessors and pinned to the v2 candidates. Predecessor containers, images, files and states were retained. All 96 earlier container states were verified unchanged. There were 15 network attachment metadata operations, no application lifecycle operations, no firewall writes and no private key reads. Live allocation and live interface binding remain unproven. Receipt: evidence/provider-v2-network-handover-target-20261008.json.

Adapter: f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67. Internal 172.21.0.3 / 02:42:ac:15:00:03 / oufint0; egress 172.22.0.3 / 02:42:ac:16:00:03 / oufeg0.
Southbound: 1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916. Backend 172.18.0.14 / 02:42:ac:12:00:0e / oufback0; internal 172.21.0.2 / 02:42:ac:15:00:02 / oufint0; egress 172.22.0.2 / 02:42:ac:16:00:02 / oufeg0. Existing alias and zero gateway priorities were preserved.

Do not repeat creation, image import, network apply or network handover. Durable claims retain the blocked first attempt and completed handover. Do not manually start the candidates; the registered runtime candidate allowlist remains empty.

## Required next work
The transaction-specific provisioner is not complete. It must bind exact expected OCI and frame-policy artifact hashes to the existing installation authority, creation-only issuer, node-attestor v4, final approval producer, broker/preparer and runtime allowlist. Complete rootfs acceptance, actual namespace/guard/lease admission and rejection evidence must be proven before application release. Independently signed complete authorization cannot be replaced by unsigned preparation/CI flags.

The fixed reader scripts/read_provider_v2_admission_manifest.py reads only the six hash-bound private policy/context/template files and the existing hash-bound installation authority profile. It emits expected application hashes, public identity/resource facts and authority/key bindings. It reads private application policy bytes but prints no environment, argument or source-file content. It never reads private key files, signs, writes configuration or invokes Docker. It does not grant approval.

The self-hosted runner has no general sudo and cannot read these root-private files. The preparation workflow publishes a source-hash checked, read-only operator command at /home/oufadmin/ouf-v2-admission-manifest-read-v2.sh. Executing that fixed command supplies the private-input manifest needed for the remaining transaction implementation. No start command is ready.

## Remaining product work
After actual provider admission, activate reviewed Semantic/MCP images and configuration with migration-aware rollback and necessary discovery grants. Discovery MCP bindings, human semantic review/adoption, final onboarding approval and ingestion execution still require deployment/verification. Existing Teatri asset: 6609b245-86ed-4315-8ce0-73f2a8555bf3. Continue through ingestion and UDP readback via chatbot; infrastructure preparation is not the acceptance result.

## Reader correction

The operator's first private read returned a generic blocked error. The reader's direct readonly lookup reproduces a KeyError on the frozen writable-root southbound baseline, which omits that optional field. The v2 reader handles the omitted field as false without modifying or normalizing the original OCI document. Four tests include both frozen role baselines and preservation of original application hashes. Stage and exception class are now reported without raw errors or secret values. Target success remains pending operator execution of the new v2 read command. Do not rerun the original reader or network handover.
