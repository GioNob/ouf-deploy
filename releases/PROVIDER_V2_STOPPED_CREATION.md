# Provider v2: create stopped candidates

The installed empty runtime is recorded in `evidence/discovery-provider-v2-runtime-registration-target-20261008.json`. The next target operation imports the two byte-verified remediated image archives when absent and creates only Docker metadata for `ouf-semantic-provider-v2` and `ouf-semantic-southbound-v2`.

The command is bound to the existing registration, startup-input and private-trust snapshots. It preserves the existing network IDs, planned addresses and old candidates. Mounts, numeric users, packaged startup, environment names and values, resource limits and stopped state are checked by readback. The existing container inventory, daemon identity, prepared files, empty runtime allowlist and live network membership must remain unchanged. Image archives are copied to a root-private spool and all layers and account files verified before import.

Docker metadata creation assigns container IDs; it does not run the application or create the admitted OCI process. Those IDs are inputs to the subsequent signed creation-intent and admission transaction. This operation does not issue installation-authority signatures, change firewall rules, publish ports, call the provider, or authorize application start. Live namespace/address allocation and the remaining admission gates are still unproven.

The transaction claim is durable before image import. Each successfully created ID is recorded before further attachments. Failure retains the snapshot and created metadata; do not rerun, adopt or delete a partial result without reviewing it.

## Validation

Real isolated Docker CI [37728138235](https://github.com/GioNob/ouf-deploy/actions/runs/37728138235) passed metadata creation and full startup/mount/network readback with stopped legacy metadata declaring the same IP. It preserved an existing running fixture and proved that the actual sealed empty runtime rejected start. CI fixture images and simulated host guard custody do not establish target admission or release acceptance.

The production script additionally checks root custody and exact target receipt/source/image bindings. The final source commit is `90840b2e8f14b08e8efd7150d929b49fc6568998`, SHA256 `998c43c244be4fe8aca229114580577a0800a9c7b230dc0eec89dd7d61661d05`.

## Product path still to complete

1. Create stopped provider v2 candidates and bind the signed admission transaction to their IDs.
2. Complete actual namespace, guard, lease and provider admission; activate the reviewed semantic/MCP configuration and required capability grants.
3. From the chatbot, use the existing Teatri asset for national discovery, semantic review and human approval, onboarding, ingestion and UDP readback.

No Teatri reupload and no local discovery fallback are part of this path.
