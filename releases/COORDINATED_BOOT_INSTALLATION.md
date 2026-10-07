# Coordinated boot command installation, 7 October 2026

This is a bounded infrastructure transition for the existing test VPS. Product operations remain chatbot/MCP-only. It does not authorize a provider start or complete discovery acceptance.

## Exact target binding

The operator's read-only output confirmed these installed bytes:
- /etc/systemd/system/ouf-semantic-boot-guard.service: 0f0791f9e12f4326d811bb2e2c61f6c9c142138056b21632034d72457a026541
- /etc/systemd/system/docker.service.d/90-ouf-semantic-boot-guard.conf: 413d5143ffe75da96ba2101c8c545f5dfb8393053058ef89cebc6221f0d2750d

The installer independently revalidates them and the original complete sealed cohort under the original lock. It uses the immutable owner package at /etc/ouf/deploy-snapshots/semantic-coordinated-owner-package-p0mxeups and new boot source at Gateway df103735c1fe75a31e6d4c752360e9368e6aa52d.

## Concrete action

The reviewed bootstrap is scripts/bootstrap-coordinated-boot-installation.sh at a6ecdc25982d3b70d18d944961614b7977110c95.
Bootstrap SHA256: c6ad494f488920edcf06c74fee278f4ce20568eb39dc7016986e7c80f96d2c59.
It downloads installer/reader bytes from private revision 9db4d34100d4728f7cb8c19dcb11f5aae2d8c269.
Installer SHA256: 4b6a7aacd6683332a303fbfef82ddc9b3eb3bcd25c9baf808efce321271fb46e.
Reader v3 SHA256: 65c8caa661005a7bf4bfe7eb1c5f45932a32c3e024095db861882f6c52998618.

The operator runs it as oufadmin, enters sudo password locally, and supplies the resulting redacted receipt. No general sudo rule is added. The bootstrap then dispatches the existing privileged-discovery-preflight.yml for independent runner readback through the same no-argument sudo capability.

## Effects and preserved state

The action creates one fresh root-private snapshot with ten sealed source files, separate QUIESCED journal without lease/start authority, sealed boot profile, exact old/new unit copies and installation receipt/journal. It changes only ExecStart in the guard unit and ExecStartPre in the Docker drop-in; other bytes and the dependency graph remain unchanged. It atomically updates the bounded reader, preserving its known v2 source at /usr/local/sbin/ouf-discovery-preflight-v2. It reloads systemd definitions and independently checks loaded commands and the unchanged Docker MainPID.

It does not restart/start/stop Docker, providers or any container; does not execute the revoking boot command during installation; does not write nft rules, change credentials/IAM/sudoers, apply database migrations, publish semantics or make provider/DNS requests. The actual staged owner CLI runs only guard mode, read-only.

The v3 reader closes the explicit newly installed receipt/source/unit profile, retains the original independent custody checks, and performs two observations under the original common lock. The historical runtime/source receipts and original journals are never rewritten to claim new acceptance.

## Recovery and failures

Publication accepts only exact prior bytes and modes. It records an attempted publication before rename, so a post-rename fsync failure remains recoverable. On failure it restores every still-owned changed file, preserves foreign bytes, reloads definitions and verifies the old profile. A foreign change or failed recovery remains ROLLBACK_BLOCKED. No failed journal or prepared snapshot is removed. No old apply is automatically replayed.

The active pointer at /etc/ouf/coordinated-boot-installation.json is published only after complete unit/source/kernel readback. An existing pointer refuses a new apply. If the command reports BLOCKED, do not rerun it: retain the output and inspect/reconcile the recorded state first. A transient failure of the final independent reader after complete publication may leave the installation present; a BLOCKED response must never be interpreted as proof that nothing changed.

## Boot and authority limits

The installed command coordinates revocation with the original sealed empty-only restorer. If kernel tables are missing, it suspends lease authority before reconstructing only the owned empty tables. Changed handles require explicit later reconciliation; no cached addresses/TTL or provider authorization are restored. Partial/foreign/nonempty structure is refused. Unrelated rules remain preserved.

Hosted tests use real root-private file publication, the actual isolated owner CLI and nft in a separate namespace. Systemd/custody adapters in the installation fixture are simulated. Prior boot-command tests execute actual isolated root CLI revocation and missing-table restoration. Neither is a real VPS reboot. Target loaded-unit readback and a controlled real reboot remain separate evidence.

The action is not release acceptance. Infrastructure authority, shared-face/live-namespace/spoof/IPv6 enforcement, purpose/TLS/OIDC/revocation admission, active lease lifecycle and real reboot remain open. Old provider/southbound images must not be started. Signed remediated role artifacts, local admission and chatbot grants/tools still need their own acceptance before CLASS/teatro/it,en and the subsequent Teatri-to-UDP flow.

## First target attempt and loader correction

The original bootstrap at 4e9dafd319de5b1466ee11285c0a950426b0af63 failed at the initial extensionless legacy-reader import, before installer target writes. The simulated module adapter masked that error in prior CI. Read-only target run 37684853514/job 113009920494 independently confirms original v2 helper, unchanged loaded commands, active Docker and all three original runtime hashes. That bootstrap is withdrawn. Both loaders now use explicit SourceFileLoader and still compile only hash-verified in-memory bytes; a regression loads the actual extensionless v2 helper through both implementations. Failure output includes controlled stage, phase and snapshot metadata without raw error messages. Corrected bootstrap a6ecdc25982d3b70d18d944961614b7977110c95/source 9db4d34100d4728f7cb8c19dcb11f5aae2d8c269 passed run 37685283731/job 113011401986: 13 unit and 2 isolated native tests, zero skips. Services in installation fixtures remain simulated; actual target loaded-unit observation is still required. The correction is a new attempt after independently confirmed unchanged state, not a replay of a partially applied transaction. Installation remains pending. Evidence: `evidence/discovery-coordinated-boot-installation-loader-fix-20261007.json`.
