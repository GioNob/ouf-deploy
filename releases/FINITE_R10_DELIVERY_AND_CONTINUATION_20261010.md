# R10 recovery delivery and continuation — 10 October 2026

## Current result

R10 implementation is qualified at source commit `cd8f43d38a302af318d35890b7c83cd96fe14607`. The [native workflow 38077471178](https://github.com/GioNob/ouf-deploy/actions/runs/38077471178), job 114287350645, passed. Its logs were read: sixteen deterministic tests, actual systemctl service probes and executable hashes, both nft families with strict seconds ceilings, transient zero-TTL resampling across two fresh cycles, and persistent zero-TTL revocation with replay denial. Original installed sources were preserved; target operations were zero.

The [immutable delivery commit](https://github.com/GioNob/ouf-deploy/commit/bedfb47128bcf8356edc25744ffe3b0ea372739c) adds the launcher and its delivery tests. Four local delivery tests pass, including all seven download-failure cases, all seven checksum-failure cases, exact isolated sudo bootstrap arguments and post-download entrypoint tamper denial. Hosted [delivery CI38084153556](https://github.com/GioNob/ouf-deploy/actions/runs/38084153556), job114306998945, is SUCCESS; all four test results and logs were read.

**No R10 VPS activation result has been received in this continuation.** Delivery qualification is not live activation, continuous liveness, application health or release acceptance.

## Scope and temporal binding

The existing source-bound reference is `OUF_FINITE_LEASE_R10_DELEGATED_RECOVERY_20261010T204700_CEST`. The immutable executor admits initial execution from 20:47 until strictly before **22:47 Europe/Rome on 10 October 2026** (18:47–20:47 UTC). This continuation changes neither the reference nor its timestamps. Repository read/write authorization does not extend this privileged target window.

R10 rechecks the exact two existing R8 process generations, the owned QUIESCED journal, empty finite flow sets, unchanged configuration/source/executable custody, and the consumed R9 evidence before claiming once. R9 is retained as failed after 795 renewals with NFT_SET_TTL_UNPROVEN; it is never replayed or reset.

The new transient unit is `ouf-semantic-provider-lease-finite-r10.service`; the new exclusive claim is `/etc/ouf/provider-finite-lease-recovery-r10.claim`. Only the new sealed nft-seconds and adaptive-supervisor delta closure is used. Every refresh uses bounded fresh DNS and finite kernel membership. Stop/failure revokes; automatic restart and boot enablement are disabled. This operation does not import images, recreate containers, perform application cutover, change grants or issue provider requests from the worker.

The registered window gates initial application and worker startup; it is not a two-hour maximum duration of a successfully admitted supervisor. The claimed worker remains bound to the admitted process generations and stops on failure/stop/reboot. Do not interpret successful activation as permanent liveness.

## One operator command

Execute once on the VPS using the already authenticated GitHub CLI. This command verifies the launcher before running Bash; the launcher downloads and verifies all seven source components before invoking one isolated sudo Python bootstrap. Root revalidates the entrypoint and executes the verified in-memory bytes. No downloaded bytes are evaluated by a shell pipeline.

```bash
(
set -euo pipefail
umask 077
OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
OUF_R10_LAUNCHER="$(mktemp "$HOME/ouf-finite-r10-launch.XXXXXXXX")"
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/releases/provider-finite-r10-approved-20261010.sh?ref=bedfb47128bcf8356edc25744ffe3b0ea372739c" > "$OUF_R10_LAUNCHER"
printf '%s  %s\n' '32f583c66bde515387f4b70c60b60c0d8b16af6ae016a353df82457db7589d62' "$OUF_R10_LAUNCHER" | sha256sum -c -
bash "$OUF_R10_LAUNCHER"
)
```

Launcher SHA256: `32f583c66bde515387f4b70c60b60c0d8b16af6ae016a353df82457db7589d62`.

Keep the entire output through `OUF_FINITE_R10_APPLY_EXIT`, including the output path, and report it before any follow-up operation. A success must contain `TWO_FLOW_LEASE_ACTIVE_AND_RENEWED` plus matching active service/worker evidence and native membership for both flows. A denial can already have consumed the new claim: do not rerun automatically, reset claims, reuse R9 or silently extend the bound window. Review retained evidence first.

## Product continuation and normative boundaries

L0 Matrix v1.7 and the applicable PETs remain binding. Producer operational truth, Authorization owner enforcement, Gateway mediation, human-only THS decisions and durable evidence are preserved. No whole-platform PET acceptance is asserted by this lease recovery.

Preserve Cinema delivery/materialization 8/8 and current canonical Cinema search 3/3/2, terminal cursor null and partial=false. Teatri upload/profile is already acquired. Publisher signatures and public trust bytes have been verified separately; do not repeat consumed preparations. Application cutover, remaining negative/minimization/cursor/audit/storage and multi-file acceptance, and reusable clean-host installation remain open. Consolidate the file loop before native vertical API PULL v2.3.
