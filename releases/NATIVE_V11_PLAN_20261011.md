# Native V11 private creation plan — 11 October 2026

> **Stato corrente, 11 ottobre 2026:** il piano nativo V11 è bloccato da `CURRENT_R12_PRIVATE_WORKER_UNPROVEN`, prima di ogni scrittura protetta. La lettura diretta del runner alle 20:48 UTC conferma R12 attivo, PID2446150, zero riavvii; non dimostra readiness o lease valide. La prossima operazione è la [diagnosi root di sola lettura](R12_READINESS_DIAGNOSIS_20261011.md), senza apply, restart o reset del budget. CSV Teatri end-to-end resta aperto.


The operator confirmed [EXACT_V11_NATIVE_MANIFEST_IMAGE_CUSTODY_RECONCILED_NO_APPLY](../evidence/v11-manifest-reconciliation-target-20261011.json) at22:04 Europe/Rome: journal VERIFIED/version2, cumulative attempt1, zero new imports, one journal CAS, preserved context, exact config/rootfs and ten layers. No application/DB/provider/lease/firewall effect or domain transition grant occurred. Do not repeat the old import or R12 apply.

The prepared V11 declaration/request still names the config digest836… as the Docker image. The VPS manifest store resolves bd48… instead. The next operation publishes a NEW private review plan with only that creation Image identity changed; the original plans, source bytes and package binding remain retained.

## Qualified implementation

[Pure rebase](../tools/semantic_application_cutover/rebase_native_manifest.py), immutable sourceef5d1045f68f123f84e9c2c299b236aa9e8c3199, SHA2560f1e559b14a481d6b24ee454ff5f6209c08e959579e5fe4a53697395755b6cdf. [Root preparer](../scripts/prepare-native-v11-plan.py), source13529d23b1ada57120c0491c7b3650e5eaf9954b, SHA2561a73d3101ab085fee55137e08d04216f98f6052dde4ab36026d683af5fb26aa2. [Launcher](native-v11-plan-20261011.sh), sourceac89844d6cc2cd4412a1183ce52a601dcafe6f4d, SHA25669ef01ee15cd42c77337604f8142a4b9935cbfba0e0cc96eef979f7e3146b752.

All12 immutable downloaded files are verified before sudo and before root execution; all11 module hashes are checked before any module exec. All8 original publisher subjects are freshly verified. The preparer rehashes the bounded original ZIP and rechecks its fd identity; it authenticates the exact root-owned original declaration/request and VERIFIED import record, reconstructs its original context from the sealed importer constants and compares fresh native manifest/config/rootfs proof with the exact digest recorded by the qualified reconciler. The proof explicitly distinguishes config identity from native manifest identity. No image re-envelope/load or import journal write occurs.

| Retained binding | Value |
|---|---|
| Config image digest | sha256:83635be46d1fe61dea08597ea4488980b4349e5f6e0ed8bbd3ab6f5e2686370e |
| Native Engine manifest ID | sha256:bd48ab35db0441b1f4f48422e7190adaff176a61cddde5f981d93e496ad4b24a |
| Original declaration hash | ffc02da66a08fb1f1b06c143ef0f2aa18d68a6fb7b2bfaa616a812aa37eabe0f |
| Original creation request hash | 798de748a4fcc0d8c2b6eb70f3577430d690729a4a03bc00ebbf3adcae765836 |
| Original source | 8a2e84b32d4ce2bdc3bc529b56afb5663ab133e3 |

The unchanged qualifiedPackageBinding keeps the original config digest/source/ZIP lineage. A separate nativeImageBinding links the actual manifest descriptor and config digest to the preserved import context/version/native evidence and predecessor hashes. Image byte custody remains distinct from actual container runtime OCI and application transition authority.

Before private publication, the same sealed R12 reader verifies current two-flow finite native leases, reciprocal peer generation and all4 existing input files. The preparer recompiles the OLD request against current native application/host facts and requires exact equality; it recompiles the NEW request and permits only Image to change. Worker generation, authorization hash, semantic frame and declaration must remain stable, refreshCount may only advance, and final image/journal/private-plan/native frames are rechecked. No waits, retries, claims, budgets or shared lease locks are added. Existing HUMAN binding is only read for retained command/config custody.

[Final CI38171296773](https://github.com/GioNob/ouf-deploy/actions/runs/38171296773), job114564283363 SUCCESS:13 new rebase/source/delivery tests,8 existing creation tests,9 existing R12 custody tests. These deny all24 download/tamper positions,8 publisher failures,12 root bootstrap tamper positions and11 module tamper positions before execution, plus stale/unverified/changed evidence and generation/authorization/configuration regressions. The actual isolated containerd fixture verifies original signatures/archive/layer bytes, imports once, actually exits after the effect, reopens the durable journal, reconciles without replay and compiles the native plan using the actual Engine proof. Private declaration/host facts and authority checkpoints in CI are fixtures; the full target root preparer has not yet executed. All13 immutable remote program/module/launcher files were independently compared with hash-qualified local sources. [Qualification projection](../evidence/native-v11-plan-qualified-20261011.json).

## Necessary operator operation

The existing runner cannot sudo/read these protected root inputs. This command creates only4 new root-private drafts: declaration, creation request, observations and receipt. Existing plans, import history and R12 are untouched. Private draft publication is sequential, not atomic; an incomplete directory confers no execution permission. All application readiness/authority/transport/full OCI flags remain false. A failed custody/read never permits import replay, input reset or automatic retry.

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_LAUNCH="$(mktemp "$HOME/ouf-native-v11-plan-launch.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/releases/native-v11-plan-20261011.sh?ref=ac89844d6cc2cd4412a1183ce52a601dcafe6f4d' > "$OUF_LAUNCH"
  printf '%s  %s\n' '69ef01ee15cd42c77337604f8142a4b9935cbfba0e0cc96eef979f7e3146b752' "$OUF_LAUNCH" | sha256sum -c -
  bash "$OUF_LAUNCH"
)
```

Return only OUF_CURRENT_NATIVE_V11_PLAN= and the launcher exit/phase/output. Success must report onlyCreationImageIdentityChangedtrue, importJournalWrites0, imageImports0, cumulativeImportEffectAttemptCount1 and all4 existing inputs verified. New private hashes/directory are review artifacts, not authorization.

The next cutover work must bind the resulting native declaration/request to fresh finite application transition authority and composed producer/DB/lease fencing, backup, exclusive old endpoint release, actual full OCI/reciprocal peer/transport attestation, migration admission and application readiness. Historical Cinema8 objects must remain preserved. Teatri13-row CSV→run→ACK→object search remains OPEN; this plan cannot claim that acceptance.
