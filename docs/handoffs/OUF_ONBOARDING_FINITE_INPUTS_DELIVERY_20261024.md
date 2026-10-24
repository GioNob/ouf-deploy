# Onboarding — staged package and fresh metadata input delivery, 24 October 2026

## Actual VPS result

The operator reported ONBOARDING_FINITE_SESSION_PACKAGE_STAGED/Exit0 for /etc/ouf/deploy-snapshots/onboarding-finite-session-ee8b7756f72f82a6. Root protected, imageLoadedfalse, migrations0, activations0, humanBudgets0, targetApplyAuthorizedfalse, releaseAcceptancefalse. Operator log /home/oufadmin/ouf-onboarding-finite-package.2wfZtMWY/operator.log; bootstrap log /home/oufadmin/ouf-onboarding-delivery.7HD1CmAA/bootstrap.log. These are one staging execution and its wrapper, not two applies. Preserve both and never repeat staging.

## Qualified reader and practical limits

scripts/prepare-onboarding-finite-session-inputs-20261024.py at 6061aea966cad60eadcac926ad74eda8f6e210e9, SHA256 232309bf78af54ea238d0046d5104f02dab939cedfb20873bc7ca1a7212f786f. Published bytes read back equal. CI push40079399435/job120829594265:9testsPASS/zeroSkipped in5.470sec; PR40079402575/job120829603153/testedmerge4fc8a75b217566c0f4241b70d9aba6c553aaa555:9testsPASS/zeroSkipped in9.413sec. Direct logs read. Seven actual disposable Docker containers, actual API1.44 metadata, actual process+net/mount namespaces, actual Unix socket GET and substituted-CID rejection. Includes claim exclusivity, root/file custody, tar/config hash, manifest/authority tamper, unchanged coorte/full restored Ingestion frame, multiple changed-generation fixtures and no replay after partial/success. First native fixture failed because CLI default API metadata differed from API1.44; corrected fixture only, no production guard change. Checkout Node20 forced-to24 deprecation warning retained.

Historical journals/reviews/manifest provenance are synthetic fixture inputs, NOT VPS proof. Full installation bootstrap and current target bindings still need real observation; CI is NOT Onboarding DB admission, lifecycle authority, deployment, HUMAN budget or E2E qualification. Existing142-module sealed closure and repair definitions are hash checked and loaded for pure validators only; none of their old command entries is called.

New fixed input-preparation-v1 under the staged package is claimed before any Engine request. At most14 exact GETs, two passes over gateway/onboarding/mcp/udp/completedIngestion/Postgres/Registry; no inventory, applicationHTTP, SQL, credentialfiles, signingkeys, imageimports, Dockerwrites, originalGET or owner action. Current identities come only from retained exact reviewed contexts and completed replacement history. It checks full unchanged pins and original binding profiles, final restored Ingestion frame/process, retained Postgres and Registry generation, same boot and namespaces, repeat stability and retained file hashes. Engine response metadata, including DockerEnv which MAY contain secrets, is saved privately root0400 under0700 and NEVER printed. Private metadata is not a claim that credential values cannot exist in DockerConfig.

The candidate image has only Ubuntu base labels and NO org.opencontainers.image.revision. Its application provenance is the verified CI artifact manifest/commit/hash; do not relabel or rebuild the tested image. Kubernetes/Compose labels are reported only as declarations and cannot establish lifecycle ownership. The old databaseControlProfile is for Ingestion: preserved as evidence, explicitly MUST NOT be rebound to Onboarding. No Onboarding DB profile/admission/privileges/history are established by this capture.

## One operator invocation

Run once as oufadmin. Checksums before/after root copy, helper root exclusive0700/file0400, isolated protected Python, log and exit preserved. The protected interpreter may be rebound to the original reviewed executable. There is no runtime apply authority or APPROVO request in this read-only capture.

```bash
(
  set -euo pipefail
  umask 077
  work=$(mktemp -d "$HOME/ouf-onboarding-inputs.XXXXXXXX")
  log="$work/operator.log"
  : > "$log"
  trap 'rc=$?; trap - EXIT; set +e; printf "\nExit=%s\nDirectory=%s\nLog=%s\n" "$rc" "$work" "$log" | tee -a "$log"; exit "$rc"' EXIT
  {
    gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
    if [ ! -x "$gh_bin" ]; then gh_bin=$(command -v gh || true); fi
    if [ -z "$gh_bin" ] || [ ! -x "$gh_bin" ]; then
      printf '%s\n' 'STOP: client gh esistente assente; nessun sudo eseguito.'
      exit 2
    fi
    "$gh_bin" api --hostname github.com --method GET \
      -H 'Accept: application/vnd.github.raw+json' \
      'repos/GioNob/ouf-deploy/contents/scripts/prepare-onboarding-finite-session-inputs-20261024.py?ref=6061aea966cad60eadcac926ad74eda8f6e210e9' \
      > "$work/prepare.py"
    printf '%s  %s\n' '232309bf78af54ea238d0046d5104f02dab939cedfb20873bc7ca1a7212f786f' "$work/prepare.py" | sha256sum -c -
    sudo -- /bin/bash -c '
      set -euo pipefail
      umask 077
      root=/etc/ouf/deploy-snapshots/onboarding-finite-inputs-232309bf78af54ea
      mkdir -m 0700 -- "$root"
      chown 0:0 -- "$root"
      install -o 0 -g 0 -m 0400 -- "$1" "$root/prepare.py"
      printf "%s  %s\n" 232309bf78af54ea238d0046d5104f02dab939cedfb20873bc7ca1a7212f786f "$root/prepare.py" | sha256sum -c -
      /usr/bin/python3 -I -B -S "$root/prepare.py"
    ' ouf-onboarding-inputs "$work/prepare.py"
  } 2>&1 | tee "$log"
)
```

Expected public status CURRENT_ONBOARDING_COHORT_INPUTS_CAPTURED/complete:true with privateInputsPath/privateInputsHash and engineGetAttempts14. Paste only public JSON, Exit and log path; do NOT print/copy private inputs or Engine responses. On STOP, preserve helper root, fixed claim, partial evidence and log; do not delete, reset, relaunch under another tempdir or consume a new scope automatically. A stop before Engine still does not grant replay.

## Next after true VPS inputs

Construct distinct Onboarding-specific DB channel/admission/migration history+privileges and explicit V34 plan using the retained private metadata. Establish lifecycle owner with actual authority; labels alone cannot authorize replacement. Prepare custody, qualified closure/native entry and exact signed terminal review for only the reviewed migration/deployment delta before effects. Never enable implicit migrations to bypass validate-only. No old completed infrastructure rollout/journal may be replayed.

Only after proven deployment, authenticated HUMAN grant on the same source/version/config (proposed3 additional attempts/900sec, not yet granted), then a separate activation. Preserve started_at/cumulative3/generation4/history/dedup and all ownership/backoff/fencing/current-policy guards. No new IAM login/token requested now. Original Registry GET200 proof is retained, normal420/pub5 is historical and may grow independently; no worker restart/reinstall/reset. Repair/GET/old403/native11 claims consumed.8/8technical4/6functional/G3OPEN, F5/F6/E2E/releaseAcceptance pending. Supervisor follows E2E.
