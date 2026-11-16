#!/usr/bin/env bash
# Runbook task-56 (D-042): correzione antenati 0711 e risigillatura del rootfs dei successori R3 nello stato dopo il create.
# Uso:  bash b1-rootfs-v3.sh plan               (sola lettura; crea solo le 4 directory vuote 0700 delle viste)
#       bash b1-rootfs-v3.sh apply <planSha256> (chmod degli antenati ammessi e risultato esclusivo sotto /var/lib/ouf-storage-migration)
# Nessuna operazione sui container (niente create/start/rm), nessuna firma, nessun segreto letto.
set -euo pipefail
umask 077
C=bad45365ef03dce6804de5d8520bee2c4b90a67b
[[ $C != 0000000000000000000000000000000000000000 ]] || { echo 'pin commit da impostare dopo review D-001' >&2; exit 2; }
B=https://raw.githubusercontent.com/GioNob/ouf-deploy/$C
S=/etc/ouf/deploy-snapshots
M=/var/lib/ouf-storage-migration
INSTALL=$S/semantic-provider-r3-install-v1
DOCS=$INSTALL/versions/4/documents
A=85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef
SB=622a150067244ae8dbb4ac0f1889bc9e4b9823ed761820495f5c0849738dbc0d
PREV=$M/semantic-provider-b1-rootfs-20261115-post-create/result.json
PREV_SHA=6f42e319a8c9ba3fe1385b6b2ea814aa40df77ce814b3b4ae60c6afb430905f9
SUCC=$M/semantic-provider-preparation-a2-20261113/successors.json
SUCC_SHA=394562b4162e8d1b615a6b61897446c8316b37e7a438fa99b389dbb5f119dfdb
DOCKER_SHA=7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40
AFP_SHA=b8ce85ca15bbf6e3036fb74aa5998bd7c086cbc4ee00b58f2b7ec0978368ac35
SFP_SHA=c4aacda822aaffb5662318b81c250b1bc9b390b5aa495d5bde4e87692f805323
# Same installed sealer closure used by the B1 v1 run (task-18/21), never a new copy.
MANIFEST_SHA=fb797f12eb838bfdc5eae7cd28617f6d7d17531968d710735df248354496e250
V=/var/lib/ouf-mountpoint-0711-views
STATE=$HOME/.ouf-mountpoint-0711-state
mode=${1:-}
case "$mode" in
  plan) ;;
  apply) hash=${2:?planSha256} ;;
  *) echo 'uso: plan | apply <planSha256>' >&2; exit 2 ;;
esac
fetch() {
  sudo install -d -m 0700 "$D/$(dirname "$1")"
  curl -fsS "$B/$1" | sudo tee "$D/$1" >/dev/null
  printf '%s  %s\n' "$2" "$D/$1" | sudo sha256sum --check --status
  sudo chmod 0600 "$D/$1"
}
if [[ $mode == plan ]]; then
  D=$(sudo mktemp -d "$S/semantic-provider-mountpoint-0711-source.XXXXXXXX")
  sudo chmod 0700 "$D"
  printf '%s\n' "$D" > "$STATE"
  fetch scripts/prepare-semantic-provider-b1-rootfs-v3.py 29899e5ee25aa9e772f21fb62fb473706cdf2b8f921034efeccb3b284d350397
  fetch scripts/prepare-semantic-provider-b1-rootfs.py 8107d055fe0bfd8fe363506f39ffa006f157a292a54bbcbf4de11b011816178d
  fetch tools/semantic_image_rootfs/prepare_provider_image_rootfs.py cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32
  fetch tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5
  fetch tools/semantic_stopped_rootfs/rootfs_difference_report.py cb7b14165da33fcec227f5c9394cb5e640980b4c9be97a6289b9bbc801de8115
  fetch tools/semantic_stopped_rootfs/rootfs_image_equivalence.py 5c4fcb28a979ca2d83bcf0bdbbb7d03599170875e30b56de63874891cb79e028
  for r in adapter southbound; do
    for n in image container; do sudo install -d -m 0700 "$V/$r-$n"; done
  done
else
  D=$(cat "$STATE")
fi
[[ $D == "$S"/semantic-provider-mountpoint-0711-source.* ]] || { echo 'stato non valido' >&2; exit 2; }
MOUNT_SHA=$(sha256sum /usr/bin/mount | cut -d' ' -f1)
UMOUNT_SHA=$(sha256sum /usr/bin/umount | cut -d' ' -f1)
AOC=$INSTALL/registry/$A/epochs/2/bundle/config.json
SOC=$INSTALL/registry/$SB/epochs/2/bundle/config.json
AOC_SHA=$(sudo sha256sum "$AOC" | cut -d' ' -f1)
SOC_SHA=$(sudo sha256sum "$SOC" | cut -d' ' -f1)
echo "mount $MOUNT_SHA umount $UMOUNT_SHA"
echo "oci adapter $AOC_SHA southbound $SOC_SHA"
args=(
  --date 20261116
  --previous-result "$PREV" --previous-result-sha256 "$PREV_SHA"
  --a-successors "$SUCC" --a-successors-sha256 "$SUCC_SHA"
  --source "$S/semantic-provider-v2-offline-rootfs-s3BU0nDX/source" --source-manifest-sha256 "$MANIFEST_SHA"
  --docker /usr/bin/docker --docker-sha256 "$DOCKER_SHA"
  --mount /usr/bin/mount --mount-sha256 "$MOUNT_SHA"
  --umount /usr/bin/umount --umount-sha256 "$UMOUNT_SHA"
  --adapter-frame-policy "$DOCS/adapter/frame-policy.json" --adapter-frame-policy-sha256 "$AFP_SHA"
  --adapter-oci-config "$AOC" --adapter-oci-config-sha256 "$AOC_SHA"
  --adapter-image-view "$V/adapter-image" --adapter-container-view "$V/adapter-container"
  --southbound-frame-policy "$DOCS/southbound/frame-policy.json" --southbound-frame-policy-sha256 "$SFP_SHA"
  --southbound-oci-config "$SOC" --southbound-oci-config-sha256 "$SOC_SHA"
  --southbound-image-view "$V/southbound-image" --southbound-container-view "$V/southbound-container"
)
X=(sudo /usr/bin/python3.13 -I -B "$D/scripts/prepare-semantic-provider-b1-rootfs-v3.py")
if [[ $mode == plan && ${DIAG:-0} == 1 ]]; then
  # Read-only plan with a traceback of the first unexpected error (code paths only, never contents).
  sudo /usr/bin/python3.13 -I -B - "$D/scripts/prepare-semantic-provider-b1-rootfs-v3.py" --plan "${args[@]}" <<'PY'
import importlib.util, sys, traceback
path = sys.argv[1]; sys.argv = [path, *sys.argv[2:]]
spec = importlib.util.spec_from_file_location("reseal", path); m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
original = m.observe
def observe(*a, **k):
    try:
        return original(*a, **k)
    except Exception:
        traceback.print_exc(file=sys.stderr); raise
m.observe = observe
raise SystemExit(m.main())
PY
elif [[ $mode == plan ]]; then "${X[@]}" --plan "${args[@]}"; else "${X[@]}" --apply --plan-sha256 "$hash" "${args[@]}"; fi
