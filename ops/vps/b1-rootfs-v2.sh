#!/usr/bin/env bash
# Runbook task-49 (D-040): risigillatura del rootfs dei successori R3 nello stato dopo il create.
# Uso:  bash b1-rootfs-v2.sh plan               (sola lettura; crea solo le 4 directory vuote 0700 delle viste)
#       bash b1-rootfs-v2.sh apply <planSha256> (scrive solo il nuovo risultato sotto /var/lib/ouf-storage-migration)
# Nessuna operazione sui container (niente create/start/rm), nessuna firma, nessun segreto letto.
set -euo pipefail
C=12226de8aa9c6b95f154778b4ec1f617947006dd
B=https://raw.githubusercontent.com/GioNob/ouf-deploy/$C
S=/etc/ouf/deploy-snapshots
M=/var/lib/ouf-storage-migration
INSTALL=$S/semantic-provider-r3-install-v1
DOCS=$INSTALL/versions/4/documents
A=85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef
SB=622a150067244ae8dbb4ac0f1889bc9e4b9823ed761820495f5c0849738dbc0d
PREV=$M/semantic-provider-b1-rootfs-20261113-a2/result.json
PREV_SHA=0a542c899013a657415c838ad0856a6c4ba14a54504e4eba324a6472f6f4cbda
SUCC=$M/semantic-provider-preparation-a2-20261113/successors.json
SUCC_SHA=394562b4162e8d1b615a6b61897446c8316b37e7a438fa99b389dbb5f119dfdb
DOCKER_SHA=7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40
AFP_SHA=b8ce85ca15bbf6e3036fb74aa5998bd7c086cbc4ee00b58f2b7ec0978368ac35
SFP_SHA=c4aacda822aaffb5662318b81c250b1bc9b390b5aa495d5bde4e87692f805323
MANIFEST_SHA=1facc62fb7dff0617d1bc0cb9cd69d3df091d0ebae89794a6a008604b749503b
V=/var/lib/ouf-reseal-views
STATE=$HOME/.ouf-reseal-state
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
  D=$(sudo mktemp -d "$S/semantic-provider-reseal-source.XXXXXXXX")
  sudo chmod 0700 "$D"
  printf '%s\n' "$D" > "$STATE"
  fetch scripts/prepare-semantic-provider-b1-rootfs-v2.py eebc67fcbedbc34fb85ed99ddcfa1b6e328fabf943a0f6a7b7d08a41bcc37ccd
  fetch scripts/prepare-semantic-provider-b1-rootfs.py 8107d055fe0bfd8fe363506f39ffa006f157a292a54bbcbf4de11b011816178d
  fetch tools/semantic_image_rootfs/prepare_provider_image_rootfs.py cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32
  fetch tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5
  fetch tools/semantic_stopped_rootfs/rootfs_difference_report.py cb7b14165da33fcec227f5c9394cb5e640980b4c9be97a6289b9bbc801de8115
  fetch tools/semantic_stopped_rootfs/rootfs_image_equivalence.py 5c4fcb28a979ca2d83bcf0bdbbb7d03599170875e30b56de63874891cb79e028
  fetch tools/semantic_cohort_admission/cohort-draft/sources.json 1facc62fb7dff0617d1bc0cb9cd69d3df091d0ebae89794a6a008604b749503b
  fetch tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_admission_preparer.py 67b40905ab00ab397b67c5de9a0f5256ca2e69163b92880bc66462b6d2ec973b
  fetch tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_creation_intent.py 38a2b9c4fc7206d1d73b750316f1a7257e1da32857114775d185aea70a4d1dca
  fetch tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_deployment_broker.py 943ebeaee7d714ea5b00e59a1bac680803bff097b7f9e7cb2f218a26c61bf140
  fetch tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py acf9c5140b700fbb4448d4b8eccd3d3ae3f7e6af5e173aa0474965ad170e6141
  fetch tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_installer_approval.py 13e6d8cbec328d678f8f190bb2706606a22625329c1740f2b9c96fa4526d13e0
  fetch tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_node_attestor.py d0aa3bf56ebe6f69a324ab3260da60a737ab1508cec8adb644801999b29af191
  fetch tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_preexec_hook.py 3489f894c45f182f0a2179bf431a8cc5bde6fe94bc4d9bfda67e134a23fde143
  fetch tools/semantic_cohort_admission/cohort-draft/scripts/stage_semantic_local_producers_package.py 12411ff383c29f64d37158626415a15c3acc8303d6dae729703ab0c8f0bb0028
  fetch tools/semantic_cohort_admission/cohort-draft/tools/materialize_semantic_shared_faces.py 66986436206e9448e0bad58b651f4802a53e54eb179327c7050d963c22f33b62
  fetch tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel.py 98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de
  fetch tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_lease_refresh.py 1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_creation_intent.py 04d33434c23054ff96d8b03b44f7e65746b76317d9b2931db5b8223227f54314
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_admission.py fccde9a325939b400a95dc5e8714755727ed57b476b01c82019a15ffac8f8df4
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py 29e1942733abc74e8eb21eb927427c3e6e39806b06492f1dc614bd0805e53013
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_consumption.py 053e2e5031cd51adf957388296a808cd8ba824dbc2ab671143e756312d050aef
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_producer.py 582371358c769f7724fb76bb17fd5e11530a09ab06c19a3a66351fc77d984776
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_protocol.py 53f5629c3a57de622e51a05f9bf86b29f34328bf5756857afa458fb738f24e15
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_reauthorization.py 866801d9ef955371c66cac61bce7d0f807574ba08406adb39529155514dd818a
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_signing.py b079f11f1175afb3bcf3f2e33bfa3d06fe188a38fd8fa53b0e52d1d80cd31cad
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_dns.py c466172113d1ffe850bf2c69762113b55fbc65d9091c96dca98a74548fddf930
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_installer_approval.py 75b637b792ba1c83da95166f6c16db4c200e5affbd9220875b00de8fdb9b2c72
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_coordination.py e267e0f86637191b9830895930daa35afc10fec733b6957f427ab8a0ccddf587
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_nft.py 7a5f2b21c096228a3e4d298674e380f667c3004dd6d8ec19934a2302844c0f93
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_owner.py 92736eebeccf344e565186bce94d29c65ffe1d50638d57eae81486e7b26e884d
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_node_attestor.py ff1a13cea1c64b5ad76c09cd8b715507ee3f9016bdaf37c74e9804d575c4e91b
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_node_observation.py 5a355a9904b6fc4bf665bb79c438e1cb9f3d11f8c2505b16df9834c046fde9c2
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_peer_bindings.py 4d99b60459d7122b5126d8424fb6233a9f3de15858219cd9061131b23f45af8b
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec.py 53eb9b79efcdca0ffe93bb0c80a582a285caf9126fd97e930fa503b6106eb797
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec_native.py ef0b98c96879933480a26418edc2b971b21a116509ac87cbc39e3b2062e7a528
  for r in adapter southbound; do
    for n in image container; do sudo install -d -m 0700 "$V/$r-$n"; done
  done
else
  D=$(cat "$STATE")
fi
[[ $D == "$S"/semantic-provider-reseal-source.* ]] || { echo 'stato non valido' >&2; exit 2; }
MOUNT_SHA=$(sha256sum /usr/bin/mount | cut -d' ' -f1)
UMOUNT_SHA=$(sha256sum /usr/bin/umount | cut -d' ' -f1)
AOC=$INSTALL/registry/$A/epochs/2/bundle/config.json
SOC=$INSTALL/registry/$SB/epochs/2/bundle/config.json
AOC_SHA=$(sudo sha256sum "$AOC" | cut -d' ' -f1)
SOC_SHA=$(sudo sha256sum "$SOC" | cut -d' ' -f1)
echo "mount $MOUNT_SHA umount $UMOUNT_SHA"
echo "oci adapter $AOC_SHA southbound $SOC_SHA"
args=(
  --date 20261115
  --previous-result "$PREV" --previous-result-sha256 "$PREV_SHA"
  --a-successors "$SUCC" --a-successors-sha256 "$SUCC_SHA"
  --source "$D/tools/semantic_cohort_admission/cohort-draft" --source-manifest-sha256 "$MANIFEST_SHA"
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
X=(sudo /usr/bin/python3.13 -I -B "$D/scripts/prepare-semantic-provider-b1-rootfs-v2.py")
if [[ $mode == plan ]]; then "${X[@]}" --plan "${args[@]}"; else "${X[@]}" --apply --plan-sha256 "$hash" "${args[@]}"; fi
