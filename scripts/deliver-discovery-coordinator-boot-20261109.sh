#!/usr/bin/env bash
# Bind the completed successor to boot; no Docker restart or provider start.
set -euo pipefail
if (( $# != 0 )); then printf '%s\n' 'Usage: successor boot binding (no arguments)' >&2; exit 2; fi
umask 077
ouf_boot_binding_dir=$(mktemp -d /tmp/ouf-boot-binding.XXXXXX)
trap 'rm -rf -- "$ouf_boot_binding_dir"' EXIT
ouf_boot_binding_source='6f378f07921baefd092b0b20b7f6368c0d10dd09'
mkdir "$ouf_boot_binding_dir/core"
for ouf_boot_binding_name in reconcile-discovery-placeholder-20261109.py read-discovery-lifecycle-20261109.py read-discovery-startup-20261109.py read-analysis-discovery-runtime-20261107.py quiesce-discovery-coordinator-20261109.py read-discovery-nft-drift-20261109.py stage-discovery-coordinator-successor-20261109.py activate-discovery-coordinator-boot-20261109.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 --max-filesize 65536 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_boot_binding_source/scripts/$ouf_boot_binding_name" \
    -o "$ouf_boot_binding_dir/$ouf_boot_binding_name"
done
for ouf_boot_binding_name in materialize_southbound_kernel semantic_provider_dns materialize_southbound_lease_refresh semantic_provider_lease_nft semantic_provider_lease_owner semantic_provider_lease_coordination; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 --max-filesize 65536 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_boot_binding_source/tools/semantic_cohort_admission/cohort-draft/tools/$ouf_boot_binding_name.py" \
    -o "$ouf_boot_binding_dir/core/$ouf_boot_binding_name.py"
done
(
  cd "$ouf_boot_binding_dir"
  sha256sum -c <<'SHA256'
94649eefceddc348c92172872bf0cb180c21bd057ae84f7b371d9b2aa6c6259f  reconcile-discovery-placeholder-20261109.py
4824c247ddb7c0c90b8740ebcaa1c2681dccd9efd7811666cb1c86210b322e67  read-discovery-lifecycle-20261109.py
0df0567b786f6d5317951c838062e166a4d5037a07d95a3c145b578949372a89  read-discovery-startup-20261109.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
23028447dbc9980f1e04a3c2f4583d9d9ec16624c9200854955b1ba72e69baa8  quiesce-discovery-coordinator-20261109.py
98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de  core/materialize_southbound_kernel.py
c466172113d1ffe850bf2c69762113b55fbc65d9091c96dca98a74548fddf930  core/semantic_provider_dns.py
1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084  core/materialize_southbound_lease_refresh.py
7a5f2b21c096228a3e4d298674e380f667c3004dd6d8ec19934a2302844c0f93  core/semantic_provider_lease_nft.py
92736eebeccf344e565186bce94d29c65ffe1d50638d57eae81486e7b26e884d  core/semantic_provider_lease_owner.py
e267e0f86637191b9830895930daa35afc10fec733b6957f427ab8a0ccddf587  core/semantic_provider_lease_coordination.py
1c30699b12129fd2c322753167932871a171e744c8d780a31142789eb4326b06  read-discovery-nft-drift-20261109.py
8e9cfe1e8073d33423e11f51e0a790530ec14e3cedbc6a5620a0ecff962e815d  stage-discovery-coordinator-successor-20261109.py
3538db93c67b230cf5aacdb45250df6c39da5f9727528859b8a91c0bfff2ae48  activate-discovery-coordinator-boot-20261109.py
SHA256
)
sudo python3 -I -B "$ouf_boot_binding_dir/activate-discovery-coordinator-boot-20261109.py"
