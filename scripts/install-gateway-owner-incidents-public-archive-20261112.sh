#!/usr/bin/env bash
# Verify reviewed artifact then import only. A and B are separate human actions.
set -euo pipefail
test "$#" = 5 || { echo 'usage: bash install-gateway-owner-incidents-public-archive-20261112.sh ARTIFACT_DIR MANIFEST_SHA256 IMAGE_ID DOCKER_BIN DOCKER_SOCKET' >&2; exit 2; }
ouf_artifact=$(realpath -e -- "$1")
ouf_manifest_sha=$2
ouf_image=$3
ouf_docker_bin=$4
ouf_docker_socket=$5
[[ "$ouf_manifest_sha" =~ ^[a-f0-9]{64}$ && "$ouf_image" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 2
[[ "$ouf_docker_bin" = /* && "$ouf_docker_socket" = /* ]] || exit 2
cd -- "$ouf_artifact"
printf '%s  manifest.json\n' "$ouf_manifest_sha" | sha256sum --check --status -
python3 -I -B - "$ouf_image" <<'PY'
import hashlib,json,pathlib,sys
m=json.loads(pathlib.Path('manifest.json').read_text())
assert m['schema']=='ouf.gateway-owner-incidents-archive.v1'
assert m['sourceCommit']=='2a760ca90cf860a6dcae3eef536e87524aa0fa04'
assert sys.argv[1] in m['imageIds']
def sha(path):
    h=hashlib.sha256()
    with pathlib.Path(path).open('rb') as f:
        for raw in iter(lambda:f.read(1048576),b''):h.update(raw)
    return h.hexdigest()
assert sha('image.tar.gz')==m['archiveSha256']
expected={'scripts/apply-gateway-collector-incidents-20261112.py',
          'scripts/apply-gateway-owner-incidents-20261112.py',
          'scripts/apply-ingestion-operational-receipt-20261112.py',
          'scripts/launch-gateway-collector-incidents-20261112.sh',
          'scripts/launch-gateway-owner-incidents-20261112.sh',
          'scripts/install-gateway-owner-incidents-public-archive-20261112.sh',
          'tools/acquisition_read_native/retained_mac.py',
          'collector/operational_incidents.py',
          'docs/OUF_GATEWAY_OWNER_INCIDENTS_DEPLOY_20261112.md'}
assert set(m['files'])==expected
for path,expected_sha in m['files'].items():assert sha(path)==expected_sha
assert sha('collector/operational_incidents.py')=='cbc6ee191a85289efe57b8f0cd8c1d57c16bc3d9bd1910b7eeb8717581292854'
PY
sha256sum --check SHA256SUMS
sudo env DOCKER_API_VERSION=1.44 "$ouf_docker_bin" --host "unix://$ouf_docker_socket" --config /nonexistent load --input image.tar.gz >/dev/null
ouf_actual=$(sudo env DOCKER_API_VERSION=1.44 "$ouf_docker_bin" --host "unix://$ouf_docker_socket" --config /nonexistent image inspect "$ouf_image" --format '{{.Id}}')
test "$ouf_actual" = "$ouf_image"
printf '%s\n' "$ouf_actual"
