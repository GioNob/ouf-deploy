#!/usr/bin/env bash
# Human launcher. Verify an already downloaded public artifact, then import only.
# No container stop/create/start; plan/apply is a separate, reviewed human step.
set -euo pipefail
test "$#" = 5 || { echo 'usage: bash install-ingestion-operational-receipt-public-archive-20261112.sh ARTIFACT_DIR MANIFEST_SHA256 EXPECTED_IMAGE_ID DOCKER_BIN DOCKER_SOCKET' >&2; exit 2; }
ouf_artifact=$(realpath -e -- "$1")
ouf_manifest_sha=$2
ouf_image=$3
ouf_docker_bin=$4
ouf_docker_socket=$5
[[ "$ouf_manifest_sha" =~ ^[a-f0-9]{64}$ && "$ouf_image" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 2
[[ "$ouf_docker_bin" = /* && "$ouf_docker_socket" = /* ]] || exit 2
cd -- "$ouf_artifact"
printf '%s  manifest.json\n' "$ouf_manifest_sha" | sha256sum --check --status -
# Anchor every delivered executable and the image to the approved CI manifest.
python3 -I -B - "$ouf_image" <<'PY'
import hashlib,json,pathlib,sys
m=json.loads(pathlib.Path('manifest.json').read_text())
assert m['sourceCommit']=='01756a5a22ddc88beba270b7645a64440b1e5a7b'
assert sys.argv[1] in m['imageIds']
def sha(p):
    h=hashlib.sha256()
    with pathlib.Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()
assert sha('image.tar.gz')==m['archiveSha256']
expected={'scripts/apply-ingestion-operational-receipt-20261112.py',
          'scripts/install-ingestion-operational-receipt-public-archive-20261112.sh',
          'scripts/launch-ingestion-operational-receipt-20261112.sh',
          'tools/acquisition_read_native/retained_mac.py'}
assert set(m['files'])==expected
for p,s in m['files'].items():assert sha(p)==s
PY
sudo env DOCKER_API_VERSION=1.44 "$ouf_docker_bin" --host "unix://$ouf_docker_socket" --config /nonexistent load --input image.tar.gz >/dev/null
ouf_actual=$(sudo env DOCKER_API_VERSION=1.44 "$ouf_docker_bin" --host "unix://$ouf_docker_socket" --config /nonexistent image inspect "$ouf_image" \
  --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}')
test "$ouf_actual" = "$ouf_image 01756a5a22ddc88beba270b7645a64440b1e5a7b"
printf '%s\n' "$ouf_actual"
