#!/usr/bin/env bash
# Pinned delivery only; runtime changes are in the qualified Python controller.
set -euo pipefail
ouf_work=$(mktemp -d /tmp/ouf-semantic-application.XXXXXX)
trap 'rm -rf -- "$ouf_work"' EXIT
ouf_base='https://raw.githubusercontent.com/GioNob/ouf-deploy/c52804add2b26f5f9dad6e84073844cdc75aa880'
if [ -n "${OUF_SEMANTIC_CANDIDATE_ZIP:-}" ]; then
  ouf_zip=$OUF_SEMANTIC_CANDIDATE_ZIP
else
  if ! command -v gh >/dev/null 2>&1; then
    printf '%s\n' '{"status":"DELIVERY_INCOMPLETE","reason":"GITHUB_CLI_OR_LOCAL_CANDIDATE_ZIP_REQUIRED","serviceChanges":false}'
    exit 2
  fi
  ouf_zip="$ouf_work/candidate.zip"
  if ! timeout 300 gh api --method GET repos/GioNob/ouf-semantic-registry/actions/artifacts/13066396654/zip > "$ouf_zip" 2> "$ouf_work/github.stderr"; then
    printf '%s\n' '{"status":"DELIVERY_INCOMPLETE","reason":"CANDIDATE_DOWNLOAD_FAILED","serviceChanges":false}'
    exit 2
  fi
fi
python3 - "$ouf_zip" <<'PY'
import hashlib,pathlib,sys
p=pathlib.Path(sys.argv[1]);assert p.is_file() and p.stat().st_size==203419418,'candidate archive size differs'
h=hashlib.sha256()
with p.open('rb') as f:
 while b:=f.read(1048576):h.update(b)
assert h.hexdigest()=='1a7045ffb39486f2579fb342d7fd881f5a123f74a0810d353bce3c755bfc76ba','candidate archive hash differs'
PY
for ouf_file in \
  scripts/read-analysis-discovery-runtime-20261107.py \
  scripts/read-discovery-contract-20261108.py \
  scripts/apply-gateway-analysis-delta-20261108.py \
  scripts/upgrade-semantic-v11-v12-20261108.py \
  scripts/upgrade-semantic-application-20261108.py \
  tools/acquisition_read_native/retained_mac.py \
  releases/semantic-migration-source-20261108.json \
  releases/semantic-migration-helper-20261108.json
do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    "$ouf_base/$ouf_file" -o "$ouf_work/${ouf_file##*/}"
done
(
  cd "$ouf_work"
  sha256sum -c - <<'SHA256'
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
7064c8443bb323c12a56846267e4faa9cb25bf3e6dfb35455e753fbe71ce8b01  apply-gateway-analysis-delta-20261108.py
af319a963f8556f5feb7459d369afe1e362f482562cb674d8a6028c5f1a128cc  upgrade-semantic-v11-v12-20261108.py
2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1  upgrade-semantic-application-20261108.py
cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce  retained_mac.py
b1ae156656b6b89f4fb20e3a7611d23a46bbcda8bc05aa2c27c42becde21c438  semantic-migration-source-20261108.json
13ea1d621cadc703e2f67b099f4f719ffcb46447a093454233efa7f64c40c4b0  semantic-migration-helper-20261108.json
SHA256
)
sudo python3 -I -B "$ouf_work/upgrade-semantic-application-20261108.py" "$ouf_zip"
