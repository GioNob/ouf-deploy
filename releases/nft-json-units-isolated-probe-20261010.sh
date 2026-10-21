#!/usr/bin/env bash
# Confirm the installed nft JSON units in one disposable network namespace.
(
set -euo pipefail
umask 077
OUF_PHASE=DOWNLOAD_PINNED_ISOLATED_UNIT_PROBE
OUF_DIR=not_created
trap 'OUF_CODE=$?; printf "OUF_NFT_UNIT_PROBE_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
OUF_DIR="$(mktemp -d "$HOME/ouf-nft-unit-probe.XXXXXXXX")"
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/probe_installed_nft_units.py?ref=587455fee0342d8aa603aa587b916fae4f27517a' > "$OUF_DIR/probe.py"
printf '%s  %s\n' '818254e83191eecb232ecc9eaf22e3290e2675627780511d2294401aaa040bf5' "$OUF_DIR/probe.py" | sha256sum -c -
OUF_PHASE=PROVE_SECONDS_IN_NEW_NAMESPACE_NO_HOST_FIREWALL_OR_LEASE_WRITES
sudo /usr/bin/python3 -I -B -c '
import hashlib,pathlib,sys
path=sys.argv[1]
with pathlib.Path(path).open("rb") as stream:raw=stream.read(16385)
if len(raw)>16384 or hashlib.sha256(raw).hexdigest()!="818254e83191eecb232ecc9eaf22e3290e2675627780511d2294401aaa040bf5":raise SystemExit("PINNED_ISOLATED_PROBE_HASH_MISMATCH")
module={"__name__":"sealed_nft_unit_probe","__file__":path}
exec(compile(raw,path,"exec"),module);sys.argv=[path]
raise SystemExit(module["main"]())
' "$OUF_DIR/probe.py" | tee "$OUF_DIR/result.txt"
)
