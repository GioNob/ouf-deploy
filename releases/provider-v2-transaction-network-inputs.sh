#!/usr/bin/env bash
# Capture missing installation metadata only. Never start/apply/register.
set -Eeuo pipefail
umask 077
oufStage=FETCH_READER
trap 'printf "OUF_TRANSACTION_NETWORK_BOOTSTRAP=BLOCKED STAGE=%s REASON=COMMAND_FAILED\n" "$oufStage"' ERR
oufReadDir="$(mktemp -d)"
/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh api \
  "repos/GioNob/ouf-deploy/contents/tools/semantic_transaction_network_inputs/read_provider_transaction_network_inputs.py?ref=9c185b51db4cb116167d5ce0e457587003e1d7b6" \
  --jq .content | base64 --decode > "$oufReadDir/read.py"
oufStage=ROOT_NETWORK_INPUT_CAPTURE
sudo /usr/bin/python3 -I -B -c '
import hashlib,json,sys
from pathlib import Path
raw=Path(sys.argv[1]).open("rb").read(65537)
if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:
 print("OUF_TRANSACTION_NETWORK_INPUTS="+json.dumps({"status":"BLOCKED","stage":"READER_SOURCE","reason":"PINNED_READER_BYTES_MISMATCH","secretValuesPrinted":False}))
 raise SystemExit(1)
exec(compile(raw,sys.argv[1],"exec"),{"__name__":"__main__","__file__":sys.argv[1]})
' "$oufReadDir/read.py" "deaebc79c37a59c57866261aa6f34133f3f9c4c1092ec2185af79110a451d961"
