#!/usr/bin/env bash
# Private source/configuration staging only. No sudo rule or live guard change.
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufTmp="$(mktemp -d)"
trap 'rm -rf -- "$oufTmp"' EXIT
"$oufGh" api "repos/GioNob/ouf-deploy/contents/scripts/stage-coordinated-provider-owner.py?ref=29e5256f30587fc15cb21688ceb80c46ed4e1a72" --jq .content | base64 --decode > "$oufTmp/stager.py"
printf '%s\n' 'fc0a01b7672e794740a81fa0bc6bf3610a81026127ca0574b62553bd29b44d1d  '"$oufTmp/stager.py" | sha256sum --check --status
for oufRelative in scripts/run_semantic_coordinated_lease_owner.py tools/semantic_provider_coordinated_supervisor.py tools/semantic_provider_lease_coordination.py tools/semantic_provider_lease_owner.py tools/semantic_provider_lease_nft.py tools/semantic_provider_dns.py tools/materialize_southbound_kernel.py tools/materialize_southbound_lease_refresh.py; do
  mkdir -p "$oufTmp/source/${oufRelative%/*}"
  "$oufGh" api "repos/GioNob/ouf-api-gateway/contents/$oufRelative?ref=a10df126d229dfefd9e0a4d716a07f1f535b6cd6" --jq .content | base64 --decode > "$oufTmp/source/$oufRelative"
done
sudo /usr/bin/python3 -I -B - "$oufTmp/stager.py" "$oufTmp/source" <<'OUF_STAGE'
import hashlib,os,stat,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>131072:
        raise SystemExit("STAGER_INPUT_INVALID")
    raw=os.read(fd,131073)
finally:os.close(fd)
if len(raw)!=info.st_size or hashlib.sha256(raw).hexdigest()!="fc0a01b7672e794740a81fa0bc6bf3610a81026127ca0574b62553bd29b44d1d":
    raise SystemExit("STAGER_HASH_MISMATCH")
source_directory=sys.argv[2]
sys.argv=[sys.argv[1],"--source-directory",source_directory]
exec(compile(raw,sys.argv[0],"exec"),{"__name__":"__main__","__file__":sys.argv[0]})
OUF_STAGE
"$oufGh" workflow run privileged-discovery-preflight.yml --repo GioNob/ouf-deploy --ref main
