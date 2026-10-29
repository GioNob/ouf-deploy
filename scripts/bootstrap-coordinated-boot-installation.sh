#!/usr/bin/env bash
# Bounded boot-command transition; no daemon, container or provider activation.
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufTmp="$(mktemp -d)"
trap 'rm -rf -- "$oufTmp"' EXIT
"$oufGh" api "repos/GioNob/ouf-deploy/contents/scripts/install-coordinated-boot-guard.py?ref=9db4d34100d4728f7cb8c19dcb11f5aae2d8c269" --jq .content | base64 --decode > "$oufTmp/installer.py"
printf '%s\n' '4b6a7aacd6683332a303fbfef82ddc9b3eb3bcd25c9baf808efce321271fb46e  '"$oufTmp/installer.py" | sha256sum --check --status
mkdir -p "$oufTmp/source/scripts" "$oufTmp/source/tools"
for oufRelative in scripts/run_semantic_coordinated_boot_guard.py tools/semantic_provider_boot_coordination.py; do
  "$oufGh" api "repos/GioNob/ouf-api-gateway/contents/$oufRelative?ref=df103735c1fe75a31e6d4c752360e9368e6aa52d" --jq .content | base64 --decode > "$oufTmp/source/$oufRelative"
done
"$oufGh" api "repos/GioNob/ouf-deploy/contents/scripts/privileged-discovery-preflight-v3.py?ref=9db4d34100d4728f7cb8c19dcb11f5aae2d8c269" --jq .content | base64 --decode > "$oufTmp/source/privileged-discovery-preflight-v3.py"
sudo /usr/bin/python3 -I -B - "$oufTmp/installer.py" "$oufTmp/source" <<'OUF_INSTALL'
import hashlib,os,stat,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>131072:
        raise SystemExit("INSTALLER_INPUT_INVALID")
    raw=os.read(fd,131073)
finally:os.close(fd)
if len(raw)!=info.st_size or hashlib.sha256(raw).hexdigest()!="4b6a7aacd6683332a303fbfef82ddc9b3eb3bcd25c9baf808efce321271fb46e":
    raise SystemExit("INSTALLER_HASH_MISMATCH")
source_directory=sys.argv[2]
sys.argv=[sys.argv[1],"--source-directory",source_directory]
exec(compile(raw,sys.argv[0],"exec"),{"__name__":"__main__","__file__":sys.argv[0],"__ouf_verified_source__":raw})
OUF_INSTALL
"$oufGh" workflow run privileged-discovery-preflight.yml --repo GioNob/ouf-deploy --ref main
