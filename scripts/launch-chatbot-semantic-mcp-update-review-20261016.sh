#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]]
ouf_stage="$(mktemp -d "$HOME/ouf-semantic-mcp-update-review.XXXXXXXX")"
ouf_ref='e055287fbe1842512434f7a3b553f52fc962ceb2'
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-chatbot-semantic-mcp-update-review-20261016.py?ref=$ouf_ref" --jq .content | base64 --decode > "$ouf_stage/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/read-chatbot-semantic-mcp-reprocessing-preflight-20261016.py?ref=$ouf_ref" --jq .content | base64 --decode > "$ouf_stage/reader.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/image_custody.py?ref=$ouf_ref" --jq .content | base64 --decode > "$ouf_stage/image_custody.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/actions/artifacts/12059844351/zip' > "$ouf_stage/candidate.zip"
printf '%s  %s\n' \
 '3c7acf9e1a19b135c97e05607ea3293ab9b7eff081351861822d30e929fff809' "$ouf_stage/prepare.py" \
 'cff7fa19d332ba07e2675a6effb336e7877e7b6f24a907b01977f1fb1441ecdb' "$ouf_stage/reader.py" \
 '9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2' "$ouf_stage/image_custody.py" \
 '4924985e236c03976287c7dcb130c4cc579c71499e6c53371b05f3a0cb5ce359' "$ouf_stage/candidate.zip" | sha256sum --check -
echo "Log preparazione privata: $ouf_stage/prepare.log"
echo 'Fasi tecniche 8/8; funzionali 0/6. Solo nuova revisione privata: nessun token, firma, grant, stop o migrazione.'
sudo /usr/bin/python3 -I -B - "$ouf_stage" <<'PY' 2>&1 | tee "$ouf_stage/prepare.log"
import hashlib,os,stat,subprocess,sys,tempfile
from pathlib import Path
assert os.geteuid()==0 and sys.flags.isolated
os.umask(0o077)
expected={
 'prepare.py':('3c7acf9e1a19b135c97e05607ea3293ab9b7eff081351861822d30e929fff809',1048576),
 'reader.py':('cff7fa19d332ba07e2675a6effb336e7877e7b6f24a907b01977f1fb1441ecdb',1048576),
 'image_custody.py':('9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2',1048576),
 'candidate.zip':('4924985e236c03976287c7dcb130c4cc579c71499e6c53371b05f3a0cb5ce359',20000000)}
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_nlink','st_mode','st_size','st_mtime_ns','st_ctime_ns'))
with tempfile.TemporaryDirectory(prefix='ouf-mcp-update-preparer-')as temporary:
 target=Path(temporary)
 for name,(digest,maximum)in expected.items():
  path=Path(sys.argv[1])/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   before=os.fstat(fd);assert stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum
   data=bytearray()
   while len(data)<=maximum:
    block=os.read(fd,min(1048576,maximum+1-len(data)))
    if not block:break
    data.extend(block)
   assert len(data)==before.st_size and pin(before)==pin(os.fstat(fd))==pin(path.lstat())and hashlib.sha256(data).hexdigest()==digest
   with (target/name).open('xb')as output:output.write(data)
   (target/name).chmod(0o600)
  finally:os.close(fd)
 result=subprocess.run([sys.executable,'-I','-B',str(target/'prepare.py'),str(target/'candidate.zip'),str(target/'reader.py'),str(target/'image_custody.py')],
  stdin=subprocess.DEVNULL,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},timeout=190)
 raise SystemExit(result.returncode)
PY
