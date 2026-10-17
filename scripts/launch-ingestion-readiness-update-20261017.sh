#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile.' >&2; exit 1; }
ouf_stage="$(mktemp -d "$HOME/ouf-readiness-execution.XXXXXXXX")"
echo 'Scarico solo il codice verificato; uso le immagini private gia preparate. Tecniche8/8; funzionali1/6.'
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/execute-ingestion-readiness-update-20261017.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/execute.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/runtime.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/runtime.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/releases/ingestion-readiness-execution-selection-20261017.json?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/case.json"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/iam_binding_candidate.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/iam_binding_candidate.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/migration_root_custody.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/migration_root_custody.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/continued_owner.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/continued_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/review.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/review.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/human_session.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/human_session.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/gateway.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/gateway.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/installed_owner.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/installed_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/supervisor.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/supervisor.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/image_custody.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/image_custody.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/entry.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/mcp_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/authority.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/mcp_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/permit.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/mcp_permit.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/plan.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/mcp_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/session.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/mcp_session.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/owner.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/mcp_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/native.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/mcp_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/entry.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/readiness_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/authority.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/readiness_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/plan.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/readiness_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/owner.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/readiness_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/native.py?ref=1b487b8d90ef54928adfd6156fee55e8e3cc7b2e' --jq .content | base64 --decode > "$ouf_stage/readiness_native.py"
printf '%s  %s\n' \
 '517b1f4d910430d236b9e16c5c05368f349cc791bf9b21a5e679fda16bae8d61' "$ouf_stage/execute.py" \
 '9b75c379881c9fead1f7cd97db553557770688d19f57fe453bb8ba0a6cc3fb38' "$ouf_stage/runtime.py" \
 'fc015d7d68f04dd98a8e4ba6be5da7b171e1af8cb773b9a8c7e2783c2fc50e67' "$ouf_stage/case.json" \
 'dcfab9f362ddfd9be95dcd41ee8281d5cecc074918e4ed3995e19dd17da1801b' "$ouf_stage/iam_binding_candidate.py" \
 '1b8aaa23d26ad9b6e04d7b61eead1af1f80ad4c6cd131d48c21ce7e183b207c2' "$ouf_stage/migration_root_custody.py" \
 '1d64e5bf7540dd8c3bee5c40e15d0b9fc0541600317b2f7ad53639e42d0904df' "$ouf_stage/continued_owner.py" \
 'fa595c5cc12108653e1ac06a4cc04433d5e2f69345720ce70787b7b51b837432' "$ouf_stage/review.py" \
 '11dc195dfa0fa63a35e9ba3bf0b6a65fd73e3d76be7efa9fed8b4d2f852e8d75' "$ouf_stage/human_session.py" \
 '5e7182d899a25a299b103d63f6bf81822280f09e58b963c38f735aa2a4fee72f' "$ouf_stage/gateway.py" \
 '5455d56e973f6c6d9a35900193ac50dab44147a9bd7dedfa13d356bd91901cba' "$ouf_stage/installed_owner.py" \
 '1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf' "$ouf_stage/supervisor.py" \
 '9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2' "$ouf_stage/image_custody.py" \
 '0207289f77a735e446a49a0a40bb7d667706cef265595530bf28a3d42139da16' "$ouf_stage/mcp_entry.py" \
 '36079b8394c06a96c719081c98ee244ffb827e8133582b9579cd300a780bec54' "$ouf_stage/mcp_authority.py" \
 '85825789906152ba43c5c28fb0b502820f18d9a86a47bac59e47aca29e3f9103' "$ouf_stage/mcp_permit.py" \
 'abfd55c5e25aa0323aec43ce3e90a34073680267a127a3ad4994013316f28c82' "$ouf_stage/mcp_plan.py" \
 'a05e9722923a333444400cd60df296bac1277dcaf44c6d94d9e0adca9336c620' "$ouf_stage/mcp_session.py" \
 'c9fe376bcb1d83c1139b8216920e1c797022a6e73a8d78d6c30c89c17d1ad775' "$ouf_stage/mcp_owner.py" \
 '7ecc130876b88fead82f371b29f797751d6bf78530891c89ff1526504cf5034a' "$ouf_stage/mcp_native.py" \
 '2be394b68e5b5e4cf004814aaa020f5139496e161609ad6d9341c5849f5d5696' "$ouf_stage/readiness_entry.py" \
 '94d4718ed9091de55cf9cd67fc7ecc2265a9db822e5c367e55c4c252773a494c' "$ouf_stage/readiness_authority.py" \
 'f6ab1ae11208cc058aff861ce918db1a246056540b1f6ebe9cbc4983e565ec6c' "$ouf_stage/readiness_plan.py" \
 '4ec7b297bc5154dad2426a7cc7fcc09379c0d36404bcf97c68be825a2b7ab560' "$ouf_stage/readiness_owner.py" \
 '3bf1096eeea0cf6b3fa2c3bef3ac54eb8795ef81e43cfea91d79eba09bd002e3' "$ouf_stage/readiness_native.py" | sha256sum --check -
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/releases/ingestion-readiness-scoped-code-package-20261017.json?ref=1cfa7ec55cef65c9cc174ea37bd66aba5677d3dc' --jq .content | base64 --decode > "$ouf_stage/package.json"
printf '%s  %s\n' '10114cc5bf02d6e3699650c0cdf0bbd71c8871ff32547767841d9e94c5458674' "$ouf_stage/package.json" | sha256sum --check -
echo "Log della sessione: $ouf_stage/run.log"
echo 'Prima RIAPRO LOGIN e browser; poi APPROVO worker (188+128=316) e APPROVO rollout separato.'
echo 'Lascia questo terminale aperto sul PC. Il worker dura massimo un ora; Ctrl-C cancella. In caso di STOP conserva il log.'
sudo /usr/bin/python3 -u -I -B -S - "$ouf_stage" <<'ROOTPY' 2>&1 | tee "$ouf_stage/run.log"
import hashlib,json,os,re,stat,sys,tempfile
from pathlib import Path
assert os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
os.umask(0o077)
source=Path(sys.argv[1])
def read(name,expected,maximum=262144):
 assert re.fullmatch('[A-Za-z0-9_.-]+',name)
 fd=os.open(source/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);assert stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum
  raw=bytearray()
  while len(raw)<=maximum:
   part=os.read(fd,min(65536,maximum+1-len(raw)))
   if not part:break
   raw.extend(part)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  assert len(raw)==before.st_size and pin(before)==pin(os.fstat(fd))and hashlib.sha256(raw).hexdigest()==expected
  return bytes(raw)
 finally:os.close(fd)
manifest_raw=read('package.json','10114cc5bf02d6e3699650c0cdf0bbd71c8871ff32547767841d9e94c5458674');package=json.loads(manifest_raw)
assert package['sourceCommit']=='1b487b8d90ef54928adfd6156fee55e8e3cc7b2e'
files={'package.json':manifest_raw,'execute.py':read('execute.py',package['executorSha256']),
 'runtime.py':read('runtime.py',package['loaderSha256']),'case.json':read('case.json',package['caseSha256'])}
# Only this verified bootstrap's static overlay declaration selects source names.
ns={'__name__':'readiness_stage_metadata'};exec(compile(files['execute.py'],'<verified-bootstrap-stage>','exec'),ns)
assert set(package['sourceHashes'])==set(ns['OVERLAYS'])
for module,(name,path)in ns['OVERLAYS'].items():files[name]=read(name,package['sourceHashes'][module])
parent=Path('/etc/ouf/deploy-snapshots')
for p in(parent,*parent.parents):
 s=p.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
code=Path(tempfile.mkdtemp(prefix='ingestion-readiness-executor-code-',dir=parent));code.chmod(0o700)
for name,raw in files.items():
 fd=os.open(code/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 finally:os.close(fd)
fd=os.open(code,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
print('OUF_READINESS_EXECUTOR_CODE='+str(code),flush=True)
sys.argv=[str(code/'execute.py'),str(code),'1b487b8d90ef54928adfd6156fee55e8e3cc7b2e','10114cc5bf02d6e3699650c0cdf0bbd71c8871ff32547767841d9e94c5458674']
exec(compile(files['execute.py'],'<verified-scoped-readiness-bootstrap>','exec'),{'__name__':'__main__'})
ROOTPY
