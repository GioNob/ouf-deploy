#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'Client GitHub non disponibile; nessuna esecuzione sudo.' >&2; exit 1; }
ouf_stage="$(mktemp -d "$HOME/ouf-scoped-mcp-session.XXXXXXXX")"
ouf_source_ref='800b62fd1a03781efefb38e5c2f1595ab27f9206'
while read -r ouf_path ouf_name; do
 ouf_file_ref="$ouf_source_ref"
 [[ "$ouf_name" != case.json ]] || ouf_file_ref="4c99716a60581bf685ef5a91390fa0ad390fb1b0"
 "$ouf_gh" api "repos/GioNob/ouf-deploy/contents/$ouf_path?ref=$ouf_file_ref" --jq .content | base64 --decode > "$ouf_stage/$ouf_name"
done <<'FILES'
tools/semantic_mcp_update/authority.py authority.py
releases/semantic-mcp-scoped-update-v3-selection-20261017.json case.json
tools/chatbot_file_cohort/continued_owner.py continued_owner.py
tools/semantic_mcp_update/entry.py entry.py
scripts/execute-semantic-mcp-scoped-20261017.py execute.py
tools/chatbot_file_cohort/human_session.py human_session.py
tools/semantic_policy_token_owner/iam_binding_candidate.py iam_binding_candidate.py
tools/semantic_policy_token_owner/installed_owner.py installed_owner.py
tools/semantic_policy_token_owner/migration_root_custody.py migration_root_custody.py
tools/semantic_mcp_update/native.py native.py
tools/semantic_mcp_update/owner.py owner.py
tools/semantic_mcp_update/permit.py permit.py
tools/semantic_mcp_update/plan.py plan.py
tools/chatbot_file_cohort/review.py review.py
tools/semantic_mcp_update/runtime.py runtime.py
tools/semantic_mcp_update/session.py session.py
tools/semantic_policy_token_owner/supervisor.py supervisor.py
FILES
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/releases/semantic-mcp-scoped-update-v3-package-20261017.json?ref=4c99716a60581bf685ef5a91390fa0ad390fb1b0' --jq .content | base64 --decode > "$ouf_stage/package.json"
printf '%s  %s\n' \
 '36079b8394c06a96c719081c98ee244ffb827e8133582b9579cd300a780bec54' "$ouf_stage/authority.py" \
 '6e10049d2ecb3e8e8cde0c435a8f99805c4b50f1b2999f861702cb5320cbb963' "$ouf_stage/case.json" \
 'a0d753e14859e70442cd7591c078ba2eec59349a83c1db07fca79364e01ccc34' "$ouf_stage/continued_owner.py" \
 '0207289f77a735e446a49a0a40bb7d667706cef265595530bf28a3d42139da16' "$ouf_stage/entry.py" \
 'b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2' "$ouf_stage/execute.py" \
 '11dc195dfa0fa63a35e9ba3bf0b6a65fd73e3d76be7efa9fed8b4d2f852e8d75' "$ouf_stage/human_session.py" \
 'dcfab9f362ddfd9be95dcd41ee8281d5cecc074918e4ed3995e19dd17da1801b' "$ouf_stage/iam_binding_candidate.py" \
 '985cdb79f45e0eb591b4af29fdf395fa625d9c98099edf38eb387ab50dcc12a4' "$ouf_stage/installed_owner.py" \
 '1b8aaa23d26ad9b6e04d7b61eead1af1f80ad4c6cd131d48c21ce7e183b207c2' "$ouf_stage/migration_root_custody.py" \
 '7ecc130876b88fead82f371b29f797751d6bf78530891c89ff1526504cf5034a' "$ouf_stage/native.py" \
 'c9fe376bcb1d83c1139b8216920e1c797022a6e73a8d78d6c30c89c17d1ad775' "$ouf_stage/owner.py" \
 '85825789906152ba43c5c28fb0b502820f18d9a86a47bac59e47aca29e3f9103' "$ouf_stage/permit.py" \
 'abfd55c5e25aa0323aec43ce3e90a34073680267a127a3ad4994013316f28c82' "$ouf_stage/plan.py" \
 'fa595c5cc12108653e1ac06a4cc04433d5e2f69345720ce70787b7b51b837432' "$ouf_stage/review.py" \
 'd35ed0ea91599c876d94ebba87031b7a53845737a80df876f67387dab8547e20' "$ouf_stage/runtime.py" \
 'a05e9722923a333444400cd60df296bac1277dcaf44c6d94d9e0adca9336c620' "$ouf_stage/session.py" \
 '1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf' "$ouf_stage/supervisor.py" \
 'b003df45158ef05fb6638d5175cbcdfd0a597eb4ae92a22e3ae1bea3adba3fdc' "$ouf_stage/package.json" | sha256sum --check -
echo "Log della sessione: $ouf_stage/run.log"
echo 'Fasi tecniche 8/8; funzionali 0/6. Sessione attiva conservata; file amministrativo UID:GID1000:1000, modo0600, dal mount PostgreSQL in sola lettura.'
echo 'Due APPROVO separati: permesso di un solo tentativo aggiuntivo, poi aggiornamento del solo MCP con backup e migrazione atomica12->13. Nessun dispatch semantico.'
echo 'Lascia aperti il terminale PC e quello del worker. Prima revisione entro08:19:11 CEST. In caso di STOP non rilanciare; incolla il log per riconciliare.'
sudo /usr/bin/python3 -u -I -B -S - "$ouf_stage" <<'PYROOT' 2>&1 | tee "$ouf_stage/run.log"
import hashlib,json,os,stat,subprocess,sys,tempfile
from pathlib import Path
assert os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
os.umask(0o077)
expected={'authority.py': ('36079b8394c06a96c719081c98ee244ffb827e8133582b9579cd300a780bec54', 131072), 'case.json': ('6e10049d2ecb3e8e8cde0c435a8f99805c4b50f1b2999f861702cb5320cbb963', 131072), 'continued_owner.py': ('a0d753e14859e70442cd7591c078ba2eec59349a83c1db07fca79364e01ccc34', 131072), 'entry.py': ('0207289f77a735e446a49a0a40bb7d667706cef265595530bf28a3d42139da16', 131072), 'execute.py': ('b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2', 131072), 'human_session.py': ('11dc195dfa0fa63a35e9ba3bf0b6a65fd73e3d76be7efa9fed8b4d2f852e8d75', 131072), 'iam_binding_candidate.py': ('dcfab9f362ddfd9be95dcd41ee8281d5cecc074918e4ed3995e19dd17da1801b', 131072), 'installed_owner.py': ('985cdb79f45e0eb591b4af29fdf395fa625d9c98099edf38eb387ab50dcc12a4', 131072), 'migration_root_custody.py': ('1b8aaa23d26ad9b6e04d7b61eead1af1f80ad4c6cd131d48c21ce7e183b207c2', 131072), 'native.py': ('7ecc130876b88fead82f371b29f797751d6bf78530891c89ff1526504cf5034a', 131072), 'owner.py': ('c9fe376bcb1d83c1139b8216920e1c797022a6e73a8d78d6c30c89c17d1ad775', 131072), 'permit.py': ('85825789906152ba43c5c28fb0b502820f18d9a86a47bac59e47aca29e3f9103', 131072), 'plan.py': ('abfd55c5e25aa0323aec43ce3e90a34073680267a127a3ad4994013316f28c82', 131072), 'review.py': ('fa595c5cc12108653e1ac06a4cc04433d5e2f69345720ce70787b7b51b837432', 131072), 'runtime.py': ('d35ed0ea91599c876d94ebba87031b7a53845737a80df876f67387dab8547e20', 65536), 'session.py': ('a05e9722923a333444400cd60df296bac1277dcaf44c6d94d9e0adca9336c620', 131072), 'supervisor.py': ('1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf', 131072), 'package.json': ('b003df45158ef05fb6638d5175cbcdfd0a597eb4ae92a22e3ae1bea3adba3fdc', 131072)}
base=Path('/etc/ouf/deploy-snapshots')
for path in(base,*base.parents):
 info=path.lstat()
 assert stat.S_ISDIR(info.st_mode)and info.st_uid==info.st_gid==0 and not info.st_mode&0o022
code=Path(tempfile.mkdtemp(prefix='semantic-mcp-update-executor-code-',dir=base));code.chmod(0o700)
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
for name,(digest,maximum)in expected.items():
 path=Path(sys.argv[1])/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  assert stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum
  raw=bytearray()
  while len(raw)<=maximum:
   part=os.read(fd,min(65536,maximum+1-len(raw)))
   if not part:break
   raw.extend(part)
  assert len(raw)==before.st_size and pin(before)==pin(os.fstat(fd))==pin(path.lstat())
  assert hashlib.sha256(raw).hexdigest()==digest
  target=code/name;out=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   with os.fdopen(os.dup(out),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
  finally:os.close(out)
 finally:os.close(fd)
package=json.loads((code/'package.json').read_bytes())
assert package['sourceCommit']=='800b62fd1a03781efefb38e5c2f1595ab27f9206'and package['mode']=='MCP_UPDATE'
print('OUF_SCOPED_EXECUTOR_CODE='+str(code),flush=True)
result=subprocess.run([sys.executable,'-u','-I','-B','-S',str(code/'execute.py'),str(code),'800b62fd1a03781efefb38e5c2f1595ab27f9206','MCP_UPDATE'],
 stdin=subprocess.DEVNULL,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
raise SystemExit(result.returncode)
PYROOT
