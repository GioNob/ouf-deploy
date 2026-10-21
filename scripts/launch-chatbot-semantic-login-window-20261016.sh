#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile; nessuna esecuzione sudo.' >&2; exit 1; }
ouf_stage="$(mktemp -d "$HOME/ouf-semantic-login-window.XXXXXXXX")"
while read -r ouf_path ouf_sha ouf_name; do
  "$ouf_gh" api "repos/GioNob/ouf-deploy/contents/$ouf_path?ref=29363efbaf1d509aae02e7b7819ef3f57e1593da" --jq .content |
    base64 --decode > "$ouf_stage/$ouf_name"
  printf '%s  %s\n' "$ouf_sha" "$ouf_stage/$ouf_name" | sha256sum --check -
done <<'SOURCES'
scripts/reopen-chatbot-semantic-login-window-20261016.py 82f408108a929ffcf5dfc7250dce1c83f436f9ff379e0545edf13e72c2424148 execute.py
tools/semantic_policy_token_owner/iam_binding_candidate.py dcfab9f362ddfd9be95dcd41ee8281d5cecc074918e4ed3995e19dd17da1801b iam_binding_candidate.py
tools/semantic_policy_token_owner/migration_root_custody.py 1b8aaa23d26ad9b6e04d7b61eead1af1f80ad4c6cd131d48c21ce7e183b207c2 migration_root_custody.py
tools/chatbot_file_cohort/continued_owner.py 028abe1a046e11a83d14ffb9e3ab80acc59febdab58ea3b97def2cc8bc435601 continued_owner.py
tools/chatbot_file_cohort/review.py fa595c5cc12108653e1ac06a4cc04433d5e2f69345720ce70787b7b51b837432 review.py
tools/chatbot_file_cohort/human_session.py 11dc195dfa0fa63a35e9ba3bf0b6a65fd73e3d76be7efa9fed8b4d2f852e8d75 human_session.py
tools/semantic_policy_token_owner/installed_owner.py 786e2725770730fd6be50bdf59e7657e3f3ee5c3399d70e31888a51d19a9adae installed_owner.py
tools/semantic_policy_token_owner/supervisor.py 1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf supervisor.py
SOURCES
echo "Log della sessione: $ouf_stage/run.log"
echo 'Fasi tecniche 8/8; funzionali 0/6. Login scaduto: serve consenso esplicito a una nuova finestra, senza azzerare i 42 tentativi OAuth.'
echo 'Prima RIAPRO LOGIN, poi browser e revisione APPROVO separata. Massimo 86 ulteriori richieste OAuth, cumulativo 128.'
echo 'Usa questo solo terminale. Dopo APPROVO resta in primo piano per massimo un’ora; nessun rinnovo automatico.'
sudo /usr/bin/python3 -I -B -S - "$ouf_stage" <<'PY' 2>&1 | tee "$ouf_stage/run.log"
import hashlib,json,os,stat,subprocess,sys,tempfile
from pathlib import Path
assert os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
expected={
 'execute.py':'82f408108a929ffcf5dfc7250dce1c83f436f9ff379e0545edf13e72c2424148',
 'iam_binding_candidate.py':'dcfab9f362ddfd9be95dcd41ee8281d5cecc074918e4ed3995e19dd17da1801b',
 'migration_root_custody.py':'1b8aaa23d26ad9b6e04d7b61eead1af1f80ad4c6cd131d48c21ce7e183b207c2',
 'continued_owner.py':'028abe1a046e11a83d14ffb9e3ab80acc59febdab58ea3b97def2cc8bc435601',
 'review.py':'fa595c5cc12108653e1ac06a4cc04433d5e2f69345720ce70787b7b51b837432',
 'human_session.py':'11dc195dfa0fa63a35e9ba3bf0b6a65fd73e3d76be7efa9fed8b4d2f852e8d75',
 'installed_owner.py':'786e2725770730fd6be50bdf59e7657e3f3ee5c3399d70e31888a51d19a9adae',
 'supervisor.py':'1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf'}
modules={
 'iam_binding_candidate':'iam_binding_candidate.py',
 'migration_root_custody':'migration_root_custody.py',
 'tools.chatbot_file_cohort.continued_owner':'continued_owner.py',
 'tools.chatbot_file_cohort.review':'review.py',
 'tools.chatbot_file_cohort.human_session':'human_session.py',
 'tools.semantic_policy_token_owner.installed_owner':'installed_owner.py',
 'tools.semantic_policy_token_owner.supervisor':'supervisor.py'}
commit='29363efbaf1d509aae02e7b7819ef3f57e1593da'
parent=Path('/etc/ouf/deploy-snapshots')
assert parent.resolve()==parent
for path in (parent,*parent.parents):
 s=path.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and not s.st_mode&0o022
pin=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
# Preserve this code-only root copy for subsequent exact review/readback.
directory=Path(tempfile.mkdtemp(prefix='semantic-token-executor-code-',dir=parent));directory.chmod(0o700)
for name,sha in expected.items():
 fd=os.open(Path(sys.argv[1])/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=131072
  raw=os.read(fd,131073)
  assert len(raw)==before.st_size and pin(before)==pin(os.fstat(fd)) and hashlib.sha256(raw).hexdigest()==sha
 finally:os.close(fd)
 target=directory/name
 with target.open('xb')as output:output.write(raw);output.flush();os.fsync(output.fileno())
 target.chmod(0o600)
package={'sourceCommit':commit,'executorSha256':expected['execute.py'],
 'sourceHashes':{module:expected[name]for module,name in modules.items()}}
with (directory/'package.json').open('x')as output:
 json.dump(package,output,sort_keys=True,separators=(',',':'));output.flush();os.fsync(output.fileno())
(directory/'package.json').chmod(0o600)
result=subprocess.run([sys.executable,'-u','-I','-B','-S',str(directory/'execute.py'),str(directory),commit],
 stdin=subprocess.DEVNULL,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},timeout=11000)
raise SystemExit(result.returncode)
PY
