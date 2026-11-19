#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile; nessuna esecuzione sudo.' >&2; exit 1; }
ouf_stage="$(mktemp -d "$HOME/ouf-semantic-token-session.XXXXXXXX")"
while read -r ouf_path ouf_sha ouf_name; do
  "$ouf_gh" api "repos/GioNob/ouf-deploy/contents/$ouf_path?ref=c3e39aaf5783be6428fdb95dff1a3836748c0ce3" --jq .content |
    base64 --decode > "$ouf_stage/$ouf_name"
  printf '%s  %s\n' "$ouf_sha" "$ouf_stage/$ouf_name" | sha256sum --check -
done <<'SOURCES'
scripts/execute-chatbot-semantic-token-session-20261016.py 114a63a7dda897b1c2c275fe3f428b484a9cb9a02d4ffcde53b9a202b2c77e8c execute.py
tools/semantic_policy_token_owner/iam_binding_candidate.py dcfab9f362ddfd9be95dcd41ee8281d5cecc074918e4ed3995e19dd17da1801b iam_binding_candidate.py
tools/semantic_policy_token_owner/migration_root_custody.py 1b8aaa23d26ad9b6e04d7b61eead1af1f80ad4c6cd131d48c21ce7e183b207c2 migration_root_custody.py
tools/chatbot_file_cohort/continued_owner.py 527e12ddb78478f336e80b72fd1a12c1fde24e41bd15ae1ef5ed23154ca39f61 continued_owner.py
tools/chatbot_file_cohort/review.py 4ce3d56059524107c628c5a9d1ccda0a6373081416877a13f7ca48ac6687e014 review.py
tools/semantic_policy_token_owner/installed_owner.py 786e2725770730fd6be50bdf59e7657e3f3ee5c3399d70e31888a51d19a9adae installed_owner.py
tools/semantic_policy_token_owner/supervisor.py 1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf supervisor.py
SOURCES
echo "Log della sessione: $ouf_stage/run.log"
echo 'Fasi tecniche 8/8; funzionali 0/6. Login HUMAN e revisione esatta precedono ogni nuovo grant.'
echo 'Dopo APPROVO lascia aperto il terminale; il comando resta in primo piano per massimo un’ora.'
sudo /usr/bin/python3 -I -B -S - "$ouf_stage" <<'PY' 2>&1 | tee "$ouf_stage/run.log"
import hashlib,json,os,stat,subprocess,sys,tempfile
from pathlib import Path
assert os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
expected={
 'execute.py':'114a63a7dda897b1c2c275fe3f428b484a9cb9a02d4ffcde53b9a202b2c77e8c',
 'iam_binding_candidate.py':'dcfab9f362ddfd9be95dcd41ee8281d5cecc074918e4ed3995e19dd17da1801b',
 'migration_root_custody.py':'1b8aaa23d26ad9b6e04d7b61eead1af1f80ad4c6cd131d48c21ce7e183b207c2',
 'continued_owner.py':'527e12ddb78478f336e80b72fd1a12c1fde24e41bd15ae1ef5ed23154ca39f61',
 'review.py':'4ce3d56059524107c628c5a9d1ccda0a6373081416877a13f7ca48ac6687e014',
 'installed_owner.py':'786e2725770730fd6be50bdf59e7657e3f3ee5c3399d70e31888a51d19a9adae',
 'supervisor.py':'1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf'}
modules={
 'iam_binding_candidate':'iam_binding_candidate.py',
 'migration_root_custody':'migration_root_custody.py',
 'tools.chatbot_file_cohort.continued_owner':'continued_owner.py',
 'tools.chatbot_file_cohort.review':'review.py',
 'tools.semantic_policy_token_owner.installed_owner':'installed_owner.py',
 'tools.semantic_policy_token_owner.supervisor':'supervisor.py'}
commit='c3e39aaf5783be6428fdb95dff1a3836748c0ce3'
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
