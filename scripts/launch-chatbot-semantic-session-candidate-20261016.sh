#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] || { echo 'Client GitHub non disponibile; nessuna esecuzione sudo.' >&2; exit 1; }
ouf_stage="$(mktemp -d "$HOME/ouf-semantic-session-candidate.XXXXXXXX")"
while read -r ouf_path ouf_sha ouf_name; do
  "$ouf_gh" api "repos/GioNob/ouf-deploy/contents/$ouf_path?ref=8bcd9165385732549590bd750589aeb980194707" --jq .content |
    base64 --decode > "$ouf_stage/$ouf_name"
  printf '%s  %s\n' "$ouf_sha" "$ouf_stage/$ouf_name" | sha256sum --check -
done <<'SOURCES'
scripts/prepare-chatbot-semantic-session-candidate-20261016.py ca9bd95d898e05109ef6f0277ce57f1625f18ce55a9a55d7979eb45882fc7506 prepare.py
tools/semantic_policy_token_owner/installed_owner.py 016cf2703333297f8c3dd8839c7228532535a2be99fa1b5694452b16ba7ca0f8 installed-owner.py
tools/semantic_policy_token_owner/supervisor.py 1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf supervisor.py
tools/semantic_policy_token_owner/producer.py 2b218432f719c4bb4efa47a2786238b518617ac09023e588e8e605cb18f7c4dd producer.py
SOURCES
echo "Log preparazione candidato: $ouf_stage/prepare.log"
sudo /usr/bin/python3 -I -B - "$ouf_stage" <<'PY' 2>&1 | tee "$ouf_stage/prepare.log"
import hashlib,os,stat,subprocess,sys,tempfile
from pathlib import Path
assert os.geteuid()==0 and sys.flags.isolated
expected={
 'prepare.py':'ca9bd95d898e05109ef6f0277ce57f1625f18ce55a9a55d7979eb45882fc7506',
 'installed-owner.py':'016cf2703333297f8c3dd8839c7228532535a2be99fa1b5694452b16ba7ca0f8',
 'supervisor.py':'1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf',
 'producer.py':'2b218432f719c4bb4efa47a2786238b518617ac09023e588e8e605cb18f7c4dd'}
parent=Path('/etc/ouf/deploy-snapshots')
assert parent.resolve()==parent
for path in (parent,*parent.parents):
 s=path.lstat()
 assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
pin=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
with tempfile.TemporaryDirectory(prefix='semantic-session-candidate-code-',dir=parent)as d:
 paths=[]
 for name,sha in expected.items():
  fd=os.open(Path(sys.argv[1])/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   before=os.fstat(fd)
   assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=131072
   raw=os.read(fd,131073)
   assert len(raw)==before.st_size and pin(before)==pin(os.fstat(fd)) and hashlib.sha256(raw).hexdigest()==sha
  finally:os.close(fd)
  target=Path(d)/name
  with target.open('xb')as out:out.write(raw)
  target.chmod(0o600);paths.append(str(target))
 result=subprocess.run([sys.executable,'-I','-B',*paths],stdin=subprocess.DEVNULL,
  env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},timeout=150)
 raise SystemExit(result.returncode)
PY
