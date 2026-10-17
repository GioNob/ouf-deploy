#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo "Client GitHub non disponibile." >&2; exit 1; }
ouf_stage="$(mktemp -d "$HOME/ouf-linked-property-review.XXXXXXXX")"
echo 'Preparo la revisione privata delle policy generiche. Tecniche8/8; funzionali2/6.'
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/linked_property_rollout/preparation.py?ref=a18f9bafe4db8888cff16c94327f9134956e7bc8' --jq .content | base64 --decode > "$ouf_stage/prepare.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/image_custody.py?ref=a18f9bafe4db8888cff16c94327f9134956e7bc8' --jq .content | base64 --decode > "$ouf_stage/image_custody.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/releases/linked-property-qualified-20261017.json?ref=a18f9bafe4db8888cff16c94327f9134956e7bc8' --jq .content | base64 --decode > "$ouf_stage/release.json"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/releases/linked-property-migration-manifest-20261017.json?ref=a18f9bafe4db8888cff16c94327f9134956e7bc8' --jq .content | base64 --decode > "$ouf_stage/migrations.json"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/releases/linked-property-preparation-selection-20261017.json?ref=a18f9bafe4db8888cff16c94327f9134956e7bc8' --jq .content | base64 --decode > "$ouf_stage/selection.json"
cat > "$ouf_stage/package.json" <<'PACKAGE'
{"files":{"image_custody.py":"9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2","migrations.json":"93e05a9aa02ecc8cea2983fdb095459a027c8ff27bdfea3b9ab347d20bad08aa","prepare.py":"800e7e04fe2a5898f7ca6d28f6eea241c71ee72314706f52c4962a0cd1955100","release.json":"d53893fd97e44e3b532910202bb86cef6d9725bb735932019e6a711e53776e7f","selection.json":"0bb8e41ae68a220d7b56d67acb64cde64f22cddc3b96a5d5dc8267378362c988"},"runtimeAuthorityIssued":false,"schema":"ouf.linked-property-private-preparation-code.v1","sourceCommit":"a18f9bafe4db8888cff16c94327f9134956e7bc8"}
PACKAGE
printf '%s  %s\n' '800e7e04fe2a5898f7ca6d28f6eea241c71ee72314706f52c4962a0cd1955100' "$ouf_stage/prepare.py" | sha256sum --check -
printf '%s  %s\n' '9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2' "$ouf_stage/image_custody.py" | sha256sum --check -
printf '%s  %s\n' 'd53893fd97e44e3b532910202bb86cef6d9725bb735932019e6a711e53776e7f' "$ouf_stage/release.json" | sha256sum --check -
printf '%s  %s\n' '93e05a9aa02ecc8cea2983fdb095459a027c8ff27bdfea3b9ab347d20bad08aa' "$ouf_stage/migrations.json" | sha256sum --check -
printf '%s  %s\n' '0bb8e41ae68a220d7b56d67acb64cde64f22cddc3b96a5d5dc8267378362c988' "$ouf_stage/selection.json" | sha256sum --check -
printf '%s  %s\n' 'c77894b5e1f9990e25e9a3d813ea03985ae6bc30da1a80dd96ba2027b4ecfe99' "$ouf_stage/package.json" | sha256sum --check -
ouf_cache="$HOME/ouf-linked-property-candidate-39062596949"
mkdir -p "$ouf_cache"
ouf_archive="$ouf_cache/candidate.zip"
if [ -f "$ouf_archive" ] && [ ! -L "$ouf_archive" ] && printf '%s  %s\n' '97a1b432522e14da85b137cd378e12ee97f96ef0e98280dfe80299e03c62e6dc' "$ouf_archive" | sha256sum --check --status -; then
 echo 'Riutilizzo il pacchetto gia scaricato, dopo verifica esatta.'
else
 echo 'Scarico le due immagini qualificate: circa868 MB. Nessun login o worker viene avviato.'
 ouf_download="$(mktemp "$ouf_cache/download.XXXXXXXX")"
 timeout 600 "$ouf_gh" api 'repos/GioNob/ouf-deploy/actions/artifacts/12111508257/zip' > "$ouf_download"
 printf '%s  %s\n' '97a1b432522e14da85b137cd378e12ee97f96ef0e98280dfe80299e03c62e6dc' "$ouf_download" | sha256sum --check -
 mv -f -- "$ouf_download" "$ouf_archive"
fi
echo "Log della preparazione: $ouf_stage/run.log"
echo 'Solo nuovi file privati e letture DB: nessuna migrazione, firma, grant, login, stop o modifica servizi.'
echo 'Massimo5 minuti dopo sudo. Incolla OUF_LINKED_PROPERTY_PRIVATE_REVIEW oppure STOP.'
sudo /usr/bin/python3 -u -I -B -S - "$ouf_stage" "$ouf_archive" <<'ROOTPY' 2>&1 | tee "$ouf_stage/run.log"
import hashlib,json,os,re,stat,sys,tempfile
from pathlib import Path
assert os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
os.umask(0o077)
source=Path(sys.argv[1]); archive=Path(sys.argv[2])
def read(name,expected):
 assert re.fullmatch('[A-Za-z0-9_.-]+',name)
 fd=os.open(source/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd); assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=8388608
  raw=bytearray()
  while len(raw)<=8388608:
   part=os.read(fd,min(65536,8388609-len(raw)))
   if not part:break
   raw.extend(part)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  assert len(raw)==before.st_size and pin(before)==pin(os.fstat(fd)) and hashlib.sha256(raw).hexdigest()==expected
  return bytes(raw)
 finally:os.close(fd)
manifest=read('package.json','c77894b5e1f9990e25e9a3d813ea03985ae6bc30da1a80dd96ba2027b4ecfe99'); package=json.loads(manifest)
assert package['sourceCommit']=='a18f9bafe4db8888cff16c94327f9134956e7bc8' and set(package['files'])=={'prepare.py','image_custody.py','release.json','migrations.json','selection.json'}
verified={'package.json':manifest,**{n:read(n,h)for n,h in package['files'].items()}}
parent=Path('/etc/ouf/deploy-snapshots')
for p in(parent,*parent.parents):
 s=p.lstat(); assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
code=Path(tempfile.mkdtemp(prefix='linked-property-review-code-',dir=parent)); code.chmod(0o700)
for name,raw in verified.items():
 fd=os.open(code/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw); stream.flush(); os.fsync(stream.fileno())
 finally:os.close(fd)
fd=os.open(code,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
sys.argv=[str(code/'prepare.py'),str(code),str(archive),'c77894b5e1f9990e25e9a3d813ea03985ae6bc30da1a80dd96ba2027b4ecfe99']
exec(compile(verified['prepare.py'],'<verified-linked-property-private-preparation>','exec'),{'__name__':'__main__'})
ROOTPY
