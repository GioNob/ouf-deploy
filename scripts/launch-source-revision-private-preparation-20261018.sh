#!/usr/bin/env bash
# Installation-specific private preparation. No runtime grant, login or deployment.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile.' >&2; exit 1; }
ouf_stage="$(mktemp -d "$HOME/ouf-source-revision-prepare.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/prepare-source-revision-inputs.py?ref=459dc8e3d26de7c7297972c93196dbbf494ffd81' --jq .content | base64 --decode > "$ouf_stage/prepare.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/releases/source-revision-private-preparation-20261018.json?ref=459dc8e3d26de7c7297972c93196dbbf494ffd81' --jq .content | base64 --decode > "$ouf_stage/selection.json"
printf '%s  %s\n' 'a9caad5f31b6eb4f1d3f7e4ef8b34c4abfd5a1bbe96d433136ae4fc590b83c5e' "$ouf_stage/prepare.py" 'd7cb3b6c92c250ddc655f1eeb5d9a2dba1d2c0317ca39363ce5e1306a12f3036' "$ouf_stage/selection.json" | sha256sum --check -
echo "Log della preparazione: $ouf_stage/read.log"
echo 'Tecniche8/8; funzionali4/6. Unica preparazione privata: immagini gia consegnate, generazioni e metadati in sola lettura.'
echo 'Serve la password sudo del VPS. Nessun login OUF, firma, pubblicazione, modifica servizi/database o ripresa job.'
echo 'Massimo5 minuti. Dopo STOP conserva il log: nessun rilancio automatico.'
sudo /usr/bin/python3 -I -B -S - "$ouf_stage" <<'ROOTPY' 2>&1 | tee "$ouf_stage/read.log"
import hashlib,json,os,stat,sys,tempfile
from pathlib import Path
assert os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
os.umask(0o077)
root=Path(sys.argv[1]); files={}
pins={'prepare.py':'a9caad5f31b6eb4f1d3f7e4ef8b34c4abfd5a1bbe96d433136ae4fc590b83c5e','selection.json':'d7cb3b6c92c250ddc655f1eeb5d9a2dba1d2c0317ca39363ce5e1306a12f3036'}
for name,wanted in pins.items():
    path=root/name
    assert path.resolve()==path
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=131072
        raw=os.read(fd,131073)
        seal=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        assert len(raw)==before.st_size and seal(before)==seal(os.fstat(fd))==seal(path.lstat()) and hashlib.sha256(raw).hexdigest()==wanted
        files['prepare.py' if name.endswith('.py') else 'selection.json']=raw
    finally:os.close(fd)
parent=Path('/etc/ouf/deploy-snapshots')
for path in(parent,*parent.parents):
    info=path.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
code=Path(tempfile.mkdtemp(prefix='source-revision-preparation-code-',dir=parent));code.chmod(0o700)
for name,raw in files.items():
    fd=os.open(code/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as output:output.write(raw);output.flush();os.fsync(output.fileno())
fd=os.open(code,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
print(json.dumps({'check':'VERIFIED_PREPARATION_CODE','codeDirectory':str(code),'sourceSha256':'a9caad5f31b6eb4f1d3f7e4ef8b34c4abfd5a1bbe96d433136ae4fc590b83c5e','selectionSha256':'d7cb3b6c92c250ddc655f1eeb5d9a2dba1d2c0317ca39363ce5e1306a12f3036','runtimeMutations':0,'runtimeAuthorityIssued':False}),flush=True)
os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B','-S',str(code/'prepare.py'),str(code/'selection.json'),'d7cb3b6c92c250ddc655f1eeb5d9a2dba1d2c0317ca39363ce5e1306a12f3036'])
ROOTPY
