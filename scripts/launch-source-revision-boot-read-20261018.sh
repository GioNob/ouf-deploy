#!/usr/bin/env bash
# Installation-specific diagnostic delivery. No service, lease, rule or configuration mutation.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile.' >&2; exit 1; }
ouf_read="$(mktemp -d "$HOME/ouf-boot-guard-read.XXXXXXXX")"
ouf_ref=5fd40b5e0af165f6b41faa5036fa8f607c5f5cf6
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/read-source-revision-boot-guard.py?ref=$ouf_ref" --jq .content | base64 --decode > "$ouf_read/read.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/releases/source-revision-boot-read-selection-20261018.json?ref=$ouf_ref" --jq .content | base64 --decode > "$ouf_read/selection.json"
printf '%s  %s\n' 'c63ee1872d4e78c16bead93c80c0c0fefa694814222a89cf93d23e084b4b63fd' "$ouf_read/read.py" '36c47400fc3dc7669b04d6bc18e204a70ca7502f3749d8d92a292ddf4bdc0978' "$ouf_read/selection.json" | sha256sum --check -
printf '%s\n' 'Tecniche 8/8; funzionali 4/6. Unica diagnosi protetta della guardia di avvio.' 'Nessun login OUF, avvio Docker, ripristino tabelle, modifica, pubblicazione o retry.' "Log della lettura: $ouf_read/read.log"
sudo /usr/bin/python3 -I -B -S - "$ouf_read/read.py" "$ouf_read/selection.json" <<'OUF_VERIFIED_BOOT_READ' | tee "$ouf_read/read.log"
import hashlib,json,os,signal,stat,sys
from pathlib import Path
def verified(path,expected):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        first=os.fstat(fd)
        if not stat.S_ISREG(first.st_mode)or first.st_nlink!=1 or not 0<=first.st_size<=65536:raise ValueError('unsafe delivery')
        raw=os.read(fd,65537);last=os.fstat(fd)
        pin=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if len(raw)!=first.st_size or pin(first)!=pin(last)or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('delivery changed')
        return raw
    finally:os.close(fd)
try:
    if os.geteuid()!=0 or os.getegid()!=0 or not(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)or len(sys.argv)!=3:raise ValueError('isolated root read required')
    signal.alarm(90)
    source=verified(sys.argv[1],'c63ee1872d4e78c16bead93c80c0c0fefa694814222a89cf93d23e084b4b63fd')
    selection=verified(sys.argv[2],'36c47400fc3dc7669b04d6bc18e204a70ca7502f3749d8d92a292ddf4bdc0978')
    namespace={'__name__':'verified_boot_metadata_reader','__file__':sys.argv[1]}
    exec(compile(source,'<verified-boot-metadata-reader>','exec'),namespace)
    result=namespace['collect'](namespace['parse'](selection))
    result['readerSha256']=hashlib.sha256(source).hexdigest()
    result['selectionSha256']=hashlib.sha256(selection).hexdigest()
    print(json.dumps(result,sort_keys=True));sys.exit(0 if result['readComplete']else 2)
except Exception as error:
    print(json.dumps({'schema':'ouf.source-revision-private-boot-read.v1','readComplete':False,
      'runtimeMutations':0,'errorClass':type(error).__name__,'exceptionMessagePrinted':False,
      'completedTechnicalPhases':8,'functionalMilestonesProven':4},sort_keys=True));sys.exit(2)
OUF_VERIFIED_BOOT_READ
