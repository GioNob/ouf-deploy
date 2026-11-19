#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile; nessuna preparazione sudo.' >&2; exit 1; }
ouf_stage="$(mktemp -d "$HOME/ouf-readiness-private-review.XXXXXXXX")"
ouf_cache="$HOME/ouf-readiness-candidates-39011934307"
/usr/bin/python3 - "$ouf_cache" <<'PY'
import os,stat,sys
from pathlib import Path
p=Path(sys.argv[1])
if not p.exists():p.mkdir(mode=0o700)
s=p.lstat()
assert stat.S_ISDIR(s.st_mode) and not p.is_symlink() and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700
for place in (str(p),'/etc'):
 v=os.statvfs(place)
 assert v.f_bavail*v.f_frsize>=5*1024**3,'Spazio libero insufficiente per preparare e conservare il pacchetto privato.'
PY
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/prepare-ingestion-readiness-update-review-20261017.py?ref=8ce9ce52e691caa5567bb4684fe74e63f0527c61' --jq .content | base64 --decode > "$ouf_stage/prepare.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/releases/ingestion-readiness-private-selection-20261017.json?ref=a16860a78811da6da60a645680a64df3d3ac08a0' --jq .content | base64 --decode > "$ouf_stage/case.json"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/image_custody.py?ref=0c91f31465064819805e417bd9e2f4e10a4aee23' --jq .content | base64 --decode > "$ouf_stage/image_custody.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/gateway.py?ref=0c91f31465064819805e417bd9e2f4e10a4aee23' --jq .content | base64 --decode > "$ouf_stage/gateway_custody.py"
printf '%s  %s\n' \
 '0eb23cebb00bf69732b70e56e4733f522bd0ac7576643e0e9063c2fdcb8962cc' "$ouf_stage/prepare.py" \
 '18ff5a8436d2058c6e9c6820cf8b017facb58e42ce718eee4bf0c1591781ae40' "$ouf_stage/case.json" \
 '9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2' "$ouf_stage/image_custody.py" \
 '5e7182d899a25a299b103d63f6bf81822280f09e58b963c38f735aa2a4fee72f' "$ouf_stage/gateway_custody.py" | sha256sum --check -
ouf_zip="$ouf_cache/candidate.zip"
if [ ! -e "$ouf_zip" ]; then
 echo 'Scarico il pacchetto qualificato: circa908 MB. Nessun login o worker viene avviato.'
 ouf_part="$(mktemp "$ouf_cache/download.XXXXXXXX")"
 trap 'if [ -n "${ouf_part:-}" ]; then rm -f -- "$ouf_part"; fi' EXIT
 timeout 600 "$ouf_gh" api 'repos/GioNob/ouf-deploy/actions/artifacts/12092994033/zip' > "$ouf_part"
 printf '%s  %s\n' '0f744ae117672199ccf7309988122b75e48bf37fb5da98796a428abb70a30033' "$ouf_part" | sha256sum --check -
 ln -- "$ouf_part" "$ouf_zip"
 rm -f -- "$ouf_part"
 ouf_part=''
else
 echo 'Riutilizzo il pacchetto già scaricato, dopo verifica esatta.'
fi
[ ! -L "$ouf_zip" ] && [ -f "$ouf_zip" ]
printf '%s  %s\n' '0f744ae117672199ccf7309988122b75e48bf37fb5da98796a428abb70a30033' "$ouf_zip" | sha256sum --check -
echo "Log preparazione privata: $ouf_stage/prepare.log"
echo 'Fasi tecniche8/8; funzionali1/6. Solo nuova revisione privata: nessun token, firma, grant, stop o aggiornamento servizi.'
sudo /usr/bin/python3 -u -I -B -S - "$ouf_stage/prepare.py" "$ouf_zip" "$ouf_stage/case.json" "$ouf_stage/image_custody.py" "$ouf_stage/gateway_custody.py" <<'PY' 2>&1 | tee "$ouf_stage/prepare.log"
import hashlib,os,stat,sys
assert os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 before=os.fstat(fd)
 assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=131072
 raw=os.read(fd,131073);after=os.fstat(fd)
 pin=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 assert len(raw)==before.st_size and pin(before)==pin(after)
 assert hashlib.sha256(raw).hexdigest()=='0eb23cebb00bf69732b70e56e4733f522bd0ac7576643e0e9063c2fdcb8962cc'
finally:os.close(fd)
sys.argv=[sys.argv[1],*sys.argv[2:]]
exec(compile(raw,'<verified-private-readiness-preparation>','exec'),{'__name__':'__main__'})
PY

