#!/usr/bin/env bash
# Private packet only. No SQL, key opening, OAuth or container lifecycle.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-rollout-packet.XXXXXXXX")"
ouf_report_log() { printf 'Log diagnostico conservato: %s/read.log\n' "$ouf_read"; }
trap ouf_report_log EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/dc60174ad95da264e893aca017911aafdc44d04b' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' '15a024914bc37ce293b79a343f9c6d157e3153943daf9ddea04362aee3b147d8' "$ouf_read/read.py" | sha256sum -c -
timeout 240 "$ouf_gh" api 'repos/GioNob/ouf-deploy/actions/artifacts/12245228551/zip' > "$ouf_read/candidate.zip"
printf '%s  %s\n' '02974a024e66d2f3adb9933f654954868598f6dfcec8899bf76daced9a1aeb02' "$ouf_read/candidate.zip" | sha256sum -c -
printf '%s\n' 'PACCHETTO PRIVATO: verifica ZIP e immagine, cinque GET Engine, config Gateway e soli metadati chiave.' 'Puo proporre un nuovo bind config per env Nginx; conserva file e contesti precedenti. ZERO import, SQL, OAuth, chiavi lette/generate o lifecycle.' 
sudo /usr/bin/python3 -I -B -S - "$ouf_read/read.py" '15a024914bc37ce293b79a343f9c6d157e3153943daf9ddea04362aee3b147d8' "$ouf_read/candidate.zip" <<'OUF_READ' | tee "$ouf_read/read.log"
import hashlib,os,stat,sys
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd)
  if not(stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=262144):raise ValueError('DELIVERY_CUSTODY')
  raw=os.read(fd,262145)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  if len(raw)!=s.st_size or pin(s)!=pin(os.fstat(fd))or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise ValueError('DELIVERY_HASH')
 finally:os.close(fd)
 sys.argv=['<verified-ingestion-rollout-packet>',sys.argv[3]]
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except Exception:
 print('STOP_RECONCILE: consegna diagnostica non verificata; nessun replay.',flush=True);raise SystemExit(2)
OUF_READ

