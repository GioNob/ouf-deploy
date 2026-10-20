#!/usr/bin/env bash
# Reconcile retained packet only. Preserve original files and claim; no runtime authority.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-frame-mac-reconcile.XXXXXXXX")"
ouf_report_log() { printf 'Log diagnostico conservato: %s/read.log\n' "$ouf_read"; }
trap ouf_report_log EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/1a908cf497a919faa0a5d1946ba8575fb402f96b' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' '4e7dbb2f35cd2e628cebc6d2d30006ee1694505d1c1a297b815cdb66ab28ce29' "$ouf_read/read.py" | sha256sum -c -
printf '%s\n' 'RICONCILIAZIONE FRAME: kkj_njiz e config gia preparato in 0wd4wyuf; cinque GET Engine.' 'Solo piano privato: MAC legacy verificato e preservato per endpoint. ZERO staging config, download/import, SQL, OAuth o lifecycle.'
sudo /usr/bin/python3 -I -B -S - "$ouf_read/read.py" '4e7dbb2f35cd2e628cebc6d2d30006ee1694505d1c1a297b815cdb66ab28ce29' <<'OUF_READ' | tee "$ouf_read/read.log"
import hashlib,os,stat,sys
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd)
  if not(stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=131072):raise ValueError('DELIVERY_CUSTODY')
  raw=os.read(fd,131073)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  if len(raw)!=s.st_size or pin(s)!=pin(os.fstat(fd))or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise ValueError('DELIVERY_HASH')
 finally:os.close(fd)
 sys.argv=['<verified-ingestion-frame-mac-reconcile>']
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except Exception:
 print('STOP_RECONCILE: consegna diagnostica non verificata; nessun replay.',flush=True);raise SystemExit(2)
OUF_READ

