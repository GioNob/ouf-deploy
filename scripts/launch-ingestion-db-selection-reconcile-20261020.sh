#!/usr/bin/env bash
# Files-only STOP reconciliation. Zero Docker, DB, OAuth or runtime authority.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-db-selection-reconcile.XXXXXXXX")"
ouf_report_log() { printf 'Log diagnostico conservato: %s/read.log\n' "$ouf_read"; }
trap ouf_report_log EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/6619184c829e499c52339bd03013692472e1c8eb' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' '9b6f99173b041de44de93ca0845d788ca92a7818e98ab1a8ec8512f66521bc5f' "$ouf_read/read.py" | sha256sum -c -
printf '%s\n' 'RICONCILIAZIONE: soli metadati privati gia selezionati; confronto separato schema, binding Engine e hash piano DB.' 'ZERO Docker, SQL, OAuth, credenziali, login/refresh, scritture runtime o replay. Contesti e claim conservati.'
sudo /usr/bin/python3 -I -B -S - "$ouf_read/read.py" '9b6f99173b041de44de93ca0845d788ca92a7818e98ab1a8ec8512f66521bc5f' <<'OUF_READ' | tee "$ouf_read/read.log"
import hashlib,os,stat,sys
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd)
  if not(stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=65536):raise ValueError('DELIVERY_CUSTODY')
  raw=os.read(fd,65537)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  if len(raw)!=s.st_size or pin(s)!=pin(os.fstat(fd))or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise ValueError('DELIVERY_HASH')
 finally:os.close(fd)
 sys.argv=['<verified-ingestion-db-selection-reconcile>']
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except Exception:
 print('STOP_RECONCILE: consegna diagnostica non verificata; nessun replay.',flush=True);raise SystemExit(2)
OUF_READ

