#!/usr/bin/env bash
# Postboot-bound DB read preflight. No migration, login, refresh or runtime authority.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-db-postboot-read.XXXXXXXX")"
ouf_report_log() { printf 'Log diagnostico conservato: %s/read.log\n' "$ouf_read"; }
trap ouf_report_log EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/034c3146c88e28bea42d42f92b20c0cf7ae08d42' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' '82ccde1ccd0b889480eefd1bae7eaee749bfe9592244e796eebafc26d643f849' "$ouf_read/read.py" | sha256sum -c -
printf '%s\n' 'PROVENIENZA POSTBOOT: coppia privata e ricevuta vincolate a SHA256 esatti; nessuna modifica ai documenti storici.' 'LETTURA DB: quattro GET Docker e UNA sessione psql READ ONLY nel PostgreSQL gia selezionato, come ruolo applicativo esistente.' 'Zero DDL/DML, migrazioni, permessi cambiati, container avviati o job. Nessun file credenziali, login/refresh OAuth o autorita runtime.'
sudo /usr/bin/python3 -I -B -S - "$ouf_read/read.py" '82ccde1ccd0b889480eefd1bae7eaee749bfe9592244e796eebafc26d643f849' <<'OUF_READ' | tee "$ouf_read/read.log"
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
 sys.argv=['<verified-ingestion-db-postboot-preflight>']
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except Exception:
 print('STOP_RECONCILE: consegna diagnostica non verificata; nessun replay.',flush=True);raise SystemExit(2)
OUF_READ

