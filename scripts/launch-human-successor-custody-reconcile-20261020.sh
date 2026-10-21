#!/usr/bin/env bash
# Exact retained-installation diagnostic, not a portable installer default.
# No login, window, budget, service call or retained-context modification.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-human-custody-reconcile.XXXXXXXX")"
ouf_report_log() { printf 'Log diagnostico conservato: %s/read.log\n' "$ouf_read"; }
trap ouf_report_log EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/861414cc31f155fb5f71c17d4df702ab47a55663' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' '505b6e82a0c3d5b668ec92106e470974cc5526cd0bef460f6dc6178d2ba32eec' "$ouf_read/read.py" | sha256sum -c -
printf '%s\n' 'RICONCILIAZIONE SOLA: originale completo, profilo storico massimo8MiB e diagnostica distinta dei metadati.' 'Nessun bearer aperto, login, rinnovo, reset, scrittura di journal, SQL, Engine, Gateway o owner API.'
sudo python3 -I -B -S - "$ouf_read/read.py" '505b6e82a0c3d5b668ec92106e470974cc5526cd0bef460f6dc6178d2ba32eec' <<'OUF_READ' | tee "$ouf_read/read.log"
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
 sys.argv=['<verified-human-custody-reconcile>']
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except Exception:
 print('STOP_RECONCILE: consegna diagnostica non verificata; nessun replay.',flush=True);raise SystemExit(2)
OUF_READ
