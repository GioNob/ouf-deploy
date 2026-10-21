#!/usr/bin/env bash
# Installation-specific explicit budget decision; no login or runtime continuation.
set -euo pipefail
umask 077
[[ "$#" -le 1 ]] || exit 2
ouf_mode="${1:-prepare}"
case "$ouf_mode" in prepare|grant-budget|status) ;; *) exit 2 ;; esac
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-oauth-budget-extension.XXXXXXXX")"
trap 'printf "Log conservato: %s/budget.log\n" "$ouf_read"' EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/6fa36ac46ffef0db7f162be3b4a519f8c9fc6911' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/operator.py"
printf '%s  %s\n' '504237182ef70270de75d919500657c0315723068156056f468cb82f28bcd261' "$ouf_read/operator.py" | sha256sum -c -
sudo python3 -I -B -S - "$ouf_read/operator.py" '504237182ef70270de75d919500657c0315723068156056f468cb82f28bcd261' "$ouf_mode" <<'OUF_READER' | tee "$ouf_read/budget.log"
import hashlib,os,stat,sys
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd)
  if not(stat.S_ISREG(info.st_mode)and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and 0<info.st_size<=262144):raise ValueError()
  raw=os.read(fd,262145)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  if len(raw)!=info.st_size or pin(info)!=pin(os.fstat(fd))or pin(info)!=pin(os.stat(sys.argv[1],follow_symlinks=False))or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise ValueError()
 finally:os.close(fd)
 sys.argv=['<verified-technical-oauth-budget>',sys.argv[3]]
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: pacchetto budget non verificato; conserva contesti e claim.',flush=True)
 raise SystemExit(2)
OUF_READER
