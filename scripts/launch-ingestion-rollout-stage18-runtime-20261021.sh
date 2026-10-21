#!/usr/bin/env bash
# Retained-installation foreground stage18 control. No automatic invocation.
set -euo pipefail
umask 077
[[ "$#" -eq 1 ]] || exit 2
case "$1" in preflight|review|approve|import-prefix|step|reconcile|status) ;; *) exit 2 ;; esac
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_stage="$(mktemp -d "$HOME/ouf-stage18-runtime.XXXXXXXX")"
trap 'printf "Log conservato: %s/operator.log\nLauncher conservato: %s\n" "$ouf_stage" "$0"' EXIT
ouf_cache="${0}.operator.py"
if [[ -e "$ouf_cache" || -L "$ouf_cache" ]]; then
 [[ -f "$ouf_cache" && ! -L "$ouf_cache" ]] || exit 2
 cat -- "$ouf_cache" > "$ouf_stage/operator.py"
else
 "$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/d1884acd9e994de3d8ba4c709aee42d76bdfa144' --jq .content | tr -d '\n' | base64 --decode > "$ouf_stage/operator.py"
fi
printf '%s  %s\n' '9af3c7456ce7904a2a35d9920d92eb54acc1bdd90e13fb3330b6fa8dd95f0c7f' "$ouf_stage/operator.py" | sha256sum -c -
if [[ ! -e "$ouf_cache" && ! -L "$ouf_cache" ]]; then
 ( set -o noclobber; cat -- "$ouf_stage/operator.py" > "$ouf_cache" ) || exit 2
fi
sudo python3 -I -B -S - "$ouf_stage/operator.py" '9af3c7456ce7904a2a35d9920d92eb54acc1bdd90e13fb3330b6fa8dd95f0c7f' "$@" <<'OUF_STAGE18' | tee "$ouf_stage/operator.log"
import hashlib,os,stat,sys
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd)
  if not(stat.S_ISREG(info.st_mode)and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and 0<info.st_size<=1048576):raise ValueError()
  raw=os.read(fd,1048577)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  if len(raw)!=info.st_size or pin(info)!=pin(os.fstat(fd))or pin(info)!=pin(os.stat(sys.argv[1],follow_symlinks=False))or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise ValueError()
 finally:os.close(fd)
 sys.argv=['<verified-stage18-operator>']+sys.argv[3:]
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: pacchetto stage18 non verificato; conserva contesti e claim.',flush=True)
 raise SystemExit(2)
OUF_STAGE18
