#!/usr/bin/env bash
# Exact one-use GET-only stage8 metadata capture; one explicit mode, never downloads code.
set -euo pipefail
umask 077
[[ "$#" -ge 1 && "$#" -le 2 ]] || exit 2
[[ "$#" -eq 1 && "$1" == prepare ]] || exit 2
ouf_cache="${0}.operator.py"
[[ -f "$ouf_cache" && ! -L "$ouf_cache" ]] || { printf '%s
' 'STOP: cache verificata assente; nessuna invocazione.' >&2; exit 2; }
ouf_stage="$(mktemp -d "$HOME/ouf-stage8-live-inputs.XXXXXXXX")"
trap 'printf "Log conservato: %s/operator.log\nLauncher conservato: %s\n" "$ouf_stage" "$0"' EXIT
cat -- "$ouf_cache" > "$ouf_stage/operator.py"
printf '%s  %s\n' '8ca3009d6232f6a0ce166bb22b4594878a1acb1e2e16161315c229a553d894b0' "$ouf_stage/operator.py" | sha256sum -c -
sudo python3 -I -B -S - "$ouf_stage/operator.py" '8ca3009d6232f6a0ce166bb22b4594878a1acb1e2e16161315c229a553d894b0' "$@" <<'OUF_PATCH_VERIFIED' | tee "$ouf_stage/operator.log"
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
 sys.argv=['<verified-ingestion-patch>']+sys.argv[3:]
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: pacchetto patch non verificato; conserva contesti e claim.',flush=True)
 raise SystemExit(2)
OUF_PATCH_VERIFIED
