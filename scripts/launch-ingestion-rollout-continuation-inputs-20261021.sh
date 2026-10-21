#!/usr/bin/env bash
# Installation-specific live metadata reader; never continues or renews a rollout.
set -euo pipefail
umask 077
[[ "$#" -eq 0 ]] || exit 2
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-rollout-continuation-inputs.XXXXXXXX")"
trap 'printf "Log conservato: %s/reader.log\n" "$ouf_read"' EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/51c8e68a1ad9b36fadf220b8fe67cb3f3df40358' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/reader.py"
printf '%s  %s\n' '8337fa934ce2fa1204c67783acedf21471bbfcde9cf1aebd685012866660beb0' "$ouf_read/reader.py" | sha256sum -c -
sudo python3 -I -B -S - "$ouf_read/reader.py" '8337fa934ce2fa1204c67783acedf21471bbfcde9cf1aebd685012866660beb0' <<'OUF_READER' | tee "$ouf_read/reader.log"
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
 sys.argv=['<verified-rollout-continuation-input-reader>']
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: lettore non verificato; conserva contesti e claim.',flush=True)
 raise SystemExit(2)
OUF_READER
