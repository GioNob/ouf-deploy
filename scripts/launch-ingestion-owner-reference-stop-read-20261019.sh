#!/usr/bin/env bash
# Read-only retained-host diagnosis. No login, OAuth, runtime dispatch or apply.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-owner-stop-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/8b667d34d4f31bc4df12b21f54a4d5fae6b45e66' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' '47452ec96e0ce1ef46af2d751b14ede6a62b2a6f89d9576575f1b7a4ef7e34b0' "$ouf_read/read.py" | sha256sum -c -
printf '%s\n' 'SOLO LETTURA: journal del tentativo tr33g8bg. Nessun login, token HTTP, owner o Gateway.' 'Un journal contenente credenziali viene letto privatamente; nessun valore o hash delle credenziali viene stampato.'
sudo /usr/bin/python3 -I -B -S - "$ouf_read/read.py" '47452ec96e0ce1ef46af2d751b14ede6a62b2a6f89d9576575f1b7a4ef7e34b0' <<'OUF_READ' | tee "$ouf_read/read.log"
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
 sys.argv=['<verified-owner-stop-reader>']
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except Exception:
 print('STOP_RECONCILE: consegna diagnostica non verificata; nessun replay.',flush=True);raise SystemExit(2)
OUF_READ
printf 'Log diagnostico: %s/read.log\n' "$ouf_read"
