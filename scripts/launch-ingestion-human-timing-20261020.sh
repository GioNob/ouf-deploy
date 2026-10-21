#!/usr/bin/env bash
# One offline timing inspection of retained history, even expired. No login or runtime authority.
set -euo pipefail
umask 077
[[ "$#" -eq 0 ]] || { printf '%s\n' 'STOP: questa lettura non accetta modi o comandi.' >&2; exit 2; }
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-human-timing.XXXXXXXX")"
ouf_report() { printf 'Launcher conservato: %s\nLog conservato: %s/timing.log\n' "${BASH_SOURCE[0]}" "$ouf_read"; }
trap ouf_report EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/d1649ace18f9739ed5d729c5054b65e9d9c1e939' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/timing.py"
printf '%s  %s\n' 'ad7e2383da96fa19dabf64a5dc69bdb857279cb12ce93758ab58043e320e8a84' "$ouf_read/timing.py" | sha256sum -c -
sudo python3 -I -B -S - "$ouf_read/timing.py" 'ad7e2383da96fa19dabf64a5dc69bdb857279cb12ce93758ab58043e320e8a84' <<'OUF_OPERATOR' | tee "$ouf_read/timing.log"
import hashlib,os,stat,sys
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd)
  if not(stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=1048576):raise ValueError('DELIVERY_CUSTODY')
  raw=os.read(fd,1048577)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  if len(raw)!=s.st_size or pin(s)!=pin(os.fstat(fd))or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise ValueError('DELIVERY_HASH')
 finally:os.close(fd)
 sys.argv=['<verified-offline-human-timing-inspection>']
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: consegna della lettura non verificata; conserva contesti e claim.',flush=True);raise SystemExit(2)
OUF_OPERATOR
printf '%s\n' 'Lettura conclusa. Incolla in chat il JSON pubblico e il percorso timing.log. Non eseguire login o altri passi.'
