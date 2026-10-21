#!/usr/bin/env bash
# Explicit foreground native control. Default prepare has no authentication or runtime effects.
set -euo pipefail
umask 077
ouf_mode="${1:-prepare}"
case "$ouf_mode" in
  prepare) [[ "$#" -le 1 ]] || exit 2 ;;
  status|approve|initialize|step|reconcile) [[ "$#" -eq 2 && "$2" == /* ]] || exit 2 ;;
  review) [[ "$#" -eq 3 && "$2" == /* && "$3" == /* ]] || exit 2 ;;
  *) printf '%s\n' 'STOP: modo non qualificato.' >&2; exit 2 ;;
esac
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-rollout-production.XXXXXXXX")"
ouf_report() { printf 'Launcher conservato: %s\nLog conservato: %s/control.log\n' "${BASH_SOURCE[0]}" "$ouf_read"; }
trap ouf_report EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/807f789d82df8768e9b05c7c44a01449361aba7d' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/control.py"
printf '%s  %s\n' '42b2569a0ba1f2234dfbcc011588cdf133d0e5c97a3f3433b903750f010448ea' "$ouf_read/control.py" | sha256sum -c -
ouf_args=("$ouf_mode")
if [[ "$#" -ge 2 ]]; then ouf_args+=("$2"); fi
if [[ "$#" -eq 3 ]]; then ouf_args+=("$3"); fi
sudo python3 -I -B -S - "$ouf_read/control.py" '42b2569a0ba1f2234dfbcc011588cdf133d0e5c97a3f3433b903750f010448ea' "${ouf_args[@]}" <<'OUF_OPERATOR' | tee "$ouf_read/control.log"
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
 sys.argv=['<verified-explicit-native-production-control>',*sys.argv[3:]]
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: consegna del controllo non verificata; conserva contesti e claim.',flush=True);raise SystemExit(2)
OUF_OPERATOR
