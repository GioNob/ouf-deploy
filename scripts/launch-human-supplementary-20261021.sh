#!/usr/bin/env bash
# Explicit supplementary HUMAN control. Default prepare has zero network or writes.
set -euo pipefail
umask 077
ouf_mode="${1:-prepare}"
case "$ouf_mode" in
  prepare) [[ "$#" -le 1 ]] || exit 2 ;;
  status|step) [[ "$#" -eq 2 && "$2" == /* ]] || exit 2 ;;
  open-window) [[ "$#" -eq 1 ]] || exit 2 ;;
  *) printf '%s\n' 'STOP: modo non qualificato.' >&2; exit 2 ;;
esac
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-human-supplementary.XXXXXXXX")"
ouf_report() { printf 'Launcher conservato: %s\nLog conservato: %s/operator.log\n' "${BASH_SOURCE[0]}" "$ouf_read"; }
trap ouf_report EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/abb0c83976daa61cc5c3abc9da71382249972e4c' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/operator.py"
printf '%s  %s\n' '3974ee39263621d04a8d8dee6ec50c240fe853c61d17d158d23596953447bf2c' "$ouf_read/operator.py" | sha256sum -c -
ouf_args=("$ouf_mode")
if [[ "$#" -ge 2 ]]; then ouf_args+=("$2"); fi
if [[ "$#" -eq 3 ]]; then ouf_args+=("$3"); fi
sudo python3 -I -B -S - "$ouf_read/operator.py" '3974ee39263621d04a8d8dee6ec50c240fe853c61d17d158d23596953447bf2c' "${ouf_args[@]}" <<'OUF_OPERATOR' | tee "$ouf_read/operator.log"
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
 sys.argv=['<verified-supplementary-human-operator>',*sys.argv[3:]]
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: consegna del controllo non verificata; conserva contesti e claim.',flush=True);raise SystemExit(2)
OUF_OPERATOR
printf '%s\n' 'Incolla il JSON pubblico e il percorso operator.log. Dopo STOP conserva tutto: non rieseguire.'
