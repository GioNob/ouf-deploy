#!/usr/bin/env bash
# Retained installation metadata capture. Twelve exact Engine GETs; no OAuth, SQL or lifecycle.
set -euo pipefail
umask 077
ouf_mode="${1:-capture}"
case "$ouf_mode" in
  capture) [[ "$#" -le 1 ]] || exit 2 ;;
  inspect) [[ "$#" -eq 2 && "$2" == /* ]] || exit 2 ;;
  *) printf '%s\n' 'STOP: modo non qualificato.' >&2; exit 2 ;;
esac
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-native-inputs.XXXXXXXX")"
ouf_report() { printf 'Launcher conservato: %s\nLog conservato: %s/capture.log\n' "${BASH_SOURCE[0]}" "$ouf_read"; }
trap ouf_report EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/c1c1aeda9c3535b1460fd7e8819ba32232e25089' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/capture.py"
printf '%s  %s\n' '4692fb34714872a83d3095eb40882c4c7ce399ce3859def46c423927a038ff2c' "$ouf_read/capture.py" | sha256sum -c -
ouf_args=("$ouf_mode")
if [[ "$#" -eq 2 ]]; then ouf_args+=("$2"); fi
sudo python3 -I -B -S - "$ouf_read/capture.py" '4692fb34714872a83d3095eb40882c4c7ce399ce3859def46c423927a038ff2c' "${ouf_args[@]}" <<'OUF_OPERATOR' | tee "$ouf_read/capture.log"
import hashlib,os,stat,sys
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd)
  if not(stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=524288):raise ValueError('DELIVERY_CUSTODY')
  raw=os.read(fd,524289)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  if len(raw)!=s.st_size or pin(s)!=pin(os.fstat(fd))or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise ValueError('DELIVERY_HASH')
 finally:os.close(fd)
 sys.argv=['<verified-native-input-capture>',*sys.argv[3:]]
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: consegna del controllo non verificata; conserva contesti e claim.',flush=True);raise SystemExit(2)
OUF_OPERATOR
