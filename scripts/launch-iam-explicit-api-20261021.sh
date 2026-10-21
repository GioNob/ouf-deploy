#!/usr/bin/env bash
# One manually consented admin API authentication and four read-only Admin GETs.
set -euo pipefail
umask 077
ouf_mode="${1:-execute}"
case "$ouf_mode" in
  execute) [[ "$#" -le 1 ]] || exit 2 ;;
  status) [[ "$#" -eq 1 ]] || exit 2 ;;
  *) printf '%s\n' 'STOP: soltanto execute o status; login solo con consenso nel terminale.' >&2; exit 2 ;;
esac
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-iam-explicit-api.XXXXXXXX")"
ouf_report() { printf 'Launcher conservato: %s\nLog conservato: %s/api.log\n' "${BASH_SOURCE[0]}" "$ouf_read"; }
trap ouf_report EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/a20163b27aa15ea74ad70128c101036ace5f428b' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/api.py"
printf '%s  %s\n' '6c24fd27fd25e749c76a7ba39da09231daf70d35b7f39b82340388a72f99db63' "$ouf_read/api.py" | sha256sum -c -
ouf_args=("$ouf_mode")
sudo python3 -I -B -S - "$ouf_read/api.py" '6c24fd27fd25e749c76a7ba39da09231daf70d35b7f39b82340388a72f99db63' "${ouf_args[@]}" <<'OUF_OPERATOR'  | tee "$ouf_read/api.log"
import hashlib,os,stat,sys
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd)
  if not(stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=131072):raise ValueError('DELIVERY_CUSTODY')
  raw=os.read(fd,131073)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  if len(raw)!=s.st_size or pin(s)!=pin(os.fstat(fd))or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise ValueError('DELIVERY_HASH')
 finally:os.close(fd)
 sys.argv=['<verified-explicit-admin-api>',*sys.argv[3:]]
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: consegna della lettura non verificata; conserva contesti e claim.',flush=True);raise SystemExit(2)
OUF_OPERATOR
printf '%s\n' 'Operazione conclusa. Incolla il JSON pubblico e il percorso api.log. Non rieseguire: dopo STOP conserva contesto e claim. Nessuna console Keycloak.'
