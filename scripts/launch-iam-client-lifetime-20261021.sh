#!/usr/bin/env bash
# One separately reviewed client-lifetime PUT; no flow/role/realm change.
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
ouf_read="$(mktemp -d "$HOME/ouf-iam-client-lifetime.XXXXXXXX")"
ouf_report() { printf 'Launcher conservato: %s\nLog conservato: %s/policy.log\n' "${BASH_SOURCE[0]}" "$ouf_read"; }
trap ouf_report EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/2d218e2947aefc9086779e8c53fbd8306151578c' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/policy.py"
printf '%s  %s\n' 'be6c2b0d0c58e2692de5a37b16056ee1b3c5bf8500165c7157d0c4eb4f9515b7' "$ouf_read/policy.py" | sha256sum -c -
ouf_args=("$ouf_mode")
sudo python3 -I -B -S - "$ouf_read/policy.py" 'be6c2b0d0c58e2692de5a37b16056ee1b3c5bf8500165c7157d0c4eb4f9515b7' "${ouf_args[@]}" <<'OUF_OPERATOR'  | tee "$ouf_read/policy.log"
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
printf '%s\n' 'Operazione conclusa. Incolla il JSON pubblico e il percorso policy.log. Non rieseguire: dopo STOP conserva contesto e claim. Nessuna console Keycloak.'
