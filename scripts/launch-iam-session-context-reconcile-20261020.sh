#!/usr/bin/env bash
# Retained STOP reconciliation only; two remaining Engine GETs, no admin request.
set -euo pipefail
umask 077
ouf_mode="${1:-reconcile}"
case "$ouf_mode" in
  reconcile) [[ "$#" -le 1 ]] || exit 2 ;;
  status) [[ "$#" -eq 1 ]] || exit 2 ;;
  *) printf '%s\n' 'STOP: soltanto reconcile o status, nessun login o aggiornamento.' >&2; exit 2 ;;
esac
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-iam-context-reconcile.XXXXXXXX")"
ouf_report() { printf 'Launcher conservato: %s\nLog conservato: %s/reconcile.log\n' "${BASH_SOURCE[0]}" "$ouf_read"; }
trap ouf_report EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/ce7a2cc64709ae391fd09b0ab38074af30b716f2' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/reconcile.py"
printf '%s  %s\n' 'eb2b44880ad968f1224f03f11732735cdf64e545f127a0ce8f067e413ed06a3a' "$ouf_read/reconcile.py" | sha256sum -c -
ouf_args=("$ouf_mode")
sudo python3 -I -B -S - "$ouf_read/reconcile.py" 'eb2b44880ad968f1224f03f11732735cdf64e545f127a0ce8f067e413ed06a3a' "${ouf_args[@]}" <<'OUF_OPERATOR'  | tee "$ouf_read/reconcile.log"
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
 sys.argv=['<verified-retained-iam-context-reconciliation>',*sys.argv[3:]]
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: consegna della lettura non verificata; conserva contesti e claim.',flush=True);raise SystemExit(2)
OUF_OPERATOR
printf '%s\n' 'Lettura conclusa. Incolla in chat il JSON pubblico e il percorso reconcile.log. Non eseguire login o altri passi. La console Keycloak non serve.'
