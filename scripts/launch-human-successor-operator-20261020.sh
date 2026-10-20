#!/usr/bin/env bash
# Retained-installation HUMAN operator. No request without current TTY consent.
# open-window is once-only. step reserves at most ONE provider request.
set -euo pipefail
umask 077
ouf_mode="${1:-open-window}"
case "$ouf_mode" in
  open-window) [[ "$#" -le 1 ]] || exit 2 ;;
  step|status|reconcile-read) [[ "$#" -eq 2 && "$2" == /* ]] || exit 2 ;;
  *) printf '%s\n' 'STOP: modo non qualificato.' >&2; exit 2 ;;
esac
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-human-operator.XXXXXXXX")"
ouf_report() { printf 'Launcher conservato: %s\nLog conservato: %s/operator.log\n' "${BASH_SOURCE[0]}" "$ouf_read"; }
trap ouf_report EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/c2b37d1cb0975cad5c439a2b17f4e88730ece05d' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/operator.py"
printf '%s  %s\n' '7b57a1c3848ff3fae149e286c34bf7bb609ab80d99f426106b3669f659348c14' "$ouf_read/operator.py" | sha256sum -c -
ouf_args=("$ouf_mode")
if [[ "$#" -eq 2 ]]; then ouf_args+=("$2"); fi
sudo python3 -I -B -S - "$ouf_read/operator.py" '7b57a1c3848ff3fae149e286c34bf7bb609ab80d99f426106b3669f659348c14' "${ouf_args[@]}" <<'OUF_OPERATOR' | tee "$ouf_read/operator.log"
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
 sys.argv=['<verified-explicit-human-operator>',*sys.argv[3:]]
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: consegna operatore non verificata; conserva contesti e claim.',flush=True);raise SystemExit(2)
OUF_OPERATOR
python3 -I -B -S - "$ouf_read/operator.log" "${BASH_SOURCE[0]}" <<'OUF_NEXT'
import json,shlex,sys
from pathlib import Path
try:
 value=json.loads(Path(sys.argv[1]).read_text())
 if value.get('schema')!='ouf.human-explicit-successor-operator-result.v1':raise ValueError()
 if value.get('status')=='WAIT_EXPLICIT_STEP':print('Intervallo non ancora trascorso: nessuna richiesta inviata. Attendi prima del prossimo comando.')
 if value.get('complete')is True:
  print('HUMAN verificato. Conserva il contesto e restituisci solo JSON finale e percorso del log.')
 elif value.get('controlPath'):
  command='bash '+shlex.quote(sys.argv[2])+' step '+shlex.quote(value['controlPath'])
  print('Prossimo comando MANUALE, da eseguire solo quando sei pronto:\n'+command)
except Exception:pass
OUF_NEXT
