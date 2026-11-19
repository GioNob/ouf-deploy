#!/usr/bin/env bash
# Distinct read-only reconciliation of all five pinned applications. No login or renewal.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_read="$(mktemp -d "$HOME/ouf-rollout-five-apps.XXXXXXXX")"
ouf_report_log() { printf 'Log diagnostico conservato: %s/read.log\n' "$ouf_read"; }
trap ouf_report_log EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/f30dc711ea081f7c06a3a4746854f055dacb884f' --jq .content | tr -d '\n' | base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' 'd65de8d9365e38350caee1fd2ac7d934f31b8a90bab9fe301d54d215ef1dd2f7' "$ouf_read/read.py" | sha256sum -c -
printf '%s\n' 'SOLO LETTURA: riconciliazione distinta di cinque applicazioni dal piano Owner7, dieci GET Docker al massimo. Nessun login, refresh, owner, Gateway o DB.' 'Un journal contenente credenziali viene letto privatamente; nessun valore o hash delle credenziali viene stampato.'
sudo /usr/bin/python3 -I -B -S - "$ouf_read/read.py" 'd65de8d9365e38350caee1fd2ac7d934f31b8a90bab9fe301d54d215ef1dd2f7' <<'OUF_READ' | tee "$ouf_read/read.log"
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
 sys.argv=['<verified-five-application-checkpoint-v3>']
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except Exception:
 print('STOP_RECONCILE: consegna diagnostica non verificata; nessun replay.',flush=True);raise SystemExit(2)
OUF_READ

