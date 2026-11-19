#!/usr/bin/env bash
# Reconcile exact gateway metadata only; zero Engine or mounted-file contents. No lifecycle, grants, activation or replay.
set -euo pipefail
if [ "$#" -eq 0 ]; then
  mode=capture
elif [ "$#" -eq 1 ] && [ "$1" = --inspect-source ]; then
  mode=inspect
else
  printf '%s\n' '{"status":"STOP_RECONCILE","reasonCode":"EXACT_CAPTURE_MODE_REQUIRED"}'; exit 2
fi
task_tmp=$(mktemp -d -t ouf-retained-hash-reconciliation.XXXXXXXX)
trap 'rm -rf -- "$task_tmp"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --connect-timeout 10 --max-time 30 --retry 0 \
  https://raw.githubusercontent.com/GioNob/ouf-deploy/2332de54f919512ea347d7fae3bbdabf1721d337/scripts/reconcile-m2-retained-hash-metadata-20261101.py \
  --output "$task_tmp/capture.py"
privilege=()
if [ "$mode" = capture ] && [ "$(/usr/bin/id -u)" != 0 ]; then privilege=(/usr/bin/sudo -n --); fi
"${privilege[@]}" /usr/bin/timeout --signal=TERM --kill-after=5s 40s \
  /usr/bin/python3 -I -B -S - "$task_tmp/capture.py" "$mode" <<'PY'
import hashlib,json,os,stat,sys
try:
    path,mode=sys.argv[1:]
    assert mode in ('capture','inspect')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    def pin(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    try:
        before=os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=262144
        chunks=[];size=0
        while size<=262144:
            block=os.read(fd,min(65536,262145-size))
            if not block:break
            chunks.append(block);size+=len(block)
        raw=b''.join(chunks)
        assert len(raw)==before.st_size and pin(before)==pin(os.fstat(fd))
        assert hashlib.sha256(raw).hexdigest()=='5e992de54d31657f0c2fa840cfb0ca2f6e2513c15520a302bec7e8ba22f9f403'
    finally:os.close(fd)
except Exception:
    print(json.dumps({'status':'STOP_RECONCILE','reasonCode':'EXACT_CAPTURE_DOWNLOAD_UNPROVEN'}));raise SystemExit(1)
sys.argv=[path]+(['--inspect-source'] if mode=='inspect' else [])
exec(compile(raw,'<verified-retained-metadata-capture>','exec'),{'__name__':'__main__'})
PY
