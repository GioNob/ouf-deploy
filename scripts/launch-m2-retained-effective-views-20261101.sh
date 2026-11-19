#!/usr/bin/env bash
# Capture effective kernel views and live metadata only; zero Engine or mounted-file contents. No grants, lifecycle or replay.
set -euo pipefail
if [ "$#" -eq 0 ]; then
  mode=capture
elif [ "$#" -eq 1 ] && [ "$1" = --inspect-source ]; then
  mode=inspect
else
  printf '%s\n' '{"status":"STOP_RECONCILE","reasonCode":"EXACT_CAPTURE_MODE_REQUIRED"}'; exit 2
fi
task_tmp=$(mktemp -d -t ouf-retained-effective-views.XXXXXXXX)
trap 'rm -rf -- "$task_tmp"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --connect-timeout 10 --max-time 30 --retry 0 \
  https://raw.githubusercontent.com/GioNob/ouf-deploy/00de07a457442903041ad8b47899458bb283c714/scripts/prepare-m2-retained-effective-views-20261101.py \
  --output "$task_tmp/capture.py"
privilege=()
if [ "$mode" = capture ] && [ "$(/usr/bin/id -u)" != 0 ]; then privilege=(/usr/bin/sudo -n --); fi
"${privilege[@]}" /usr/bin/timeout --signal=TERM --kill-after=5s 100s \
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
        assert hashlib.sha256(raw).hexdigest()=='4ddb3625fd961bbd1cd40866227b3ff95af478b791f6058806a5414e9355d811'
    finally:os.close(fd)
except Exception:
    print(json.dumps({'status':'STOP_RECONCILE','reasonCode':'EXACT_CAPTURE_DOWNLOAD_UNPROVEN'}));raise SystemExit(1)
sys.argv=[path]+(['--inspect-source'] if mode=='inspect' else [])
exec(compile(raw,'<verified-retained-metadata-capture>','exec'),{'__name__':'__main__'})
PY
