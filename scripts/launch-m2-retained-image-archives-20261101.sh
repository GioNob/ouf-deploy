#!/usr/bin/env bash
# Installation-specific GET-only private image input; preserve all prior scopes.
set -euo pipefail
umask 077
if [ "$#" -eq 0 ]; then
  mode=capture
  maximum_seconds=1835s
elif [ "$#" -eq 1 ] && [ "$1" = --inspect-source ]; then
  mode=inspect
  maximum_seconds=20s
else
  printf '%s\n' '{"status":"STOP_RECONCILE","reasonCode":"EXACT_IMAGE_ARCHIVE_MODE_REQUIRED"}'; exit 2
fi
task_tmp=$(mktemp -d -t ouf-retained-image-archives.XXXXXXXX)
trap 'rm -rf -- "$task_tmp"' EXIT
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --tlsv1.2 \
  --connect-timeout 10 --max-time 30 --retry 0 --max-filesize 262144 \
  https://raw.githubusercontent.com/GioNob/ouf-deploy/a7cb69d8bab9bbefc3202f8008e2e744df85a5d5/scripts/prepare-m2-retained-image-archives-20261101.py \
  --output "$task_tmp/capture.py"
privilege=()
if [ "$mode" = capture ] && [ "$(/usr/bin/id -u)" != 0 ]; then privilege=(/usr/bin/sudo -n --); fi
"${privilege[@]}" /usr/bin/timeout --signal=TERM --kill-after=5s "$maximum_seconds" \
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
        assert hashlib.sha256(raw).hexdigest()=='3e281be893cf7c5dc36d6169b8a48a14d979f6a9c32bd523071d8ea4fa6f148f'
    finally:os.close(fd)
except Exception:
    print(json.dumps({'status':'STOP_RECONCILE','reasonCode':'EXACT_IMAGE_ARCHIVE_DOWNLOAD_UNPROVEN'}));raise SystemExit(1)
sys.argv=[path]+(['--inspect-source'] if mode=='inspect' else [])
exec(compile(raw,'<verified-private-image-archive-input>','exec'),{'__name__':'__main__'})
PY
