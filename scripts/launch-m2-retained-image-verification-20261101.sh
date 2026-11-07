#!/usr/bin/env bash
# Verify existing private archives without Engine, import or capture replay; preserve all seven input scopes.
set -euo pipefail
umask 077
if [ "$#" -eq 0 ]; then
  mode=verify
  maximum_seconds=635s
elif [ "$#" -eq 1 ] && [ "$1" = --inspect-source ]; then
  mode=inspect
  maximum_seconds=20s
else
  printf '%s\n' '{"status":"STOP_RECONCILE","reasonCode":"EXACT_IMAGE_VERIFICATION_MODE_REQUIRED"}'; exit 2
fi
task_tmp=$(mktemp -d -t ouf-retained-image-verification.XXXXXXXX)
trap 'rm -rf -- "$task_tmp"' EXIT
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --tlsv1.2 \
  --connect-timeout 10 --max-time 30 --retry 0 --max-filesize 262144 \
  https://raw.githubusercontent.com/GioNob/ouf-deploy/88c1df7311701e5414dc1d79ee108fe991c46f0c/scripts/prepare-m2-retained-image-verification-20261101.py \
  --output "$task_tmp/capture.py"
privilege=()
if [ "$mode" = verify ] && [ "$(/usr/bin/id -u)" != 0 ]; then privilege=(/usr/bin/sudo -n --); fi
"${privilege[@]}" /usr/bin/timeout --signal=TERM --kill-after=5s "$maximum_seconds" \
  /usr/bin/python3 -I -B -S - "$task_tmp/capture.py" "$mode" <<'PY'
import hashlib,json,os,stat,sys
try:
    path,mode=sys.argv[1:]
    assert mode in ('verify','inspect')
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
        assert hashlib.sha256(raw).hexdigest()=='70ab863a3bdb9855672acd5bf9af33d1678ad29ba35c0259ce0bf38e6b64337f'
    finally:os.close(fd)
except Exception:
    print(json.dumps({'status':'STOP_RECONCILE','reasonCode':'EXACT_IMAGE_VERIFICATION_DOWNLOAD_UNPROVEN'}));raise SystemExit(1)
sys.argv=[path]+(['--inspect-source'] if mode=='inspect' else [])
exec(compile(raw,'<verified-private-image-byte-verification>','exec'),{'__name__':'__main__'})
PY
