#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then
  printf '%s\n' 'STOP: eseguire come oufadmin, non root.'
  exit 2
fi
delivery=$(mktemp -d "${HOME}/ouf-existing-draft-publish-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_sha=14477872585ad75bf96da5bb13ed6ee4381911d81ccb0ec76d7166f3ec744932
code_commit=d70cf9cbe816f41f76d08858084bd393ece45c69
download="$delivery/publish.py"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/${code_commit}/scripts/publish-existing-descriptor-draft-20261025.py" -o "$download"
printf '%s  %s\n' "$code_sha" "$download" | sha256sum -c - | tee -a "$delivery_log"
sudo /usr/bin/python3 -I -S -B - "$download" "$code_sha" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib, os, re, stat, sys
source, expected, owner = sys.argv[1], sys.argv[2], int(sys.argv[3])
if os.geteuid() != 0 or owner <= 0 or not re.fullmatch('[a-f0-9]{64}', expected):
    raise SystemExit('STOP: identità/checksum non validi')
scope='/etc/ouf/deploy-snapshots/acquisition-existing-draft-publish-cb75ddb0-v1'
if os.path.lexists(scope):
    raise SystemExit('STOP: pubblicazione residua consumata; conservare prove, nessun rilancio')
for path in ('/', '/usr', '/usr/local', '/usr/local/lib'):
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit('STOP: custodia codice root non valida')
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= 65536:
        raise SystemExit('STOP: file scaricato non valido')
    raw = os.read(fd, 65537)
    after = os.fstat(fd)
    fields = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if fields(before) != fields(after) or len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != expected:
        raise SystemExit('STOP: checksum/custodia codice non validi')
finally:
    os.close(fd)
directory = '/usr/local/lib/ouf-existing-descriptor-draft-publish-' + expected[:16]
os.mkdir(directory, 0o700)
target = directory + '/publish.py'
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
os.fchmod(fd, 0o400)
with os.fdopen(fd, 'wb') as output:
    output.write(raw); output.flush(); os.fsync(output.fileno())
for path in (directory, '/usr/local/lib'):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
try:
    info=os.fstat(fd)
    if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o400 or hashlib.sha256(os.read(fd,65537)).hexdigest()!=expected:
        raise SystemExit('STOP: copia root non verificata')
finally:os.close(fd)
print('ProtectedCode='+target)
print(target+': OK (root0400; esecuzione root)')
PY
code="/usr/local/lib/ouf-existing-descriptor-draft-publish-${code_sha:0:16}/publish.py"
printf '%s\n' 'Sola pubblicazione del draft esistente: nuovo login IAM con ouf-admin, poi review concreta e APPROVO hash fresco su riga isolata nel terminale.' | tee -a "$delivery_log"
set +e
sudo /usr/bin/python3 -I -S -B "$code" 2>&1 | tee "$delivery/operator.log"
publication_pipeline=("${PIPESTATUS[@]}")
publication_exit=${publication_pipeline[0]}
set -e
if [[ ${publication_pipeline[1]} != 0 ]]; then publication_exit=2; fi
printf 'Exit=%s\nLog=%s\n' "$publication_exit" "$delivery/operator.log" | tee -a "$delivery_log"
exit "$publication_exit"
