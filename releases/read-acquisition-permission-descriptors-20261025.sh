#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
delivery=$(mktemp -d "${HOME}/ouf-acquisition-descriptor-read-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
if [[ $(id -u) == 0 ]]; then
  printf '%s\n' 'STOP: eseguire come oufadmin, non come root.' | tee -a "$delivery_log"
  exit 2
fi
if [[ -e /home/oufadmin/ouf-acquisition-permission-descriptor-read-20261025 || -L /home/oufadmin/ouf-acquisition-permission-descriptor-read-20261025 ]]; then
  printf '%s\n' 'STOP: claim diagnostica già presente. Conservare le prove; non rimuovere e non rilanciare.' | tee -a "$delivery_log"
  exit 2
fi
code_sha=062b1e201904b9fd7a10efcad371de17d4c0fbc3411710c310186aa7381c5cad
code_commit=d2e80980f7575ce1e71627632eeba515441d84be
download="$delivery/read.py"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/${code_commit}/scripts/read-acquisition-permission-descriptors-20261025.py" -o "$download"
printf '%s  %s\n' "$code_sha" "$download" | sha256sum -c - | tee -a "$delivery_log"
operator_uid=$(id -u)
sudo /usr/bin/python3 -I -S -B - "$download" "$code_sha" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib, os, re, stat, sys
source, expected, owner = sys.argv[1], sys.argv[2], int(sys.argv[3])
if os.geteuid() != 0 or not re.fullmatch('[a-f0-9]{64}', expected) or owner == 0:
    raise SystemExit('STOP: identità/codice non validi')
for path in ('/', '/usr', '/usr/local', '/usr/local/lib'):
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit('STOP: custodia codice pubblico non valida')
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= 32768:
        raise SystemExit('STOP: file pubblico non valido')
    raw = os.read(fd, 32769)
    after = os.fstat(fd)
    fields = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if fields(before) != fields(after) or len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != expected:
        raise SystemExit('STOP: checksum/custodia codice non valida')
finally:
    os.close(fd)
directory = '/usr/local/lib/ouf-acquisition-permission-descriptor-read-' + expected[:16]
os.mkdir(directory, 0o755)  # exclusive; no overwrite/replay of a previous delivery
target = directory + '/read.py'
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
os.fchmod(fd, 0o444)  # creation modes are filtered by the actual sudo umask
with os.fdopen(fd, 'wb') as output:
    output.write(raw)
    output.flush()
    os.fsync(output.fileno())
os.chmod(directory, 0o555)
for path in (directory, '/usr/local/lib'):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
print('ProtectedCode=' + target)
PY
code="/usr/local/lib/ouf-acquisition-permission-descriptor-read-${code_sha:0:16}/read.py"
printf '%s  %s\n' "$code_sha" "$code" | sha256sum -c - | tee -a "$delivery_log"
printf '%s\n' 'Sola lettura amministrativa. Login IAM personale nel browser; nessun grant, pubblicazione o acquisizione.' | tee -a "$delivery_log"
set +e
/usr/bin/python3 -I -S -B "$code" 2>&1 | tee "$delivery/operator.log"
pipeline_status=("${PIPESTATUS[@]}")
read_exit=${pipeline_status[0]}
set -e
if [[ ${pipeline_status[1]} != 0 ]]; then
  printf '%s\n' 'STOP: conservazione log fallita; non rilanciare.' >&2
  read_exit=2
fi
printf 'Exit=%s\nLog=%s\n' "$read_exit" "$delivery/operator.log" | tee -a "$delivery_log"
exit "$read_exit"
