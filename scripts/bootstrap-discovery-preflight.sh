#!/usr/bin/env bash
# One-time installation of a fixed read-only helper. No general sudo grant.
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufTmp="$(mktemp -d)"
trap 'rm -rf -- "$oufTmp"' EXIT
"$oufGh" api "repos/GioNob/ouf-deploy/contents/scripts/privileged-discovery-preflight.py?ref=b202829f9070777969a31755b8a5e679f09d4a37" --jq .content | base64 --decode > "$oufTmp/helper.py"
printf '%s\n' 'f005551b3dbabb5dfbe32ce8bcb07f87c745d97592abf249565fcb73def171da  '"$oufTmp/helper.py" | sha256sum --check --status
sudo /usr/bin/python3 -I -B - "$oufTmp/helper.py" <<'OUF_INSTALL'
import hashlib,os,stat,subprocess,tempfile
from pathlib import Path
expected="f005551b3dbabb5dfbe32ce8bcb07f87c745d97592abf249565fcb73def171da"
fd=os.open(__import__("sys").argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    s=os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or s.st_size>65536:raise SystemExit("HELPER_INPUT_INVALID")
    raw=os.read(fd,65537)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit("HELPER_HASH_MISMATCH")
compile(raw,"ouf-discovery-preflight","exec")
def ancestors(path):
    for p in (path.parent,*path.parent.parents):
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022:raise SystemExit("INSTALL_PARENT_UNSAFE")
def publish(path,raw,mode):
    ancestors(path)
    if path.exists() or path.is_symlink():
        s=path.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=mode or path.read_bytes()!=raw:raise SystemExit("EXISTING_HELPER_OR_RULE_DIFFERS")
        return
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(os.dup(fd),"wb") as f:f.write(raw);f.flush()
        os.fsync(fd)
    finally:os.close(fd)
    d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(d)
    finally:os.close(d)
helper=Path("/usr/local/sbin/ouf-discovery-preflight")
policy=Path("/etc/sudoers.d/ouf-discovery-preflight")
rule=b'oufadmin ALL=(root) NOPASSWD: /usr/local/sbin/ouf-discovery-preflight ""\n'
ancestors(helper);ancestors(policy)
for p,v,mode in ((helper,raw,0o755),(policy,rule,0o440)):
    if p.exists() or p.is_symlink():
        s=p.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=mode or p.read_bytes()!=v:raise SystemExit("EXISTING_HELPER_OR_RULE_DIFFERS")
fd,name=tempfile.mkstemp(prefix=".ouf-discovery-policy-",dir=policy.parent)
try:
    with os.fdopen(fd,"wb") as f:f.write(rule);f.flush();os.fsync(f.fileno())
    checked=subprocess.run(["/usr/sbin/visudo","--check","--file",name],capture_output=True)
    if checked.returncode:raise SystemExit("BOUNDED_SUDO_RULE_INVALID")
finally:Path(name).unlink(missing_ok=True)
publish(helper,raw,0o755)
publish(policy,rule,0o440)
print("OUF_DISCOVERY_READ_ONLY_HELPER=INSTALLED GENERAL_SUDO_GRANTED=false")
OUF_INSTALL
sudo -n /usr/local/sbin/ouf-discovery-preflight
