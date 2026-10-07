#!/usr/bin/env bash
# Upgrade only the known v1 read-only helper; preserve the exact sudo scope.
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufTmp="$(mktemp -d)"
trap 'rm -rf -- "$oufTmp"' EXIT
"$oufGh" api "repos/GioNob/ouf-deploy/contents/scripts/privileged-discovery-preflight-v2.py?ref=830330acd82f857c1669845fa8019a3e3f28f7cd" --jq .content | base64 --decode > "$oufTmp/helper.py"
printf '%s\n' 'a46d0900ca20ed13115572c9ab9b436105c820e81f066d6e67c2a5333292e893  '"$oufTmp/helper.py" | sha256sum --check --status
sudo /usr/bin/python3 -I -B - "$oufTmp/helper.py" <<'OUF_INSTALL'
import hashlib,os,stat,subprocess,tempfile
from pathlib import Path
expected="a46d0900ca20ed13115572c9ab9b436105c820e81f066d6e67c2a5333292e893"
previous="f005551b3dbabb5dfbe32ce8bcb07f87c745d97592abf249565fcb73def171da"
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
def publish(path,raw,mode,previous_hash=None):
    ancestors(path)
    if path.exists() or path.is_symlink():
        s=path.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=mode or s.st_nlink!=1:raise SystemExit("EXISTING_HELPER_OR_RULE_DIFFERS")
        current=path.read_bytes()
        if current==raw:return
        if previous_hash is None or hashlib.sha256(current).hexdigest()!=previous_hash:raise SystemExit("EXISTING_HELPER_OR_RULE_DIFFERS")
    fd,temporary=tempfile.mkstemp(prefix=".ouf-discovery-publish-",dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(os.dup(fd),"wb") as f:f.write(raw);f.flush()
        os.fsync(fd)
        if previous_hash is not None and path.exists():
            s=path.lstat()
            if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=mode or hashlib.sha256(path.read_bytes()).hexdigest()!=previous_hash:raise SystemExit("INSTALLED_HELPER_CHANGED")
            os.replace(temporary,path)
        else:os.link(temporary,path,follow_symlinks=False)
    finally:
        os.close(fd)
        Path(temporary).unlink(missing_ok=True)
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
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=mode or s.st_nlink!=1 or (p.read_bytes()!=v and not (p==helper and hashlib.sha256(p.read_bytes()).hexdigest()==previous)):raise SystemExit("EXISTING_HELPER_OR_RULE_DIFFERS")
fd,name=tempfile.mkstemp(prefix=".ouf-discovery-policy-",dir=policy.parent)
try:
    with os.fdopen(fd,"wb") as f:f.write(rule);f.flush();os.fsync(f.fileno())
    checked=subprocess.run(["/usr/sbin/visudo","--check","--file",name],capture_output=True)
    if checked.returncode:raise SystemExit("BOUNDED_SUDO_RULE_INVALID")
finally:Path(name).unlink(missing_ok=True)
if helper.exists() and hashlib.sha256(helper.read_bytes()).hexdigest()==previous:
    publish(helper.with_name("ouf-discovery-preflight-v1"),helper.read_bytes(),0o755)
publish(helper,raw,0o755,previous_hash=previous)
publish(policy,rule,0o440)
print("OUF_DISCOVERY_READ_ONLY_HELPER=UPGRADED_V2 GENERAL_SUDO_GRANTED=false")
OUF_INSTALL
sudo -n /usr/local/sbin/ouf-discovery-preflight
"$oufGh" workflow run privileged-discovery-preflight.yml --repo GioNob/ouf-deploy --ref main
