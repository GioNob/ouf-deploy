#!/usr/bin/env bash
# Exact continuation of the retained pre-login delivery; never rerun its bootstrap.
set -Eeuo pipefail
umask 077
retained=/home/oufadmin/ouf-acquisition-descriptor-read-delivery.XdyYVHv1
continuation="$retained/permission-mode-v1"
mkdir -m 0700 "$continuation"
continuation_log="$continuation/bootstrap.log"
trap 'continuation_exit=$?; trap - EXIT; printf "ContinuationExit=%s\nContinuationDirectory=%s\nContinuationLog=%s\n" "$continuation_exit" "$continuation" "$continuation_log" | tee -a "$continuation_log"; exit "$continuation_exit"' EXIT
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then
  printf '%s\n' 'STOP: eseguire come oufadmin, non root.' | tee -a "$continuation_log"
  exit 2
fi
sudo /usr/bin/python3 -I -S -B - "$operator_uid" <<'PY' 2>&1 | tee -a "$continuation_log"
import errno, hashlib, json, os, pwd, signal, stat, sys

HOME = '/home/oufadmin'
DELIVERY = HOME + '/ouf-acquisition-descriptor-read-delivery.XdyYVHv1'
BOOTSTRAP = HOME + '/ouf-descriptor-bootstrap.mIZy6zES'
CODEDIR = '/usr/local/lib/ouf-acquisition-permission-descriptor-read-062b1e201904b9fd'
CODE = CODEDIR + '/read.py'
CODEHASH = '062b1e201904b9fd7a10efcad371de17d4c0fbc3411710c310186aa7381c5cad'
WRAPPERHASH = '5af3e992228a0fe57adf6db4a568d61624543ea00429e7f2463b5b2836276314'
CLAIM = HOME + '/ouf-acquisition-permission-descriptor-read-20261025'
JOURNAL = CODEDIR + '/permission-mode-v1.json'


class Stop(Exception):
    pass


def require(value, code):
    if not value:
        raise Stop(code)


def no_acl(path):
    try:
        os.getxattr(path, 'system.posix_acl_access', follow_symlinks=False)
    except OSError as error:
        require(error.errno in (errno.ENODATA, errno.ENOTSUP), 'ACL_METADATA_UNAVAILABLE')
    else:
        raise Stop('EXPLICIT_ACL_REQUIRES_RECONCILIATION')


def directory(path, owner, mode=None, public=False):
    info = os.lstat(path)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner
            and not info.st_mode & 0o022, 'DIRECTORY_CUSTODY_REQUIRED')
    if mode is not None:
        require(stat.S_IMODE(info.st_mode) == mode, 'EXACT_DIRECTORY_MODE_REQUIRED')
    if public:
        require(info.st_mode & 0o001, 'ANCESTOR_TRAVERSAL_REQUIRES_RECONCILIATION')


def operator_traversal(owner, paths):
    account = pwd.getpwuid(owner)
    groups = os.getgrouplist(account.pw_name, account.pw_gid)
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups(groups)
            os.setgid(account.pw_gid)
            os.setuid(owner)
            os._exit(0 if all(os.access(path, os.X_OK) for path in paths) else 3)
        except BaseException:
            os._exit(4)
    _, status = os.waitpid(pid, 0)
    require(os.waitstatus_to_exitcode(status) == 0, 'OPERATOR_TRAVERSAL_REQUIRES_RECONCILIATION')


def absent(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    raise Stop('CONSUMED_OR_STARTED_SCOPE_NO_REPLAY')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns)


def read_file(path, owner, modes, expected=None, require_no_acl=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in modes
                and 0 < before.st_size <= 32768, 'EXACT_RETAINED_FILE_REQUIRED')
        if require_no_acl:
            no_acl(path)
        raw = os.read(fd, 32769)
        after = os.fstat(fd)
        require(identity(before) == identity(after) and before.st_mode == after.st_mode
                and before.st_ctime_ns == after.st_ctime_ns and len(raw) == before.st_size,
                'RETAINED_FILE_CHANGED')
        require(expected is None or hashlib.sha256(raw).hexdigest() == expected,
                'RETAINED_CODE_HASH_MISMATCH')
        return fd, before, raw
    except BaseException:
        os.close(fd)
        raise


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def reconcile(owner):
    require(os.geteuid() == 0 and isinstance(owner, int) and owner > 0, 'ROOT_HELPER_OPERATOR_BINDING_REQUIRED')
    for path in ('/', '/usr', '/usr/local', '/usr/local/lib'):
        directory(path, 0, public=True)
    directory(CODEDIR, 0, 0o555, public=True)
    directory('/home', 0)
    directory(HOME, owner)
    directory(BOOTSTRAP, owner, 0o700)
    directory(DELIVERY, owner, 0o700)
    directory(DELIVERY + '/permission-mode-v1', owner, 0o700)
    operator_traversal(owner, ('/', '/usr', '/usr/local', '/usr/local/lib', CODEDIR,
                              '/home', HOME, BOOTSTRAP, DELIVERY, DELIVERY + '/permission-mode-v1'))
    absent(CLAIM)
    absent(DELIVERY + '/operator.log')
    absent(JOURNAL)
    for path, expected in ((BOOTSTRAP + '/run.sh', WRAPPERHASH), (DELIVERY + '/read.py', CODEHASH)):
        fd, _, _ = read_file(path, owner, {0o600}, expected)
        os.close(fd)
    fd, _, raw = read_file(DELIVERY + '/bootstrap.log', owner, {0o600})
    os.close(fd)
    require(b'ProtectedCode=' + CODE.encode() in raw
            and b'FAILED open or read' in raw and b'DeliveryExit=1' in raw
            and b'DeliveryDirectory=' + DELIVERY.encode() in raw,
            'EXACT_PRELOGIN_DELIVERY_FAILURE_REQUIRED')
    code_fd, before, raw = read_file(CODE, 0, {0o400}, CODEHASH, require_no_acl=True)
    try:
        proof = {'schema': 'ouf.acquisition-descriptor-public-mode-reconcile.v1',
                 'state': 'CLAIMED', 'beforeMode': '0400', 'plannedAfterMode': '0444',
                 'codeHash': CODEHASH, 'codeDevice': before.st_dev, 'codeInode': before.st_ino,
                 'retainedDelivery': DELIVERY, 'chmodOperations': 0, 'budgetReset': False,
                 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False,
                 'iamRequests': 0, 'ownerRequests': 0, 'engineRequests': 0}
        proof.update(operatorTraversalProven=True, ancestorAclsUnchanged=True, codeAccessAclAbsent=True)
        journal_fd = os.open(JOURNAL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            os.fchmod(journal_fd, 0o400)
            def save():
                encoded = json.dumps(proof, sort_keys=True, separators=(',', ':')).encode()
                os.lseek(journal_fd, 0, os.SEEK_SET)
                os.ftruncate(journal_fd, 0)
                os.write(journal_fd, encoded)
                os.fsync(journal_fd)
                sync_dir(CODEDIR)
            save()  # durable CLAIMED before the single allowed metadata mutation
            require(identity(os.fstat(code_fd)) == identity(before)
                    and stat.S_IMODE(os.fstat(code_fd).st_mode) == 0o400,
                    'CODE_CHANGED_BEFORE_CHMOD')
            os.fchmod(code_fd, 0o444)
            os.fsync(code_fd)
            after = os.fstat(code_fd)
            os.lseek(code_fd, 0, os.SEEK_SET)
            require(identity(after) == identity(before) and stat.S_IMODE(after.st_mode) == 0o444
                    and hashlib.sha256(os.read(code_fd, 32769)).hexdigest() == CODEHASH,
                    'PUBLIC_MODE_RESULT_REQUIRES_RECONCILIATION')
            proof.update(state='APPLIED', chmodOperations=1, afterMode='0444',
                         codeBytesAndIdentityUnchanged=True, diagnosticFirstExecutionStillRequired=True)
            save()
            return proof
        finally:
            os.close(journal_fd)
    finally:
        os.close(code_fd)


if __name__ == '__main__':
    try:
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Stop('FINITE_METADATA_READ_EXPIRED')))
        signal.alarm(60)
        require(len(sys.argv) == 2 and sys.argv[1].isdigit(), 'EXACT_OPERATOR_ARGUMENT_REQUIRED')
        print(json.dumps(reconcile(int(sys.argv[1])), sort_keys=True, separators=(',', ':')))
    except Stop as error:
        print(json.dumps({'status': 'STOP_RECONCILE', 'reasonCode': str(error), 'automaticReplayAllowed': False}))
        sys.exit(2)
    except Exception:
        print('{"status":"STOP_RECONCILE","reasonCode":"PRIVATE_DETAILS_REDACTED","automaticReplayAllowed":false}')
        sys.exit(2)
PY
code=/usr/local/lib/ouf-acquisition-permission-descriptor-read-062b1e201904b9fd/read.py
printf '%s  %s\n' 062b1e201904b9fd7a10efcad371de17d4c0fbc3411710c310186aa7381c5cad "$code" | sha256sum -c - | tee -a "$continuation_log"
printf '%s\n' 'Primo avvio del SOLO diagnostico. Indirizzo e codice IAM compariranno qui: inserirli soltanto nel browser con ouf-admin.' | tee -a "$continuation_log"
set +e
/usr/bin/python3 -I -S -B "$code" 2>&1 | tee "$continuation/operator.log"
continuation_pipeline=("${PIPESTATUS[@]}")
read_exit=${continuation_pipeline[0]}
set -e
if [[ ${continuation_pipeline[1]} != 0 ]]; then
  read_exit=2
fi
printf 'Exit=%s\nLog=%s\n' "$read_exit" "$continuation/operator.log" | tee -a "$continuation_log"
exit "$read_exit"
