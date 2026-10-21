"""Untrusted static observation only; never authenticate or execute the producer."""
import ast, hashlib, json, os, re, shlex, signal, stat, subprocess
from pathlib import Path

TARGET = Path('/opt/ouf/ops/refresh-policy-token.py')
EXPECTED = {'/opt': (0, 0, 0o755), '/opt/ouf': (1000, 1000, 0o750),
            '/opt/ouf/ops': (0, 0, 0o700)}
PUBLIC_KEYS = {'grant_type', 'client_id', 'client_secret', 'access_token',
               'expires_in', 'token_type', 'scope', 'Authorization', 'Content-Type'}

def require(ok):
    if not ok:
        raise ValueError('STATIC_OBSERVATION_UNPROVEN')

def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def routing():
    r = subprocess.run(['/usr/bin/systemctl', '--no-pager', 'show',
        'ouf-policy-token@semantic.service', '--property=ExecStart,Type,User'],
        capture_output=True, timeout=15)
    require(r.returncode == 0 and len(r.stdout) <= 65536)
    fields = {}
    for line in r.stdout.decode().splitlines():
        key, separator, value = line.partition('=')
        if separator:
            require(key not in fields)
            fields[key] = value
    require(fields.get('Type') == 'oneshot' and fields.get('User') == 'root')
    text = fields.get('ExecStart', '')
    exe = re.search(r'\bpath=([^ ;}]+)', text)
    argv = re.search(r'argv\[\]=(.*?);', text)
    require(text.count('argv[]=') == 1 and exe and argv and exe.group(1) == '/usr/bin/python3')
    args = shlex.split(argv.group(1)); require(args and args[0] == '/usr/bin/python3')
    index = 1
    while index < len(args) and args[index] in {'-I', '-B', '-u', '-E', '-s', '-S'}:
        index += 1
    require(index < len(args) and args[index] == str(TARGET))
    return tuple(args)

def snapshot(path=TARGET, expected=EXPECTED):
    fds = []; entries = []
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        root = os.open('/', directory_flags); fds.append(root)
        s = os.fstat(root); require(s.st_uid == 0 and not s.st_mode & 0o022)
        parent = root; current = Path('/')
        for part in path.parts[1:-1]:
            current /= part
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISDIR(before.st_mode))
            custody = (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))
            require(custody == expected[str(current)])
            child = os.open(part, directory_flags, dir_fd=parent); fds.append(child)
            require(identity(before) == identity(os.fstat(child)))
            entries.append((parent, part, child, identity(before))); parent = child
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o755 and before.st_nlink == 1
                and 0 < before.st_size <= 131072)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        fds.append(fd); require(identity(before) == identity(os.fstat(fd)))
        raw = bytearray()
        while len(raw) <= 131072:
            chunk = os.read(fd, min(16384, 131073 - len(raw)))
            if not chunk: break
            raw.extend(chunk)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)))
        for parent, name, child, saved in entries:
            require(saved == identity(os.fstat(child))
                    == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        return bytes(raw), identity(before)
    finally:
        for fd in reversed(fds): os.close(fd)

def redact(raw):
    tree = ast.parse(raw); require(sum(1 for _ in ast.walk(tree)) <= 20000)
    labels = {}
    class Mask(ast.NodeTransformer):
        def visit_Dict(self, node):
            node.keys = [key if isinstance(key, ast.Constant) and type(key.value) is str
                         and key.value in PUBLIC_KEYS else self.visit(key) if key is not None
                         else None for key in node.keys]
            node.values = [self.visit(value) for value in node.values]; return node
        def visit_Constant(self, node):
            if node.value is None or type(node.value) is bool: return node
            key = (type(node.value).__name__, repr(node.value))
            labels.setdefault(key, '__REDACTED_LITERAL_' + str(len(labels) + 1) + '__')
            return ast.copy_location(ast.Constant(labels[key]), node)
    text = ast.unparse(ast.fix_missing_locations(Mask().visit(tree)))
    return {'redactedSource': text[:12000], 'redactedSourceTruncated': len(text) > 12000}

def main():
    report = {'schema': 'ouf.semantic-token-untrusted-static-observation.v1',
        'sourceAuthenticationProven': False, 'writerAuthorityProven': False,
        'outputBindingProven': False, 'producerExecuted': False, 'serviceMutations': 0,
        'protectedFileWrites': 0, 'providerCalls': 0, 'tokenGrantRequests': 0,
        'baselineRefreshed': False, 'budgetReset': False, 'r12Touched': False,
        'runtimeAuthorityIssued': False, 'notReleaseAcceptance': True,
        'sourceContentBytesRead': 0, 'execStartArgumentsPrinted': False,
        'environmentValuesPrinted': False, 'credentialPathsPrinted': False}
    try:
        require(os.geteuid() == 0 and __import__('sys').flags.isolated
                and __import__('sys').dont_write_bytecode)
        def deadline(*_): raise ValueError('STATIC_OBSERVATION_DEADLINE')
        signal.signal(signal.SIGALRM, deadline); signal.alarm(60)
        command = routing(); raw, seal = snapshot()
        report['sourceContentBytesRead'] += len(raw)
        masked = redact(raw)
        again, next_seal = snapshot(); report['sourceContentBytesRead'] += len(again)
        require(command == routing() and raw == again and seal == next_seal)
        report.update(status='UNTRUSTED_PRODUCER_STATIC_SOURCE_OBSERVED_NOT_ACCEPTED',
            producerSourcePath=str(TARGET), sourceSha256=hashlib.sha256(raw).hexdigest(),
            rootOnlyAncestorCustody=False, stableDoubleRead=True,
            sourceByteAccountingComplete=True, **masked)
        code = 0
    except Exception:
        report.update(status='UNTRUSTED_PRODUCER_STATIC_OBSERVATION_BLOCKED',
                      reason='STATIC_OBSERVATION_UNPROVEN', sourceContentBytesRead=None,
                      sourceByteAccountingComplete=False); code = 1
    finally: signal.alarm(0)
    print('OUF_TOKEN_PRODUCER_STATIC_OBSERVATION=' + json.dumps(report, sort_keys=True))
    return code

if __name__ == '__main__': raise SystemExit(main())
