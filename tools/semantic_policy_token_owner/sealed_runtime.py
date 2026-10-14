"""Closed in-memory import of the existing worker and its authority dependencies.

Component only: the installer must authenticate the explicit closure hash and
the loader/interpreter separately. Importing code issues no runtime authority,
creates no records, and does not start the worker. No local source-path fallback.
"""
import ast
from contextlib import contextmanager
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

ENTRY = 'tools.semantic_policy_token_owner.worker_entry'
MODULES = frozenset({
    'atomic_review_intake', 'cutover_authority',
    'tools.materialize_semantic_shared_faces', 'tools.materialize_southbound_kernel',
    'tools.semantic_lease_recovery.bounded_recovery',
    'tools.semantic_lease_recovery.recovery_journal',
    *('tools.semantic_policy_token_owner.' + name for name in (
        'producer', 'supervisor', 'source_stage',
        'installed_owner', 'iam_admission', 'worker_entry', 'reporter')),
    *('tools.' + name for name in (
        'semantic_provider_deployment_admission', 'semantic_provider_deployment_authentication',
        'semantic_provider_deployment_protocol', 'semantic_provider_preexec',
        'semantic_provider_preexec_native', 'semantic_provider_peer_bindings',
        'semantic_provider_lease_coordination', 'semantic_provider_lease_nft')),
})
# The separate mount observer remains in the existing signed stage. It is not
# imported by this worker and is not claimed qualified by this runtime closure.
PACKAGES = frozenset({'tools', 'tools.semantic_lease_recovery', 'tools.semantic_policy_token_owner'})
STDLIB = frozenset({
    'abc', 'contextlib', 'copy', 'ctypes', 'dataclasses', 'errno', 'fcntl',
    'hashlib', 'http', 'importlib', 'io', 'ipaddress', 'json', 'math', 'os',
    'pathlib', 'random', 're', 'selectors', 'signal', 'socket', 'ssl', 'stat',
    'subprocess', 'tempfile', 'threading', 'time', 'urllib', 'uuid',
})

class ClosureDenied(RuntimeError):
    pass

def require(ok, reason):
    if not ok:
        raise ClosureDenied(reason)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()

def filename(module):
    return module.replace('.', '-') + '.py'

def declaration(source_commit, sources, loader_bytes):
    require(type(source_commit) is str and len(source_commit) == 40
            and all(c in '0123456789abcdef' for c in source_commit), 'EXACT_SOURCE_COMMIT_REQUIRED')
    require(type(sources) is dict and set(sources) == MODULES, 'COMPLETE_RUNTIME_CLOSURE_REQUIRED')
    require(all(type(raw) is bytes and 0 < len(raw) <= 131072 for raw in sources.values())
            and sum(map(len, sources.values())) <= 1048576, 'BOUNDED_RUNTIME_SOURCES_REQUIRED')
    require(type(loader_bytes) is bytes and 0 < len(loader_bytes) <= 65536, 'EXACT_LOADER_BYTES_REQUIRED')
    compile_sources(sources)
    return {'schema': 'ouf.policy-token-executable-closure.v1', 'sourceCommit': source_commit,
            'entryModule': ENTRY, 'loaderHash': hashlib.sha256(loader_bytes).hexdigest(),
            'modules': {name: {'file': filename(name), 'sha256': hashlib.sha256(raw).hexdigest()}
                        for name, raw in sources.items()}, 'applicationReady': False,
            'runtimeAuthorityIssued': False, 'budgetReset': False, 'notReleaseAcceptance': True}

def compile_sources(sources):
    compiled = {}
    for name, raw in sources.items():
        tree = ast.parse(raw, filename='<sealed:' + name + '>')
        for node in ast.walk(tree):
            refs = [v.name for v in node.names] if isinstance(node, ast.Import) else []
            if isinstance(node, ast.ImportFrom):
                require(node.level == 0 and node.module is not None, 'RELATIVE_IMPORT_DENIED')
                refs = [node.module]
            for ref in refs:
                require(ref in sources or ref.split('.')[0] in STDLIB,
                        'DEPENDENCY_OUTSIDE_RUNTIME_CLOSURE')
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == '__import__':
                require(len(node.args) >= 1 and isinstance(node.args[0], ast.Constant)
                        and node.args[0].value == 'random', 'UNREVIEWED_DYNAMIC_IMPORT_DENIED')
        compiled[name] = compile(tree, '<sealed:' + name + '>', 'exec')
    return compiled

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_MANIFEST_KEY')
        result[key] = value
    return result

def identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

@contextmanager
def root_directory(path):
    path = Path(path)
    require(os.geteuid() == os.getegid() == 0 and path.is_absolute() and path != Path('/')
            and '..' not in path.parts and len(path.parts) <= 32, 'ROOT_EXECUTION_AND_EXACT_PATH_REQUIRED')
    fds, bindings = [], []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(parent)
        for part in path.parts[1:]:
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
                    and not before.st_mode & 0o022, 'ROOT_ANCESTRY_REQUIRED')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(child)
            require(identity(before) == identity(os.fstat(child)), 'SOURCE_DIRECTORY_CHANGED')
            bindings.append((parent, part, child, before))
            parent = child
        require(stat.S_IMODE(os.fstat(parent).st_mode) == 0o700, 'PRIVATE_BUNDLE_DIRECTORY_REQUIRED')
        yield parent
        for parent, part, child, before in bindings:
            # Reading members does not alter directory mtime/ctime.
            require(identity(before) == identity(os.fstat(child))
                    == identity(os.stat(part, dir_fd=parent, follow_symlinks=False)), 'SOURCE_DIRECTORY_CHANGED')
    finally:
        for fd in reversed(fds):
            os.close(fd)

def read_file(directory, name, limit):
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
            and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
            and 0 < before.st_size <= limit, 'PRIVATE_REGULAR_SOURCE_REQUIRED')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        require(identity(before) == identity(os.fstat(fd)), 'SOURCE_FILE_CHANGED')
        chunks, total = [], 0
        while total <= limit:
            raw = os.read(fd, min(65536, limit + 1 - total))
            if not raw:
                break
            total += len(raw)
            chunks.append(raw)
        require(total == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'SOURCE_FILE_CHANGED')
        return b''.join(chunks)
    finally:
        os.close(fd)

class MemoryLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, compiled):
        self.compiled = compiled
    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.compiled or fullname in PACKAGES:
            return importlib.util.spec_from_loader(fullname, self, is_package=fullname in PACKAGES)
        if fullname == 'tools' or fullname.startswith('tools.') or fullname in MODULES:
            raise ClosureDenied('LOCAL_IMPORT_FALLBACK_DENIED')
        return None
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        if module.__name__ in PACKAGES:
            module.__path__ = []
        else:
            exec(self.compiled[module.__name__], module.__dict__)

class VerifiedRuntime:
    def __init__(self, manifest, sources):
        self.manifest_hash = digest(manifest)
        self.compiled = compile_sources(sources)
    def load_entry(self):
        # Dedicated isolated process only. Reusing a loaded tools namespace
        # could preserve foreign classes and break exact type/authority checks.
        require(sys.flags.isolated and sys.flags.dont_write_bytecode, 'ISOLATED_NO_BYTECODE_PROCESS_REQUIRED')
        require(not any(n in MODULES or n in PACKAGES or n.startswith('tools.') for n in sys.modules),
                'PRELOADED_RUNTIME_MODULE_DENIED')
        finder = MemoryLoader(self.compiled)
        sys.meta_path.insert(0, finder)
        try:
            return __import__(ENTRY, fromlist=['build_worker'])
        except Exception:
            # Failed imports never permit a fallback/retry in this process.
            raise ClosureDenied('SEALED_RUNTIME_IMPORT_FAILED') from None

def verify_bundle(path, approved_closure_hash, executed_loader_bytes):
    require(type(approved_closure_hash) is str and len(approved_closure_hash) == 64
            and all(c in '0123456789abcdef' for c in approved_closure_hash), 'EXPLICIT_APPROVED_CLOSURE_REQUIRED')
    with root_directory(path) as directory:
        raw = read_file(directory, 'closure.json', 16384)
        manifest = json.loads(raw, object_pairs_hook=unique)
        require(digest(manifest) == approved_closure_hash, 'APPROVED_CLOSURE_CHANGED')
        require(set(os.listdir(directory)) == {'closure.json', 'sealed-runtime.py'} | {filename(n) for n in MODULES},
                'EXACT_CLOSED_BUNDLE_REQUIRED')
        loader = read_file(directory, 'sealed-runtime.py', 65536)
        require(loader == executed_loader_bytes, 'EXECUTED_LOADER_CHANGED')
        sources = {n: read_file(directory, filename(n), 131072) for n in sorted(MODULES)}
        require(manifest == declaration(manifest.get('sourceCommit'), sources, loader), 'RUNTIME_SOURCE_CLOSURE_CHANGED')
    # Only immutable memory copies survive. No source is imported from disk.
    return VerifiedRuntime(manifest, sources)
