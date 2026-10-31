#!/usr/bin/env python3
"""Explicit operator maintenance: six empty JVM directories; no application admission."""
import ast,base64,copy,fcntl,gzip,hashlib,http.client,io,json,os,re,signal,socket,stat,sys,time,types
from pathlib import Path
PLAN_ROOT='semantic-registry-jvm-residue-aaa525bab7d23982bcd72bf3f29d687a9aa105af78f53add858a1254c452824d'
PLAN_HASH='f745bebba740e28d675d14277b04f51ed4340bce59f1c9659520390b15772d9c'
PROOF_HASH='c046c4a7274f6021b15be5e9db0e875e9c5eb52252b1f17175f74c8cac3f36cc'

BASE_SHA256 = '97ee083211258c9f207e4b4aef8309fbe902e041a7b0b67bebce618adf09a9fe'
BASE_SOURCE = '#!/usr/bin/env python3\n"""Read retained stop metadata only; never execute capsule or enter application."""\nimport ast\nimport hashlib\nimport json\nimport os\nfrom pathlib import Path\nimport re\nimport stat\nimport sys\nimport time\n\nCAPSULE = \'/home/oufadmin/ouf-registry-postboot-review.LduMidpc/capsule.py\'\nCAPSULE_HASH = \'f6ab800de6ca9452258cf967dd0e194b81b620a35dff0ef357f7fdf93f45f02c\'\nCLOSURE_HASH = \'4fb611d8ffcf4446aeb25df7777dfb66fefb964c63f375863471072b8d7d2f27\'\nDECLARATION_HASH = \'c0d3bedb36ab56d4f116a4a264e49a1310b366d0ec9aadbd5a6d715331c6bdc8\'\nPREPARATION_ROOT = \'/etc/ouf/deploy-snapshots/semantic-registry-postboot-inputs-ed5451cb23ed2a28c1dbb7585cccfe64fb2837e2d33c81d2a43c1e31f243d5c2\'\nPREPARATION_HASH = \'90748d593e5292420ce967c256d757364ba8637dc0f79619c688585a2f1e5f5d\'\nREVIEW_HASH = \'cf5191895f1e67b86bdc98b7aa9e10b1292d3f8589a653839116e7c2816ba3c9\'\nAUTHORITY_HASH = \'9d8f36e7f6a942fee95278148399a1a3d140fe0b660809a465edd85f2820d607\'\nPARENT = \'/etc/ouf/deploy-snapshots\'\n\n\ndef require(ok, reason):\n    if not ok: raise ValueError(reason)\n\n\ndef encoded(v): return json.dumps(v, sort_keys=True, separators=(\',\', \':\'), allow_nan=False).encode()\ndef digest(v): return hashlib.sha256(encoded(v)).hexdigest()\ndef identity(v): return (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)\n\n\nclass Reader:\n    def __init__(self): self.reads = 0; self.bytes = 0; self.until = time.monotonic() + 30\n\n    def raw(self, path, maximum, sha=None, private=True):\n        require(time.monotonic() < self.until and self.reads < 20, \'BOUNDED_METADATA_READ_REQUIRED\')\n        # Traverse protected ancestry through held descriptors, refusing links.\n        path = Path(path)\n        require(path.is_absolute() and \'..\' not in path.parts, \'EXACT_METADATA_PATH_REQUIRED\')\n        fd = os.open(\'/\', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n        try:\n            for part in path.parts[1:-1]:\n                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)\n                info = os.fstat(child)\n                require(not info.st_mode & 0o022 and (info.st_uid == 0 or not private), \'PROTECTED_METADATA_ANCESTRY_REQUIRED\')\n                os.close(fd); fd = child\n            leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)\n            try:\n                before = os.fstat(leaf)\n                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022\n                    and (before.st_uid == 0 or not private) and 0 < before.st_size <= maximum,\n                    \'BOUNDED_PROTECTED_METADATA_REQUIRED\')\n                chunks = []; count = 0\n                while count <= before.st_size:\n                    block = os.read(leaf, min(65536, before.st_size + 1 - count))\n                    if not block: break\n                    chunks.append(block); count += len(block)\n                raw = b\'\'.join(chunks)\n                require(len(raw) == before.st_size and identity(before) == identity(os.fstat(leaf))\n                    == identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)), \'METADATA_CHANGED\')\n            finally: os.close(leaf)\n        finally: os.close(fd)\n        self.reads += 1; self.bytes += len(raw)\n        require(self.bytes <= 16777216 and (sha is None or hashlib.sha256(raw).hexdigest() == sha), \'METADATA_HASH_OR_BYTE_BOUND\')\n        return raw\n\n    def json(self, path, sha=None, maximum=8388608):\n        raw = self.raw(path, maximum, sha); value = json.loads(raw)\n        require(type(value) is dict and encoded(value) == raw, \'CANONICAL_METADATA_REQUIRED\')\n        return value\n\n\ndef inside(value):\n    require(type(value) is str and value.startswith(PARENT + \'/\') and \'..\' not in Path(value).parts\n            and str(Path(value)) == value, \'EXACT_REVIEW_BOUND_PRIVATE_PATH_REQUIRED\')\n    return Path(value)\n\n\ndef optional(reader, path, maximum=131072):\n    try: path.lstat()\n    except FileNotFoundError: return None\n    return reader.json(str(path), maximum=maximum)\n\n\ndef closed(value, allowed): return value if type(value) is str and value in allowed else \'OTHER_OR_ABSENT\'\n\n\ndef shape(value):\n    obj = type(value) is dict\n    return {\'object\': obj, \'string\': type(value) is str,\n        \'exactKeys\': obj and set(value) == {\'schema\', \'sha256\', \'entries\', \'bytes\'},\n        \'schemaMatches\': obj and value.get(\'schema\') == \'ouf.semantic-rootfs-seal.v1\',\n        \'sha256WellFormed\': obj and type(value.get(\'sha256\')) is str and re.fullmatch(\'[0-9a-f]{64}\', value[\'sha256\']) is not None,\n        \'entries\': value[\'entries\'] if obj and type(value.get(\'entries\')) is int and 0 < value[\'entries\'] <= 100000 else None,\n        \'bytes\': value[\'bytes\'] if obj and type(value.get(\'bytes\')) is int and 0 <= value[\'bytes\'] <= 8589934592 else None}\n\n\ndef inspect(reader):\n    # Parse only literal assignments; do not execute the loader or application.\n    raw = reader.raw(CAPSULE, 1048576, CAPSULE_HASH, private=False)\n    values = {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(raw).body\n        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}\n    require(set(values) == {\'CASE\', \'DELIVERY\', \'DELIVERY_HASH\', \'PACKED\', \'BOOTSTRAP\'}, \'EXACT_RETAINED_CAPSULE_FIELDS_REQUIRED\')\n    manifest = values[\'DELIVERY\'][\'nativeDeclaration\']\n    require(digest(values[\'DELIVERY\']) == values[\'DELIVERY_HASH\'] == DECLARATION_HASH and digest(manifest) == CLOSURE_HASH\n        and digest(values[\'CASE\']) == values[\'DELIVERY\'][\'caseHash\'], \'EXACT_RETAINED_CAPSULE_BINDINGS_REQUIRED\')\n    root = inside(PREPARATION_ROOT)\n    prepared = reader.json(str(root / \'prepared.json\'), PREPARATION_HASH, maximum=16777216)\n    review = reader.json(str(root / \'review.json\'), REVIEW_HASH)\n    require(review[\'currentContext\'] == prepared[\'nativeContext\'] and review[\'ownerContext\'] == prepared[\'ownerContext\']\n        and review[\'sourceClosureHash\'] == digest(prepared[\'sourceClosure\']) == CLOSURE_HASH\n        and prepared[\'sourceClosure\'] == manifest and review[\'sourceClosure\'] == manifest, \'EXACT_COMPLETED_REVIEW_INPUTS_REQUIRED\')\n    boot = Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip()\n    require(review[\'bootId\'] == boot, \'SAME_RETAINED_BOOT_REQUIRED\')\n    receipt = reader.json(str(root / \'authority/receipt.json\'), maximum=131072)\n    require(receipt.get(\'schema\') == \'ouf.semantic-registry-postboot-issued-authority.v1\'\n        and receipt.get(\'authorityHash\') == AUTHORITY_HASH and receipt.get(\'reviewHash\') == REVIEW_HASH\n        and receipt.get(\'runtimeAuthorityIssued\') is True, \'EXACT_ISSUED_AUTHORITY_RECEIPT_REQUIRED\')\n    context = prepared[\'nativeContext\']; plan = context[\'plan\']; execution = inside(context[\'executionRoot\'])\n    require(execution.name == \'semantic-registry-recovery-\' + plan[\'logicalOperationRef\'], \'EXACT_RECOVERY_OPERATION_ROOT_REQUIRED\')\n    journal = reader.json(str(execution / \'recovery.json\'), maximum=1048576)\n    require(journal[\'logicalOperationRef\'] == plan[\'logicalOperationRef\'] and journal[\'authorityHash\'] == AUTHORITY_HASH\n        and journal[\'bootId\'] == boot and type(journal[\'nextStage\']) is int and 0 <= journal[\'nextStage\'] <= 12\n        and type(journal[\'effects\']) is list and len(journal[\'effects\']) <= 12, \'EXACT_RETAINED_RECOVERY_JOURNAL_REQUIRED\')\n    require(type(journal.get(\'readAttempts\')) is int and 0 <= journal[\'readAttempts\'] <= 128\n        and type(journal.get(\'expiresUnix\')) is int and 0 < journal[\'expiresUnix\'] < 1099511627776,\n        \'BOUNDED_RETAINED_READ_AND_EXPIRY_FIELDS_REQUIRED\')\n    effects = []\n    for n, effect in enumerate(journal[\'effects\']):\n        require(effect[\'stage\'] == plan[\'stages\'][n][\'name\'], \'EXACT_ORDERED_EFFECTS_REQUIRED\')\n        effects.append({\'ordinal\': n, \'state\': closed(effect.get(\'state\'), (\'PENDING\',\'CLAIMED\',\'APPLIED\',\'UNKNOWN\',\'FAILED\')),\n            \'nativeRequestAttempted\': effect.get(\'nativeRequestAttempted\') is True,\n            \'nativeResponse204\': effect.get(\'nativeResponse204\') is True,\n            \'nativeAttestationAttempted\': effect.get(\'nativeAttestationAttempted\') is True})\n    owner_scope = review[\'scopes\'][\'semanticRegistryPostbootOwner\']; owner_root = inside(owner_scope[\'journalPath\'])\n    owner = reader.json(str(owner_root / \'recovery.json\'), maximum=65536)\n    require(owner[\'contextRef\'] == owner_scope[\'contextRef\'] and owner[\'generationRef\'] == owner_scope[\'generationRef\']\n        and type(owner[\'attempts\']) is int and 0 <= owner[\'attempts\'] <= 1\n        and owner[\'controlledPredecessorGrantAttempts\'] == 319\n        and owner[\'controlledCumulativeGrantAttempts\'] == 319 + owner[\'attempts\'], \'EXACT_RETAINED_OWNER_ACCOUNTING_REQUIRED\')\n    reads = reader.json(str(execution / \'native-reads.json\'), maximum=8192)\n    scope = review[\'scopes\'][\'semanticRegistryRecoveryReads\']; counts = reads[\'counts\']\n    require(reads[\'scopeHash\'] == digest(scope) and reads[\'authorityHash\'] == AUTHORITY_HASH\n        and set(counts) == set(scope[\'maximumRequests\']) and all(type(v) is int and 0 <= v <= scope[\'maximumRequests\'][k]\n            for k,v in counts.items()), \'EXACT_RETAINED_NATIVE_READ_COUNTERS_REQUIRED\')\n    frame = optional(reader, execution / \'node/frame-policy.json\')\n    observed = optional(reader, execution / \'node/paused-observation.json\', maximum=1048576)\n    acceptance = optional(reader, execution / \'node/paused-acceptance.json\')\n    recipe = context[\'nodeRecipe\']; expected = recipe[\'expectedRootfsSeal\']\n    observed_seal = observed.get(\'rootfsSeal\') if observed is not None else None\n    require(reader.json(str(execution / \'recovery.json\'), maximum=1048576) == journal\n        and reader.json(str(owner_root / \'recovery.json\'), maximum=65536) == owner\n        and reader.json(str(execution / \'native-reads.json\'), maximum=8192) == reads\n        and Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip() == boot, \'STOP_METADATA_CHANGED_DURING_OBSERVATION\')\n    return {\'schema\': \'ouf.semantic-registry-rootfs-stop-metadata.v1\', \'status\': \'RETAINED_ROOTFS_STOP_METADATA_OBSERVED\',\n        \'checkpoint\': journal[\'nextStage\'], \'recoveryState\': closed(journal.get(\'state\'), (\'READY\',\'IN_FLIGHT\',\'COMPLETE\',\'BLOCKED\',\'RECONCILE_REQUIRED\')),\n        \'effects\': effects, \'readAttempts\': journal.get(\'readAttempts\'), \'nativeReadCounts\': counts,\n        \'newGenerationRecorded\': type(journal.get(\'newGeneration\')) is dict,\n        \'framePolicyRetained\': frame is not None, \'pausedObservationRetained\': observed is not None,\n        \'pausedAcceptanceRetained\': acceptance is not None, \'expectedSealShape\': shape(expected),\n        \'retainedObservedSealShape\': shape(observed_seal),\n        \'retainedSealMatchesExpected\': observed_seal == expected if observed is not None else None,\n        \'ownerState\': closed(owner.get(\'state\'), (\'NEW\',\'ACTIVE\',\'BLOCKED\',\'CANCELLED\',\'PAUSED_EXHAUSTED\',\'RECONCILE_REQUIRED\',\'PUBLISHING\')),\n        \'retainedServiceGrantAttempts\': owner[\'attempts\'], \'retainedControlledGrantAttempts\': owner[\'controlledCumulativeGrantAttempts\'],\n        \'signedWindowExpiredAtObservation\': time.time() >= journal[\'expiresUnix\'],\n        \'journalObservationIsCurrentOwnerAdmission\': False, \'currentContainerStateObserved\': False,\n        \'currentRootfsRead\': False, \'rootfsMismatchCauseEstablished\': False, \'capsuleExecuted\': False,\n        \'addressesPrinted\': False, \'credentialFilesOpened\': 0, \'metadataReads\': reader.reads, \'metadataBytesRead\': reader.bytes,\n        \'engineGets\': 0, \'adminGets\': 0, \'oauthRequests\': 0, \'databaseCalls\': 0, \'runtimeEffectsDispatched\': 0,\n        \'runtimeAuthorityIssued\': False, \'readOnly\': True, \'automaticReplayAllowed\': False, \'budgetReset\': False,\n        \'serviceReadinessEstablished\': False, \'releaseAcceptance\': False}\n\n\ndef main():\n    try:\n        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site\n            and sys.dont_write_bytecode and len(sys.argv) == 1, \'ISOLATED_ROOT_METADATA_READER_REQUIRED\')\n        result = inspect(Reader())\n    except Exception as error:\n        reason = str(error)\n        if re.fullmatch(\'[A-Z][A-Z0-9_]{0,127}\', reason) is None: reason = \'ROOTFS_STOP_METADATA_UNPROVEN_PRIVATE_DETAILS_REDACTED\'\n        result = {\'schema\': \'ouf.semantic-registry-rootfs-stop-metadata.v1\', \'status\': \'STOP_RECONCILE\',\n            \'reasonCode\': reason, \'automaticReplayAllowed\': False, \'budgetReset\': False, \'runtimeEffectsDispatched\': 0}\n    print(json.dumps(result, sort_keys=True, separators=(\',\', \':\')), flush=True)\n    return 0 if result[\'status\'] == \'RETAINED_ROOTFS_STOP_METADATA_OBSERVED\' else 2\n\n\nif __name__ == \'__main__\': raise SystemExit(main())\n'

def require(value, reason):
    if not value: raise ValueError(reason)

def base_module():
    require(hashlib.sha256(BASE_SOURCE.encode()).hexdigest() == BASE_SHA256, 'EXACT_METADATA_OBSERVER_SOURCE_REQUIRED')
    module = types.ModuleType('sealed_rootfs_metadata_observer')
    exec(compile(BASE_SOURCE, '<sealed-metadata-observer>', 'exec'), module.__dict__)
    return module

def selected_definitions(source, names, namespace):
    tree = ast.parse(source); selected = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    require(len(selected) == len(names), 'EXACT_SEALED_PRIMITIVES_REQUIRED')
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<sealed-read-only-primitives>', 'exec'), namespace)

def primitives(b, reader):
    raw = reader.raw(b.CAPSULE, 1048576, b.CAPSULE_HASH, private=False)
    values = {n.targets[0].id: ast.literal_eval(n.value) for n in ast.parse(raw).body
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)}
    manifest = values['DELIVERY']['nativeDeclaration']
    with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(values['PACKED'], validate=True))) as stream:
        payload = stream.read(12582913)
    require(0 < len(payload) <= 12582912, 'BOUNDED_SEALED_SOURCE_PAYLOAD_REQUIRED')
    sources = json.loads(payload)['sources']
    require(set(sources) == set(manifest['sourceHashes']) and len(sources) == 137
        and all(hashlib.sha256(value.encode()).hexdigest() == manifest['sourceHashes'][name] for name,value in sources.items()),
        'ALL_137_SEALED_SOURCE_HASHES_REQUIRED')
    ns = {'os':os, 'stat':stat, 'Path':Path, 'hashlib':hashlib, 'json':json, 're':re, 'socket':socket,
        'http':types.SimpleNamespace(client=http.client), 'require':require, 'CreationDenied':ValueError, 'PreexecDenied':ValueError}
    selected_definitions(sources['tools.semantic_provider_deployment_authentication'], {'attributes','ancestors'}, ns)
    selected_definitions(sources['tools.semantic_provider_node_observation'], {'rootfs_seal'}, ns)
    selected_definitions(sources['engine_creation'], {'Engine'}, ns)
    return ns

class KeepingReader:
    # The independently tested Reader retains its original20reads/16MiB bound.
    def __new__(cls, b):
        class Reader(b.Reader):
            def __init__(self): super().__init__(); self.items = {}
            def json(self, path, *args, **kwargs):
                value = super().json(path, *args, **kwargs); self.items[path] = value; return value
        return Reader()

class Budget:
    def __init__(self, seconds): self.until = time.monotonic() + seconds
    def check(self): require(time.monotonic() < self.until, 'ROOTFS_DIAGNOSTIC_DEADLINE')

def sealed_rows(ns, b, root, limits, budget):
    rows, size = [], 0
    def capture(item):
        nonlocal size
        raw = b.encoded(item); size += len(raw)
        require(size <= 33554432 and len(rows) < limits['maxEntries'], 'BOUNDED_PRIVATE_ROOTFS_MANIFEST_REQUIRED')
        rows.append(copy.deepcopy(item)); return raw
    environment = dict(ns); environment['encoded'] = capture
    # Preserve the sealed code object; isolate only the capture callback.
    primitive = types.FunctionType(ns['rootfs_seal'].__code__, environment)
    seal = primitive(root, limits, budget)
    require(len(rows) == seal['entries'], 'COMPLETE_ROOTFS_TRANSCRIPT_REQUIRED')
    return seal, rows

def transcript_seal(b, rows, directory_mode=None):
    h = hashlib.sha256(b'OUF-ROOTFS-SEAL\x00V1\x00'); subdirectories = {}
    for row in rows:
        if row['kind'] == 'directory' and row['path']:
            parent = row['path'].rpartition('/')[0]; subdirectories[parent] = subdirectories.get(parent, 0) + 1
    for row in rows:
        item = copy.deepcopy(row)
        if directory_mode is not None and item['kind'] == 'directory':
            item['links'] = 1 if directory_mode == 'one' else 2 + subdirectories.get(item['path'],0)
        raw = b.encoded(item); h.update(len(raw).to_bytes(4,'big')); h.update(raw)
    return h.hexdigest()

def publish(directory_fd, name, value, b):
    require(re.fullmatch('[a-z0-9.-]{1,80}', name) is not None, 'CLOSED_DIAGNOSTIC_ARTIFACT_NAME_REQUIRED')
    raw = b.encoded(value); require(0 < len(raw) <= 34603008, 'BOUNDED_DIAGNOSTIC_ARTIFACT_REQUIRED')
    fd = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o400, dir_fd=directory_fd)
    try:
        with os.fdopen(os.dup(fd),'wb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally: os.close(fd)
    os.fsync(directory_fd)
    return hashlib.sha256(raw).hexdigest()

def open_parent(path):
    path = Path(path); require(path.is_absolute() and '..' not in path.parts, 'EXACT_DIAGNOSTIC_PARENT_REQUIRED')
    fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            info = os.fstat(child)
            if not (info.st_uid == 0 and not info.st_mode & 0o022):
                os.close(child); require(False, 'PROTECTED_DIAGNOSTIC_PARENT_REQUIRED')
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd); raise

def kernel_file(path, maximum):
    # Only fixed proc paths or exact reviewed PID paths are passed by this file.
    with open(path,'rb') as stream: raw = stream.read(maximum+1)
    require(0 < len(raw) <= maximum, 'BOUNDED_KERNEL_OBSERVATION_REQUIRED'); return raw

def generation(pin):
    pid = pin['pid']; require(type(pid) is int and pid > 1, 'EXACT_RETAINED_PID_REQUIRED')
    raw = kernel_file('/proc/'+str(pid)+'/stat',8192); end = raw.rfind(b')')
    require(end > 0, 'PROCESS_GENERATION_REQUIRED'); fields = raw[end+2:].split()
    info = os.stat('/proc/'+str(pid)+'/ns/net')
    require(int(fields[19]) == pin['startTicks'] and info.st_dev == pin['namespaceDevice'] and info.st_ino == pin['namespaceInode'],
        'RETAINED_PROCESS_GENERATION_CHANGED')
    return [pid,int(fields[19]),info.st_dev,info.st_ino]

def mount_guard(root, raw=None):
    raw = kernel_file('/proc/self/mountinfo',16777216) if raw is None else raw
    relevant = []
    for line in raw.splitlines():
        fields = line.split(); require(len(fields) >= 10, 'KERNEL_MOUNTINFO_SHAPE_REQUIRED')
        name = os.fsdecode(re.sub(rb'\\([0-7]{3})',lambda m:bytes([int(m[1],8)]),fields[4]))
        mount = Path(name)
        if mount == root or root in mount.parents:
            require(mount == root, 'HOST_ROOTFS_CONTAINS_MOUNTED_PROJECTIONS')
            relevant.append(line.hex())
    return relevant

def resource_predicates(row, context, pin):
    request = context['creationRequest']; state = row.get('State',{})
    expected = request.get('HostConfig',{}).get('ReadonlyRootfs')
    actual = row.get('HostConfig',{}).get('ReadonlyRootfs')
    return {'containerIdentityMatches':row.get('Id') == pin['containerId'],
        'imageIdentityMatches':row.get('Image') == request['Image'],
        'pidMatches':type(state.get('Pid')) is int and state['Pid'] == pin['pid'],
        'running':state.get('Running') is True,'paused':state.get('Paused') is True,
        'notRestarting':state.get('Restarting') is False,'notDead':state.get('Dead') is False,
        'reviewedRootfsFlagIsBoolean':type(expected) is bool,
        'currentRootfsFlagIsBoolean':type(actual) is bool,
        'rootfsFlagMatchesReviewed':type(expected) is bool and type(actual) is bool and actual == expected}

def paused_resource(row, context, pin):
    require(all(resource_predicates(row,context,pin).values()),'EXACT_PAUSED_REVIEWED_IMAGE_GENERATION_REQUIRED')
    state = row['State']
    return {'id':row['Id'],'image':row['Image'],'pid':state['Pid'],'startedAt':state.get('StartedAt'),
        'restartCount':row.get('RestartCount'),'paused':True,'readonlyRootfs':row['HostConfig']['ReadonlyRootfs']}

def lock_existing(path):
    parent=open_parent(Path(path).parent)
    try:fd=os.open(Path(path).name,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    finally:os.close(parent)
    try:
        s=os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,
            'EXACT_EXISTING_PRIVATE_INVOCATION_LOCK_REQUIRED')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:require(False,'OTHER_RECOVERY_OR_TOKEN_OWNER_IS_ACTIVE')
        return fd
    except BaseException:os.close(fd);raise


def frozen_generation(pin):
    value=generation(pin)
    raw=kernel_file('/proc/'+str(pin['pid'])+'/cgroup',16384)
    paths=[line[3:].decode('ascii') for line in raw.splitlines() if line.startswith(b'0::')]
    require(len(paths)==1 and paths[0].startswith('/') and '..' not in Path(paths[0]).parts
        and pin['containerId'] in paths[0],'EXACT_HOST_CONTAINER_CGROUP_V2_REQUIRED')
    path=Path('/sys/fs/cgroup'+paths[0])/'cgroup.events'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd);raw=os.read(fd,8193)
        require(len(raw)<=8192,'BOUNDED_CGROUP_FREEZE_OBSERVATION_REQUIRED')
        rows=[line.split() for line in raw.splitlines()]
        require(sum(row==[b'frozen',b'1'] for row in rows)==1,'REVIEWED_CONTAINER_MUST_REMAIN_KERNEL_FROZEN')
        return value+[info.st_dev,info.st_ino,paths[0]]
    finally:os.close(fd)


def stable_inode(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)


def relative_parent(root_fd,relative):
    parts=relative.split('/')
    require(len(parts)>=2 and parts[0]=='tmp' and all(p not in ('','.','..') for p in parts),'EXACT_RELATIVE_TMP_DIRECTORY_REQUIRED')
    fd=os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        return fd,parts[-1]
    except BaseException:os.close(fd);raise


def remove_directories(root,ordered,guard,claim,applied):
    require(type(ordered) is list and len(ordered)==6 and len({r['path'] for r in ordered})==6,'EXACT_SIX_REVIEWED_DIRECTORIES_REQUIRED')
    paths={r['path'] for r in ordered};fds=[];root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    root_pin=stable_inode(os.fstat(root_fd));removed=[]
    try:
        for row in ordered:
            parent,leaf=relative_parent(root_fd,row['path'])
            try:fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            finally:os.close(parent)
            fds.append((row,fd,stable_inode(os.fstat(fd))))
            s=os.fstat(fd)
            require(stat.S_ISDIR(s.st_mode) and s.st_uid==row['uid'] and s.st_gid==row['gid'] and stat.S_IMODE(s.st_mode)==row['mode']
                and not os.listxattr(fd) and row.get('xattrs')=={},'LIVE_DIRECTORY_OWNER_MODE_OR_XATTR_DRIFT')
            require(all(row['path']+'/'+n in paths for n in os.listdir(fd)),'LIVE_JVM_DIRECTORY_CONTAINS_UNREVIEWED_ENTRIES')
        for ordinal,(row,fd,pin) in enumerate(fds):
            guard()
            require(stable_inode(os.fstat(root_fd))==root_pin==stable_inode(root.lstat()),'LIVE_ROOTFS_INODE_CHANGED')
            parent,leaf=relative_parent(root_fd,row['path'])
            try:
                require(stable_inode(os.fstat(fd))==pin==stable_inode(os.stat(leaf,dir_fd=parent,follow_symlinks=False))
                    and not os.listxattr(fd) and os.listdir(fd)==[],'EXACT_EMPTY_REVIEWED_DIRECTORY_INODE_REQUIRED')
                # Durable intent before this single atomic syscall. Never use
                # unlink/rmtree/globs, and never replay a consumed maintenance.
                claim(ordinal,row,pin)
                os.rmdir(leaf,dir_fd=parent)
                removed.append(row['path']);os.fsync(parent)
                applied(ordinal,row,pin)
            finally:os.close(parent)
        guard();return removed
    finally:
        for _,fd,_ in fds:os.close(fd)
        os.close(root_fd)


def run():
    b=base_module();r=KeepingReader(b);start=b.inspect(r)
    require(start['checkpoint']==4 and start['recoveryState']=='IN_FLIGHT' and start['readAttempts']==5
        and start['ownerState']=='CANCELLED' and start['retainedControlledGrantAttempts']==320
        and start['nativeReadCounts']=={'databaseSessions':1,'gatewayAdminGets':6,'semanticGets':0}
        and not start['pausedAcceptanceRetained'] and not start['pausedObservationRetained'],'EXACT_CANCELLED_RECOVERY_PREFIX_REQUIRED')
    prep=r.items[b.PREPARATION_ROOT+'/prepared.json'];review=r.items[b.PREPARATION_ROOT+'/review.json'];ctx=prep['nativeContext']
    execution=Path(ctx['executionRoot']);journal=r.items[str(execution/'recovery.json')];pin=journal['newGeneration']
    root=Path(b.PARENT)/PLAN_ROOT
    plan=r.json(str(root/'cleanup-plan.json'),PLAN_HASH);proof=r.json(str(root/'proof.json'),PROOF_HASH)
    require(plan['schema']=='ouf.semantic-jvm-empty-directory-cleanup-plan.v1' and plan['proofHash']==PROOF_HASH
        and plan['preparationHash']==b.PREPARATION_HASH and plan['reviewHash']==b.REVIEW_HASH
        and plan['retainedGeneration']==pin and proof['expectedSealRestoredByRemovingOnlySixDirectories'] is True
        and proof['directories']==plan['orderedDirectories'] and len(plan['orderedDirectories'])==6
        and plan['expectedBeforeSeal']==proof['observedRootfsSeal'] and plan['expectedAfterSeal']==proof['expectedRootfsSeal']==ctx['nodeRecipe']['expectedRootfsSeal']
        and plan['operation']=='RMDIR_EMPTY_DIRECTORIES_ONLY' and plan['maximumDirectoryRemovals']==6
        and plan['grantAttemptAllowance']==0 and plan['fileUnlinkAllowed'] is False and plan['recursiveRemovalAllowed'] is False
        and plan['unpauseAllowed'] is False and plan['javaReleaseAllowed'] is False and plan['expectedSealMayBeReplaced'] is False,
        'EXACT_HASHED_MAINTENANCE_PLAN_AND_UNCHANGED_EXPECTED_SEAL_REQUIRED')
    require(pin['bootId']==review['bootId'] and pin['containerId']==ctx['plan']['stages'][0]['intent']['registryId'],
        'EXACT_RETAINED_PAUSED_CONTAINER_GENERATION_REQUIRED')
    ns=primitives(b,r);request=prep['registryInputs']['creationRequest'];recipe=ctx['nodeRecipe'];frame=r.items[str(execution/'node/frame-policy.json')]
    identity={'authorityHash':b.AUTHORITY_HASH,'planHash':PLAN_HASH,'bootId':review['bootId'],'purpose':'EXPLICIT_OPERATOR_JVM_EMPTY_DIRECTORY_MAINTENANCE_V1'}
    name='semantic-registry-jvm-cleanup-'+b.digest(identity);parent=open_parent(b.PARENT);directory=None;locks=[];gets=attempts=removed=0
    try:
        try:os.mkdir(name,0o700,dir_fd=parent)
        except FileExistsError:require(False,'MAINTENANCE_ALREADY_CLAIMED_RECONCILE_OUTCOME_ONLY')
        os.fsync(parent);directory=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        scope={**identity,'schema':'ouf.explicit-root-operator-maintenance-scope.v1',
            'authorizationSource':'EXPLICIT_ROOT_OPERATOR_INVOCATION_WITH_EXACT_PLAN_HASH',
            'maximumDirectoryRemovalAttempts':6,'maximumEngineGets':2,'priorDiagnosticEngineGets':4,
            'maximumCombinedEngineGets':6,'maximumFullRootfsPasses':2,'maximumSeconds':450,
            'maximumMetadataReads':24,'maximumMetadataBytes':16777216,'grantAttemptAllowance':0,
            'programSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'signedRuntimeAuthorityIssued':False,'priorExpiredRuntimeAuthorityReused':False,
            'retainedControlledGrantAttempts':320,'automaticReplayAllowed':False,'budgetReset':False}
        publish(directory,'scope.json',scope,b)
        publish(directory,'directory-restoration-metadata.json',{'orderedDirectories':list(reversed(plan['orderedDirectories'])),
            'automaticRestorationAllowed':False,'scope':'METADATA_ONLY_NO_FILE_CONTENTS'},b)
        owner_root=Path(review['scopes']['semanticRegistryPostbootOwner']['journalPath'])
        for path in (execution/'invocation.lock',owner_root/'invocation.lock'):locks.append(lock_existing(path))
        # Recheck all mutable retained journals after holding the exact two
        # existing protocol locks; no new token owner/native actor may enter.
        rr=KeepingReader(b)
        for path in (execution/'recovery.json',execution/'native-reads.json',owner_root/'recovery.json'):
            require(rr.json(str(path))==r.items[str(path)],'RETAINED_OPERATION_OR_OWNER_MOVED_BEFORE_MAINTENANCE')
        binding=ctx['engineBinding'];engine=ns['Engine'](binding['socketPath'],tuple(binding['socketBinding']))
        path='/v1.44/containers/'+pin['containerId']+'/json'
        def get():
            nonlocal gets
            require(gets<2,'TWO_EXACT_MAINTENANCE_ENGINE_GETS_ONLY');gets+=1
            publish(directory,'engine-get-'+str(gets)+'.json',{'attempt':gets,'requestPathHash':b.digest(path)},b)
            status,value=engine.request('GET',path)
            require(status==200 and type(value) is dict,'CURRENT_REVIEWED_CONTAINER_REQUIRED');return value
        before=get();first=paused_resource(before,{'creationRequest':request},pin);freeze=frozen_generation(pin)
        docker=recipe['dockerContext'];require(docker.get('rootfsLayout')=='docker-containerd-overlayfs-v1','EXACT_REVIEWED_CONTAINERD_LAYOUT_REQUIRED')
        merged=Path(docker['storageParent'])/'rootfs/overlayfs'/pin['containerId'];bundle=Path(docker['bundleParent'])/pin['containerId']
        oci_raw=r.raw(str(bundle/'config.json'),131072);oci=json.loads(oci_raw)
        oci_root=Path(oci['root']['path']);oci_root=oci_root if oci_root.is_absolute() else bundle/oci_root
        require(oci_root==merged and b.digest(oci)==b.digest(frame['expectedOci'])
            and oci['root'].get('readonly',False) is False and first['readonlyRootfs'] is False,'FULL_REVIEWED_OCI_AND_ROOT_BINDING_REQUIRED')
        mounts=mount_guard(merged);root_pin=stable_inode(merged.lstat())
        def guard():
            require(frozen_generation(pin)==freeze and mount_guard(merged)==mounts and stable_inode(merged.lstat())==root_pin,
                'PAUSED_GENERATION_MOUNT_OR_ROOT_CHANGED_DURING_MAINTENANCE')
        limits=recipe['observationConfiguration']['rootfsLimits']
        initial,rows=sealed_rows(ns,b,merged,limits,Budget(min(180,recipe['observationSeconds'])))
        require(transcript_seal(b,rows)==initial['sha256'] and initial==plan['expectedBeforeSeal'],'FULL_LIVE_BEFORE_SEAL_MUST_MATCH_REVIEWED_PLAN')
        bypath={row['path']:row for row in rows}
        require(all(bypath.get(row['path'])==row for row in plan['orderedDirectories']),'SIX_LIVE_DIRECTORY_METADATA_ROWS_CHANGED')
        guard();publish(directory,'preflight.json',{'fullBeforeSeal':initial,'samePausedGeneration':True,'commonLocksHeld':True},b)
        def claim(n,row,pin_value):
            nonlocal attempts
            require(attempts==n and n<6,'SIX_ORDERED_DIRECTORY_REMOVAL_ATTEMPTS_ONLY')
            publish(directory,'rmdir-'+str(n)+'-claimed.json',{'ordinal':n,'pathHash':b.digest(row['path']),
                'inode':list(pin_value),'planHash':PLAN_HASH},b);attempts+=1
        def applied(n,row,pin_value):
            nonlocal removed
            removed+=1;publish(directory,'rmdir-'+str(n)+'-applied.json',{'ordinal':n,'pathHash':b.digest(row['path'])},b)
            print(json.dumps({'schema':'ouf.semantic-jvm-cleanup-progress.v1','directoryRemovalsConfirmed':removed,
                'maximumDirectoryRemovals':6,'javaReleased':False,'oauthRequests':0,'automaticReplayAllowed':False}),flush=True)
        paths=remove_directories(merged,plan['orderedDirectories'],guard,claim,applied)
        final,rows=sealed_rows(ns,b,merged,limits,Budget(min(180,recipe['observationSeconds'])))
        require(transcript_seal(b,rows)==final['sha256'] and final==plan['expectedAfterSeal'],'POST_MAINTENANCE_ORIGINAL_INDEPENDENT_SEAL_MUST_MATCH')
        guard();require(paused_resource(get(),{'creationRequest':request},pin)==first,'CONTAINER_CHANGED_AFTER_MAINTENANCE')
        final_reader=KeepingReader(b)
        selected=[str(execution/'recovery.json'),str(execution/'native-reads.json'),str(owner_root/'recovery.json'),
            b.PREPARATION_ROOT+'/prepared.json',b.PREPARATION_ROOT+'/review.json']
        for selected_path in selected:require(final_reader.json(selected_path)==r.items[selected_path],'OLD_JOURNAL_OR_REVIEW_CHANGED')
        require(final_reader.raw(str(bundle/'config.json'),131072)==oci_raw,'FULL_OCI_CHANGED_AFTER_MAINTENANCE')
        require(r.reads+rr.reads+final_reader.reads<=24 and r.bytes+rr.bytes+final_reader.bytes<=16777216,'AGGREGATE_MAINTENANCE_METADATA_BOUND')
        result={'schema':'ouf.semantic-registry-jvm-cleanup-result.v1','status':'JVM_RESIDUE_REMOVED_ORIGINAL_SEAL_RESTORED',
            'complete':True,'directoryRemovalAttempts':attempts,'directoryRemovalsConfirmed':removed,
            'originalIndependentRootfsSealMatches':True,'expectedRootfsSealUnchanged':True,'remainingEntryCount':final['entries'],
            'fileUnlinks':0,'recursiveRemovals':0,'newFullRootfsPasses':2,'engineGets':gets,'priorDiagnosticEngineGets':4,'combinedEngineGets':4+gets,
            'retainedControlledGrantAttempts':320,'oauthRequests':0,'databaseCalls':0,'adminGets':0,'credentialProjectionSourcesOpened':0,
            'samePausedGenerationBeforeAndAfter':True,'kernelFrozenThroughoutMaintenance':True,'protocolInvocationLocksHeld':True,
            'javaReleased':False,'applicationEntryInvoked':False,'signedRuntimeAuthorityIssued':False,'priorExpiredRuntimeAuthorityReused':False,
            'explicitRootOperatorScopeInstalled':True,'runtimeEffectsDispatched':attempts,'targetApplyAuthorizedByOperatorInvocation':True,
            'automaticReplayAllowed':False,'budgetReset':False,'serviceReadinessEstablished':False,'releaseAcceptance':False,
            'privateMaintenancePath':str(Path(b.PARENT)/name),'nativeRecoveryStillAtCheckpoint':4,'nativeOwnerStillCancelled':True}
        publish(directory,'result.json',result,b);return result
    except Exception as error:
        reason=str(error)
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason) is None:reason='MAINTENANCE_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        result={'schema':'ouf.semantic-registry-jvm-cleanup-result.v1','status':'STOP_RECONCILE','reasonCode':reason,
            'directoryRemovalAttempts':attempts,'directoryRemovalsConfirmed':removed,'engineGets':gets,
            'runtimeEffectsDispatched':attempts,'runtimeEffectsMayBePartial':attempts>0,'oauthRequests':0,
            'automaticReplayAllowed':False,'budgetReset':False,'serviceReadinessEstablished':False,'releaseAcceptance':False}
        if directory is not None:publish(directory,'stop.json',result,b)
        return result
    finally:
        for fd in reversed(locks):os.close(fd)
        if directory is not None:os.close(directory)
        os.close(parent)


def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and sys.argv[1:]==['--apply-plan',PLAN_HASH],'EXPLICIT_ISOLATED_ROOT_INVOCATION_OF_EXACT_PLAN_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'MAINTENANCE_DEADLINE'));signal.alarm(450)
        result=run()
    except Exception as error:
        reason=str(error)
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason) is None:reason='MAINTENANCE_PREPARATION_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        result={'schema':'ouf.semantic-registry-jvm-cleanup-result.v1','status':'STOP_RECONCILE','reasonCode':reason,
            'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False}
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['status']=='JVM_RESIDUE_REMOVED_ORIGINAL_SEAL_RESTORED' else 2


if __name__=='__main__':raise SystemExit(main())
