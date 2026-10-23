#!/usr/bin/env python3
"""Compare authenticated archived-image namespace/content to pinned observed transcript."""
import ast,base64,copy,gzip,hashlib,io,json,os,re,signal,stat,sys,tarfile,time,types
from pathlib import Path,PurePosixPath
ANALYSIS_ROOT='semantic-registry-rootfs-transcript-837b807c83607c803f7f8001c79215a5e1a06fadb98e037e06b7c2c3a13b3c5f'
ANALYSIS_HASH='169831c121f08162a9a50996cfe97448a6ef5562c544dd7af87f989c2c95748f'
MAX_ARCHIVE_BYTES=2147483648
MAX_READ_BYTES=8589934592

MANIFEST_HASH = '92ce6633088609b68d10cb3f8310ea1a083596ed93a177b8bc634be947b71294'
MANIFEST_ROOT = 'semantic-registry-rootfs-complete-dfff207b4013107bcc645299ef91ede9edcd21665c1c7539b1e1929f129c0966'
BASE_SHA256 = '97ee083211258c9f207e4b4aef8309fbe902e041a7b0b67bebce618adf09a9fe'
BASE_SOURCE = '#!/usr/bin/env python3\n"""Read retained stop metadata only; never execute capsule or enter application."""\nimport ast\nimport hashlib\nimport json\nimport os\nfrom pathlib import Path\nimport re\nimport stat\nimport sys\nimport time\n\nCAPSULE = \'/home/oufadmin/ouf-registry-postboot-review.LduMidpc/capsule.py\'\nCAPSULE_HASH = \'f6ab800de6ca9452258cf967dd0e194b81b620a35dff0ef357f7fdf93f45f02c\'\nCLOSURE_HASH = \'4fb611d8ffcf4446aeb25df7777dfb66fefb964c63f375863471072b8d7d2f27\'\nDECLARATION_HASH = \'c0d3bedb36ab56d4f116a4a264e49a1310b366d0ec9aadbd5a6d715331c6bdc8\'\nPREPARATION_ROOT = \'/etc/ouf/deploy-snapshots/semantic-registry-postboot-inputs-ed5451cb23ed2a28c1dbb7585cccfe64fb2837e2d33c81d2a43c1e31f243d5c2\'\nPREPARATION_HASH = \'90748d593e5292420ce967c256d757364ba8637dc0f79619c688585a2f1e5f5d\'\nREVIEW_HASH = \'cf5191895f1e67b86bdc98b7aa9e10b1292d3f8589a653839116e7c2816ba3c9\'\nAUTHORITY_HASH = \'9d8f36e7f6a942fee95278148399a1a3d140fe0b660809a465edd85f2820d607\'\nPARENT = \'/etc/ouf/deploy-snapshots\'\n\n\ndef require(ok, reason):\n    if not ok: raise ValueError(reason)\n\n\ndef encoded(v): return json.dumps(v, sort_keys=True, separators=(\',\', \':\'), allow_nan=False).encode()\ndef digest(v): return hashlib.sha256(encoded(v)).hexdigest()\ndef identity(v): return (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)\n\n\nclass Reader:\n    def __init__(self): self.reads = 0; self.bytes = 0; self.until = time.monotonic() + 30\n\n    def raw(self, path, maximum, sha=None, private=True):\n        require(time.monotonic() < self.until and self.reads < 20, \'BOUNDED_METADATA_READ_REQUIRED\')\n        # Traverse protected ancestry through held descriptors, refusing links.\n        path = Path(path)\n        require(path.is_absolute() and \'..\' not in path.parts, \'EXACT_METADATA_PATH_REQUIRED\')\n        fd = os.open(\'/\', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n        try:\n            for part in path.parts[1:-1]:\n                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)\n                info = os.fstat(child)\n                require(not info.st_mode & 0o022 and (info.st_uid == 0 or not private), \'PROTECTED_METADATA_ANCESTRY_REQUIRED\')\n                os.close(fd); fd = child\n            leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)\n            try:\n                before = os.fstat(leaf)\n                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022\n                    and (before.st_uid == 0 or not private) and 0 < before.st_size <= maximum,\n                    \'BOUNDED_PROTECTED_METADATA_REQUIRED\')\n                chunks = []; count = 0\n                while count <= before.st_size:\n                    block = os.read(leaf, min(65536, before.st_size + 1 - count))\n                    if not block: break\n                    chunks.append(block); count += len(block)\n                raw = b\'\'.join(chunks)\n                require(len(raw) == before.st_size and identity(before) == identity(os.fstat(leaf))\n                    == identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)), \'METADATA_CHANGED\')\n            finally: os.close(leaf)\n        finally: os.close(fd)\n        self.reads += 1; self.bytes += len(raw)\n        require(self.bytes <= 16777216 and (sha is None or hashlib.sha256(raw).hexdigest() == sha), \'METADATA_HASH_OR_BYTE_BOUND\')\n        return raw\n\n    def json(self, path, sha=None, maximum=8388608):\n        raw = self.raw(path, maximum, sha); value = json.loads(raw)\n        require(type(value) is dict and encoded(value) == raw, \'CANONICAL_METADATA_REQUIRED\')\n        return value\n\n\ndef inside(value):\n    require(type(value) is str and value.startswith(PARENT + \'/\') and \'..\' not in Path(value).parts\n            and str(Path(value)) == value, \'EXACT_REVIEW_BOUND_PRIVATE_PATH_REQUIRED\')\n    return Path(value)\n\n\ndef optional(reader, path, maximum=131072):\n    try: path.lstat()\n    except FileNotFoundError: return None\n    return reader.json(str(path), maximum=maximum)\n\n\ndef closed(value, allowed): return value if type(value) is str and value in allowed else \'OTHER_OR_ABSENT\'\n\n\ndef shape(value):\n    obj = type(value) is dict\n    return {\'object\': obj, \'string\': type(value) is str,\n        \'exactKeys\': obj and set(value) == {\'schema\', \'sha256\', \'entries\', \'bytes\'},\n        \'schemaMatches\': obj and value.get(\'schema\') == \'ouf.semantic-rootfs-seal.v1\',\n        \'sha256WellFormed\': obj and type(value.get(\'sha256\')) is str and re.fullmatch(\'[0-9a-f]{64}\', value[\'sha256\']) is not None,\n        \'entries\': value[\'entries\'] if obj and type(value.get(\'entries\')) is int and 0 < value[\'entries\'] <= 100000 else None,\n        \'bytes\': value[\'bytes\'] if obj and type(value.get(\'bytes\')) is int and 0 <= value[\'bytes\'] <= 8589934592 else None}\n\n\ndef inspect(reader):\n    # Parse only literal assignments; do not execute the loader or application.\n    raw = reader.raw(CAPSULE, 1048576, CAPSULE_HASH, private=False)\n    values = {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(raw).body\n        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}\n    require(set(values) == {\'CASE\', \'DELIVERY\', \'DELIVERY_HASH\', \'PACKED\', \'BOOTSTRAP\'}, \'EXACT_RETAINED_CAPSULE_FIELDS_REQUIRED\')\n    manifest = values[\'DELIVERY\'][\'nativeDeclaration\']\n    require(digest(values[\'DELIVERY\']) == values[\'DELIVERY_HASH\'] == DECLARATION_HASH and digest(manifest) == CLOSURE_HASH\n        and digest(values[\'CASE\']) == values[\'DELIVERY\'][\'caseHash\'], \'EXACT_RETAINED_CAPSULE_BINDINGS_REQUIRED\')\n    root = inside(PREPARATION_ROOT)\n    prepared = reader.json(str(root / \'prepared.json\'), PREPARATION_HASH, maximum=16777216)\n    review = reader.json(str(root / \'review.json\'), REVIEW_HASH)\n    require(review[\'currentContext\'] == prepared[\'nativeContext\'] and review[\'ownerContext\'] == prepared[\'ownerContext\']\n        and review[\'sourceClosureHash\'] == digest(prepared[\'sourceClosure\']) == CLOSURE_HASH\n        and prepared[\'sourceClosure\'] == manifest and review[\'sourceClosure\'] == manifest, \'EXACT_COMPLETED_REVIEW_INPUTS_REQUIRED\')\n    boot = Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip()\n    require(review[\'bootId\'] == boot, \'SAME_RETAINED_BOOT_REQUIRED\')\n    receipt = reader.json(str(root / \'authority/receipt.json\'), maximum=131072)\n    require(receipt.get(\'schema\') == \'ouf.semantic-registry-postboot-issued-authority.v1\'\n        and receipt.get(\'authorityHash\') == AUTHORITY_HASH and receipt.get(\'reviewHash\') == REVIEW_HASH\n        and receipt.get(\'runtimeAuthorityIssued\') is True, \'EXACT_ISSUED_AUTHORITY_RECEIPT_REQUIRED\')\n    context = prepared[\'nativeContext\']; plan = context[\'plan\']; execution = inside(context[\'executionRoot\'])\n    require(execution.name == \'semantic-registry-recovery-\' + plan[\'logicalOperationRef\'], \'EXACT_RECOVERY_OPERATION_ROOT_REQUIRED\')\n    journal = reader.json(str(execution / \'recovery.json\'), maximum=1048576)\n    require(journal[\'logicalOperationRef\'] == plan[\'logicalOperationRef\'] and journal[\'authorityHash\'] == AUTHORITY_HASH\n        and journal[\'bootId\'] == boot and type(journal[\'nextStage\']) is int and 0 <= journal[\'nextStage\'] <= 12\n        and type(journal[\'effects\']) is list and len(journal[\'effects\']) <= 12, \'EXACT_RETAINED_RECOVERY_JOURNAL_REQUIRED\')\n    require(type(journal.get(\'readAttempts\')) is int and 0 <= journal[\'readAttempts\'] <= 128\n        and type(journal.get(\'expiresUnix\')) is int and 0 < journal[\'expiresUnix\'] < 1099511627776,\n        \'BOUNDED_RETAINED_READ_AND_EXPIRY_FIELDS_REQUIRED\')\n    effects = []\n    for n, effect in enumerate(journal[\'effects\']):\n        require(effect[\'stage\'] == plan[\'stages\'][n][\'name\'], \'EXACT_ORDERED_EFFECTS_REQUIRED\')\n        effects.append({\'ordinal\': n, \'state\': closed(effect.get(\'state\'), (\'PENDING\',\'CLAIMED\',\'APPLIED\',\'UNKNOWN\',\'FAILED\')),\n            \'nativeRequestAttempted\': effect.get(\'nativeRequestAttempted\') is True,\n            \'nativeResponse204\': effect.get(\'nativeResponse204\') is True,\n            \'nativeAttestationAttempted\': effect.get(\'nativeAttestationAttempted\') is True})\n    owner_scope = review[\'scopes\'][\'semanticRegistryPostbootOwner\']; owner_root = inside(owner_scope[\'journalPath\'])\n    owner = reader.json(str(owner_root / \'recovery.json\'), maximum=65536)\n    require(owner[\'contextRef\'] == owner_scope[\'contextRef\'] and owner[\'generationRef\'] == owner_scope[\'generationRef\']\n        and type(owner[\'attempts\']) is int and 0 <= owner[\'attempts\'] <= 1\n        and owner[\'controlledPredecessorGrantAttempts\'] == 319\n        and owner[\'controlledCumulativeGrantAttempts\'] == 319 + owner[\'attempts\'], \'EXACT_RETAINED_OWNER_ACCOUNTING_REQUIRED\')\n    reads = reader.json(str(execution / \'native-reads.json\'), maximum=8192)\n    scope = review[\'scopes\'][\'semanticRegistryRecoveryReads\']; counts = reads[\'counts\']\n    require(reads[\'scopeHash\'] == digest(scope) and reads[\'authorityHash\'] == AUTHORITY_HASH\n        and set(counts) == set(scope[\'maximumRequests\']) and all(type(v) is int and 0 <= v <= scope[\'maximumRequests\'][k]\n            for k,v in counts.items()), \'EXACT_RETAINED_NATIVE_READ_COUNTERS_REQUIRED\')\n    frame = optional(reader, execution / \'node/frame-policy.json\')\n    observed = optional(reader, execution / \'node/paused-observation.json\', maximum=1048576)\n    acceptance = optional(reader, execution / \'node/paused-acceptance.json\')\n    recipe = context[\'nodeRecipe\']; expected = recipe[\'expectedRootfsSeal\']\n    observed_seal = observed.get(\'rootfsSeal\') if observed is not None else None\n    require(reader.json(str(execution / \'recovery.json\'), maximum=1048576) == journal\n        and reader.json(str(owner_root / \'recovery.json\'), maximum=65536) == owner\n        and reader.json(str(execution / \'native-reads.json\'), maximum=8192) == reads\n        and Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip() == boot, \'STOP_METADATA_CHANGED_DURING_OBSERVATION\')\n    return {\'schema\': \'ouf.semantic-registry-rootfs-stop-metadata.v1\', \'status\': \'RETAINED_ROOTFS_STOP_METADATA_OBSERVED\',\n        \'checkpoint\': journal[\'nextStage\'], \'recoveryState\': closed(journal.get(\'state\'), (\'READY\',\'IN_FLIGHT\',\'COMPLETE\',\'BLOCKED\',\'RECONCILE_REQUIRED\')),\n        \'effects\': effects, \'readAttempts\': journal.get(\'readAttempts\'), \'nativeReadCounts\': counts,\n        \'newGenerationRecorded\': type(journal.get(\'newGeneration\')) is dict,\n        \'framePolicyRetained\': frame is not None, \'pausedObservationRetained\': observed is not None,\n        \'pausedAcceptanceRetained\': acceptance is not None, \'expectedSealShape\': shape(expected),\n        \'retainedObservedSealShape\': shape(observed_seal),\n        \'retainedSealMatchesExpected\': observed_seal == expected if observed is not None else None,\n        \'ownerState\': closed(owner.get(\'state\'), (\'NEW\',\'ACTIVE\',\'BLOCKED\',\'CANCELLED\',\'PAUSED_EXHAUSTED\',\'RECONCILE_REQUIRED\',\'PUBLISHING\')),\n        \'retainedServiceGrantAttempts\': owner[\'attempts\'], \'retainedControlledGrantAttempts\': owner[\'controlledCumulativeGrantAttempts\'],\n        \'signedWindowExpiredAtObservation\': time.time() >= journal[\'expiresUnix\'],\n        \'journalObservationIsCurrentOwnerAdmission\': False, \'currentContainerStateObserved\': False,\n        \'currentRootfsRead\': False, \'rootfsMismatchCauseEstablished\': False, \'capsuleExecuted\': False,\n        \'addressesPrinted\': False, \'credentialFilesOpened\': 0, \'metadataReads\': reader.reads, \'metadataBytesRead\': reader.bytes,\n        \'engineGets\': 0, \'adminGets\': 0, \'oauthRequests\': 0, \'databaseCalls\': 0, \'runtimeEffectsDispatched\': 0,\n        \'runtimeAuthorityIssued\': False, \'readOnly\': True, \'automaticReplayAllowed\': False, \'budgetReset\': False,\n        \'serviceReadinessEstablished\': False, \'releaseAcceptance\': False}\n\n\ndef main():\n    try:\n        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site\n            and sys.dont_write_bytecode and len(sys.argv) == 1, \'ISOLATED_ROOT_METADATA_READER_REQUIRED\')\n        result = inspect(Reader())\n    except Exception as error:\n        reason = str(error)\n        if re.fullmatch(\'[A-Z][A-Z0-9_]{0,127}\', reason) is None: reason = \'ROOTFS_STOP_METADATA_UNPROVEN_PRIVATE_DETAILS_REDACTED\'\n        result = {\'schema\': \'ouf.semantic-registry-rootfs-stop-metadata.v1\', \'status\': \'STOP_RECONCILE\',\n            \'reasonCode\': reason, \'automaticReplayAllowed\': False, \'budgetReset\': False, \'runtimeEffectsDispatched\': 0}\n    print(json.dumps(result, sort_keys=True, separators=(\',\', \':\')), flush=True)\n    return 0 if result[\'status\'] == \'RETAINED_ROOTFS_STOP_METADATA_OBSERVED\' else 2\n\n\nif __name__ == \'__main__\': raise SystemExit(main())\n'

def require(ok, reason):
    if not ok:raise ValueError(reason)

def base_module():
    require(hashlib.sha256(BASE_SOURCE.encode()).hexdigest()==BASE_SHA256,'EXACT_BASE_METADATA_SOURCE_REQUIRED')
    b=types.ModuleType('sealed_metadata');exec(compile(BASE_SOURCE,'<sealed-metadata>','exec'),b.__dict__);return b

def publish(fd,name,value,b):
    raw=b.encoded(value);require(len(raw)<=8388608,'BOUNDED_PRIVATE_ANALYSIS_ARTIFACT_REQUIRED')
    child=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=fd)
    try:
        with os.fdopen(os.dup(child),'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally:os.close(child)
    os.fsync(fd);return hashlib.sha256(raw).hexdigest()

def open_parent(path):
    path=Path(path);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        require(path.is_absolute() and '..' not in path.parts,'EXACT_PRIVATE_PARENT_REQUIRED')
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);s=os.fstat(child)
            if s.st_uid!=0 or s.st_mode&0o022:os.close(child);require(False,'PROTECTED_PRIVATE_PARENT_REQUIRED')
            os.close(fd);fd=child
        return fd
    except BaseException:os.close(fd);raise

class Work:
    def __init__(self):self.until=time.monotonic()+240;self.readBytes=0;self.entries=0;self.expandedBytes=0
    def check(self):require(time.monotonic()<self.until,'ARCHIVE_COMPARISON_DEADLINE')


class Counted:
    def __init__(self,stream,work):self.stream=stream;self.work=work
    def read(self,n=-1):
        self.work.check();require(0<=n<=MAX_ARCHIVE_BYTES,'BOUNDED_ARCHIVE_READ_REQUIRED')
        data=self.stream.read(n);self.work.readBytes+=len(data)
        require(self.work.readBytes<=MAX_READ_BYTES,'ARCHIVE_READ_BYTE_BUDGET');return data
    def seek(self,*args):self.work.check();return self.stream.seek(*args)
    def tell(self):return self.stream.tell()
    def seekable(self):return True


class BoundedTarInfo(tarfile.TarInfo):
    def _proc_pax(self,tarfile):
        require(self.size<=1048576,'BOUNDED_LAYER_PAX_METADATA_REQUIRED')
        return super()._proc_pax(tarfile)
    def _proc_gnulong(self,tarfile):
        require(self.size<=8192,'BOUNDED_LAYER_LONGNAME_REQUIRED')
        return super()._proc_gnulong(tarfile)


def bounded_tar(**kwargs):return tarfile.open(tarinfo=BoundedTarInfo,**kwargs)


def image_primitive(values):
    with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(values['PACKED'],validate=True))) as z:payload=z.read(12582913)
    require(len(payload)<=12582912,'BOUNDED_SEALED_SOURCE_REQUIRED')
    sources=json.loads(payload)['sources'];manifest=values['DELIVERY']['nativeDeclaration']
    require(set(sources)==set(manifest['sourceHashes']) and len(sources)==137
        and all(hashlib.sha256(v.encode()).hexdigest()==manifest['sourceHashes'][k] for k,v in sources.items()),'EXACT_137_SEALED_SOURCES_REQUIRED')
    source=sources['image_custody'];names={'ImageCustodyDenied','require','hashed','parsed','archive'}
    chosen=[n for n in ast.parse(source).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
    require(len(chosen)==len(names),'EXACT_IMAGE_ARCHIVE_PRIMITIVES_REQUIRED')
    ns={'gzip':gzip,'hashlib':hashlib,'json':json,'re':re,'tarfile':types.SimpleNamespace(open=bounded_tar),'PurePosixPath':PurePosixPath,'LIMIT':MAX_ARCHIVE_BYTES}
    exec(compile(ast.Module(body=chosen,type_ignores=[]),'<sealed-image-custody>','exec'),ns)
    return ns['archive']


def canonical(name):
    require(type(name) is str and len(name)<=4096 and '\x00' not in name,'BOUNDED_LAYER_PATH_REQUIRED')
    while name.startswith('./'):name=name[2:]
    name=name.rstrip('/')
    if name in ('','.'):return ''
    p=PurePosixPath(name)
    require(not p.is_absolute() and '..' not in p.parts and str(p)==name,'SAFE_CANONICAL_LAYER_PATH_REQUIRED')
    return name


def parent_guard(path,namespace):
    p=PurePosixPath(path)
    for ancestor in p.parents:
        key='' if str(ancestor)=='.' else str(ancestor)
        if key in namespace:require(namespace[key]['kind']=='directory','LAYER_PARENT_SYMLINK_OR_FILE_REQUIRES_INDEPENDENT_RESOLUTION')


def namespace(source,audit,work):
    # No tar extraction or host path resolution. Ordered hardlink objects retain
    # content identity even if their original pathname is later overwritten.
    result={};layer_reports=[]
    with bounded_tar(fileobj=source,mode='r:') as outer:
        members={row.name:row for row in outer}
        for name in audit['layerMembers']:
            work.check();adds=[];whiteouts=[]
            with outer.extractfile(members[name]) as raw,bounded_tar(fileobj=raw,mode='r|*') as layer:
                for row in layer:
                    work.check();work.entries+=1;require(work.entries<=100000,'LAYER_ENTRY_BOUND')
                    p=canonical(row.name)
                    if p=='':continue
                    leaf=p.rpartition('/')[2];parent=p.rpartition('/')[0]
                    if leaf.startswith('.wh.'):
                        require(row.size==0,'ZERO_BYTE_WHITEOUT_REQUIRED')
                        whiteouts.append((parent,leaf));continue
                    meta={'mode':row.mode&0o7777,'uid':row.uid,'gid':row.gid,'hardlinkMetadataUnproven':False}
                    require(row.uid>=0 and row.gid>=0 and 0<=row.size<=MAX_ARCHIVE_BYTES,'BOUNDED_LAYER_METADATA_REQUIRED')
                    if row.isdir():entry={'kind':'directory',**meta}
                    elif row.issym():
                        require(len(row.linkname)<=4096,'BOUNDED_SYMLINK_TARGET_REQUIRED');entry={'kind':'symlink','target':row.linkname,**meta}
                    elif row.islnk():entry={'kind':'hardlink','target':canonical(row.linkname),**meta}
                    elif row.isfile():
                        h=hashlib.sha256();count=0
                        with layer.extractfile(row) as data:
                            while True:
                                work.check();block=data.read(65536)
                                if not block:break
                                count+=len(block);work.expandedBytes+=len(block)
                                require(count<=row.size and work.expandedBytes<=MAX_ARCHIVE_BYTES,'LAYER_CONTENT_BYTE_BOUND');h.update(block)
                        require(count==row.size,'COMPLETE_LAYER_FILE_REQUIRED')
                        entry={'kind':'file','size':count,'sha256':h.hexdigest(),**meta}
                    else:raise ValueError('LAYER_SPECIAL_ENTRY_REQUIRES_SEPARATE_REVIEW')
                    adds.append((p,entry))
            # OCI whiteouts affect lower layers only, independent of tar order.
            for parent,leaf in whiteouts:
                target=parent if leaf=='.wh..wh..opq' else (parent+'/' if parent else '')+leaf[4:]
                parent_guard(target,result)
                for p in list(result):
                    if (p.startswith(target+'/') if target else p!='') or leaf!='.wh..wh..opq' and p==target:del result[p]
            for p,entry in adds:
                parent_guard(p,result)
                if entry['kind']=='hardlink':
                    require(entry['target'] in result and result[entry['target']]['kind']=='file','FORWARD_OR_NONFILE_HARDLINK_REQUIRES_SEPARATE_REVIEW')
                    entry=result[entry['target']];entry['hardlinkMetadataUnproven']=True
                if p in result and result[p]['kind']=='directory' and entry['kind']!='directory':
                    for child in list(result):
                        if child.startswith(p+'/'):del result[child]
                result[p]=entry
                for parent in PurePosixPath(p).parents:
                    key='' if str(parent)=='.' else str(parent)
                    if key not in result:result[key]={'kind':'directory','mode':None,'uid':None,'gid':None,'hardlinkMetadataUnproven':False}
                require(len(result)<=100000,'FINAL_IMAGE_NAMESPACE_BOUND')
            layer_reports.append({'entries':len(adds),'whiteouts':len(whiteouts)})
    return result,layer_reports


def compare(archived,entries):
    observed={row['path']:row for row in entries};require(len(observed)==len(entries),'UNIQUE_OBSERVED_PATHS_REQUIRED')
    # Root directory inode metadata is filesystem-specific and is not supplied
    # by every layer tar. Compare all non-root paths; native seal remains false.
    archive_paths=set(archived)-{''};observed_paths=set(observed)-{''};common=archive_paths&observed_paths
    differences=[];unknown=0
    for p in sorted(common):
        a=archived[p];v=observed[p];fields=[]
        if a['kind']!=v['kind']:fields.append('kind')
        elif a['kind']=='file':
            if a['size']!=v['size']:fields.append('size')
            if a['sha256']!=v['sha256']:fields.append('sha256')
        elif a['kind']=='symlink' and a['target']!=v['target']:fields.append('target')
        if a['hardlinkMetadataUnproven'] or a['mode'] is None:unknown+=1
        else:
            fields.extend(k for k in ('mode','uid','gid') if a[k]!=v[k])
        if fields:differences.append({'path':p,'fields':fields,'archive':a,'observed':v})
    return {'extraEntries':[observed[p] for p in sorted(observed_paths-archive_paths)],
        'missingEntries':[{'path':p,**archived[p]} for p in sorted(archive_paths-observed_paths)],
        'differences':differences,'commonPaths':len(common),'archivePaths':len(archive_paths),'observedPaths':len(observed_paths),
        'hardlinkOrImplicitParentMetadataUnprovenCount':unknown,'rootInodeMetadataCompared':False,'nlinkCompared':False,'xattrsCompared':False,
        'archiveModelRejectsParentSymlinksAndForwardHardlinks':True,'comparisonDoesNotProveNativeSealEquality':True}


def inspect():
    b=base_module()
    class Reader(b.Reader):
        def __init__(self):super().__init__();self.items={}
        def json(self,path,*args,**kwargs):
            value=super().json(path,*args,**kwargs);self.items[path]=value;return value
    r=Reader();start=b.inspect(r)
    require(start['checkpoint']==4 and start['ownerState']=='CANCELLED' and start['retainedControlledGrantAttempts']==320,'EXACT_RETAINED_NATIVE_STOP_REQUIRED')
    prep=r.items[b.PREPARATION_ROOT+'/prepared.json'];review=r.items[b.PREPARATION_ROOT+'/review.json'];registry=prep['registryInputs']
    raw=r.raw(b.CAPSULE,1048576,b.CAPSULE_HASH,private=False)
    values={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(raw).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
    case=values['CASE']['preparation'];ref=case['historicalReview'];historical=r.json(ref['path'],ref['sha256'])
    ref=historical['scopes']['finiteActionProcess']['bundle']
    require(ref['sha256']==case['lineageReceipt']['historicalBundleHash'],'EXACT_HISTORICAL_BUNDLE_REFERENCE_REQUIRED')
    bundle=r.json(ref['path'],ref['sha256']);original=bundle['prepared']
    require(b.digest(original)==historical['privateInputHashes']['preparedInputs'] and original['registry']==registry,'SAME_REVIEWED_ARCHIVE_INPUT_CHAIN_REQUIRED')
    selected=[row for row in original['imagePlan']['images'] if row.get('module')=='semantic']
    require(len(selected)==1,'ONE_RETAINED_SEMANTIC_ARCHIVE_REQUIRED');selected=selected[0];audit=registry['imageAudit']
    for field in ('archiveSha256','imageId','sourceCommit','configSha256','layerMembers','layers'):
        require(selected['audit'][field]==audit[field],'RETAINED_ARCHIVE_PLAN_AUDIT_DRIFT')
    require(prep['nativeContext']['nodeRecipe']['imageConfigurationHash']==audit['configSha256'],'REVIEWED_IMAGE_CONFIGURATION_BINDING_REQUIRED')
    manifest=r.json(str(Path(b.PARENT)/MANIFEST_ROOT/'rootfs-manifest.json'),MANIFEST_HASH)
    analysis=r.json(str(Path(b.PARENT)/ANALYSIS_ROOT/'analysis.json'),ANALYSIS_HASH)
    require(manifest['authorityHash']==b.AUTHORITY_HASH and manifest['expectedRootfsSeal']==prep['nativeContext']['nodeRecipe']['expectedRootfsSeal']
        and analysis['searchComplete'] is True and analysis['matchingVariants']==[] and analysis['testedVariants']==226,
        'EXACT_NEGATIVE_TRANSCRIPT_ANALYSIS_REQUIRED')
    verifier=image_primitive(values)
    identity={'authorityHash':b.AUTHORITY_HASH,'manifestHash':MANIFEST_HASH,'archiveSha256':audit['archiveSha256'],'purpose':'ARCHIVED_IMAGE_NAMESPACE_COMPARISON_V1'}
    name='semantic-registry-archive-comparison-'+b.digest(identity);parent=open_parent(b.PARENT);directory=None;archive_fd=None
    try:
        try:os.mkdir(name,0o700,dir_fd=parent)
        except FileExistsError:require(False,'ARCHIVE_COMPARISON_ALREADY_CONSUMED')
        os.fsync(parent);directory=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        publish(directory,'claim.json',{**identity,'maximumArchiveBytes':MAX_ARCHIVE_BYTES,'maximumReadBytes':MAX_READ_BYTES,
            'maximumSeconds':240,'maximumEngineGets':0,'automaticReplayAllowed':False,'budgetReset':False},b)
        path=b.inside(selected['archivePath']);source_parent=open_parent(path.parent)
        try:archive_fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=source_parent)
        finally:os.close(source_parent)
        before=os.fstat(archive_fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and not before.st_mode&0o077
            and 0<before.st_size<=MAX_ARCHIVE_BYTES,'PROTECTED_BOUNDED_ARCHIVE_REQUIRED')
        work=Work()
        with os.fdopen(os.dup(archive_fd),'rb') as stream:
            counted=Counted(stream,work)
            actual=verifier(counted,audit['archiveSha256'],audit['imageId'],audit['sourceCommit'])
            for field in ('archiveSha256','imageId','sourceCommit','configSha256','layerMembers','layers'):
                require(actual[field]==audit[field],'CURRENT_ARCHIVE_BYTE_AUDIT_DRIFT')
            counted.seek(0);archived,layers=namespace(counted,audit,work)
        require(b.identity(before)==b.identity(os.fstat(archive_fd))==b.identity(path.lstat()),'ARCHIVE_CHANGED_DURING_COMPARISON')
        result=compare(archived,manifest['entries']);result.update(schema='ouf.archived-image-rootfs-comparison.v1',diagnosticOnly=True,
            archiveSha256=audit['archiveSha256'],manifestHash=MANIFEST_HASH,layers=layers)
        sha=publish(directory,'comparison.json',result,b)
        differences=result['differences']
        count=lambda keys:sum(bool(set(row['fields'])&set(keys)) for row in differences)
        return {'schema':'ouf.semantic-registry-archived-image-comparison.v1','status':'ARCHIVED_IMAGE_COMPARED','complete':True,
            'archiveBytesReaudited':True,'layerBytesReaudited':True,'archiveBindingFromExactHistoricalBundle':True,
            'extraEntryCount':len(result['extraEntries']),'missingEntryCount':len(result['missingEntries']),
            'kindDifferenceCount':count(['kind']),'contentDifferenceCount':count(['size','sha256']),
            'symlinkTargetDifferenceCount':count(['target']),'modeOwnerDifferenceCount':count(['mode','uid','gid']),
            'hardlinkOrImplicitParentMetadataUnprovenCount':result['hardlinkOrImplicitParentMetadataUnprovenCount'],
            'rootInodeMetadataCompared':False,'nlinkCompared':False,'xattrsCompared':False,'nativeSealEqualityProven':False,
            'archiveReadBytes':work.readBytes,'layerEntriesRead':work.entries,'layerFileContentBytes':work.expandedBytes,
            'privateComparisonHash':sha,'privateComparisonPath':str(Path(b.PARENT)/name/'comparison.json'),
            'metadataReads':r.reads,'metadataBytesRead':r.bytes,'priorDiagnosticEngineGets':4,'engineGets':0,
            'retainedControlledGrantAttempts':320,'currentContainerStateObserved':False,'liveRootfsContentsRead':False,
            'credentialFilesOpened':0,'addressesPrinted':False,'capsuleExecuted':False,'applicationEntryInvoked':False,
            'oauthRequests':0,'databaseCalls':0,'adminGets':0,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,
            'readOnlyRuntime':True,'automaticReplayAllowed':False,'budgetReset':False,'serviceReadinessEstablished':False,'releaseAcceptance':False}
    finally:
        if archive_fd is not None:os.close(archive_fd)
        if directory is not None:os.close(directory)
        os.close(parent)


def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,
            'ISOLATED_ROOT_ARCHIVE_READER_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'ARCHIVE_COMPARISON_DEADLINE'));signal.alarm(270)
        value=inspect()
    except Exception as error:
        reason=str(error)
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason) is None:reason='ARCHIVE_COMPARISON_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        value={'schema':'ouf.semantic-registry-archived-image-comparison.v1','status':'STOP_RECONCILE','reasonCode':reason,
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0}
    print(json.dumps(value,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if value['status']=='ARCHIVED_IMAGE_COMPARED' else 2


if __name__=='__main__':raise SystemExit(main())
