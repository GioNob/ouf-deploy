#!/usr/bin/env python3
"""Analyze a pinned complete rootfs transcript; never read or modify live rootfs."""
import copy
import hashlib
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import sys
import time
import types

MANIFEST_HASH='92ce6633088609b68d10cb3f8310ea1a083596ed93a177b8bc634be947b71294'
MANIFEST_ROOT='semantic-registry-rootfs-complete-dfff207b4013107bcc645299ef91ede9edcd21665c1c7539b1e1929f129c0966'
MAX_HASH_BYTES=17179869184
MAX_VARIANTS=4096
MAX_CANDIDATES=24

BASE_SHA256 = '97ee083211258c9f207e4b4aef8309fbe902e041a7b0b67bebce618adf09a9fe'
BASE_SOURCE = '#!/usr/bin/env python3\n"""Read retained stop metadata only; never execute capsule or enter application."""\nimport ast\nimport hashlib\nimport json\nimport os\nfrom pathlib import Path\nimport re\nimport stat\nimport sys\nimport time\n\nCAPSULE = \'/home/oufadmin/ouf-registry-postboot-review.LduMidpc/capsule.py\'\nCAPSULE_HASH = \'f6ab800de6ca9452258cf967dd0e194b81b620a35dff0ef357f7fdf93f45f02c\'\nCLOSURE_HASH = \'4fb611d8ffcf4446aeb25df7777dfb66fefb964c63f375863471072b8d7d2f27\'\nDECLARATION_HASH = \'c0d3bedb36ab56d4f116a4a264e49a1310b366d0ec9aadbd5a6d715331c6bdc8\'\nPREPARATION_ROOT = \'/etc/ouf/deploy-snapshots/semantic-registry-postboot-inputs-ed5451cb23ed2a28c1dbb7585cccfe64fb2837e2d33c81d2a43c1e31f243d5c2\'\nPREPARATION_HASH = \'90748d593e5292420ce967c256d757364ba8637dc0f79619c688585a2f1e5f5d\'\nREVIEW_HASH = \'cf5191895f1e67b86bdc98b7aa9e10b1292d3f8589a653839116e7c2816ba3c9\'\nAUTHORITY_HASH = \'9d8f36e7f6a942fee95278148399a1a3d140fe0b660809a465edd85f2820d607\'\nPARENT = \'/etc/ouf/deploy-snapshots\'\n\n\ndef require(ok, reason):\n    if not ok: raise ValueError(reason)\n\n\ndef encoded(v): return json.dumps(v, sort_keys=True, separators=(\',\', \':\'), allow_nan=False).encode()\ndef digest(v): return hashlib.sha256(encoded(v)).hexdigest()\ndef identity(v): return (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)\n\n\nclass Reader:\n    def __init__(self): self.reads = 0; self.bytes = 0; self.until = time.monotonic() + 30\n\n    def raw(self, path, maximum, sha=None, private=True):\n        require(time.monotonic() < self.until and self.reads < 20, \'BOUNDED_METADATA_READ_REQUIRED\')\n        # Traverse protected ancestry through held descriptors, refusing links.\n        path = Path(path)\n        require(path.is_absolute() and \'..\' not in path.parts, \'EXACT_METADATA_PATH_REQUIRED\')\n        fd = os.open(\'/\', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n        try:\n            for part in path.parts[1:-1]:\n                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)\n                info = os.fstat(child)\n                require(not info.st_mode & 0o022 and (info.st_uid == 0 or not private), \'PROTECTED_METADATA_ANCESTRY_REQUIRED\')\n                os.close(fd); fd = child\n            leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)\n            try:\n                before = os.fstat(leaf)\n                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022\n                    and (before.st_uid == 0 or not private) and 0 < before.st_size <= maximum,\n                    \'BOUNDED_PROTECTED_METADATA_REQUIRED\')\n                chunks = []; count = 0\n                while count <= before.st_size:\n                    block = os.read(leaf, min(65536, before.st_size + 1 - count))\n                    if not block: break\n                    chunks.append(block); count += len(block)\n                raw = b\'\'.join(chunks)\n                require(len(raw) == before.st_size and identity(before) == identity(os.fstat(leaf))\n                    == identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)), \'METADATA_CHANGED\')\n            finally: os.close(leaf)\n        finally: os.close(fd)\n        self.reads += 1; self.bytes += len(raw)\n        require(self.bytes <= 16777216 and (sha is None or hashlib.sha256(raw).hexdigest() == sha), \'METADATA_HASH_OR_BYTE_BOUND\')\n        return raw\n\n    def json(self, path, sha=None, maximum=8388608):\n        raw = self.raw(path, maximum, sha); value = json.loads(raw)\n        require(type(value) is dict and encoded(value) == raw, \'CANONICAL_METADATA_REQUIRED\')\n        return value\n\n\ndef inside(value):\n    require(type(value) is str and value.startswith(PARENT + \'/\') and \'..\' not in Path(value).parts\n            and str(Path(value)) == value, \'EXACT_REVIEW_BOUND_PRIVATE_PATH_REQUIRED\')\n    return Path(value)\n\n\ndef optional(reader, path, maximum=131072):\n    try: path.lstat()\n    except FileNotFoundError: return None\n    return reader.json(str(path), maximum=maximum)\n\n\ndef closed(value, allowed): return value if type(value) is str and value in allowed else \'OTHER_OR_ABSENT\'\n\n\ndef shape(value):\n    obj = type(value) is dict\n    return {\'object\': obj, \'string\': type(value) is str,\n        \'exactKeys\': obj and set(value) == {\'schema\', \'sha256\', \'entries\', \'bytes\'},\n        \'schemaMatches\': obj and value.get(\'schema\') == \'ouf.semantic-rootfs-seal.v1\',\n        \'sha256WellFormed\': obj and type(value.get(\'sha256\')) is str and re.fullmatch(\'[0-9a-f]{64}\', value[\'sha256\']) is not None,\n        \'entries\': value[\'entries\'] if obj and type(value.get(\'entries\')) is int and 0 < value[\'entries\'] <= 100000 else None,\n        \'bytes\': value[\'bytes\'] if obj and type(value.get(\'bytes\')) is int and 0 <= value[\'bytes\'] <= 8589934592 else None}\n\n\ndef inspect(reader):\n    # Parse only literal assignments; do not execute the loader or application.\n    raw = reader.raw(CAPSULE, 1048576, CAPSULE_HASH, private=False)\n    values = {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(raw).body\n        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}\n    require(set(values) == {\'CASE\', \'DELIVERY\', \'DELIVERY_HASH\', \'PACKED\', \'BOOTSTRAP\'}, \'EXACT_RETAINED_CAPSULE_FIELDS_REQUIRED\')\n    manifest = values[\'DELIVERY\'][\'nativeDeclaration\']\n    require(digest(values[\'DELIVERY\']) == values[\'DELIVERY_HASH\'] == DECLARATION_HASH and digest(manifest) == CLOSURE_HASH\n        and digest(values[\'CASE\']) == values[\'DELIVERY\'][\'caseHash\'], \'EXACT_RETAINED_CAPSULE_BINDINGS_REQUIRED\')\n    root = inside(PREPARATION_ROOT)\n    prepared = reader.json(str(root / \'prepared.json\'), PREPARATION_HASH, maximum=16777216)\n    review = reader.json(str(root / \'review.json\'), REVIEW_HASH)\n    require(review[\'currentContext\'] == prepared[\'nativeContext\'] and review[\'ownerContext\'] == prepared[\'ownerContext\']\n        and review[\'sourceClosureHash\'] == digest(prepared[\'sourceClosure\']) == CLOSURE_HASH\n        and prepared[\'sourceClosure\'] == manifest and review[\'sourceClosure\'] == manifest, \'EXACT_COMPLETED_REVIEW_INPUTS_REQUIRED\')\n    boot = Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip()\n    require(review[\'bootId\'] == boot, \'SAME_RETAINED_BOOT_REQUIRED\')\n    receipt = reader.json(str(root / \'authority/receipt.json\'), maximum=131072)\n    require(receipt.get(\'schema\') == \'ouf.semantic-registry-postboot-issued-authority.v1\'\n        and receipt.get(\'authorityHash\') == AUTHORITY_HASH and receipt.get(\'reviewHash\') == REVIEW_HASH\n        and receipt.get(\'runtimeAuthorityIssued\') is True, \'EXACT_ISSUED_AUTHORITY_RECEIPT_REQUIRED\')\n    context = prepared[\'nativeContext\']; plan = context[\'plan\']; execution = inside(context[\'executionRoot\'])\n    require(execution.name == \'semantic-registry-recovery-\' + plan[\'logicalOperationRef\'], \'EXACT_RECOVERY_OPERATION_ROOT_REQUIRED\')\n    journal = reader.json(str(execution / \'recovery.json\'), maximum=1048576)\n    require(journal[\'logicalOperationRef\'] == plan[\'logicalOperationRef\'] and journal[\'authorityHash\'] == AUTHORITY_HASH\n        and journal[\'bootId\'] == boot and type(journal[\'nextStage\']) is int and 0 <= journal[\'nextStage\'] <= 12\n        and type(journal[\'effects\']) is list and len(journal[\'effects\']) <= 12, \'EXACT_RETAINED_RECOVERY_JOURNAL_REQUIRED\')\n    require(type(journal.get(\'readAttempts\')) is int and 0 <= journal[\'readAttempts\'] <= 128\n        and type(journal.get(\'expiresUnix\')) is int and 0 < journal[\'expiresUnix\'] < 1099511627776,\n        \'BOUNDED_RETAINED_READ_AND_EXPIRY_FIELDS_REQUIRED\')\n    effects = []\n    for n, effect in enumerate(journal[\'effects\']):\n        require(effect[\'stage\'] == plan[\'stages\'][n][\'name\'], \'EXACT_ORDERED_EFFECTS_REQUIRED\')\n        effects.append({\'ordinal\': n, \'state\': closed(effect.get(\'state\'), (\'PENDING\',\'CLAIMED\',\'APPLIED\',\'UNKNOWN\',\'FAILED\')),\n            \'nativeRequestAttempted\': effect.get(\'nativeRequestAttempted\') is True,\n            \'nativeResponse204\': effect.get(\'nativeResponse204\') is True,\n            \'nativeAttestationAttempted\': effect.get(\'nativeAttestationAttempted\') is True})\n    owner_scope = review[\'scopes\'][\'semanticRegistryPostbootOwner\']; owner_root = inside(owner_scope[\'journalPath\'])\n    owner = reader.json(str(owner_root / \'recovery.json\'), maximum=65536)\n    require(owner[\'contextRef\'] == owner_scope[\'contextRef\'] and owner[\'generationRef\'] == owner_scope[\'generationRef\']\n        and type(owner[\'attempts\']) is int and 0 <= owner[\'attempts\'] <= 1\n        and owner[\'controlledPredecessorGrantAttempts\'] == 319\n        and owner[\'controlledCumulativeGrantAttempts\'] == 319 + owner[\'attempts\'], \'EXACT_RETAINED_OWNER_ACCOUNTING_REQUIRED\')\n    reads = reader.json(str(execution / \'native-reads.json\'), maximum=8192)\n    scope = review[\'scopes\'][\'semanticRegistryRecoveryReads\']; counts = reads[\'counts\']\n    require(reads[\'scopeHash\'] == digest(scope) and reads[\'authorityHash\'] == AUTHORITY_HASH\n        and set(counts) == set(scope[\'maximumRequests\']) and all(type(v) is int and 0 <= v <= scope[\'maximumRequests\'][k]\n            for k,v in counts.items()), \'EXACT_RETAINED_NATIVE_READ_COUNTERS_REQUIRED\')\n    frame = optional(reader, execution / \'node/frame-policy.json\')\n    observed = optional(reader, execution / \'node/paused-observation.json\', maximum=1048576)\n    acceptance = optional(reader, execution / \'node/paused-acceptance.json\')\n    recipe = context[\'nodeRecipe\']; expected = recipe[\'expectedRootfsSeal\']\n    observed_seal = observed.get(\'rootfsSeal\') if observed is not None else None\n    require(reader.json(str(execution / \'recovery.json\'), maximum=1048576) == journal\n        and reader.json(str(owner_root / \'recovery.json\'), maximum=65536) == owner\n        and reader.json(str(execution / \'native-reads.json\'), maximum=8192) == reads\n        and Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip() == boot, \'STOP_METADATA_CHANGED_DURING_OBSERVATION\')\n    return {\'schema\': \'ouf.semantic-registry-rootfs-stop-metadata.v1\', \'status\': \'RETAINED_ROOTFS_STOP_METADATA_OBSERVED\',\n        \'checkpoint\': journal[\'nextStage\'], \'recoveryState\': closed(journal.get(\'state\'), (\'READY\',\'IN_FLIGHT\',\'COMPLETE\',\'BLOCKED\',\'RECONCILE_REQUIRED\')),\n        \'effects\': effects, \'readAttempts\': journal.get(\'readAttempts\'), \'nativeReadCounts\': counts,\n        \'newGenerationRecorded\': type(journal.get(\'newGeneration\')) is dict,\n        \'framePolicyRetained\': frame is not None, \'pausedObservationRetained\': observed is not None,\n        \'pausedAcceptanceRetained\': acceptance is not None, \'expectedSealShape\': shape(expected),\n        \'retainedObservedSealShape\': shape(observed_seal),\n        \'retainedSealMatchesExpected\': observed_seal == expected if observed is not None else None,\n        \'ownerState\': closed(owner.get(\'state\'), (\'NEW\',\'ACTIVE\',\'BLOCKED\',\'CANCELLED\',\'PAUSED_EXHAUSTED\',\'RECONCILE_REQUIRED\',\'PUBLISHING\')),\n        \'retainedServiceGrantAttempts\': owner[\'attempts\'], \'retainedControlledGrantAttempts\': owner[\'controlledCumulativeGrantAttempts\'],\n        \'signedWindowExpiredAtObservation\': time.time() >= journal[\'expiresUnix\'],\n        \'journalObservationIsCurrentOwnerAdmission\': False, \'currentContainerStateObserved\': False,\n        \'currentRootfsRead\': False, \'rootfsMismatchCauseEstablished\': False, \'capsuleExecuted\': False,\n        \'addressesPrinted\': False, \'credentialFilesOpened\': 0, \'metadataReads\': reader.reads, \'metadataBytesRead\': reader.bytes,\n        \'engineGets\': 0, \'adminGets\': 0, \'oauthRequests\': 0, \'databaseCalls\': 0, \'runtimeEffectsDispatched\': 0,\n        \'runtimeAuthorityIssued\': False, \'readOnly\': True, \'automaticReplayAllowed\': False, \'budgetReset\': False,\n        \'serviceReadinessEstablished\': False, \'releaseAcceptance\': False}\n\n\ndef main():\n    try:\n        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site\n            and sys.dont_write_bytecode and len(sys.argv) == 1, \'ISOLATED_ROOT_METADATA_READER_REQUIRED\')\n        result = inspect(Reader())\n    except Exception as error:\n        reason = str(error)\n        if re.fullmatch(\'[A-Z][A-Z0-9_]{0,127}\', reason) is None: reason = \'ROOTFS_STOP_METADATA_UNPROVEN_PRIVATE_DETAILS_REDACTED\'\n        result = {\'schema\': \'ouf.semantic-registry-rootfs-stop-metadata.v1\', \'status\': \'STOP_RECONCILE\',\n            \'reasonCode\': reason, \'automaticReplayAllowed\': False, \'budgetReset\': False, \'runtimeEffectsDispatched\': 0}\n    print(json.dumps(result, sort_keys=True, separators=(\',\', \':\')), flush=True)\n    return 0 if result[\'status\'] == \'RETAINED_ROOTFS_STOP_METADATA_OBSERVED\' else 2\n\n\nif __name__ == \'__main__\': raise SystemExit(main())\n'

def require(ok, reason):
    if not ok:raise ValueError(reason)


def base_module():
    require(hashlib.sha256(BASE_SOURCE.encode()).hexdigest()==BASE_SHA256,'EXACT_BASE_METADATA_SOURCE_REQUIRED')
    b=types.ModuleType('sealed_metadata');exec(compile(BASE_SOURCE,'<sealed-metadata>','exec'),b.__dict__);return b


class Work:
    def __init__(self):self.until=time.monotonic()+90;self.hashBytes=0;self.variants=0
    def charge(self,n):
        require(time.monotonic()<self.until and self.hashBytes+n<=MAX_HASH_BYTES,'TRANSCRIPT_ANALYSIS_WORK_BOUND')
        self.hashBytes+=n


def seal(b,rows,removed,links,work):
    h=hashlib.sha256(b'OUF-ROOTFS-SEAL\x00V1\x00');count=total=0
    parents={}
    for p in removed:
        if rows[p]['kind']=='directory':
            parent=p.rpartition('/')[0];parents[parent]=parents.get(parent,0)+1
    for p,row in rows.items():
        if p in removed:continue
        item=row
        if links=='subtract-removed-directories' and row['kind']=='directory' and p in parents:
            item=dict(row,links=row['links']-parents[p])
            if item['links']<1:return None
        raw=b.encoded(item);work.charge(len(raw)+4);h.update(len(raw).to_bytes(4,'big'));h.update(raw)
        count+=1
        if row['kind']=='file':total+=row['size']
    return {'schema':'ouf.semantic-rootfs-seal.v1','sha256':h.hexdigest(),'entries':count,'bytes':total}


def targets(request):
    host=request.get('HostConfig',{});result=[]
    for entry in host.get('Binds') or []:
        require(type(entry) is str and len(entry.split(':'))==3,'EXACT_REVIEWED_BIND_FORMAT_REQUIRED')
        result.append(entry.split(':')[1])
    for entry in host.get('Mounts') or []:
        require(type(entry) is dict and type(entry.get('Target')) is str,'EXACT_REVIEWED_MOUNT_TARGET_REQUIRED')
        result.append(entry['Target'])
    require(1<=len(result)<=16,'BOUNDED_EXACT_REVIEWED_MOUNTS_REQUIRED')
    for p in result:
        v=PurePosixPath(p)
        require(v.is_absolute() and '..' not in v.parts and str(v)==p and p!='/','CANONICAL_REVIEWED_MOUNT_DESTINATION_REQUIRED')
    return result


def candidates(rows,mounts):
    roles={}
    def add(path,role):roles.setdefault(path,[]).append(role)
    for ordinal,mount in enumerate(mounts):
        path=PurePosixPath(mount)
        for item in (path,*path.parents):
            if str(item)=='/':continue
            add(str(item)[1:],{'kind':'reviewed-mount-target' if item==path else 'reviewed-mount-ancestor','ordinal':ordinal})
    for ordinal,path in enumerate(('.dockerenv','etc/hosts','etc/hostname','etc/resolv.conf')):
        add(path,{'kind':'docker-container-scaffold-candidate','ordinal':ordinal})
    eligible={p for p in roles if p in rows and (rows[p]['kind']=='directory'
        or rows[p]['kind']=='file' and rows[p]['size']==0)}
    # A directory can be removed only together with all its descendants. A
    # subtree containing any other entry cannot be considered a placeholder.
    for path in tuple(eligible):
        if rows[path]['kind']=='directory' and any(p.startswith(path+'/') and p not in eligible for p in rows):eligible.remove(path)
    return {p:roles[p] for p in sorted(eligible)}


def analyze(b,entries,expected,observed,mounts,work):
    require(type(entries) is list and 1<=len(entries)<=100000,'BOUNDED_TRANSCRIPT_ENTRIES_REQUIRED')
    rows={}
    for row in entries:
        require(type(row) is dict and type(row.get('path')) is str and row['path'] not in rows,'UNIQUE_TRANSCRIPT_PATHS_REQUIRED')
        p=row['path'];parts=PurePosixPath(p)
        require((p=='' or not parts.is_absolute() and '..' not in parts.parts and str(parts)==p)
            and row.get('kind') in ('directory','file','symlink') and type(row.get('links')) is int and row['links']>=1,
            'CANONICAL_NATIVE_TRANSCRIPT_ENTRY_REQUIRED')
        if row['kind']=='file':require(type(row.get('size')) is int and row['size']>=0,'TRANSCRIPT_FILE_SIZE_REQUIRED')
        rows[p]=row
    require('' in rows and rows['']['kind']=='directory','TRANSCRIPT_ROOT_DIRECTORY_REQUIRED')
    require(seal(b,rows,set(),'unchanged',work)==observed,'COMPLETE_NATIVE_TRANSCRIPT_SEAL_MISMATCH')
    count=observed['entries']-expected['entries'];require(count==6 and observed['bytes']==expected['bytes'],'EXACT_SIX_ENTRY_ZERO_BYTE_DIFFERENCE_REQUIRED')
    options=candidates(rows,mounts)
    require(len(options)<=MAX_CANDIDATES,'MOUNT_SCAFFOLD_CANDIDATE_BOUND')
    matches=[];tested=0;closed=0;considered=0;complete=True
    one_pass=sum(len(b.encoded(row))+4 for row in rows.values())
    for subset in itertools.combinations(options,count):
        if considered==4096 or time.monotonic()>=work.until:
            complete=False;break
        considered+=1
        selected=set(subset)
        if any(rows[p]['kind']=='directory' and any(q.startswith(p+'/') and q not in selected for q in rows) for p in selected):continue
        closed+=1
        for links in ('unchanged','subtract-removed-directories'):
            if tested==MAX_VARIANTS or work.hashBytes+one_pass>MAX_HASH_BYTES or time.monotonic()>=work.until:
                complete=False;break
            result=seal(b,rows,selected,links,work);tested+=1;work.variants+=1
            if result==expected:matches.append({'removedPaths':list(subset),'directoryLinkRule':links,
                'removedEntries':[rows[p] for p in subset],'roles':[options[p] for p in subset]})
        if not complete:break
    return {'schema':'ouf.rootfs-scaffold-transcript-analysis.v1','diagnosticOnly':True,
        'candidatePaths':options,'matchingVariants':matches,'testedVariants':tested,'closedSubsets':closed,
        'searchComplete':complete,'subsetsConsidered':considered,'maximumVariants':MAX_VARIANTS,'hashBytes':work.hashBytes,
        'expectedSeal':expected,'observedSeal':observed,'removedEntriesCountForEachVariant':6,
        'hypothesisIsNotRuntimeProvenance':True,'variantDoesNotGrantAcceptance':True}


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


def inspect():
    b=base_module()
    class Reader(b.Reader):
        def __init__(self):super().__init__();self.items={}
        def json(self,path,*args,**kwargs):
            v=super().json(path,*args,**kwargs);self.items[path]=v;return v
    r=Reader();start=b.inspect(r)
    require(start['checkpoint']==4 and start['recoveryState']=='IN_FLIGHT' and start['readAttempts']==5
        and start['ownerState']=='CANCELLED' and start['retainedControlledGrantAttempts']==320,
        'EXACT_RETAINED_ROOTFS_STOP_REQUIRED')
    prepared=r.items[b.PREPARATION_ROOT+'/prepared.json'];review=r.items[b.PREPARATION_ROOT+'/review.json']
    context=prepared['nativeContext'];execution=Path(context['executionRoot']);journal=r.items[str(execution/'recovery.json')]
    identity={'authorityHash':b.AUTHORITY_HASH,'operation':journal['logicalOperationRef'],'boot':review['bootId'],'purpose':'PAUSED_ROOTFS_COMPLETE_OBSERVATION_V1'}
    require('semantic-registry-rootfs-complete-'+b.digest(identity)==MANIFEST_ROOT,'EXACT_COMPLETED_OBSERVATION_ROOT_REQUIRED')
    root=Path(b.PARENT)/MANIFEST_ROOT
    manifest=r.json(str(root/'rootfs-manifest.json'),MANIFEST_HASH,maximum=8388608)
    observation=r.json(str(root/'observation.json'),maximum=32768)
    require(manifest['schema']=='ouf.rootfs-diagnostic-manifest.v1' and manifest['authorityHash']==b.AUTHORITY_HASH
        and manifest['diagnosticOnly'] is True and manifest['expectedRootfsSeal']==context['nodeRecipe']['expectedRootfsSeal']
        and observation['schema']=='ouf.semantic-registry-paused-rootfs-complete-observation.v1'
        and observation['status']=='PAUSED_ROOTFS_OBSERVED' and observation['privateManifestHash']==MANIFEST_HASH
        and observation['combinedDiagnosticEngineGets']==4 and observation['fullRootfsPasses']==1
        and observation['samePausedGenerationBeforeAndAfter'] is True and observation['fullPausedOciMatchesRetainedFrame'] is True
        and observation['rootfsSealMatchesExpected'] is False,'EXACT_COMPLETED_ROOTFS_OBSERVATION_REQUIRED')
    mounts=targets(prepared['registryInputs']['creationRequest'])
    successor={'authorityHash':b.AUTHORITY_HASH,'manifestHash':MANIFEST_HASH,'purpose':'RETAINED_SCAFFOLD_TRANSCRIPT_ANALYSIS_V1'}
    name='semantic-registry-rootfs-transcript-'+b.digest(successor);parent=open_parent(b.PARENT);directory=None
    try:
        try:os.mkdir(name,0o700,dir_fd=parent)
        except FileExistsError:require(False,'TRANSCRIPT_ANALYSIS_ALREADY_CONSUMED')
        os.fsync(parent);directory=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        publish(directory,'claim.json',{**successor,'maximumVariants':MAX_VARIANTS,'maximumHashBytes':MAX_HASH_BYTES,
            'maximumSeconds':90,'maximumEngineGets':0,'automaticReplayAllowed':False,'budgetReset':False},b)
        result=analyze(b,manifest['entries'],manifest['expectedRootfsSeal'],manifest['observedRootfsSeal'],mounts,Work())
        # No mutable live state is adopted; all analysis is bound to this exact
        # immutable transcript and completed reviewed configuration.
        artifact=publish(directory,'analysis.json',result,b)
        matches=result['matchingVariants'];distinct={tuple(v['removedPaths']) for v in matches}
        return {'schema':'ouf.semantic-registry-rootfs-transcript-analysis.v1','status':'RETAINED_TRANSCRIPT_ANALYZED','complete':True,
            'candidateCount':len(result['candidatePaths']),'testedVariants':result['testedVariants'],'searchComplete':result['searchComplete'],
            'matchingVariantCount':len(matches),'distinctMatchingEntrySets':len(distinct),'sixEntryScaffoldVariantMatchesExpected':bool(matches),
            'matchingEntryRoles':matches[0]['roles'] if len(distinct)==1 else [],
            'diagnosticOnly':True,'hypothesisIsNotRuntimeProvenance':True,'variantDoesNotGrantAcceptance':True,
            'hashBytes':result['hashBytes'],'maximumHashBytes':MAX_HASH_BYTES,'maximumVariants':MAX_VARIANTS,
            'privateAnalysisHash':artifact,'privateAnalysisPath':str(Path(b.PARENT)/name/'analysis.json'),
            'priorDiagnosticEngineGets':4,'engineGets':0,'retainedControlledGrantAttempts':320,
            'metadataReads':r.reads,'metadataBytesRead':r.bytes,'currentContainerStateObserved':False,'liveRootfsContentsRead':False,
            'credentialFilesOpened':0,'addressesPrinted':False,'applicationEntryInvoked':False,'capsuleExecuted':False,
            'oauthRequests':0,'adminGets':0,'databaseCalls':0,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,
            'automaticReplayAllowed':False,'budgetReset':False,'readOnlyRuntime':True,'serviceReadinessEstablished':False,'releaseAcceptance':False}
    finally:
        if directory is not None:os.close(directory)
        os.close(parent)


def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv)==1,'ISOLATED_ROOT_TRANSCRIPT_READER_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'TRANSCRIPT_ANALYSIS_DEADLINE'));signal.alarm(100)
        value=inspect()
    except Exception as error:
        reason=str(error)
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason) is None:reason='TRANSCRIPT_ANALYSIS_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        value={'schema':'ouf.semantic-registry-rootfs-transcript-analysis.v1','status':'STOP_RECONCILE','reasonCode':reason,
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0}
    print(json.dumps(value,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if value['status']=='RETAINED_TRANSCRIPT_ANALYZED' else 2


if __name__=='__main__':raise SystemExit(main())
