#!/usr/bin/env python3
"""Prove JVM residue hypothesis on retained metadata; prepare cleanup plan only."""
import hashlib,json,os,re,stat,sys,time,types
from pathlib import Path,PurePosixPath
COMPARISON_ROOT='semantic-registry-archive-comparison-4d8c3d00403c7ed0caeac97ed652bbd88a32d61bbeb6148bf1df23f5ece9b4c7'
COMPARISON_HASH='5d7e8b849cbee5aa944fa20cc4e657ce1c39bb19af427944d4d851beef998431'

MANIFEST_HASH = '92ce6633088609b68d10cb3f8310ea1a083596ed93a177b8bc634be947b71294'
MANIFEST_ROOT = 'semantic-registry-rootfs-complete-dfff207b4013107bcc645299ef91ede9edcd21665c1c7539b1e1929f129c0966'
MAX_HASH_BYTES = 17179869184
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

def residue(entries,request,readiness):
    require(type(request.get('User')) is str and re.fullmatch('[0-9]+:[0-9]+',request['User']),'EXACT_REVIEWED_RUNTIME_UID_GID_REQUIRED')
    uid,gid=map(int,request['User'].split(':'));port=readiness['health']['port']
    require(0<uid<=4294967295 and 0<gid<=4294967295 and type(port) is int and 1<=port<=65535,'EXACT_RUNTIME_USER_AND_CONFIGURED_PORT_REQUIRED')
    rows={v['path']:v for v in entries};require(len(rows)==len(entries),'UNIQUE_NATIVE_TRANSCRIPT_PATHS_REQUIRED')
    hs=[p for p in rows if re.fullmatch(r'tmp/hsperfdata_[A-Za-z0-9_-]{1,64}',p)]
    pattern=r'tmp/tomcat\.'+re.escape(str(port))+r'\.[0-9]{1,20}'
    tomcat=[p for p in rows if re.fullmatch(pattern,p)]
    require(len(hs)==len(tomcat)==1,'EXACT_SINGLE_HISTORICAL_JVM_RESIDUE_REQUIRED')
    root=tomcat[0];paths=[hs[0],root,root+'/work',root+'/work/Tomcat',root+'/work/Tomcat/localhost',root+'/work/Tomcat/localhost/ROOT']
    require(len(set(paths))==6 and all(p in rows for p in paths),'EXACT_SIX_JVM_DIRECTORIES_REQUIRED')
    selected=set(paths)
    for p in paths:
        row=rows[p]
        require(row['kind']=='directory' and row['uid']==uid and row['gid']==gid and row['xattrs']=={}
            and row['mode']==(0o700 if p==root else 0o755),'EXACT_NONSECRET_JVM_DIRECTORY_METADATA_REQUIRED')
        require(all(not q.startswith(p+'/') or q in selected for q in rows),'JVM_RESIDUE_SUBTREE_CONTAINS_OTHER_ENTRIES')
    return rows,sorted(paths,key=lambda p:(-p.count('/'),p)),uid,gid,port


def prove(b,manifest,request,readiness):
    rows,paths,uid,gid,port=residue(manifest['entries'],request,readiness);work=Work()
    require(seal(b,rows,set(),'unchanged',work)==manifest['observedRootfsSeal'],'COMPLETE_RETAINED_NATIVE_SEAL_REQUIRED')
    expected=manifest['expectedRootfsSeal'];observed=manifest['observedRootfsSeal']
    require(observed['entries']==expected['entries']+6 and observed['bytes']==expected['bytes'],'EXACT_SIX_DIRECTORY_ZERO_BYTE_DELTA_REQUIRED')
    variants={rule:seal(b,rows,set(paths),rule,work)==expected for rule in ('unchanged','subtract-removed-directories')}
    return {'matchingRules':[rule for rule,match in variants.items() if match],'variants':variants,'paths':paths,
        'directories':[rows[p] for p in paths],'runtimeUid':uid,'runtimeGid':gid,'configuredPort':port,'hashBytes':work.hashBytes}


def inspect():
    b=base_module()
    class Reader(b.Reader):
        def __init__(self):super().__init__();self.items={}
        def json(self,path,*args,**kwargs):
            v=super().json(path,*args,**kwargs);self.items[path]=v;return v
    r=Reader();start=b.inspect(r)
    require(start['checkpoint']==4 and start['readAttempts']==5 and start['recoveryState']=='IN_FLIGHT'
        and start['ownerState']=='CANCELLED' and start['retainedControlledGrantAttempts']==320,'EXACT_NATIVE_STOP_AND_CONSUMED_GRANT_REQUIRED')
    prep=r.items[b.PREPARATION_ROOT+'/prepared.json'];review=r.items[b.PREPARATION_ROOT+'/review.json']
    context=prep['nativeContext'];execution=Path(context['executionRoot']);journal=r.items[str(execution/'recovery.json')]
    manifest=r.json(str(Path(b.PARENT)/MANIFEST_ROOT/'rootfs-manifest.json'),MANIFEST_HASH)
    comparison=r.json(str(Path(b.PARENT)/COMPARISON_ROOT/'comparison.json'),COMPARISON_HASH)
    require(manifest['schema']=='ouf.rootfs-diagnostic-manifest.v1' and manifest['authorityHash']==b.AUTHORITY_HASH
        and manifest['diagnosticOnly'] is True and manifest['expectedRootfsSeal']==context['nodeRecipe']['expectedRootfsSeal']
        and comparison['manifestHash']==MANIFEST_HASH,'EXACT_REVIEWED_TRANSCRIPT_AND_COMPARISON_REQUIRED')
    require({row['path'] for row in comparison['differences']}=={'etc/hostname','etc/hosts','etc/resolv.conf'}
        and all(row['observed']['kind']=='file' and row['observed']['size']==0 and row['observed']['uid']==row['observed']['gid']==0
            for row in comparison['differences']),'ONLY_DOCKER_NETWORK_METADATA_ARCHIVE_DIFFERENCES_REQUIRED')
    result=prove(b,manifest,prep['registryInputs']['creationRequest'],prep['registryInputs']['readinessScope'])
    matched=bool(result['matchingRules'])
    identity={'authorityHash':b.AUTHORITY_HASH,'manifestHash':MANIFEST_HASH,'comparisonHash':COMPARISON_HASH,'purpose':'JVM_RESIDUE_PROOF_AND_CLEANUP_PLAN_V1'}
    name='semantic-registry-jvm-residue-'+b.digest(identity);parent=open_parent(b.PARENT);directory=None
    try:
        try:os.mkdir(name,0o700,dir_fd=parent)
        except FileExistsError:require(False,'JVM_RESIDUE_PROOF_ALREADY_RETAINED')
        os.fsync(parent);directory=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        proof_hash=publish(directory,'proof.json',{'schema':'ouf.jvm-residue-proof.v1',**identity,**result,
            'expectedRootfsSeal':manifest['expectedRootfsSeal'],'observedRootfsSeal':manifest['observedRootfsSeal'],
            'expectedSealRestoredByRemovingOnlySixDirectories':matched,'runtimeEffectsDispatched':0},b)
        plan_path=None;plan_hash=None
        if matched:
            # Concrete plan only: no directory is opened, removed, recreated or
            # treated as currently empty. A later apply must revalidate live
            # paused generation and the complete pinned original seal first.
            plan={'schema':'ouf.semantic-jvm-empty-directory-cleanup-plan.v1','preparationHash':b.PREPARATION_HASH,
                'reviewHash':b.REVIEW_HASH,'manifestHash':MANIFEST_HASH,'proofHash':proof_hash,
                'retainedGeneration':journal['newGeneration'],'expectedBeforeSeal':manifest['observedRootfsSeal'],
                'expectedAfterSeal':manifest['expectedRootfsSeal'],'orderedDirectories':result['directories'],
                'operation':'RMDIR_EMPTY_DIRECTORIES_ONLY','maximumDirectoryRemovals':6,
                'requiresFreshPausedGenerationAndFullSealBeforeApply':True,'requiresMountAndFdIdentityGuards':True,
                'requiresNoOtherLiveMutationOwner':True,'requiresPostApplyIndependentSealEquality':True,
                'requiresExplicitSuccessorExecutionScope':True,'requiresRetainedOutcomeReconciliationOnPartialFailure':True,
                'expectedSealMayBeReplaced':False,'fileUnlinkAllowed':False,'recursiveRemovalAllowed':False,
                'unpauseAllowed':False,'javaReleaseAllowed':False,'grantAttemptAllowance':0,
                'retainedControlledGrantAttempts':320,'priorDiagnosticEngineGets':4,
                'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False}
            plan_hash=publish(directory,'cleanup-plan.json',plan,b);plan_path=str(Path(b.PARENT)/name/'cleanup-plan.json')
        return {'schema':'ouf.semantic-registry-jvm-residue-proof-result.v1','status':'JVM_RESIDUE_PROOF_RETAINED','complete':True,
            'expectedSealRestoredByRemovingOnlySixDirectories':matched,'matchingDirectoryLinkRules':result['matchingRules'],
            'selectedDirectoryCount':6,'selectedRelativeImagePaths':result['paths'],
            'remainingEntryCount':manifest['observedRootfsSeal']['entries']-6,'fileContentBytesChanged':0,
            'nativeExpectedSealUnchanged':True,'cleanupPlanPrepared':matched,'privateCleanupPlanHash':plan_hash,'privateCleanupPlanPath':plan_path,
            'privateProofHash':proof_hash,'privateProofPath':str(Path(b.PARENT)/name/'proof.json'),
            'priorDirectoryMetadataIsCurrentEmptyDirectoryProof':False,'currentContainerStateObserved':False,'liveRootfsContentsRead':False,
            'engineGets':0,'priorDiagnosticEngineGets':4,'retainedControlledGrantAttempts':320,'metadataReads':r.reads,'metadataBytesRead':r.bytes,
            'credentialFilesOpened':0,'oauthRequests':0,'adminGets':0,'databaseCalls':0,'applicationEntryInvoked':False,'capsuleExecuted':False,
            'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,
            'serviceReadinessEstablished':False,'releaseAcceptance':False}
    finally:
        if directory is not None:os.close(directory)
        os.close(parent)


def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,
            'ISOLATED_ROOT_JVM_RESIDUE_PROOF_REQUIRED')
        result=inspect()
    except Exception as error:
        reason=str(error)
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason) is None:reason='JVM_RESIDUE_PROOF_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        result={'schema':'ouf.semantic-registry-jvm-residue-proof-result.v1','status':'STOP_RECONCILE','reasonCode':reason,
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0}
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['status']=='JVM_RESIDUE_PROOF_RETAINED' else 2


if __name__=='__main__':raise SystemExit(main())
