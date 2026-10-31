#!/usr/bin/env python3
"""Retain exact completed-maintenance and cancelled-session inputs; no runtime dispatch."""
import hashlib,json,os,re,stat,sys,time,types,fcntl
from pathlib import Path

MAINTENANCE_PROGRAM_HASH = '1e5027620b99479a75a802e624e7bfd1d493b2080892398880fa89045b98e1eb'

class Snapshot:
    """Bounded phases share a single explicit aggregate budget, never a reset."""
    def __init__(self, b):
        self.b=b; self.phase=b.Reader(); self.reads=0; self.bytes=0
        self.until=time.monotonic()+30; self.files={}; self.items={}
    def raw(self,path,maximum,sha=None,private=True):
        self.b.require(time.monotonic()<self.until and self.reads<96,'RESUMPTION_METADATA_READ_BOUND')
        if self.phase.reads==20:self.phase=self.b.Reader()
        raw=self.phase.raw(path,maximum,sha,private)
        self.reads+=1; self.bytes+=len(raw)
        self.b.require(self.bytes<=33554432,'RESUMPTION_METADATA_BYTE_BOUND')
        value={'sha256':hashlib.sha256(raw).hexdigest(),'maximum':maximum,'private':private}
        old=self.files.get(str(path))
        self.b.require(old is None or old==value,'RESUMPTION_INPUT_CHANGED')
        self.files[str(path)]=value
        return raw
    def json(self,path,sha=None,maximum=8388608):
        raw=self.raw(path,maximum,sha); value=json.loads(raw)
        self.b.require(type(value) is dict and self.b.encoded(value)==raw,'CANONICAL_RESUMPTION_INPUT_REQUIRED')
        self.items[str(path)]=value; return value
    def recheck(self):
        for path,pin in list(self.files.items()):
            self.raw(path,pin['maximum'],pin['sha256'],pin['private'])


def maintenance_identity(b,boot):
    return {'authorityHash':b.AUTHORITY_HASH,'planHash':PLAN_HASH,'bootId':boot,
        'purpose':'EXPLICIT_OPERATOR_JVM_EMPTY_DIRECTORY_MAINTENANCE_V1'}


def verify_completed(b,r,root,plan,boot):
    expected=maintenance_identity(b,boot)
    scope=r.json(str(root/'scope.json')); result=r.json(str(root/'result.json'))
    require(all(scope.get(k)==v for k,v in expected.items()) and scope.get('programSha256')==MAINTENANCE_PROGRAM_HASH
        and scope.get('authorizationSource')=='EXPLICIT_ROOT_OPERATOR_INVOCATION_WITH_EXACT_PLAN_HASH'
        and scope.get('grantAttemptAllowance')==0 and scope.get('retainedControlledGrantAttempts')==320,
        'EXACT_COMPLETED_MAINTENANCE_SCOPE_REQUIRED')
    require(result.get('schema')=='ouf.semantic-registry-jvm-cleanup-result.v1'
        and result.get('status')=='JVM_RESIDUE_REMOVED_ORIGINAL_SEAL_RESTORED'
        and all(result.get(k) is True for k in ('complete','originalIndependentRootfsSealMatches',
            'expectedRootfsSealUnchanged','samePausedGenerationBeforeAndAfter','kernelFrozenThroughoutMaintenance',
            'protocolInvocationLocksHeld','nativeOwnerStillCancelled'))
        and result.get('directoryRemovalAttempts')==result.get('directoryRemovalsConfirmed')==6
        and result.get('engineGets')==2 and result.get('combinedEngineGets')==6
        and result.get('retainedControlledGrantAttempts')==320 and result.get('nativeRecoveryStillAtCheckpoint')==4
        and result.get('remainingEntryCount')==plan['expectedAfterSeal']['entries']
        and result.get('privateMaintenancePath')==str(root)
        and all(result.get(k)==0 for k in ('oauthRequests','databaseCalls','adminGets','fileUnlinks','recursiveRemovals'))
        and all(result.get(k) is False for k in ('javaReleased','applicationEntryInvoked','signedRuntimeAuthorityIssued',
            'priorExpiredRuntimeAuthorityReused','automaticReplayAllowed','budgetReset','serviceReadinessEstablished','releaseAcceptance')),
        'COMPLETE_ORIGINAL_SEAL_RESTORATION_RECEIPT_REQUIRED')
    preflight=r.json(str(root/'preflight.json'))
    require(preflight.get('fullBeforeSeal')==plan['expectedBeforeSeal'],'ORIGINAL_MAINTENANCE_PREFLIGHT_REQUIRED')
    for i,row in enumerate(plan['orderedDirectories']):
        claim=r.json(str(root/('rmdir-'+str(i)+'-claimed.json')))
        applied=r.json(str(root/('rmdir-'+str(i)+'-applied.json')))
        require(claim.get('ordinal')==applied.get('ordinal')==i and claim.get('planHash')==PLAN_HASH
            and claim.get('pathHash')==applied.get('pathHash')==b.digest(row['path'])
            and type(claim.get('inode')) is list and len(claim['inode'])==5,
            'SIX_ORDERED_DURABLE_REMOVAL_RECEIPTS_REQUIRED')
    for i in (1,2):
        marker=r.json(str(root/('engine-get-'+str(i)+'.json')))
        require(marker=={'attempt':i,'requestPathHash':b.digest('/v1.44/containers/'+plan['retainedGeneration']['containerId']+'/json')},
            'EXACT_TWO_COMPLETED_MAINTENANCE_REQUEST_MARKERS_REQUIRED')
    r.json(str(root/'directory-restoration-metadata.json'))
    expected_names={'scope.json','result.json','preflight.json','directory-restoration-metadata.json',
        'engine-get-1.json','engine-get-2.json'}
    expected_names.update('rmdir-'+str(i)+'-'+kind+'.json' for i in range(6) for kind in ('claimed','applied'))
    fd=open_parent(root)
    try:require(set(os.listdir(fd))==expected_names,'COMPLETED_MAINTENANCE_ARTIFACT_SET_CHANGED')
    finally:os.close(fd)
    return result


def capture(b):
    r=Snapshot(b); start=b.inspect(r)
    require(start['checkpoint']==4 and start['recoveryState']=='IN_FLIGHT' and start['readAttempts']==5
        and start['ownerState']=='CANCELLED' and start['retainedControlledGrantAttempts']==320
        and start['nativeReadCounts']=={'databaseSessions':1,'gatewayAdminGets':6,'semanticGets':0}
        and not start['pausedAcceptanceRetained'] and not start['pausedObservationRetained'],
        'UNCHANGED_CANCELLED_PAUSED_RECOVERY_PREFIX_REQUIRED')
    prepared=r.items[b.PREPARATION_ROOT+'/prepared.json'];review=r.items[b.PREPARATION_ROOT+'/review.json']
    execution=Path(prepared['nativeContext']['executionRoot'])
    owner=Path(review['scopes']['semanticRegistryPostbootOwner']['journalPath'])
    journal=r.items[str(execution/'recovery.json')]
    plan=r.json(str(Path(b.PARENT)/PLAN_ROOT/'cleanup-plan.json'),PLAN_HASH)
    require(plan['retainedGeneration']==journal['newGeneration']
        and plan['expectedAfterSeal']==prepared['nativeContext']['nodeRecipe']['expectedRootfsSeal']
        and len(plan['orderedDirectories'])==6,'SAME_REVIEWED_MAINTAINED_GENERATION_REQUIRED')
    maintenance=Path(b.PARENT)/('semantic-registry-jvm-cleanup-'+b.digest(maintenance_identity(b,review['bootId'])))
    locks=[];parent=directory=None
    try:
        for path in (execution/'invocation.lock',owner/'invocation.lock'):locks.append(lock_existing(path))
        result=verify_completed(b,r,maintenance,plan,review['bootId'])
        records={name:r.json(str(owner/name),maximum=1048576)
            for name in ('owner-session.json','owner-admission.json','owner-first-grant.json')}
        session=records['owner-session.json'];marker=records['owner-admission.json']
        scope=review['scopes']['semanticRegistryPostbootOwner']
        require(session==scope and marker.get('state')=='BLOCKED'
            and all(marker.get(k)==scope[k] for k in ('contextRef','generationRef')),
            'EXACT_CANCELLED_CURRENT_BOOT_SESSION_AND_BLOCKED_MARKER_REQUIRED')
        fence=scope['fenceBinding'];fencepath=b.inside(fence['path'])
        require(r.json(str(fencepath),maximum=16384)==fence['value'],'EXACT_RETAINED_POSTBOOT_GLOBAL_FENCE_REQUIRED')
        r.recheck()
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==review['bootId'],'SAME_BOOT_AT_RESUMPTION_CAPTURE_REQUIRED')
        pins={path:{'sha256':v['sha256']} for path,v in r.files.items()}
        identity={'operation':'PREPARE_EXPLICIT_CHECKPOINT_FOUR_SUCCESSOR_INPUTS_V1','priorAuthorityHash':b.AUTHORITY_HASH,
            'maintenanceResultHash':b.digest(result),'nativeJournalHash':b.digest(journal),
            'ownerJournalHash':b.digest(r.items[str(owner/'recovery.json')]),'bootId':review['bootId']}
        value={'schema':'ouf.semantic-registry-resumption-inputs.v1','identity':identity,
            'inputBindings':pins,'retainedNativeJournal':journal,'retainedNativeReads':r.items[str(execution/'native-reads.json')],
            'retainedOwnerJournal':r.items[str(owner/'recovery.json')],'retainedOwnerRecords':records,
            'retainedFence':fence,'maintenanceResult':result,'privatePreparedInputs':b.PREPARATION_ROOT+'/prepared.json',
            'retainedControlledGrantAttempts':320,'newGrantAllowance':0,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False}
        name='semantic-registry-resumption-inputs-'+b.digest(identity);parent=open_parent(b.PARENT)
        try:os.mkdir(name,0o700,dir_fd=parent)
        except FileExistsError:require(False,'EXISTING_RESUMPTION_INPUTS_RETAINED_NO_REPLAY')
        os.fsync(parent);directory=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        sha=publish(directory,'inputs.json',value,b)
        return {'schema':'ouf.semantic-registry-resumption-inputs-result.v1','status':'CHECKPOINT_FOUR_SUCCESSOR_INPUTS_RETAINED',
            'complete':True,'privateInputsPath':str(Path(b.PARENT)/name/'inputs.json'),'privateInputsHash':sha,
            'priorMaintenanceReceiptVerified':True,'retainedNativeCheckpoint':4,'retainedControlledGrantAttempts':320,
            'nativeEffectReplayAllowed':False,'ownerCancelled':True,'metadataReads':r.reads,'metadataBytesRead':r.bytes,
            'currentContainerStateObserved':False,'liveRootfsRead':False,'engineGets':0,'adminGets':0,'oauthRequests':0,
            'credentialFilesOpened':0,'databaseCalls':0,'runtimeEffectsDispatched':0,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'addressesPrinted':False,'readOnlyRuntime':True,
            'automaticReplayAllowed':False,'budgetReset':False,'serviceReadinessEstablished':False,'releaseAcceptance':False}
    finally:
        if directory is not None:os.close(directory)
        if parent is not None:os.close(parent)
        for fd in reversed(locks):os.close(fd)


def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv)==1,'ISOLATED_ROOT_RESUMPTION_CAPTURE_REQUIRED')
        result=capture(base_module())
    except Exception as error:
        reason=str(error)
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason) is None:reason='RESUMPTION_INPUTS_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        result={'schema':'ouf.semantic-registry-resumption-inputs-result.v1','status':'STOP_RECONCILE','reasonCode':reason,
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0}
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['status']=='CHECKPOINT_FOUR_SUCCESSOR_INPUTS_RETAINED' else 2


PLAN_ROOT = 'semantic-registry-jvm-residue-aaa525bab7d23982bcd72bf3f29d687a9aa105af78f53add858a1254c452824d'
PLAN_HASH = 'f745bebba740e28d675d14277b04f51ed4340bce59f1c9659520390b15772d9c'
PROOF_HASH = 'c046c4a7274f6021b15be5e9db0e875e9c5eb52252b1f17175f74c8cac3f36cc'
BASE_SHA256 = '97ee083211258c9f207e4b4aef8309fbe902e041a7b0b67bebce618adf09a9fe'
BASE_SOURCE = '#!/usr/bin/env python3\n"""Read retained stop metadata only; never execute capsule or enter application."""\nimport ast\nimport hashlib\nimport json\nimport os\nfrom pathlib import Path\nimport re\nimport stat\nimport sys\nimport time\n\nCAPSULE = \'/home/oufadmin/ouf-registry-postboot-review.LduMidpc/capsule.py\'\nCAPSULE_HASH = \'f6ab800de6ca9452258cf967dd0e194b81b620a35dff0ef357f7fdf93f45f02c\'\nCLOSURE_HASH = \'4fb611d8ffcf4446aeb25df7777dfb66fefb964c63f375863471072b8d7d2f27\'\nDECLARATION_HASH = \'c0d3bedb36ab56d4f116a4a264e49a1310b366d0ec9aadbd5a6d715331c6bdc8\'\nPREPARATION_ROOT = \'/etc/ouf/deploy-snapshots/semantic-registry-postboot-inputs-ed5451cb23ed2a28c1dbb7585cccfe64fb2837e2d33c81d2a43c1e31f243d5c2\'\nPREPARATION_HASH = \'90748d593e5292420ce967c256d757364ba8637dc0f79619c688585a2f1e5f5d\'\nREVIEW_HASH = \'cf5191895f1e67b86bdc98b7aa9e10b1292d3f8589a653839116e7c2816ba3c9\'\nAUTHORITY_HASH = \'9d8f36e7f6a942fee95278148399a1a3d140fe0b660809a465edd85f2820d607\'\nPARENT = \'/etc/ouf/deploy-snapshots\'\n\n\ndef require(ok, reason):\n    if not ok: raise ValueError(reason)\n\n\ndef encoded(v): return json.dumps(v, sort_keys=True, separators=(\',\', \':\'), allow_nan=False).encode()\ndef digest(v): return hashlib.sha256(encoded(v)).hexdigest()\ndef identity(v): return (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)\n\n\nclass Reader:\n    def __init__(self): self.reads = 0; self.bytes = 0; self.until = time.monotonic() + 30\n\n    def raw(self, path, maximum, sha=None, private=True):\n        require(time.monotonic() < self.until and self.reads < 20, \'BOUNDED_METADATA_READ_REQUIRED\')\n        # Traverse protected ancestry through held descriptors, refusing links.\n        path = Path(path)\n        require(path.is_absolute() and \'..\' not in path.parts, \'EXACT_METADATA_PATH_REQUIRED\')\n        fd = os.open(\'/\', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n        try:\n            for part in path.parts[1:-1]:\n                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)\n                info = os.fstat(child)\n                require(not info.st_mode & 0o022 and (info.st_uid == 0 or not private), \'PROTECTED_METADATA_ANCESTRY_REQUIRED\')\n                os.close(fd); fd = child\n            leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)\n            try:\n                before = os.fstat(leaf)\n                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022\n                    and (before.st_uid == 0 or not private) and 0 < before.st_size <= maximum,\n                    \'BOUNDED_PROTECTED_METADATA_REQUIRED\')\n                chunks = []; count = 0\n                while count <= before.st_size:\n                    block = os.read(leaf, min(65536, before.st_size + 1 - count))\n                    if not block: break\n                    chunks.append(block); count += len(block)\n                raw = b\'\'.join(chunks)\n                require(len(raw) == before.st_size and identity(before) == identity(os.fstat(leaf))\n                    == identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)), \'METADATA_CHANGED\')\n            finally: os.close(leaf)\n        finally: os.close(fd)\n        self.reads += 1; self.bytes += len(raw)\n        require(self.bytes <= 16777216 and (sha is None or hashlib.sha256(raw).hexdigest() == sha), \'METADATA_HASH_OR_BYTE_BOUND\')\n        return raw\n\n    def json(self, path, sha=None, maximum=8388608):\n        raw = self.raw(path, maximum, sha); value = json.loads(raw)\n        require(type(value) is dict and encoded(value) == raw, \'CANONICAL_METADATA_REQUIRED\')\n        return value\n\n\ndef inside(value):\n    require(type(value) is str and value.startswith(PARENT + \'/\') and \'..\' not in Path(value).parts\n            and str(Path(value)) == value, \'EXACT_REVIEW_BOUND_PRIVATE_PATH_REQUIRED\')\n    return Path(value)\n\n\ndef optional(reader, path, maximum=131072):\n    try: path.lstat()\n    except FileNotFoundError: return None\n    return reader.json(str(path), maximum=maximum)\n\n\ndef closed(value, allowed): return value if type(value) is str and value in allowed else \'OTHER_OR_ABSENT\'\n\n\ndef shape(value):\n    obj = type(value) is dict\n    return {\'object\': obj, \'string\': type(value) is str,\n        \'exactKeys\': obj and set(value) == {\'schema\', \'sha256\', \'entries\', \'bytes\'},\n        \'schemaMatches\': obj and value.get(\'schema\') == \'ouf.semantic-rootfs-seal.v1\',\n        \'sha256WellFormed\': obj and type(value.get(\'sha256\')) is str and re.fullmatch(\'[0-9a-f]{64}\', value[\'sha256\']) is not None,\n        \'entries\': value[\'entries\'] if obj and type(value.get(\'entries\')) is int and 0 < value[\'entries\'] <= 100000 else None,\n        \'bytes\': value[\'bytes\'] if obj and type(value.get(\'bytes\')) is int and 0 <= value[\'bytes\'] <= 8589934592 else None}\n\n\ndef inspect(reader):\n    # Parse only literal assignments; do not execute the loader or application.\n    raw = reader.raw(CAPSULE, 1048576, CAPSULE_HASH, private=False)\n    values = {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(raw).body\n        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}\n    require(set(values) == {\'CASE\', \'DELIVERY\', \'DELIVERY_HASH\', \'PACKED\', \'BOOTSTRAP\'}, \'EXACT_RETAINED_CAPSULE_FIELDS_REQUIRED\')\n    manifest = values[\'DELIVERY\'][\'nativeDeclaration\']\n    require(digest(values[\'DELIVERY\']) == values[\'DELIVERY_HASH\'] == DECLARATION_HASH and digest(manifest) == CLOSURE_HASH\n        and digest(values[\'CASE\']) == values[\'DELIVERY\'][\'caseHash\'], \'EXACT_RETAINED_CAPSULE_BINDINGS_REQUIRED\')\n    root = inside(PREPARATION_ROOT)\n    prepared = reader.json(str(root / \'prepared.json\'), PREPARATION_HASH, maximum=16777216)\n    review = reader.json(str(root / \'review.json\'), REVIEW_HASH)\n    require(review[\'currentContext\'] == prepared[\'nativeContext\'] and review[\'ownerContext\'] == prepared[\'ownerContext\']\n        and review[\'sourceClosureHash\'] == digest(prepared[\'sourceClosure\']) == CLOSURE_HASH\n        and prepared[\'sourceClosure\'] == manifest and review[\'sourceClosure\'] == manifest, \'EXACT_COMPLETED_REVIEW_INPUTS_REQUIRED\')\n    boot = Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip()\n    require(review[\'bootId\'] == boot, \'SAME_RETAINED_BOOT_REQUIRED\')\n    receipt = reader.json(str(root / \'authority/receipt.json\'), maximum=131072)\n    require(receipt.get(\'schema\') == \'ouf.semantic-registry-postboot-issued-authority.v1\'\n        and receipt.get(\'authorityHash\') == AUTHORITY_HASH and receipt.get(\'reviewHash\') == REVIEW_HASH\n        and receipt.get(\'runtimeAuthorityIssued\') is True, \'EXACT_ISSUED_AUTHORITY_RECEIPT_REQUIRED\')\n    context = prepared[\'nativeContext\']; plan = context[\'plan\']; execution = inside(context[\'executionRoot\'])\n    require(execution.name == \'semantic-registry-recovery-\' + plan[\'logicalOperationRef\'], \'EXACT_RECOVERY_OPERATION_ROOT_REQUIRED\')\n    journal = reader.json(str(execution / \'recovery.json\'), maximum=1048576)\n    require(journal[\'logicalOperationRef\'] == plan[\'logicalOperationRef\'] and journal[\'authorityHash\'] == AUTHORITY_HASH\n        and journal[\'bootId\'] == boot and type(journal[\'nextStage\']) is int and 0 <= journal[\'nextStage\'] <= 12\n        and type(journal[\'effects\']) is list and len(journal[\'effects\']) <= 12, \'EXACT_RETAINED_RECOVERY_JOURNAL_REQUIRED\')\n    require(type(journal.get(\'readAttempts\')) is int and 0 <= journal[\'readAttempts\'] <= 128\n        and type(journal.get(\'expiresUnix\')) is int and 0 < journal[\'expiresUnix\'] < 1099511627776,\n        \'BOUNDED_RETAINED_READ_AND_EXPIRY_FIELDS_REQUIRED\')\n    effects = []\n    for n, effect in enumerate(journal[\'effects\']):\n        require(effect[\'stage\'] == plan[\'stages\'][n][\'name\'], \'EXACT_ORDERED_EFFECTS_REQUIRED\')\n        effects.append({\'ordinal\': n, \'state\': closed(effect.get(\'state\'), (\'PENDING\',\'CLAIMED\',\'APPLIED\',\'UNKNOWN\',\'FAILED\')),\n            \'nativeRequestAttempted\': effect.get(\'nativeRequestAttempted\') is True,\n            \'nativeResponse204\': effect.get(\'nativeResponse204\') is True,\n            \'nativeAttestationAttempted\': effect.get(\'nativeAttestationAttempted\') is True})\n    owner_scope = review[\'scopes\'][\'semanticRegistryPostbootOwner\']; owner_root = inside(owner_scope[\'journalPath\'])\n    owner = reader.json(str(owner_root / \'recovery.json\'), maximum=65536)\n    require(owner[\'contextRef\'] == owner_scope[\'contextRef\'] and owner[\'generationRef\'] == owner_scope[\'generationRef\']\n        and type(owner[\'attempts\']) is int and 0 <= owner[\'attempts\'] <= 1\n        and owner[\'controlledPredecessorGrantAttempts\'] == 319\n        and owner[\'controlledCumulativeGrantAttempts\'] == 319 + owner[\'attempts\'], \'EXACT_RETAINED_OWNER_ACCOUNTING_REQUIRED\')\n    reads = reader.json(str(execution / \'native-reads.json\'), maximum=8192)\n    scope = review[\'scopes\'][\'semanticRegistryRecoveryReads\']; counts = reads[\'counts\']\n    require(reads[\'scopeHash\'] == digest(scope) and reads[\'authorityHash\'] == AUTHORITY_HASH\n        and set(counts) == set(scope[\'maximumRequests\']) and all(type(v) is int and 0 <= v <= scope[\'maximumRequests\'][k]\n            for k,v in counts.items()), \'EXACT_RETAINED_NATIVE_READ_COUNTERS_REQUIRED\')\n    frame = optional(reader, execution / \'node/frame-policy.json\')\n    observed = optional(reader, execution / \'node/paused-observation.json\', maximum=1048576)\n    acceptance = optional(reader, execution / \'node/paused-acceptance.json\')\n    recipe = context[\'nodeRecipe\']; expected = recipe[\'expectedRootfsSeal\']\n    observed_seal = observed.get(\'rootfsSeal\') if observed is not None else None\n    require(reader.json(str(execution / \'recovery.json\'), maximum=1048576) == journal\n        and reader.json(str(owner_root / \'recovery.json\'), maximum=65536) == owner\n        and reader.json(str(execution / \'native-reads.json\'), maximum=8192) == reads\n        and Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip() == boot, \'STOP_METADATA_CHANGED_DURING_OBSERVATION\')\n    return {\'schema\': \'ouf.semantic-registry-rootfs-stop-metadata.v1\', \'status\': \'RETAINED_ROOTFS_STOP_METADATA_OBSERVED\',\n        \'checkpoint\': journal[\'nextStage\'], \'recoveryState\': closed(journal.get(\'state\'), (\'READY\',\'IN_FLIGHT\',\'COMPLETE\',\'BLOCKED\',\'RECONCILE_REQUIRED\')),\n        \'effects\': effects, \'readAttempts\': journal.get(\'readAttempts\'), \'nativeReadCounts\': counts,\n        \'newGenerationRecorded\': type(journal.get(\'newGeneration\')) is dict,\n        \'framePolicyRetained\': frame is not None, \'pausedObservationRetained\': observed is not None,\n        \'pausedAcceptanceRetained\': acceptance is not None, \'expectedSealShape\': shape(expected),\n        \'retainedObservedSealShape\': shape(observed_seal),\n        \'retainedSealMatchesExpected\': observed_seal == expected if observed is not None else None,\n        \'ownerState\': closed(owner.get(\'state\'), (\'NEW\',\'ACTIVE\',\'BLOCKED\',\'CANCELLED\',\'PAUSED_EXHAUSTED\',\'RECONCILE_REQUIRED\',\'PUBLISHING\')),\n        \'retainedServiceGrantAttempts\': owner[\'attempts\'], \'retainedControlledGrantAttempts\': owner[\'controlledCumulativeGrantAttempts\'],\n        \'signedWindowExpiredAtObservation\': time.time() >= journal[\'expiresUnix\'],\n        \'journalObservationIsCurrentOwnerAdmission\': False, \'currentContainerStateObserved\': False,\n        \'currentRootfsRead\': False, \'rootfsMismatchCauseEstablished\': False, \'capsuleExecuted\': False,\n        \'addressesPrinted\': False, \'credentialFilesOpened\': 0, \'metadataReads\': reader.reads, \'metadataBytesRead\': reader.bytes,\n        \'engineGets\': 0, \'adminGets\': 0, \'oauthRequests\': 0, \'databaseCalls\': 0, \'runtimeEffectsDispatched\': 0,\n        \'runtimeAuthorityIssued\': False, \'readOnly\': True, \'automaticReplayAllowed\': False, \'budgetReset\': False,\n        \'serviceReadinessEstablished\': False, \'releaseAcceptance\': False}\n\n\ndef main():\n    try:\n        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site\n            and sys.dont_write_bytecode and len(sys.argv) == 1, \'ISOLATED_ROOT_METADATA_READER_REQUIRED\')\n        result = inspect(Reader())\n    except Exception as error:\n        reason = str(error)\n        if re.fullmatch(\'[A-Z][A-Z0-9_]{0,127}\', reason) is None: reason = \'ROOTFS_STOP_METADATA_UNPROVEN_PRIVATE_DETAILS_REDACTED\'\n        result = {\'schema\': \'ouf.semantic-registry-rootfs-stop-metadata.v1\', \'status\': \'STOP_RECONCILE\',\n            \'reasonCode\': reason, \'automaticReplayAllowed\': False, \'budgetReset\': False, \'runtimeEffectsDispatched\': 0}\n    print(json.dumps(result, sort_keys=True, separators=(\',\', \':\')), flush=True)\n    return 0 if result[\'status\'] == \'RETAINED_ROOTFS_STOP_METADATA_OBSERVED\' else 2\n\n\nif __name__ == \'__main__\': raise SystemExit(main())\n'

def require(value, reason):
    if not value: raise ValueError(reason)

def base_module():
    require(hashlib.sha256(BASE_SOURCE.encode()).hexdigest() == BASE_SHA256, 'EXACT_METADATA_OBSERVER_SOURCE_REQUIRED')
    module = types.ModuleType('sealed_rootfs_metadata_observer')
    exec(compile(BASE_SOURCE, '<sealed-metadata-observer>', 'exec'), module.__dict__)
    return module

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


if __name__=='__main__':raise SystemExit(main())
