#!/usr/bin/env python3
"""Classify exact retained root-path/OCI flags; no Engine or rootfs-content IO."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import types

BASE_SHA256 = '97ee083211258c9f207e4b4aef8309fbe902e041a7b0b67bebce618adf09a9fe'
BASE_SOURCE = '#!/usr/bin/env python3\n"""Read retained stop metadata only; never execute capsule or enter application."""\nimport ast\nimport hashlib\nimport json\nimport os\nfrom pathlib import Path\nimport re\nimport stat\nimport sys\nimport time\n\nCAPSULE = \'/home/oufadmin/ouf-registry-postboot-review.LduMidpc/capsule.py\'\nCAPSULE_HASH = \'f6ab800de6ca9452258cf967dd0e194b81b620a35dff0ef357f7fdf93f45f02c\'\nCLOSURE_HASH = \'4fb611d8ffcf4446aeb25df7777dfb66fefb964c63f375863471072b8d7d2f27\'\nDECLARATION_HASH = \'c0d3bedb36ab56d4f116a4a264e49a1310b366d0ec9aadbd5a6d715331c6bdc8\'\nPREPARATION_ROOT = \'/etc/ouf/deploy-snapshots/semantic-registry-postboot-inputs-ed5451cb23ed2a28c1dbb7585cccfe64fb2837e2d33c81d2a43c1e31f243d5c2\'\nPREPARATION_HASH = \'90748d593e5292420ce967c256d757364ba8637dc0f79619c688585a2f1e5f5d\'\nREVIEW_HASH = \'cf5191895f1e67b86bdc98b7aa9e10b1292d3f8589a653839116e7c2816ba3c9\'\nAUTHORITY_HASH = \'9d8f36e7f6a942fee95278148399a1a3d140fe0b660809a465edd85f2820d607\'\nPARENT = \'/etc/ouf/deploy-snapshots\'\n\n\ndef require(ok, reason):\n    if not ok: raise ValueError(reason)\n\n\ndef encoded(v): return json.dumps(v, sort_keys=True, separators=(\',\', \':\'), allow_nan=False).encode()\ndef digest(v): return hashlib.sha256(encoded(v)).hexdigest()\ndef identity(v): return (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)\n\n\nclass Reader:\n    def __init__(self): self.reads = 0; self.bytes = 0; self.until = time.monotonic() + 30\n\n    def raw(self, path, maximum, sha=None, private=True):\n        require(time.monotonic() < self.until and self.reads < 20, \'BOUNDED_METADATA_READ_REQUIRED\')\n        # Traverse protected ancestry through held descriptors, refusing links.\n        path = Path(path)\n        require(path.is_absolute() and \'..\' not in path.parts, \'EXACT_METADATA_PATH_REQUIRED\')\n        fd = os.open(\'/\', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n        try:\n            for part in path.parts[1:-1]:\n                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)\n                info = os.fstat(child)\n                require(not info.st_mode & 0o022 and (info.st_uid == 0 or not private), \'PROTECTED_METADATA_ANCESTRY_REQUIRED\')\n                os.close(fd); fd = child\n            leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)\n            try:\n                before = os.fstat(leaf)\n                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022\n                    and (before.st_uid == 0 or not private) and 0 < before.st_size <= maximum,\n                    \'BOUNDED_PROTECTED_METADATA_REQUIRED\')\n                chunks = []; count = 0\n                while count <= before.st_size:\n                    block = os.read(leaf, min(65536, before.st_size + 1 - count))\n                    if not block: break\n                    chunks.append(block); count += len(block)\n                raw = b\'\'.join(chunks)\n                require(len(raw) == before.st_size and identity(before) == identity(os.fstat(leaf))\n                    == identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)), \'METADATA_CHANGED\')\n            finally: os.close(leaf)\n        finally: os.close(fd)\n        self.reads += 1; self.bytes += len(raw)\n        require(self.bytes <= 16777216 and (sha is None or hashlib.sha256(raw).hexdigest() == sha), \'METADATA_HASH_OR_BYTE_BOUND\')\n        return raw\n\n    def json(self, path, sha=None, maximum=8388608):\n        raw = self.raw(path, maximum, sha); value = json.loads(raw)\n        require(type(value) is dict and encoded(value) == raw, \'CANONICAL_METADATA_REQUIRED\')\n        return value\n\n\ndef inside(value):\n    require(type(value) is str and value.startswith(PARENT + \'/\') and \'..\' not in Path(value).parts\n            and str(Path(value)) == value, \'EXACT_REVIEW_BOUND_PRIVATE_PATH_REQUIRED\')\n    return Path(value)\n\n\ndef optional(reader, path, maximum=131072):\n    try: path.lstat()\n    except FileNotFoundError: return None\n    return reader.json(str(path), maximum=maximum)\n\n\ndef closed(value, allowed): return value if type(value) is str and value in allowed else \'OTHER_OR_ABSENT\'\n\n\ndef shape(value):\n    obj = type(value) is dict\n    return {\'object\': obj, \'string\': type(value) is str,\n        \'exactKeys\': obj and set(value) == {\'schema\', \'sha256\', \'entries\', \'bytes\'},\n        \'schemaMatches\': obj and value.get(\'schema\') == \'ouf.semantic-rootfs-seal.v1\',\n        \'sha256WellFormed\': obj and type(value.get(\'sha256\')) is str and re.fullmatch(\'[0-9a-f]{64}\', value[\'sha256\']) is not None,\n        \'entries\': value[\'entries\'] if obj and type(value.get(\'entries\')) is int and 0 < value[\'entries\'] <= 100000 else None,\n        \'bytes\': value[\'bytes\'] if obj and type(value.get(\'bytes\')) is int and 0 <= value[\'bytes\'] <= 8589934592 else None}\n\n\ndef inspect(reader):\n    # Parse only literal assignments; do not execute the loader or application.\n    raw = reader.raw(CAPSULE, 1048576, CAPSULE_HASH, private=False)\n    values = {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(raw).body\n        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}\n    require(set(values) == {\'CASE\', \'DELIVERY\', \'DELIVERY_HASH\', \'PACKED\', \'BOOTSTRAP\'}, \'EXACT_RETAINED_CAPSULE_FIELDS_REQUIRED\')\n    manifest = values[\'DELIVERY\'][\'nativeDeclaration\']\n    require(digest(values[\'DELIVERY\']) == values[\'DELIVERY_HASH\'] == DECLARATION_HASH and digest(manifest) == CLOSURE_HASH\n        and digest(values[\'CASE\']) == values[\'DELIVERY\'][\'caseHash\'], \'EXACT_RETAINED_CAPSULE_BINDINGS_REQUIRED\')\n    root = inside(PREPARATION_ROOT)\n    prepared = reader.json(str(root / \'prepared.json\'), PREPARATION_HASH, maximum=16777216)\n    review = reader.json(str(root / \'review.json\'), REVIEW_HASH)\n    require(review[\'currentContext\'] == prepared[\'nativeContext\'] and review[\'ownerContext\'] == prepared[\'ownerContext\']\n        and review[\'sourceClosureHash\'] == digest(prepared[\'sourceClosure\']) == CLOSURE_HASH\n        and prepared[\'sourceClosure\'] == manifest and review[\'sourceClosure\'] == manifest, \'EXACT_COMPLETED_REVIEW_INPUTS_REQUIRED\')\n    boot = Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip()\n    require(review[\'bootId\'] == boot, \'SAME_RETAINED_BOOT_REQUIRED\')\n    receipt = reader.json(str(root / \'authority/receipt.json\'), maximum=131072)\n    require(receipt.get(\'schema\') == \'ouf.semantic-registry-postboot-issued-authority.v1\'\n        and receipt.get(\'authorityHash\') == AUTHORITY_HASH and receipt.get(\'reviewHash\') == REVIEW_HASH\n        and receipt.get(\'runtimeAuthorityIssued\') is True, \'EXACT_ISSUED_AUTHORITY_RECEIPT_REQUIRED\')\n    context = prepared[\'nativeContext\']; plan = context[\'plan\']; execution = inside(context[\'executionRoot\'])\n    require(execution.name == \'semantic-registry-recovery-\' + plan[\'logicalOperationRef\'], \'EXACT_RECOVERY_OPERATION_ROOT_REQUIRED\')\n    journal = reader.json(str(execution / \'recovery.json\'), maximum=1048576)\n    require(journal[\'logicalOperationRef\'] == plan[\'logicalOperationRef\'] and journal[\'authorityHash\'] == AUTHORITY_HASH\n        and journal[\'bootId\'] == boot and type(journal[\'nextStage\']) is int and 0 <= journal[\'nextStage\'] <= 12\n        and type(journal[\'effects\']) is list and len(journal[\'effects\']) <= 12, \'EXACT_RETAINED_RECOVERY_JOURNAL_REQUIRED\')\n    require(type(journal.get(\'readAttempts\')) is int and 0 <= journal[\'readAttempts\'] <= 128\n        and type(journal.get(\'expiresUnix\')) is int and 0 < journal[\'expiresUnix\'] < 1099511627776,\n        \'BOUNDED_RETAINED_READ_AND_EXPIRY_FIELDS_REQUIRED\')\n    effects = []\n    for n, effect in enumerate(journal[\'effects\']):\n        require(effect[\'stage\'] == plan[\'stages\'][n][\'name\'], \'EXACT_ORDERED_EFFECTS_REQUIRED\')\n        effects.append({\'ordinal\': n, \'state\': closed(effect.get(\'state\'), (\'PENDING\',\'CLAIMED\',\'APPLIED\',\'UNKNOWN\',\'FAILED\')),\n            \'nativeRequestAttempted\': effect.get(\'nativeRequestAttempted\') is True,\n            \'nativeResponse204\': effect.get(\'nativeResponse204\') is True,\n            \'nativeAttestationAttempted\': effect.get(\'nativeAttestationAttempted\') is True})\n    owner_scope = review[\'scopes\'][\'semanticRegistryPostbootOwner\']; owner_root = inside(owner_scope[\'journalPath\'])\n    owner = reader.json(str(owner_root / \'recovery.json\'), maximum=65536)\n    require(owner[\'contextRef\'] == owner_scope[\'contextRef\'] and owner[\'generationRef\'] == owner_scope[\'generationRef\']\n        and type(owner[\'attempts\']) is int and 0 <= owner[\'attempts\'] <= 1\n        and owner[\'controlledPredecessorGrantAttempts\'] == 319\n        and owner[\'controlledCumulativeGrantAttempts\'] == 319 + owner[\'attempts\'], \'EXACT_RETAINED_OWNER_ACCOUNTING_REQUIRED\')\n    reads = reader.json(str(execution / \'native-reads.json\'), maximum=8192)\n    scope = review[\'scopes\'][\'semanticRegistryRecoveryReads\']; counts = reads[\'counts\']\n    require(reads[\'scopeHash\'] == digest(scope) and reads[\'authorityHash\'] == AUTHORITY_HASH\n        and set(counts) == set(scope[\'maximumRequests\']) and all(type(v) is int and 0 <= v <= scope[\'maximumRequests\'][k]\n            for k,v in counts.items()), \'EXACT_RETAINED_NATIVE_READ_COUNTERS_REQUIRED\')\n    frame = optional(reader, execution / \'node/frame-policy.json\')\n    observed = optional(reader, execution / \'node/paused-observation.json\', maximum=1048576)\n    acceptance = optional(reader, execution / \'node/paused-acceptance.json\')\n    recipe = context[\'nodeRecipe\']; expected = recipe[\'expectedRootfsSeal\']\n    observed_seal = observed.get(\'rootfsSeal\') if observed is not None else None\n    require(reader.json(str(execution / \'recovery.json\'), maximum=1048576) == journal\n        and reader.json(str(owner_root / \'recovery.json\'), maximum=65536) == owner\n        and reader.json(str(execution / \'native-reads.json\'), maximum=8192) == reads\n        and Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip() == boot, \'STOP_METADATA_CHANGED_DURING_OBSERVATION\')\n    return {\'schema\': \'ouf.semantic-registry-rootfs-stop-metadata.v1\', \'status\': \'RETAINED_ROOTFS_STOP_METADATA_OBSERVED\',\n        \'checkpoint\': journal[\'nextStage\'], \'recoveryState\': closed(journal.get(\'state\'), (\'READY\',\'IN_FLIGHT\',\'COMPLETE\',\'BLOCKED\',\'RECONCILE_REQUIRED\')),\n        \'effects\': effects, \'readAttempts\': journal.get(\'readAttempts\'), \'nativeReadCounts\': counts,\n        \'newGenerationRecorded\': type(journal.get(\'newGeneration\')) is dict,\n        \'framePolicyRetained\': frame is not None, \'pausedObservationRetained\': observed is not None,\n        \'pausedAcceptanceRetained\': acceptance is not None, \'expectedSealShape\': shape(expected),\n        \'retainedObservedSealShape\': shape(observed_seal),\n        \'retainedSealMatchesExpected\': observed_seal == expected if observed is not None else None,\n        \'ownerState\': closed(owner.get(\'state\'), (\'NEW\',\'ACTIVE\',\'BLOCKED\',\'CANCELLED\',\'PAUSED_EXHAUSTED\',\'RECONCILE_REQUIRED\',\'PUBLISHING\')),\n        \'retainedServiceGrantAttempts\': owner[\'attempts\'], \'retainedControlledGrantAttempts\': owner[\'controlledCumulativeGrantAttempts\'],\n        \'signedWindowExpiredAtObservation\': time.time() >= journal[\'expiresUnix\'],\n        \'journalObservationIsCurrentOwnerAdmission\': False, \'currentContainerStateObserved\': False,\n        \'currentRootfsRead\': False, \'rootfsMismatchCauseEstablished\': False, \'capsuleExecuted\': False,\n        \'addressesPrinted\': False, \'credentialFilesOpened\': 0, \'metadataReads\': reader.reads, \'metadataBytesRead\': reader.bytes,\n        \'engineGets\': 0, \'adminGets\': 0, \'oauthRequests\': 0, \'databaseCalls\': 0, \'runtimeEffectsDispatched\': 0,\n        \'runtimeAuthorityIssued\': False, \'readOnly\': True, \'automaticReplayAllowed\': False, \'budgetReset\': False,\n        \'serviceReadinessEstablished\': False, \'releaseAcceptance\': False}\n\n\ndef main():\n    try:\n        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site\n            and sys.dont_write_bytecode and len(sys.argv) == 1, \'ISOLATED_ROOT_METADATA_READER_REQUIRED\')\n        result = inspect(Reader())\n    except Exception as error:\n        reason = str(error)\n        if re.fullmatch(\'[A-Z][A-Z0-9_]{0,127}\', reason) is None: reason = \'ROOTFS_STOP_METADATA_UNPROVEN_PRIVATE_DETAILS_REDACTED\'\n        result = {\'schema\': \'ouf.semantic-registry-rootfs-stop-metadata.v1\', \'status\': \'STOP_RECONCILE\',\n            \'reasonCode\': reason, \'automaticReplayAllowed\': False, \'budgetReset\': False, \'runtimeEffectsDispatched\': 0}\n    print(json.dumps(result, sort_keys=True, separators=(\',\', \':\')), flush=True)\n    return 0 if result[\'status\'] == \'RETAINED_ROOTFS_STOP_METADATA_OBSERVED\' else 2\n\n\nif __name__ == \'__main__\': raise SystemExit(main())\n'

def require(ok, reason):
    if not ok:raise ValueError(reason)


def base_module():
    require(hashlib.sha256(BASE_SOURCE.encode()).hexdigest() == BASE_SHA256,'EXACT_METADATA_OBSERVER_SOURCE_REQUIRED')
    b=types.ModuleType('sealed_metadata');exec(compile(BASE_SOURCE,'<sealed-metadata>','exec'),b.__dict__);return b


def classify(root, merged, bundle, reviewed):
    require(type(root) is dict and type(root.get('path')) is str and type(merged) is str,
        'EXACT_ROOT_PATH_STRINGS_REQUIRED')
    selected=Path(root['path']);selected=selected if selected.is_absolute() else bundle/selected
    actual=root.get('readonly',False)
    return {'ociRootPathAbsolute':Path(root['path']).is_absolute(),
        'ociRootPathHasParentSegments':'..' in selected.parts,
        'rootPathLexicallyMatchesStorage':selected == Path(merged),
        'rootPathNormalizedMatchesStorage':os.path.normpath(str(selected)) == os.path.normpath(merged),
        'ociReadonlyKeyPresent':'readonly' in root,
        'ociReadonlyExplicitBoolean':type(root.get('readonly')) is bool,
        'ociReadonlyEffectiveBoolean':type(actual) is bool,
        'ociReadonlyEffectiveValue':actual if type(actual) is bool else None,
        'reviewedReadonlyValue':reviewed if type(reviewed) is bool else None,
        'ociReadonlyEffectiveMatchesReviewed':type(actual) is bool and type(reviewed) is bool and actual == reviewed,
        'oldExplicitReadonlyPredicatePasses':type(root.get('readonly')) is bool and root['readonly'] == reviewed}


def inspect():
    b=base_module()
    class Reader(b.Reader):
        def __init__(self):super().__init__();self.items={}
        def json(self,path,*args,**kwargs):
            v=super().json(path,*args,**kwargs);self.items[path]=v;return v
    r=Reader();start=b.inspect(r)
    require(start['checkpoint']==4 and start['readAttempts']==5 and start['recoveryState']=='IN_FLIGHT'
        and start['ownerState']=='CANCELLED' and start['retainedControlledGrantAttempts']==320
        and not start['pausedAcceptanceRetained'] and not start['pausedObservationRetained'],
        'EXACT_RETAINED_ROOTFS_STOP_REQUIRED')
    prep=r.items[b.PREPARATION_ROOT+'/prepared.json'];review=r.items[b.PREPARATION_ROOT+'/review.json']
    ctx=prep['nativeContext'];execution=b.inside(ctx['executionRoot']);journal=r.items[str(execution/'recovery.json')]
    cid=journal['newGeneration']['containerId']
    require(re.fullmatch('[0-9a-f]{64}',cid) is not None and cid==ctx['plan']['stages'][0]['intent']['registryId'],
        'EXACT_RETAINED_CONTAINER_REQUIRED')
    identity={'authorityHash':b.AUTHORITY_HASH,'operation':journal['logicalOperationRef'],'boot':review['bootId'],'purpose':'PAUSED_ROOTFS_DIAGNOSTIC_V1'}
    prior=Path(b.PARENT)/('semantic-registry-rootfs-diagnostic-'+b.digest(identity))
    proof=Reader();pclaim=proof.json(str(prior/'claim.json'),maximum=8192)
    pmarker=proof.json(str(prior/'engine-get-1.json'),maximum=8192)
    pstop=proof.json(str(prior/'stop.json'),maximum=8192)
    path='/v1.44/containers/'+cid+'/json'
    require(pclaim=={**identity,'maximumEngineGets':3,'maximumFullRootfsPasses':1,'maximumSeconds':180,
        'retainedControlledGrantAttempts':320,'automaticReplayAllowed':False,'budgetReset':False}
        and pmarker=={'attempt':1,'requestPathHash':b.digest(path)}
        and pstop=={'reasonCode':'EXACT_PAUSED_READONLY_IMAGE_GENERATION_REQUIRED','engineGets':1,'automaticReplayAllowed':False},
        'EXACT_FIRST_DIAGNOSTIC_STOP_REQUIRED')
    identity['purpose']='PAUSED_ROOTFS_DIAGNOSTIC_RECONCILIATION_V1'
    successor=Path(b.PARENT)/('semantic-registry-rootfs-reconciliation-'+b.digest(identity))
    claim=proof.json(str(successor/'claim.json'),maximum=8192)
    marker=proof.json(str(successor/'engine-get-1.json'),maximum=8192)
    stop=proof.json(str(successor/'stop.json'),maximum=8192)
    predicates=proof.json(str(successor/'resource-predicates.json'),maximum=8192)
    predecessor={'claimHash':b.digest(pclaim),'markerHash':b.digest(pmarker),'stopHash':b.digest(pstop),
        'priorEngineGets':1,'maximumRemainingEngineGets':2,'priorRootfsPasses':0}
    require(claim=={**identity,'predecessor':predecessor,'maximumEngineGets':2,'maximumCombinedDiagnosticEngineGets':3,
        'maximumFullRootfsPasses':1,'maximumSeconds':180,'retainedControlledGrantAttempts':320,'automaticReplayAllowed':False,'budgetReset':False}
        and marker==pmarker and stop=={'reasonCode':'SAME_HOST_IMAGE_AND_OCI_ROOT_REQUIRED','engineGets':1,'automaticReplayAllowed':False},
        'EXACT_SECOND_DIAGNOSTIC_STOP_REQUIRED')
    require(set(predicates)=={'predicates','reviewedRootfsReadOnly','currentRootfsReadOnly'}
        and set(predicates['predicates'])=={'containerIdentityMatches','imageIdentityMatches','pidMatches','running','paused','notRestarting','notDead',
            'reviewedRootfsFlagIsBoolean','currentRootfsFlagIsBoolean','rootfsFlagMatchesReviewed'}
        and all(v is True for v in predicates['predicates'].values()),'EXACT_RETAINED_GENERATION_PREDICATES_REQUIRED')
    # Refuse successor activity after this stop; listing reads no image bytes.
    require(set(os.listdir(prior))=={'claim.json','engine-get-1.json','stop.json'}
        and set(os.listdir(successor))=={'claim.json','engine-get-1.json','resource-predicates.json','stop.json'},
        'DIAGNOSTIC_ATTEMPT_SET_CHANGED')
    request=prep['registryInputs']['creationRequest'];reviewed=request['HostConfig'].get('ReadonlyRootfs')
    require(type(reviewed) is bool and predicates['reviewedRootfsReadOnly'] is reviewed
        and predicates['currentRootfsReadOnly'] is reviewed,'RETAINED_REVIEWED_ROOT_FLAG_REQUIRED')
    docker=ctx['nodeRecipe']['dockerContext'];layout=docker.get('rootfsLayout','graphdriver-merged-dir-v1')
    require(layout=='docker-containerd-overlayfs-v1','RETAINED_CONTAINERD_LAYOUT_REQUIRED_FOR_ZERO_ENGINE_READ')
    merged=docker['storageParent']+'/rootfs/overlayfs/'+cid
    bundle=Path(docker['bundleParent'])/cid
    raw=r.raw(str(bundle/'config.json'),131072);oci=json.loads(raw)
    frame=r.items[str(execution/'node/frame-policy.json')]
    require(b.digest(oci)==b.digest(frame['expectedOci']),'CURRENT_FULL_OCI_DIFFERS_FROM_RETAINED_FRAME')
    result=classify(oci['root'],merged,bundle,reviewed)
    require(r.raw(str(bundle/'config.json'),131072)==raw,'OCI_CHANGED_DURING_METADATA_READ')
    for selected,value in list(proof.items.items()):
        require(proof.json(selected,maximum=8192)==value,'DIAGNOSTIC_PROOF_CHANGED')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==review['bootId'],'BOOT_CHANGED')
    require(r.reads<=13 and r.bytes<=16777216 and proof.reads==14 and proof.bytes<=114688,'ROOT_BINDING_METADATA_BUDGET')
    return {'schema':'ouf.semantic-registry-root-binding-metadata.v1','status':'ROOT_BINDING_METADATA_CLASSIFIED',
        'complete':True,'rootBinding':result,'fullOciMatchesRetainedFrame':True,
        'retainedGenerationPredicates':predicates['predicates'],'retainedPredicatesAreCurrentRuntimeProof':False,
        'priorDiagnosticEngineGets':2,'maximumCombinedDiagnosticEngineGets':3,'engineGets':0,
        'remainingDiagnosticEngineGets':1,'currentContainerStateObserved':False,'rootfsContentsRead':False,
        'metadataReads':r.reads+proof.reads,'metadataBytesRead':r.bytes+proof.bytes,
        'retainedControlledGrantAttempts':320,'credentialFilesOpened':0,'addressesPrinted':False,
        'capsuleExecuted':False,'applicationEntryInvoked':False,'oauthRequests':0,'databaseCalls':0,'adminGets':0,
        'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,'readOnly':True,
        'automaticReplayAllowed':False,'budgetReset':False,'rootfsMismatchCauseEstablished':False,
        'serviceReadinessEstablished':False,'releaseAcceptance':False}


def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv)==1,'ISOLATED_ROOT_METADATA_READER_REQUIRED')
        v=inspect()
    except Exception as error:
        reason=str(error)
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason) is None:reason='ROOT_BINDING_METADATA_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        v={'schema':'ouf.semantic-registry-root-binding-metadata.v1','status':'STOP_RECONCILE','reasonCode':reason,
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0}
    print(json.dumps(v,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if v['status']=='ROOT_BINDING_METADATA_CLASSIFIED' else 2


if __name__=='__main__':raise SystemExit(main())
