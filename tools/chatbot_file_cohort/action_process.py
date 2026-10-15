"""A single finite systemd process for the reviewed acceptance action.

The process starts before the first token grant. SSH disconnection cannot create
a new worker invocation. Restart and boot enablement are absent; a consumed start
claim is reconciled, never repeated. Permanent service authority is not inferred.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

import iam_binding_candidate as evidence
import iam_governance_intake as governance
from iam_owner_action import publish
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def require(ok, reason):
    evidence.require(ok, reason)


def duration_microseconds(value):
    require(type(value) is str and re.fullmatch(r'\d+(?:us|ms|min|s|h)(?: \d+(?:us|ms|min|s|h))*',value),
            'FINITE_SYSTEMD_RUNTIME_DURATION_REQUIRED')
    units={'us':1,'ms':1000,'s':1000000,'min':60000000,'h':3600000000}
    return sum(int(number)*units[unit] for number,unit in re.findall(r'(\d+)(us|ms|min|s|h)',value))


def private_file(binding, maximum):
    require(type(binding) is dict and set(binding) == {'path','sha256'}
            and type(binding['path']) is str and Path(binding['path']).is_absolute()
            and re.fullmatch('[0-9a-f]{64}', str(binding['sha256'])), 'EXACT_PROCESS_ARTIFACT_BINDING_REQUIRED')
    path = Path(binding['path'])
    with protected_directory(path.parent) as directory:
        fd = os.open(path.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                    and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                    and 0 < before.st_size <= maximum, 'PRIVATE_PROCESS_ARTIFACT_CUSTODY_REQUIRED')
            raw = bytearray()
            while len(raw) <= maximum:
                part = os.read(fd, min(65536, maximum+1-len(raw)))
                if not part:
                    break
                raw.extend(part)
            require(len(raw) == before.st_size and evidence.identity(before) == evidence.identity(os.fstat(fd))
                    == evidence.identity(os.stat(path.name, dir_fd=directory, follow_symlinks=False))
                    and hashlib.sha256(raw).hexdigest() == binding['sha256'],
                    'PROCESS_ARTIFACT_CHANGED_OR_HASH_MISMATCH')
            return bytes(raw)
        finally:
            os.close(fd)


def compile_process_plan(*, logical_operation, source_closure_hash, programs,
                         bootstrap, bundle, authority_directory, directory_plan, maximum_seconds=3600):
    require(re.fullmatch('[0-9a-f]{64}', str(logical_operation))
            and re.fullmatch('[0-9a-f]{64}', str(source_closure_hash)), 'EXACT_FULL_ACTION_PROCESS_SCOPE_REQUIRED')
    require(type(programs) is dict and set(programs) == {'python', 'systemdRun', 'systemctl'}
            and all(type(v) is dict and set(v) == {'path','sha256'} for v in programs.values()),
            'QUALIFIED_NATIVE_PROCESS_COMMANDS_REQUIRED')
    for program in programs.values():
        require(governance.executable(program['path']) == program, 'PROCESS_COMMAND_BINDING_CHANGED')
    for value in (bootstrap, bundle):
        require(type(value) is dict and set(value) == {'path','sha256'}
                and Path(value['path']).is_absolute() and re.fullmatch('[0-9a-f]{64}', str(value['sha256'])),
                'QUALIFIED_PRIVATE_CHILD_SOURCE_BUNDLE_REQUIRED')
    parent = Path(authority_directory).parent
    require(parent == evidence.PARENT and re.fullmatch('chatbot-file-cohort-signed-[0-9a-f]{64}', Path(authority_directory).name),
            'FIXED_PRIVATE_AGGREGATE_AUTHORITY_DIRECTORY_REQUIRED')
    require(type(maximum_seconds) is int and 1 <= maximum_seconds <= 3600,
            'FINITE_PROCESS_DURATION_REQUIRED')
    require(type(directory_plan) is dict and 1 <= len(directory_plan) <= 24
            and all(type(name) is str and re.fullmatch('[A-Za-z][A-Za-z0-9]{0,63}', name)
                    and type(path) is str and Path(path).is_relative_to(authority_directory)
                    and Path(path) != Path(authority_directory) and '..' not in Path(path).parts
                    and str(Path(path)) == path for name,path in directory_plan.items())
            and len(set(directory_plan.values())) == len(directory_plan),
            'CLOSED_PRIVATE_ACTION_DIRECTORY_PLAN_REQUIRED')
    unit = 'ouf-file-cohort-'+logical_operation[:32]+'.service'
    argv = [programs['python']['path'], '-I', '-B', '-S', bootstrap['path'], bundle['path'], authority_directory]
    return {'profile':'ouf.chatbot-file-cohort-finite-process.v1',
        'logicalOperationHash':logical_operation, 'sourceClosureHash':source_closure_hash,
        'programs':copy.deepcopy(programs), 'bootstrap':copy.deepcopy(bootstrap), 'bundle':copy.deepcopy(bundle),
        'authorityDirectory':authority_directory, 'unit':unit, 'argv':argv,
        'directoryPlan':copy.deepcopy(directory_plan),
        'maximumElapsedSeconds':maximum_seconds, 'restart':'no', 'enableAtBoot':False,
        'standardOutput':'journal','standardError':'journal',
        'startsBeforeFirstGrant':True, 'sameInvocationWorkerHandoffRequired':True,
        'automaticReplayAllowed':False, 'permanentRuntimeAcceptance':False}


AUTHORIZATION_ONLY_PREDECESSOR_SOURCE='6959b1dbaeb30ca3a838c7d6243a55e9cfc5118a'
IMAGE_IDENTITY_PREDECESSOR_SOURCE='b64645982655f58a2907bf1425dd86fd6ab0ed9f'


def observed_private_json(path,maximum):
    """Read one sealed snapshot within the caller's explicit artifact bound.

    The IAM snapshot helper has an independent fixed512KiB protocol limit;
    a complete closed-source bundle has an explicit8MiB limit instead. Do not
    route that bundle through the smaller protocol or relax its custody rules.
    """
    require(type(maximum)is int and 0<maximum<=8388608,'BOUNDED_PREVIOUS_ACTION_RECORD_REQUIRED')
    path=Path(path)
    guard=evidence.protected_parent() if path.parent==evidence.PARENT else protected_directory(path.parent)
    with guard as directory:
        def snapshot():
            before=os.stat(path.name,dir_fd=directory,follow_symlinks=False)
            evidence.require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
                and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1,
                'PRIVATE_SNAPSHOT_CUSTODY_UNPROVEN')
            require(0<before.st_size<=maximum,'BOUNDED_PREVIOUS_ACTION_RECORD_REQUIRED')
            fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            try:
                require(evidence.identity(before)==evidence.identity(os.fstat(fd)),'PREVIOUS_ACTION_READ_DRIFT')
                value=bytearray()
                while len(value)<=maximum:
                    part=os.read(fd,min(65536,maximum+1-len(value)))
                    if not part:break
                    value.extend(part)
                require(len(value)==before.st_size and evidence.identity(before)==evidence.identity(os.fstat(fd))
                    ==evidence.identity(os.stat(path.name,dir_fd=directory,follow_symlinks=False)),
                    'PREVIOUS_ACTION_READ_DRIFT')
                return bytes(value)
            finally:os.close(fd)
        raw=snapshot()
        require(snapshot()==raw,'PREVIOUS_ACTION_READ_DRIFT')
    binding={'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}
    return evidence.decode(raw),binding


def image_predecessor_readback(review,authority_hash):
    """Read the single known completed-load/failed-config-ID-check attempt.

    Preserve all old journals. Native manifest, raw config/layer descriptors,
    current rootfs and execution fields must all match before a successor may
    recognize that image as already imported. No old authority is exercised.
    """
    from image_custody import archive,native_identity,loaded
    from image_import import Import
    from engine_creation import Engine
    from tools.chatbot_file_cohort.images import private_open,image_import_scope
    process=review['scopes']['finiteActionProcess']
    binding=process['bundle'];bundle=evidence.decode(private_file(binding,8388608))
    prepared=bundle['prepared'];plan=prepared['imagePlan']
    require(bundle['declaration']==review['sourceClosure']['declaration']
        and digest(prepared)==review['privateInputHashes']['preparedInputs']
        and image_import_scope(plan)==review['scopes']['cohortImageImport']
        and plan['cohortManifestHash']==review['privateInputHashes']['cohortManifest'],
        'EXACT_PREVIOUS_IMAGE_PLAN_REQUIRED')
    engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
    receipts=[];bindings=[binding]
    for row in plan['images']:
        module=row['module'];audit=row['audit']
        path=Path(process['directoryPlan']['image'+module.capitalize()])/'recovery.json'
        record,record_binding=observed_private_json(path,65536);bindings.append(record_binding)
        initial=Import.initial(audit,authority_hash)
        if module!='semantic':
            require(record==initial,'UNATTEMPTED_PREVIOUS_IMAGE_HISTORY_REQUIRED')
            receipts.append({'module':module,'effectAttemptCount':0,'outcome':'UNATTEMPTED'})
            continue
        require(record=={**initial,'version':1,'state':'IN_FLIGHT','effectAttemptCount':1},
                'EXACT_PREVIOUS_SEMANTIC_IMPORT_CLAIM_REQUIRED')
        with private_open(row['archivePath']) as source:
            actual=archive(source,audit['archiveSha256'],audit['imageId'],audit['sourceCommit'])
        require({k:v for k,v in actual.items() if k!='configBytes'}==audit,
                'PREVIOUS_AUTHENTICATED_ARCHIVE_DRIFT')
        actual['nativeIdentity']=native_identity(actual);identity=actual['nativeIdentity']['nativeImageId']
        code,native=engine.request('GET','/v1.44/images/'+identity+'/json')
        require(code==200,'PREVIOUS_NATIVE_MANIFEST_IMAGE_REQUIRED')
        proof=loaded(actual,native)
        require(engine.request('GET','/v1.44/images/'+identity+'/json')==(code,native),
                'PREVIOUS_IMAGE_CHANGED_DURING_RECONCILIATION')
        receipts.append({'module':module,'effectAttemptCount':1,'outcome':'APPLIED_NATIVE_MANIFEST_VERIFIED',
            'configurationImageId':audit['imageId'],'nativeImageId':identity,
            'archiveSha256':audit['archiveSha256'],'nativeCustodyHash':digest(proof)})
    return receipts,bindings


def pregrant_native_readback(review,authority_hash):
    """Prove completed five-image/APISIX effects without issuing any command."""
    from image_custody import loaded,runtime_image_id
    from image_import import Import
    from engine_creation import Engine
    from tools.chatbot_file_cohort.images import image_import_scope
    from tools.chatbot_file_cohort.gateway_runtime import runtime_scope,STEPS
    from legacy_retirement import GATEWAY_RECORD_HASH
    process=review['scopes']['finiteActionProcess'];binding=process['bundle']
    bundle=evidence.decode(private_file(binding,8388608));prepared=bundle['prepared'];plan=prepared['imagePlan']
    require(bundle['declaration']==review['sourceClosure']['declaration']
        and digest(prepared)==review['privateInputHashes']['preparedInputs']
        and image_import_scope(plan)==review['scopes']['cohortImageImport']
        and plan['cohortManifestHash']==review['privateInputHashes']['cohortManifest'],
        'EXACT_PREGRANT_PREPARED_PLAN_REQUIRED')
    engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
    receipts=[];bindings=[binding]
    require([row['module'] for row in plan['images']]==['semantic','udp','onboarding','ingestion','mcp'],
        'EXACT_PREGRANT_FIVE_IMAGES_REQUIRED')
    for row in plan['images']:
        module=row['module'];audit=row['audit']
        path=Path(process['directoryPlan']['image'+module.capitalize()])/'recovery.json'
        record,record_binding=observed_private_json(path,65536);bindings.append(record_binding)
        initial=Import.initial(audit,authority_hash)
        state=Import.validate_record(audit,record,initial['contextHash'])
        require(state==record and state['authorityHash']==authority_hash and state['state']=='VERIFIED'
            and state['effectAttemptCount']==(0 if module=='semantic' else 1),
            'COMPLETED_PREGRANT_IMAGE_HISTORY_REQUIRED')
        identity=runtime_image_id(audit);code,native=engine.request('GET','/v1.44/images/'+identity+'/json')
        require(code==200,'PREGRANT_VERIFIED_IMAGE_MISSING')
        proof=loaded(audit,native)
        require(digest(proof)==state['nativeEvidenceHash']
            and engine.request('GET','/v1.44/images/'+identity+'/json')==(code,native),
            'PREGRANT_NATIVE_IMAGE_PROOF_DRIFT')
        receipts.append({'module':module,'effectAttemptCount':state['effectAttemptCount'],
            'outcome':'VERIFIED_NATIVE_IMAGE_RETAINED','nativeImageId':identity,'nativeCustodyHash':digest(proof)})
    runtime=prepared['gatewayRuntimePlan'];scope=runtime_scope(runtime)
    path=Path(process['directoryPlan']['gatewayRuntime'])/'recovery.json'
    journal,journal_binding=observed_private_json(path,65536);bindings.append(journal_binding)
    require(journal_binding['sha256']==GATEWAY_RECORD_HASH
        and scope==review['scopes']['gatewayRuntimeInstallation']
        and journal.get('schema')==scope['profile'] and journal.get('authorityHash')==authority_hash
        and journal.get('planHash')==scope['planHash'] and journal.get('budgetReset')is False
        and journal.get('nextStep')==len(STEPS) and len(journal.get('effects',[]))==len(STEPS)
        and all(effect.get('step')==step and effect.get('state')=='APPLIED'
            and effect.get('intentHash')==digest({'planHash':scope['planHash'],'step':step})
            for effect,step in zip(journal['effects'],STEPS)),
        'COMPLETED_PREGRANT_APISIX_HISTORY_REQUIRED')
    expected=journal['effects'][-1]['evidence']['runtimeBinding'];identity=expected['containerId']
    require(re.fullmatch('[0-9a-f]{64}',identity) is not None,'EXACT_PREGRANT_APISIX_ID_REQUIRED')
    code,native=engine.request('GET','/v1.44/containers/'+identity+'/json')
    require(code==200 and Engine.runtime_binding(native)==expected
        and native['Name']=='/'+runtime['oldName'] and native['State']['Running']is True
        and native['State']['Paused']is False and native['RestartCount']==0
        and journal['effects'][3]['evidence']['containerId']==identity
        and engine.request('GET','/v1.44/containers/'+identity+'/json')==(code,native),
        'PREGRANT_APISIX_GENERATION_DRIFT')
    old_id=runtime['oldRuntimeBinding']['containerId']
    code,old=engine.request('GET','/v1.44/containers/'+old_id+'/json')
    old_host=copy.deepcopy(runtime['oldHostConfig']);old_host['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
    require(code==200 and old['Id']==old_id and old['Image']==runtime['oldRuntimeBinding']['imageId']
        and old['Name']=='/'+runtime['retiredName'] and old['State']['Running']is False
        and old['State']['Pid']==0 and old['HostConfig']==old_host
        and digest(old['Config'])==runtime['oldRuntimeBinding']['configHash']
        and digest(old['Mounts'])==runtime['oldRuntimeBinding']['mountsHash'],
        'PREGRANT_RETAINED_APISIX_DRIFT')
    return receipts,{'runtimeBinding':expected,'completedSteps':list(STEPS),
        'oldContainerRetained':True,'automaticReplayAllowed':False},bindings


def post_credential_discovery(owner):
    from tools.semantic_policy_token_owner.iam_admission import IamProfile,PinnedIamOpener,OnlineIamAdmission
    from tools.semantic_policy_token_owner.producer import CredentialFile
    value=copy.deepcopy(owner['iamProfile'])
    for key in ('required_scopes','allowed_scopes','peer_addresses'):value[key]=tuple(value[key])
    profile=IamProfile(**value);transport=PinnedIamOpener(profile)
    require(transport.trust_digest()==owner['tlsTrustSetHash'],'POST_CREDENTIAL_IAM_TRUST_DRIFT')
    credential=CredentialFile(Path(owner['binding']['output_directory']).parent/'unused-no-credential-read')
    # prepare performs only the public discovery GET; CredentialFile.read is
    # never called here. No POST, introspection or SERVICE bearer is obtained.
    admission=OnlineIamAdmission(profile,credential,transport)
    require(admission.prepare(time.monotonic()+10)is True,'POST_CREDENTIAL_PUBLIC_DISCOVERY_UNPROVEN')
    return {'discoveryIdentityVerified':True,'tlsTrustSetVerified':True,'grantRequests':0,
        'credentialFilesRead':False,'maximumSeconds':10}


def post_credential_native_readback(review,authority_hash,proof):
    import legacy_retirement as legacy
    from image_import import Import
    from image_custody import loaded,runtime_image_id
    from engine_creation import Engine
    from tools.chatbot_file_cohort.images import image_import_scope
    require(proof.get('schema')==legacy.POST_PROFILE and proof.get('predecessorReviewHash')==digest(review)
        and proof.get('predecessorAuthorityHash')==authority_hash,'EXACT_POST_CREDENTIAL_NATIVE_PROOF_REQUIRED')
    original=evidence.decode(legacy.private(evidence.PARENT/legacy.CONTEXT/'review.json',legacy.REVIEW))
    old_images,gateway,bindings=pregrant_native_readback(original,legacy.AUTHORITY)
    process=review['scopes']['finiteActionProcess'];bundle_binding=process['bundle']
    bundle=evidence.decode(private_file(bundle_binding,8388608));prepared=bundle['prepared'];plan=prepared['imagePlan']
    require(bundle['declaration']==review['sourceClosure']['declaration']
        and digest(prepared)==review['privateInputHashes']['preparedInputs']
        and image_import_scope(plan)==review['scopes']['cohortImageImport']
        and plan['cohortManifestHash']==review['privateInputHashes']['cohortManifest'],
        'EXACT_POST_CREDENTIAL_PREPARED_PLAN_REQUIRED')
    engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
    require([row['module'] for row in plan['images']]==[r['module'] for r in old_images]
        and prepared['gatewayRuntimePlan']is None
        and prepared['gatewayPlan']['transportBinding']['runtimeBinding']==gateway['runtimeBinding'],
        'POST_CREDENTIAL_RETAINED_APISIX_BINDING_DRIFT')
    scope={'profile':'ouf.chatbot-file-cohort.gateway-runtime.v1','required':False,
        'retainedTransportHash':digest(prepared['gatewayPlan']['transportBinding']),
        'proposalKeyHash':prepared['gatewayPlan']['proposalKeyBinding']['sha256'],
        'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False}
    require(review['scopes']['gatewayRuntimeInstallation']==scope,'POST_CREDENTIAL_GATEWAY_SCOPE_DRIFT')
    receipts=[];bindings.append(bundle_binding)
    for row,previous in zip(plan['images'],old_images):
        module=row['module'];audit=row['audit'];identity=runtime_image_id(audit)
        require(identity==previous['nativeImageId'],'POST_CREDENTIAL_IMAGE_NATIVE_ID_DRIFT')
        path=Path(process['directoryPlan']['image'+module.capitalize()])/'recovery.json'
        state,bound=observed_private_json(path,65536);bindings.append(bound)
        initial=Import.initial(audit,authority_hash)
        require(Import.validate_record(audit,state,initial['contextHash'])==state
            and state['state']=='VERIFIED' and state['effectAttemptCount']==0
            and state['authorityHash']==authority_hash,'POST_CREDENTIAL_IMAGE_MUST_BE_VERIFIED_WITHOUT_RELOAD')
        code,native=engine.request('GET','/v1.44/images/'+identity+'/json')
        require(code==200,'POST_CREDENTIAL_VERIFIED_IMAGE_MISSING');native_proof=loaded(audit,native)
        require(digest(native_proof)==state['nativeEvidenceHash']==previous['nativeCustodyHash']
            and engine.request('GET','/v1.44/images/'+identity+'/json')==(code,native),
            'POST_CREDENTIAL_NATIVE_IMAGE_DRIFT')
        receipts.append({'module':module,'effectAttemptCount':0,'outcome':'VERIFIED_NATIVE_IMAGE_RETAINED',
            'nativeImageId':identity,'nativeCustodyHash':digest(native_proof)})
    discovery=post_credential_discovery(prepared['owner'])
    return receipts,gateway,bindings,discovery


def previous_authorization_actions(manifest_hash,systemctl,exclude_context=None):
    """Reconcile only the known auth-only predecessor; never resume a start claim.

    An expired, stopped window plus empty unapplied stage journals proves that
    no first grant or application attempt is being reset. Any later-stage or
    ambiguous history requires a separate owner reconciliation path.
    """
    require(re.fullmatch('[0-9a-f]{64}',str(manifest_hash)),'EXACT_RECOVERY_COHORT_REQUIRED')
    require(governance.executable(systemctl['path'])==systemctl,'RECOVERY_SYSTEMCTL_BINDING_CHANGED')
    with evidence.protected_parent():
        contexts=sorted(evidence.PARENT.glob('chatbot-file-cohort-signed-*'))
    require(len(contexts)<=16,'BOUNDED_PREVIOUS_COHORT_CONTEXTS_REQUIRED')
    from legacy_retirement import POST_SOURCE,POST_CONTEXT,POST_AUTHORITY,observe_post_credential
    post_proof=None
    post_path=evidence.PARENT/POST_CONTEXT/'review.json'
    if os.path.lexists(post_path):
        post_review,_=observed_private_json(post_path,262144)
        if post_review.get('privateInputHashes',{}).get('cohortManifest')==manifest_hash:
            post_proof=observe_post_credential(post_review,POST_AUTHORITY)
    result=[]
    for context in contexts:
        if str(context)==exclude_context:continue
        require(re.fullmatch('chatbot-file-cohort-signed-[0-9a-f]{64}',context.name),
                'EXACT_PREVIOUS_ACTION_CONTEXT_REQUIRED')
        review,review_binding=observed_private_json(context/'review.json',262144)
        if review.get('privateInputHashes',{}).get('cohortManifest')!=manifest_hash:continue
        source=review['sourceClosure']['declaration']['sourceCommit']
        image_recovery=source==IMAGE_IDENTITY_PREDECESSOR_SOURCE
        from legacy_retirement import SOURCE as PREGRANT_SOURCE,observe as observe_pregrant
        pregrant_recovery=source==PREGRANT_SOURCE
        post_credential=source==POST_SOURCE
        require(review.get('schema')=='ouf.chatbot-file-cohort-full-action-review.v1'
            and source in (AUTHORIZATION_ONLY_PREDECESSOR_SOURCE,IMAGE_IDENTITY_PREDECESSOR_SOURCE,PREGRANT_SOURCE,POST_SOURCE),
            'PREVIOUS_ACTION_SOURCE_REQUIRES_OWNER_RECONCILIATION')
        process=review['scopes']['finiteActionProcess'];operation=process['logicalOperationHash']
        require(context.name=='chatbot-file-cohort-signed-'+operation
            and process['authorityDirectory']==str(context)
            and process['unit']=='ouf-file-cohort-'+operation[:32]+'.service',
            'PREVIOUS_ACTION_PROCESS_IDENTITY_DRIFT')
        decision,decision_binding=observed_private_json(context/'decision.json',8192)
        require(decision.get('approvedReviewHash')==digest(review)
            and decision.get('approvedSourceClosureHash')==review['sourceClosureHash']
            and type(decision.get('approvedAt'))is int
            and decision.get('decision')=='APPROVE_ONE_FINITE_CHATBOT_FILE_COHORT_ACTION'
            and decision.get('state')=='ACTIVE'
            and type(decision.get('expiresAt'))is int and 0<decision['expiresAt']-decision['approvedAt']<=3600
            and type(decision.get('expiresAt'))is int and decision['expiresAt']<=time.time(),
            'PREVIOUS_FINITE_WINDOW_MUST_BE_EXPIRED')
        authority,authority_binding=observed_private_json(context/'authority.json',131072)
        require(authority.get('expiresAt')==decision['expiresAt']
            and authority.get('finiteActionProcess')==process
            and authority.get('sourceClosureHash')==review['sourceClosureHash']
            and authority.get('chatbotFileAuthorization')==review['scopes']['chatbotFileAuthorization'],
            'PREVIOUS_AUTHORITY_SCOPE_DRIFT')
        if image_recovery or pregrant_recovery or post_credential:
            require(authority.get('cohortImageImport')==review['scopes']['cohortImageImport'],
                    'PREVIOUS_IMAGE_AUTHORITY_SCOPE_DRIFT')
        status,status_binding=observed_private_json(context/'delivery-status.json',8192)
        require(status.get('schema')=='ouf.chatbot-file-cohort-delivery-status.v1'
            and status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION'
            and status.get('authorityHash')==authority_binding['sha256']
            and status.get('budgetReset') is False,'PREVIOUS_ACTION_OUTCOME_REQUIRES_RECONCILIATION')
        output=subprocess.run([systemctl['path'],'show',process['unit'],
            '--property=ActiveState,MainPID'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,timeout=10,check=False)
        require(output.returncode==0 and len(output.stdout)<=8192,'PREVIOUS_PROCESS_STATE_UNAVAILABLE')
        rows=dict(line.split('=',1) for line in output.stdout.decode().splitlines() if '=' in line)
        require(rows.get('ActiveState') in ('inactive','failed') and rows.get('MainPID')=='0',
                'PREVIOUS_FINITE_PROCESS_MUST_BE_STOPPED')
        claim,claim_binding=observed_private_json(evidence.PARENT/('chatbot-file-cohort-process-'+operation+'.claim.json'),8192)
        require(claim.get('authorityHash')==authority_binding['sha256'] and claim.get('planHash')==digest(process)
            and claim.get('state')=='START_CONSUMED_OUTCOME_UNPROVEN'
            and claim.get('automaticReplayAllowed') is False
            and type(claim.get('runtimeMaxSeconds'))is int and 0<claim['runtimeMaxSeconds']<=3600,
            'PREVIOUS_START_CLAIM_MUST_BE_RETAINED')
        completed,completed_binding=observed_private_json(context/'directories.completed.json',32768)
        wanted=process['directoryPlan']
        require({'authorization','containers','databases','gateway','gatewayRuntime','backups','dockerCli',
            'imageSemantic','imageUdp','imageOnboarding','imageIngestion','imageMcp'}<=set(wanted)
            and len(wanted)<=24,'COMPLETE_PREVIOUS_APPLICATION_DIRECTORY_PLAN_REQUIRED')
        require(completed.get('authorityHash')==authority_binding['sha256']
            and completed.get('planHash')==digest(wanted),'PREVIOUS_DIRECTORY_PLAN_DRIFT')
        for name,path in wanted.items():
            require(Path(path).is_relative_to(context) and Path(path)!=context,'PREVIOUS_STAGE_PATH_DRIFT')
            with protected_directory(path) as directory:
                info=os.fstat(directory)
                require(completed['identities'].get(path)=={'device':info.st_dev,'inode':info.st_ino},
                        'PREVIOUS_STAGE_DIRECTORY_IDENTITY_DRIFT')
                allowed=({'recovery.json','recovery.lock','invocation.lock'} if name=='authorization' or
                    (image_recovery or pregrant_recovery or post_credential) and name in {'imageSemantic','imageUdp','imageOnboarding','imageIngestion','imageMcp'}
                    or pregrant_recovery and name=='gatewayRuntime' else
                    {Path(p).name for p in wanted.values() if Path(p).parent==Path(path)})
                require(set(os.listdir(directory))<=allowed,
                        'PREVIOUS_APPLICATION_OR_TOKEN_STAGE_HISTORY_REQUIRES_OWNER_RECONCILIATION')
        auth_path=Path(wanted['authorization'])/'recovery.json'
        journal,journal_binding=observed_private_json(auth_path,65536)
        require(journal.get('schema')=='ouf.chatbot-file-authorization-journal.v1'
            and journal.get('authorityHash')==authority_binding['sha256']
            and journal.get('planHash')==review['scopes']['chatbotFileAuthorization']['planHash']
            and journal.get('budgetReset') is False,'PREVIOUS_AUTHORIZATION_HISTORY_DRIFT')
        effects=journal.get('effects',{})
        require((effects or image_recovery or pregrant_recovery or post_credential) and all(e.get('state')=='APPLIED' and type(e.get('attempts'))is int
            and 1<=e['attempts']<=128 for e in effects.values()),
            'AMBIGUOUS_PREVIOUS_AUTHORIZATION_EFFECT_REQUIRES_OWNER_RECONCILIATION')
        image_receipts,image_bindings=([],[])
        if image_recovery:
            require(status.get('reason')=='ValueError','EXACT_PREVIOUS_IMAGE_IDENTITY_FAILURE_REQUIRED')
            image_receipts,image_bindings=image_predecessor_readback(review,authority_binding['sha256'])
        recovery_proof=None;gateway_receipt=None;discovery=None
        if pregrant_recovery:
            require(status.get('reason')=='RETIREMENT_QUIESCENCE_UNPROVEN','EXACT_PREGRANT_FAILURE_REQUIRED')
            if post_proof is None:
                recovery_proof=observe_pregrant(review,authority_binding['sha256'])
            else:
                from legacy_retirement import retained_pregrant
                require(digest(retained_pregrant(review,authority_binding['sha256']))==post_proof['originalPregrantProofHash'],
                    'POST_CREDENTIAL_ORIGINAL_PREGRANT_HISTORY_DRIFT')
            image_receipts,gateway_receipt,image_bindings=pregrant_native_readback(review,authority_binding['sha256'])
        if post_credential:
            require(post_proof is not None and status.get('reason')=='OSError',
                'EXACT_POST_CREDENTIAL_IO_FAILURE_REQUIRED')
            recovery_proof=post_proof
            image_receipts,gateway_receipt,image_bindings,discovery=post_credential_native_readback(
                review,authority_binding['sha256'],post_proof)
        result.append({'schema':'ouf.chatbot-post-credential-predecessor-readback.v1' if post_credential else
                'ouf.chatbot-pregrant-predecessor-readback.v1' if pregrant_recovery else
                'ouf.chatbot-image-identity-predecessor-readback.v1' if image_recovery else
                'ouf.chatbot-auth-only-predecessor-readback.v1',
            'context':str(context),'unit':process['unit'],'authorityHash':authority_binding['sha256'],
            'sourceCommit':source,'expiredAt':decision['expiresAt'],
            'processStopped':True,'startClaimRetained':True,'budgetReset':False,
            'applicationStageClaimsPresent':False,'firstGrantStageClaimsPresent':False,
            'priorAuthorizationEffectAttempts':{n:e['attempts'] for n,e in sorted(effects.items())},
            **({'imageImportReadback':image_receipts} if image_recovery or pregrant_recovery or post_credential else {}),
            **({'ownerPregrantRecovery':recovery_proof,'gatewayRuntimeReadback':gateway_receipt} if pregrant_recovery or post_credential else {}),
            **({'postCredentialPublicDiscovery':discovery} if post_credential else {}),
            **({'historicalOwnerSupersededBy':{'authorityHash':POST_AUTHORITY,'proofHash':digest(post_proof)}}
                if pregrant_recovery and post_proof is not None else {}),
            'recordBindings':[review_binding,decision_binding,authority_binding,status_binding,
                claim_binding,completed_binding,journal_binding,*image_bindings]})
    return result


def verify_previous_authorization_actions(expected,manifest_hash,systemctl,context):
    require(previous_authorization_actions(manifest_hash,systemctl,str(context))==expected,
            'PREVIOUS_ACTION_HISTORY_CHANGED_BEFORE_NEW_EXECUTION')


class FiniteActionProcess:
    def __init__(self, action, plan):
        require(type(action) is AggregateAction, 'REAL_AGGREGATE_PROCESS_AUTHORITY_REQUIRED')
        expected = compile_process_plan(logical_operation=plan['logicalOperationHash'],
            source_closure_hash=plan['sourceClosureHash'], programs=plan['programs'],
            bootstrap=plan['bootstrap'], bundle=plan['bundle'], authority_directory=plan['authorityDirectory'],
            directory_plan=plan['directoryPlan'],
            maximum_seconds=plan['maximumElapsedSeconds'])
        require(plan == expected and plan['sourceClosureHash'] == action.closure,
                'EXACT_FULL_ACTION_PROCESS_PLAN_REQUIRED')
        self.action, self.plan, self.plan_hash = action, copy.deepcopy(plan), digest(plan)
        self.claim = 'chatbot-file-cohort-process-'+plan['logicalOperationHash']+'.claim.json'

    def guard(self):
        require(digest(self.plan) == self.plan_hash, 'PROCESS_PLAN_CHANGED')
        self.action.guard('finiteActionProcess', self.plan)
        for program in self.plan['programs'].values():
            require(governance.executable(program['path']) == program, 'PROCESS_COMMAND_CHANGED')
        private_file(self.plan['bootstrap'], 131072)
        private_file(self.plan['bundle'], 8388608)
        directory = Path(self.plan['authorityDirectory'])
        require(private_file({'path':str(directory/'authority.json'), 'sha256':self.action.authority_hash}, 131072)
                == self.action.raw, 'EXACT_CHILD_AUTHORITY_CONTEXT_REQUIRED')

    def properties(self):
        self.guard()
        result = subprocess.run([self.plan['programs']['systemctl']['path'], 'show', self.plan['unit'],
            '--property=Id,LoadState,ActiveState,SubState,MainPID,Transient,Restart,RuntimeMaxUSec,DropInPaths,EnvironmentFiles,StandardOutput,StandardError'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LANG':'C', 'LC_ALL':'C'})
        require(result.returncode == 0 and len(result.stdout) <= 8192, 'FINITE_PROCESS_STATE_UNAVAILABLE')
        rows = {}
        for line in result.stdout.decode('utf-8').splitlines():
            key, separator, value = line.partition('=')
            require(separator and key not in rows, 'FINITE_PROCESS_STATE_SHAPE_INVALID')
            rows[key] = value
        require(rows.get('Id') == self.plan['unit'], 'EXACT_FINITE_PROCESS_UNIT_REQUIRED')
        return rows

    def verify(self):
        rows = self.properties()
        with evidence.protected_parent() as directory:
            claim = evidence.decode(evidence.read_member(directory,self.claim))
        require(type(claim.get('runtimeMaxSeconds')) is int
                and 1 <= claim['runtimeMaxSeconds'] <= self.plan['maximumElapsedSeconds']
                and claim == {'schema':'ouf.chatbot-file-cohort-process-claim.v1',
                    'planHash':self.plan_hash, 'authorityHash':self.action.authority_hash,
                    'state':'START_CONSUMED_OUTCOME_UNPROVEN', 'automaticReplayAllowed':False,
                    'runtimeMaxSeconds':claim['runtimeMaxSeconds']}
                and duration_microseconds(rows.get('RuntimeMaxUSec')) == claim['runtimeMaxSeconds']*1000000,
                'ACTUAL_FINITE_PROCESS_RUNTIME_LIMIT_CHANGED')
        require(rows.get('LoadState') == 'loaded' and rows.get('ActiveState') == 'active'
                and rows.get('SubState') == 'running' and rows.get('Transient') == 'yes'
                and rows.get('Restart') == 'no' and not rows.get('DropInPaths')
                and rows.get('StandardOutput')=='journal' and rows.get('StandardError')=='journal'
                and not rows.get('EnvironmentFiles') and rows.get('MainPID', '').isdigit()
                and int(rows['MainPID']) > 1, 'EXACT_ACTIVE_FINITE_PROCESS_REQUIRED')
        pid = int(rows['MainPID'])
        # Actual process arguments, not only the service manager's declared row.
        raw = Path('/proc/'+str(pid)+'/cmdline').read_bytes()
        require(len(raw) <= 32768 and raw.endswith(b'\0')
                and raw[:-1].split(b'\0') == [v.encode() for v in self.plan['argv']],
                'ACTUAL_FINITE_PROCESS_ARGUMENTS_CHANGED')
        status = Path('/proc/'+str(pid)+'/status').read_text()
        require(re.search(r'^Uid:\s+0\s+0\s+0\s+0$', status, re.MULTILINE)
                and re.search(r'^Gid:\s+0\s+0\s+0\s+0$', status, re.MULTILINE),
                'ACTUAL_FINITE_PROCESS_ROOT_CUSTODY_REQUIRED')
        require(self.properties() == rows, 'FINITE_PROCESS_CHANGED_DURING_OBSERVATION')
        return {'schema':'ouf.chatbot-file-cohort-finite-process-observation.v1',
            'unit':self.plan['unit'], 'mainPid':pid, 'planHash':self.plan_hash,
            'authorityHash':self.action.authority_hash, 'sameInvocationWorkerRequired':True,
            'restart':'no', 'permanentRuntimeAcceptance':False, 'notReleaseAcceptance':True}

    def start(self):
        self.guard()
        with evidence.protected_parent() as directory:
            try:
                previous = evidence.decode(evidence.read_member(directory, self.claim))
            except FileNotFoundError:
                previous = None
            if previous is not None:
                require(previous == {'schema':'ouf.chatbot-file-cohort-process-claim.v1',
                    'planHash':self.plan_hash, 'authorityHash':self.action.authority_hash,
                    'state':'START_CONSUMED_OUTCOME_UNPROVEN', 'automaticReplayAllowed':False,
                    'runtimeMaxSeconds':previous.get('runtimeMaxSeconds')},
                    'FINITE_PROCESS_RETAINED_START_CLAIM_CHANGED')
                return self.verify()
            rows = self.properties()
            require(rows.get('LoadState') == 'not-found' and rows.get('ActiveState') == 'inactive'
                    and rows.get('MainPID') == '0', 'FINITE_ACTION_UNIT_ALREADY_EXISTS')
            remaining = int(evidence.decode(self.action.raw)['expiresAt']-time.time())
            require(0 < remaining <= self.plan['maximumElapsedSeconds'], 'FINITE_PROCESS_AUTHORITY_EXPIRED')
            claim = {'schema':'ouf.chatbot-file-cohort-process-claim.v1', 'planHash':self.plan_hash,
                'authorityHash':self.action.authority_hash, 'state':'START_CONSUMED_OUTCOME_UNPROVEN',
                'automaticReplayAllowed':False, 'runtimeMaxSeconds':remaining}
            require(publish(directory, self.claim, encoded(claim)), 'FINITE_PROCESS_START_ALREADY_CONSUMED')
        self.guard()
        argv = [self.plan['programs']['systemdRun']['path'], '--quiet', '--collect',
            '--description=OUF finite reviewed CSV chatbot action',
            '--unit='+self.plan['unit'], '--property=Type=exec', '--property=Restart=no',
            '--property=StandardOutput=journal', '--property=StandardError=journal',
            '--property=RuntimeMaxSec='+str(remaining), '--property=KillMode=control-group',
            '--property=TimeoutStopSec=30', '--property=UMask=0077', '--property=WorkingDirectory=/',
            '--', *self.plan['argv']]
        # A timeout/ambiguous result never submits systemd-run twice.
        try:
            subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=30, check=False,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LANG':'C', 'LC_ALL':'C'})
        except subprocess.TimeoutExpired:
            pass
        return self.verify()
