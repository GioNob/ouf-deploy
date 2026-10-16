"""Fixed unsigned paused-attestation reprocessing; no old authority or replay.

Six applied effects and the failed seventh intent are retained. A NEW signed
HUMAN scope may seed a distinct active journal for changed attestation inputs.
This module never signs, grants, creates/unpauses a container or reopens a DB.
"""
import copy,hashlib,json,os,re,stat,time
from pathlib import Path
from types import SimpleNamespace
import iam_binding_candidate as evidence
from tools.chatbot_file_cohort.plan import digest,encoded,require,sha
from tools.chatbot_file_cohort.action_process import observed_private_json,private_file
from tools.chatbot_file_cohort import postgrant_recovery as original
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal
from engine_creation import Engine
from file_only_profile import PHASES,FileOnlyProfile
from native_evidence_store import NativeEvidenceStore
from transition_journal import Transition

PROFILE='ouf.chatbot-paused-unsigned-attestation-reprocessing.v1'
SOURCE='0525c4186a5613000905ba4dfae6766827ad9f06'
AUTHORITY='fa7bdc08f0c0ea048b064774648176cf54ce51279118ce1df0ff296fc8616d3b'
REVIEW='892cc1048a526d0e4705a58ce91a9b5a3f6712796d64fb98b619d8ad397bfc8f'
CONTEXT='chatbot-file-cohort-signed-6876e1b33e42a03b673d68f2acbb1f80dcf0cbb9bc50d8f945099f8535d86ad3'
TRANSITION_HASH='af9c88a9ca302cc69ec11b2a85035510eb03d7282d7409b46be88aa720ecbb8f'
WORKER_HASH='779053bf26eee3faff47217295fd325cf71bffa131c0ed66de0af414079bbc55'
SESSION_HASH='17a6c711beae9887d446d521bd765d2fab3cafc3eee6e4ccd4c62c523b8b2785'
ADMISSION_HASH='14d0c98eabf416c044b68cf6fde4d8068c900fc03f3ca3bc11980aea1fede9e6'
CLAIM='chatbot-file-cohort-paused-attestation-'+AUTHORITY+'.claim.json'
MOUNT_TARGETS=['/run/secrets/semantic-read-owner.key','/run/ouf/proposal.key','/run/ouf-semantic-db','/run/ouf-semantic-auth']
ORIGINAL_SEAL={'schema':'ouf.semantic-rootfs-seal.v1','entries':9301,'bytes':1719645735,'sha256':'510f56436da3e36b700b244e5e2476db9d4984216866e412b0484f951bfdb8a2'}
ROOTFS_SEAL={'schema':'ouf.semantic-rootfs-seal.v1','entries':9302,'bytes':1719645735,'sha256':'a73d7520737345d67030baaa2405478b3784fc84060f6ec6ccc6109f98ac2f11'}
IMAGE_CONFIG='29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489'
CI_WITNESS={'sourceCommit':'a535e987b52f66d75b805541d89012b883a8864b','runId':38784418792,
    'artifactId':11997695755,'artifactSha256':'04c83865f23deb1d0e6c20cc752e07240dc791a360c3d726c77359a930cffb9d',
    'entriesSha256':'988dffb5f8e7426f3de0211db987edbf6de6dbebb11883133b11f5d734cfb3ff',
    'moduleSource':'eccef11a97367f20e278db40b9ed6f45dd980c37','imageConfigurationHash':IMAGE_CONFIG,
    'mountTargets':MOUNT_TARGETS,'rootfsSeal':ROOTFS_SEAL,'javaStarted':False,'runtimeAcceptance':False}

def validate_boundary(row,intents):
    require(row.get('schema')=='ouf.semantic-cutover-journal.v2'and row.get('version')==13
        and row.get('state')=='IN_FLIGHT'and row.get('nextPhase')==6 and len(row.get('effects',[]))==7
        and row.get('transitionAuthorityEvidenceHash')==original.AUTHORITY
        and row.get('databaseMayHaveChanged')is False and row.get('applicationWritesMayHaveOccurred')is True
        and row.get('automaticReplayAllowed')is False and row.get('preMigrationRestoreAllowed')is False,
        'EXACT_SIX_APPLIED_UNSIGNED_ATTESTATION_BOUNDARY_REQUIRED')
    for i,effect in enumerate(row['effects']):
        require(effect.get('phase')==PHASES[i]and effect.get('intentHash')==digest(intents[PHASES[i]])
            and effect.get('authorityEvidenceHash')==(original.AUTHORITY if i<5 else AUTHORITY)
            and effect.get('state')==('APPLIED'if i<6 else'IN_FLIGHT')
            and (i==6 or sha(effect.get('nativeEvidenceHash'))),'PAUSED_APPLIED_PREFIX_OR_FAILED_INTENT_DRIFT')
    return copy.deepcopy(row)

def validate_worker(first,worker,admission,session):
    require(digest(first)==original.FIRST_HASH and worker.get('state')=='CANCELLED'
        and worker.get('attempts')==1 and worker.get('publicationCount')==1
        and worker.get('controlledPredecessorGrantAttempts')==1 and worker.get('controlledCumulativeGrantAttempts')==2
        and worker.get('firstGrantReceiptHash')==digest(first)and worker.get('workerSessionHash')==digest(session)
        and admission.get('state')=='BLOCKED'and admission.get('version')==3
        and session.get('predecessorGrantAttempts')==1
        and session.get('predecessorFirstGrantOperation')==first['operation']
        and session.get('predecessorFirstGrantScopeHash')==first['scopeHash'],
        'PAUSED_CANCELLED_PUBLISHED_WORKER_CUMULATIVE_TWO_REQUIRED')
    return {'controlledCumulativeGrantAttempts':2,'cancelledWorkerHash':digest(worker),'workerSessionHash':digest(session)}

def unsigned_node(predecessor):
    paths=predecessor['prepared']['registry']['directoryPlan'];node=Path(paths['node'])
    with protected_directory(node)as directory:
        require(set(os.listdir(directory))=={'frame-policy.json'},'FAILED_NODE_MUST_REMAIN_UNSIGNED_NO_ISSUANCE_CLAIM')
    require(not os.path.lexists(Path(paths['evidence'])/'ATTEST_NEW_OCI_PEER.json'),
        'PREVIOUS_ATTESTATION_EFFECT_OR_ACCEPTANCE_PRESENT')

def read_predecessor():
    base=original.read_predecessor();root=evidence.PARENT/CONTEXT;bindings=copy.deepcopy(base['recordBindings'])
    def read(path,expected=None,maximum=262144):
        value,binding=observed_private_json(path,maximum)
        require(expected is None or binding['sha256']==expected,'PAUSED_PINNED_RECORD_DRIFT')
        bindings.append(binding);return value
    review=read(root/'review.json',REVIEW);authority=read(root/'authority.json',AUTHORITY,131072)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and all(authority.get(k)==v for k,v in review['scopes'].items()),'EXACT_FAILED_PAUSED_SIGNED_SCOPE_REQUIRED')
    decision=read(root/'decision.json');require(decision.get('approvedReviewHash')==REVIEW
        and decision.get('approvedSourceClosureHash')==review['sourceClosureHash']
        and decision.get('decision')=='APPROVE_ONE_FINITE_CHATBOT_FILE_COHORT_ACTION'
        and decision.get('state')=='ACTIVE'and decision.get('expiresAt')==authority['expiresAt']<=time.time(),
        'PAUSED_PREVIOUS_FINITE_WINDOW_MUST_BE_EXPIRED')
    process=review['scopes']['finiteActionProcess'];require(process['authorityDirectory']==str(root),'EXACT_PAUSED_CONTEXT_REQUIRED')
    original.stopped_process(process,review['sourceClosure']['executables']['systemctl'])
    status=read(root/'delivery-status.json');require(status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION'
        and status.get('reason')=='ValueError'and status.get('authorityHash')==AUTHORITY,'EXACT_PAUSED_FAILURE_REQUIRED')
    claim=read(evidence.PARENT/original.CLAIM)
    require(claim.get('authorityHash')==AUTHORITY and claim.get('state')=='CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY',
        'PREVIOUS_GLOBAL_CONTINUATION_CLAIM_MUST_REMAIN_RESERVED')
    b=process['bundle'];bundle=read(b['path'],b['sha256'],8388608);prepared=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']and digest(prepared)==review['privateInputHashes']['preparedInputs'],
        'PAUSED_ORIGINAL_PRIVATE_BUNDLE_DRIFT')
    paths=prepared['registry']['directoryPlan'];row=read(Path(paths['transition'])/'recovery.json',TRANSITION_HASH)
    validate_boundary(row,prepared['registry']['intents'])
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    worker=read(owner/'recovery.json',WORKER_HASH);session=read(owner/'owner-session.json',SESSION_HASH)
    admission=read(owner/'owner-admission.json',ADMISSION_HASH)
    require(read(owner/'owner-first-grant.json',original.FIRST_HASH)==base['firstGrant'],'PAUSED_FIRST_GRANT_MUST_REMAIN_ORIGINAL')
    validate_worker(base['firstGrant'],worker,admission,session)
    require(worker['bootId']==base['firstGrant']['bootId'],'PAUSED_KERNEL_BOOT_DRIFT')
    require(prepared['postGrantRecovery']['profile']==original.PROFILE
        and prepared['postGrantRecovery']['predecessorAuthorityHash']==original.AUTHORITY,
        'PAUSED_ORIGINAL_RECOVERY_LINEAGE_REQUIRED')
    # Every completed payload is copied exactly; no lifecycle acknowledgement
    # can be inferred from container name or a freshly assembled receipt.
    payloads=copy.deepcopy(base['payloads']);payloads['evidence']={}
    for effect in row['effects'][:6]:
        phase=effect['phase'];value=read(Path(paths['evidence'])/(phase+'.json'))
        require(digest(value)==effect['nativeEvidenceHash'],'PAUSED_COMPLETED_NATIVE_PAYLOAD_DRIFT')
        payloads['evidence'][phase]=value
    policy=read(Path(paths['node'])/'frame-policy.json',maximum=131072)
    result={**base,'recoveryProfile':PROFILE,'rootPredecessor':base,'review':review,'prepared':prepared,
        'authority':authority,'transition':row,'bundle':bundle,'worker':worker,'session':session,'admission':admission,
        'payloads':payloads,'recordBindings':bindings,'failedPolicy':policy}
    unsigned_node(result)
    for label in ('authorization','containers','databases','gateway'):
        value=read(Path(process['directoryPlan'][label])/'recovery.json')
        require(not value.get('effects')and not value.get('backups')and not value.get('nextStep',0),
            'PAUSED_LATER_APPLICATION_EFFECT_REQUIRES_DIFFERENT_RECOVERY')
    return result

def proposed_recipe(registry,*,retained_mount=False):
    from compile_file_only_frame_policy import recompile_bridge_proposal
    request=registry['creationRequest'];recipe=copy.deepcopy(registry['nodeRecipe'])
    targets=[]
    for row in request['HostConfig'].get('Binds',[]):
        parts=row.split(':');require(len(parts)==3 and parts[2]=='ro','EXACT_PAUSED_READONLY_BIND_PROFILE_REQUIRED');targets.append(parts[1])
    require(targets==MOUNT_TARGETS and not request['HostConfig'].get('Mounts')
        and not request['HostConfig'].get('Tmpfs')and not request['HostConfig'].get('VolumesFrom')
        and registry['imageAudit']['configSha256']==IMAGE_CONFIG
        and registry['imageAudit']['sourceCommit']==CI_WITNESS['moduleSource']
        and recipe['imageConfigurationHash']==IMAGE_CONFIG and recipe['expectedRootfsSeal']==(ROOTFS_SEAL if retained_mount else ORIGINAL_SEAL),
        'EXACT_INDEPENDENT_RETAINED_MOUNT_CI_IMAGE_PROFILE_REQUIRED')
    recipe['template'],recipe['launch']=recompile_bridge_proposal(recipe['template'],recipe['launch'],request)
    recipe['expectedRootfsSeal']=copy.deepcopy(ROOTFS_SEAL)
    return recipe

def current_paused_native(previous,engine,native,*,running=False):
    """All static native mismatches fail BEFORE IAM/HUMAN interactive steps."""
    from gated_process_observation import GatedProcessObservation
    from file_only_node_owner import ObservationBudget
    from tools.semantic_provider_node_observation import rootfs_seal,NodeObservation
    from tools.semantic_provider_deployment_authentication import attributes,ancestors,decode
    from compile_file_only_frame_policy import compile_policy,private_bridge_namespace_name
    from tools.chatbot_file_cohort.backup_recovery import PROFILE as BACKUP_PROFILE
    require(not running or previous.get('recoveryProfile') in (BACKUP_PROFILE,'ouf.chatbot-created-mcp-migration-continuation.v1'),'EXACT_RUNNING_BACKUP_RECOVERY_REQUIRED')
    registry=previous['prepared']['registry'];request=registry['creationRequest'];recipe=proposed_recipe(registry,retained_mount=running or previous.get('recoveryProfile')in('ouf.chatbot-paused-unsigned-attestation-reprocessing.v2','ouf.chatbot-signed-paused-admission-reprocessing.v1'))
    stage=previous['payloads']['evidence']['STAGE_PAUSED_REPLACEMENT']
    require(native['Id']==original.CREATED_ID and native['RestartCount']==0
        and native['State']['Status']==('running' if running else 'paused') and native['State']['Paused'] is (not running) and native['State']['Running']is True
        and Engine.runtime_binding(native)==Engine.runtime_binding(stage),'EXACT_RETAINED_PAUSED_STAGE_GENERATION_REQUIRED')
    process=GatedProcessObservation(request);before=process.observe(native['State']['Pid'])
    require(before['processKind']==('APPLICATION_RUNNING' if running else 'GATE_WAITING'),'EXACT_RETAINED_PROCESS_KIND_REQUIRED')
    if running:
        release=previous['payloads']['evidence']['START_REPLACEMENT']
        require(before['generation']==release['generation'] and Engine.runtime_binding(native)==release['runtimeBinding'],
            'SAME_PREVIOUSLY_RELEASED_APPLICATION_GENERATION_REQUIRED')
    budget=ObservationBudget(180);config=recipe['observationConfiguration'];runner=NodeObservation(config,budget)
    state=decode(runner.run(config['runtimeBinding'],['--root',recipe['runtimeRoot'],'state',native['Id']],16384),16384)
    context=copy.deepcopy(recipe['dockerContext']);layout=context.pop('rootfsLayout',None)
    require(layout=='docker-containerd-overlayfs-v1'and state.get('id')==native['Id']
        and state.get('pid')==native['State']['Pid']and state.get('status')==('running' if running else 'paused')
        and state.get('bundle')==context['bundleParent']+'/'+native['Id'],'PAUSED_REVIEWED_RUNC_LAYOUT_REQUIRED')
    path=Path(state['bundle'])/'config.json';ancestors(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        initial=os.fstat(fd);require(stat.S_ISREG(initial.st_mode)and initial.st_uid==initial.st_gid==0
            and initial.st_nlink==1 and stat.S_IMODE(initial.st_mode)in(0o600,0o644)and 0<initial.st_size<=131072,
            'PAUSED_ROOT_CONTROLLED_RUNTIME_OCI_REQUIRED')
        raw=os.read(fd,131073);require(len(raw)==initial.st_size and attributes(initial)==attributes(os.fstat(fd))==attributes(path.lstat()),
            'PAUSED_RUNTIME_OCI_CHANGED_DURING_READ')
    finally:os.close(fd)
    oci=decode(raw,131072);root=Path(context['storageParent'])/'rootfs/overlayfs'/native['Id']
    sandbox=native['NetworkSettings']['SandboxKey']
    require(str(Path(sandbox).parent)==context['networkNamespaceParent']and Path(sandbox).stat().st_ino==before['generation']['namespaceInode'],
        'PAUSED_SANDBOX_KERNEL_NAMESPACE_DRIFT')
    context.update(containerId=native['Id'],networkNamespaceName=private_bridge_namespace_name(request),rootfsPath=str(root))
    policy=compile_policy(recipe['template'],recipe['launch'],context,execution_profile=FileOnlyProfile(request,registry['configtree']),
        renewable_token=recipe['renewableToken'],delegation_key_metadata_hash=recipe['delegationKeyMetadataHash'],proposal_receipt_key=recipe['proposalReceiptKey'])
    require(digest(policy['expectedOci'])==digest(oci),'PAUSED_PROPOSED_COMPLETE_OCI_DOES_NOT_MATCH_NATIVE')
    with open('/proc/self/mountinfo','rb')as stream:mountinfo=stream.read(1048577)
    require(len(mountinfo)<=1048576,'PAUSED_HOST_MOUNT_METADATA_UNBOUNDED')
    for line in mountinfo.decode().splitlines():
        text=line.split(' - ',1)[0].split()[4];point=Path(re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),text))
        require(point==root or not point.is_relative_to(root),'PRIVATE_SUBMOUNT_VISIBLE_IN_PAUSED_IMAGE_SCAN')
    for item in [*policy['sources'],policy['configtree'],policy['renewableToken']]:
        view=root/item['target'].lstrip('/')
        if view.exists():
            a=view.stat();b=Path(item['source']).stat()
            require((a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino),'PRIVATE_BIND_VISIBLE_IN_PAUSED_IMAGE_SCAN')
    if running:
        from tools.chatbot_file_cohort.running_rootfs import observe
        observe(root,config['rootfsLimits'],budget,ROOTFS_SEAL,native['State']['Pid'])
    else:
        require(rootfs_seal(root,config['rootfsLimits'],budget)==ROOTFS_SEAL,'PAUSED_INDEPENDENT_RETAINED_IMAGE_SEAL_DRIFT')
    after=engine.inspect(SimpleNamespace(context=previous['transition']['contextHash']))
    require(process.observe(native['State']['Pid'])==before and path.read_bytes()==raw
        and (same_running_native(native,after) if running else after==native),
        'PAUSED_NATIVE_GENERATION_CHANGED_DURING_PREFLIGHT')
    return {'completeOci':True,'independentRootfs':True,'samePausedGate':not running,'sameReleasedApplication':running,'privateBindContentsRead':False}

def same_running_native(before,after):
    # Docker health log samples may advance while scanning a live JVM. Every
    # configuration/generation binding and lifecycle flag remains exact; fresh
    # application readiness is independently required by backup_recovery.
    return Engine.runtime_binding(before)==Engine.runtime_binding(after) and all(
        v['RestartCount']==0 and v['State']['Running']is True and v['State']['Paused']is False
        and v['State']['Status']=='running' for v in(before,after))

def proof_scope(previous,actor):
    require(actor=={k:previous['prepared']['authorization']['plan']['selection'][k]for k in ('issuer','tenant','subject')},
        'PAUSED_SAME_CURRENT_HUMAN_ACTOR_REQUIRED')
    row=previous['transition'];base=previous['rootPredecessor'];root_proof=original.proof_scope(base,actor)
    return {**root_proof,'profile':PROFILE,'pausedPredecessorSource':SOURCE,'pausedPredecessorAuthorityHash':AUTHORITY,
        'pausedPredecessorReviewHash':REVIEW,'predecessorTransitionHash':TRANSITION_HASH,
        'appliedPrefixHash':digest(row['effects'][:6]),'appliedPrefixPhaseCount':6,
        'failedUnsignedIntentHash':digest(row['effects'][6]),'cancelledWorkerHash':WORKER_HASH,'workerSessionHash':SESSION_HASH,
        'recordBindings':copy.deepcopy(previous['recordBindings']),'originalNodeRecipeHash':digest(previous['prepared']['registry']['nodeRecipe']),
        'independentRootfsQualification':copy.deepcopy(CI_WITNESS),
        'newBudget':{'actor':copy.deepcopy(actor),'reason':'CORRECT_INDEPENDENT_OCI_AND_MOUNT_ROOTFS_REPROCESS_UNSIGNED_ATTESTATION',
            'decisionRef':'CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION','priorControlledGrantAttempts':2,
            'priorWorkerGrantAttempts':1,'maximumNewWorkerAttempts':128,'maximumSeconds':3600,'automaticRenewalAllowed':False},
        'stageReplayAllowed':False,'signalReplayAllowed':False,'unsignedFailedIntentRetained':True}

def retained_bindings(proof):
    require(proof.get('profile')==PROFILE and proof.get('pausedPredecessorAuthorityHash')==AUTHORITY
        and proof.get('predecessorTransitionHash')==TRANSITION_HASH and proof.get('cancelledWorkerHash')==WORKER_HASH
        and proof.get('workerSessionHash')==SESSION_HASH and proof.get('independentRootfsQualification')==CI_WITNESS
        and proof.get('newBudget',{}).get('priorControlledGrantAttempts')==2,'EXACT_PAUSED_REPROCESSING_PROOF_REQUIRED')
    for binding in proof['recordBindings']:private_file(binding,8388608)
    unsigned_node({'prepared':{'registry':{'directoryPlan':next_paths(proof)}}})

def next_paths(proof):
    # These paths are not selected by untrusted directory search. They are
    # resolved from the fixed, hash-bound failed bundle already in the proof.
    review=evidence.decode(private_file({'path':str(evidence.PARENT/CONTEXT/'review.json'),'sha256':REVIEW},8388608))
    bundle=evidence.decode(private_file(review['scopes']['finiteActionProcess']['bundle'],8388608))
    return bundle['prepared']['registry']['directoryPlan']

def reprocessing_marker(old,proof,authority_hash,new_intent):
    return {'schema':'ouf.unsigned-paused-attestation-governed-reprocessing.v1','predecessorJournalHash':digest(old),
        'failedIntent':copy.deepcopy(old['effects'][6]),'proofHash':digest(proof),'newAuthorityHash':authority_hash,
        'newIntentHash':new_intent,'decisionRef':'CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION','automaticReplayAllowed':False}

def successor_seed(previous,proof,authority_hash,intents):
    old=validate_boundary(previous['transition'],previous['prepared']['registry']['intents'])
    require(digest(old)==proof['predecessorTransitionHash']and digest(old['effects'][:6])==proof['appliedPrefixHash']
        and all(intents[phase]==previous['prepared']['registry']['intents'][phase]for phase in PHASES[:6])
        and digest(intents['ATTEST_NEW_OCI_PEER'])!=old['effects'][6]['intentHash'],
        'PAUSED_REPROCESSING_MUST_KEEP_SIX_EFFECTS_AND_BIND_CHANGED_INTENT')
    seed=copy.deepcopy(old);seed.update(version=old['version']+1,state='READY',effects=copy.deepcopy(old['effects'][:6]))
    seed['governedUnsignedReprocessing']=reprocessing_marker(old,proof,authority_hash,digest(intents['ATTEST_NEW_OCI_PEER']))
    return seed

def verify_successor_transition(row,scope,authority_hash):
    proof=scope['postGrantRecovery'];marker=row.get('governedUnsignedReprocessing',{})
    require(proof.get('profile')==PROFILE and proof.get('pausedPredecessorAuthorityHash')==AUTHORITY
        and proof.get('predecessorAuthorityHash')==original.AUTHORITY and proof.get('predecessorTransitionHash')==TRANSITION_HASH
        and row.get('transitionAuthorityEvidenceHash')==original.AUTHORITY and row.get('contextHash')==proof['transitionContextHash']
        and row.get('creationRequestHash')==scope['creationRequestHash']and row.get('nextPhase',-1)>=6
        and row.get('version',0)>=14 and len(row.get('effects',[]))>=6
        and digest(row['effects'][:6])==proof['appliedPrefixHash']
        and all(e.get('state')=='APPLIED'for e in row['effects'][:6])
        and all(e.get('authorityEvidenceHash')==authority_hash and e.get('intentHash')==scope['phaseIntentHashes'].get(e.get('phase'))for e in row['effects'][6:])
        and set(marker)=={'schema','predecessorJournalHash','failedIntent','proofHash','newAuthorityHash','newIntentHash','decisionRef','automaticReplayAllowed'}
        and marker.get('schema')=='ouf.unsigned-paused-attestation-governed-reprocessing.v1'
        and marker.get('predecessorJournalHash')==TRANSITION_HASH and digest(marker.get('failedIntent'))==proof['failedUnsignedIntentHash']
        and marker.get('proofHash')==digest(proof)and marker.get('newAuthorityHash')==authority_hash
        and marker.get('newIntentHash')==scope['phaseIntentHashes']['ATTEST_NEW_OCI_PEER']
        and marker.get('decisionRef')=='CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION'
        and marker.get('automaticReplayAllowed')is False,
        'PAUSED_HISTORY_MARKER_OR_NEW_AUTHORITY_DRIFT')
    return True

def seed_registry(previous,directories,action,scope):
    action.guard('applicationRegistryCutover',scope);proof=scope['postGrantRecovery'];retained_bindings(proof)
    old=validate_boundary(previous['transition'],previous['prepared']['registry']['intents']);seed=copy.deepcopy(old)
    require(digest(old)==TRANSITION_HASH and digest(old['effects'][:6])==proof['appliedPrefixHash']
        and all(scope['phaseIntentHashes'][phase]==digest(previous['prepared']['registry']['intents'][phase])for phase in PHASES[:6])
        and scope['phaseIntentHashes']['ATTEST_NEW_OCI_PEER']!=old['effects'][6]['intentHash'], 'EXACT_CHANGED_PAUSED_INTENT_AND_SEED_REQUIRED')
    seed.update(version=14,state='READY',effects=copy.deepcopy(old['effects'][:6]))
    seed['governedUnsignedReprocessing']=reprocessing_marker(old,proof,action.authority_hash,scope['phaseIntentHashes']['ATTEST_NEW_OCI_PEER'])
    verify_successor_transition(seed,scope,action.authority_hash)
    journal=Journal(directories['transition'])
    require(not any(os.path.lexists(journal.root/p)for p in ('recovery.json','recovery.lock','invocation.lock')),'PAUSED_NEW_JOURNAL_ALREADY_CONSUMED')
    for name,phases in previous['payloads'].items():
        store=NativeEvidenceStore(directories[name])
        for phase,value in phases.items():store.publish(phase,value)
    journal.initialize(seed);require(journal.read()==seed,'PAUSED_SEED_PUBLICATION_DRIFT')
    return journal
