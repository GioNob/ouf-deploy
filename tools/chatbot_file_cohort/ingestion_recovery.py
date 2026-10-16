"""Exact phase-6 checkpoint: completed Gateway and never-started Ingestion.

Incident pins bind retained evidence; they are not installation defaults.
"""
import copy,json,os
from pathlib import Path
import iam_binding_candidate as evidence
from engine_creation import Engine
from tools.chatbot_file_cohort.plan import digest,require,sha
from tools.chatbot_file_cohort.action_process import observed_private_json

PROFILE='ouf.chatbot-created-ingestion-continuation.v1'
CONTEXT='chatbot-file-cohort-signed-9e843050f99e2da257ec6c33221ae0c963f78412c7d31c119af97ae81dfa442f'
SOURCE='e2252339dcc127e9237b8120727bf27439f506f0'
REVIEW='50b5e2348c950ab9832cf890c7d0129f6ba92c8b05eb5d853fcd94ad1574b8cb'
AUTHORITY='50ce40e69082a813ba92b7dd9defacc1e6ccb904a3be8ef20226f80fca468893'
STATUS='754d7680d799e7734b729286329f0a52ada6bc7a0736ffea170fbc6484b4da86'
CONTAINERS='cb05a28fc2103320699c0932b8d02720052eb2de462b0107f5337545fa357132'
DATABASE='09003397e313e7d2de5ccaa42040711ebb84bb151ec066adad2e8890eb3defe6'
GATEWAY='da5f379e279f1ec76ac8eb7835d3039f9cd72e9ae749adefeeae9e71c1755989'
WORKER='0c5b278a4290695093633cd46e85110970ea7eb5001f9aa2e086c4467e441850'
SESSION='df7e97ec0096213c38633a93984a4bfd38b316210a7f09012c2ecc1922521920'
ADMISSION='f4ee96d83361565e59a9d5763c20e2ebe35a47fc4be1626aad9794ba53c03ec3'
CREATED='cbf3067d946cf21a8f4abbb03ed47a217f2f39624ed1a5fb23a642325129ee35'
NATIVE='d14d56632ea3e442ad249b83ce5719f1102238a31aeb1513290084ecaba36f5b'
ROUTES='a6504c3d830019e84ca73e76fd62cb3a47ea6d07efe00d106a0e475fe770d574'
CLAIM='chatbot-file-cohort-created-ingestion-'+AUTHORITY+'.claim.json'

def available():return os.path.lexists(evidence.PARENT/CONTEXT)

def validate_worker(first,worker,admission,session):
    from tools.chatbot_file_cohort import postgrant_recovery as original
    require(digest(first)==original.FIRST_HASH and digest(worker)==WORKER and digest(session)==SESSION
        and digest(admission)==ADMISSION and worker.get('state')=='CANCELLED'
        and worker.get('attempts')==worker.get('publicationCount')==1
        and worker.get('controlledPredecessorGrantAttempts')==8 and worker.get('controlledCumulativeGrantAttempts')==9
        and worker.get('workerSessionHash')==SESSION and worker.get('firstGrantReceiptHash')==digest(first)
        and admission.get('state')=='BLOCKED' and admission.get('version')==3
        and session.get('schema')=='ouf.policy-token-new-finite-worker-session.v8'
        and session.get('predecessorGrantAttempts')==8
        and session.get('predecessorFirstGrantOperation')==first['operation']
        and session.get('predecessorFirstGrantScopeHash')==first['scopeHash'],
        'INGESTION_CANCELLED_WORKER_CUMULATIVE_NINE_REQUIRED')

def validate_containers(plan,row):
    from tools.chatbot_file_cohort.containers import STAGES
    steps=[m+'.'+s for m in ('udp','onboarding','ingestion','mcp')for s in STAGES]
    require(digest(row)==CONTAINERS and row.get('planHash')==digest(plan) and row.get('authorityHash')==AUTHORITY
        and row.get('budgetReset')is False and row.get('nextStep')==11
        and len(row.get('effects',[]))==12 and [e.get('step')for e in row['effects']]==steps[:12]
        and all(e.get('state')=='APPLIED'for e in row['effects'][:11])
        and row['effects'][-1].get('state')=='CLAIMED','EXACT_INGESTION_CREATE_CLAIM_REQUIRED')
    by_module={r['module']:r for r in plan['replacements']}
    for e in row['effects']:
        module,stage=e['step'].split('.')
        require(e.get('intentHash')==digest({'modulePlan':by_module[module],'stage':stage}), 'INGESTION_HISTORY_INTENT_DRIFT')
        if e['state']=='APPLIED':require(e.get('evidenceHash')==digest(e['evidence']),'INGESTION_HISTORY_EVIDENCE_DRIFT')
    require(row.get('gates',{}).get('gateway',{}).get('scopeHash')==plan['gatewayPlanHash'],
        'COMPLETED_GATEWAY_GATE_REQUIRED')

def validate_gateway(plan,row):
    require(digest(row)==GATEWAY and row.get('schema')=='ouf.chatbot-file-cohort.gateway-publication.v1'
        and row.get('planHash')==digest(plan) and row.get('authorityHash')==AUTHORITY
        and row.get('budgetReset')is False and row.get('nextStep')==len(plan['changes'])==28
        and len(row.get('effects',[]))==28 and digest(plan['proposedRoutes'])==ROUTES,
        'EXACT_COMPLETED_INGESTION_PREDECESSOR_GATEWAY_REQUIRED')
    for e,c in zip(row['effects'],plan['changes']):
        require(e.get('state')=='APPLIED' and e.get('routeId')==c['id'] and e.get('intentHash')==digest(c),
            'COMPLETED_GATEWAY_EFFECT_DRIFT')

def enrich(previous):
    from tools.chatbot_file_cohort import gateway_recovery as base,gateway_retained as retained
    from tools.chatbot_file_cohort.postgrant_recovery import stopped_process,FIRST_HASH
    root=evidence.PARENT/CONTEXT;bindings=copy.deepcopy(previous['recordBindings'])
    def read(path,expected=None,maximum=2097152):
        value,binding=observed_private_json(path,maximum)
        require(expected is None or binding['sha256']==expected,'INGESTION_RETAINED_RECORD_DRIFT')
        bindings.append(binding);return value
    review=read(root/'review.json',REVIEW,8388608);authority=read(root/'authority.json',AUTHORITY)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and all(authority.get(k)==v for k,v in review['scopes'].items()),'INGESTION_RETAINED_AUTHORITY_DRIFT')
    decision=read(root/'decision.json')
    require(decision.get('state')=='ACTIVE' and decision.get('approvedReviewHash')==REVIEW
        and decision.get('approvedSourceClosureHash')==review['sourceClosureHash']
        and decision.get('expiresAt')==authority['expiresAt'],'INGESTION_RETAINED_DECISION_DRIFT')
    process=review['scopes']['finiteActionProcess'];require(process['authorityDirectory']==str(root),'EXACT_INGESTION_CONTEXT_REQUIRED')
    stopped_process(process,review['sourceClosure']['executables']['systemctl'])
    status=read(root/'delivery-status.json',STATUS)
    require(status.get('authorityHash')==AUTHORITY and status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION'
        and status.get('reason')=='COHORT_REPLACEMENT_PROCESS_CONFIG_DRIFT','EXACT_INGESTION_CONFIG_PAUSE_REQUIRED')
    bundle=read(process['bundle']['path'],process['bundle']['sha256'],8388608);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']
        and digest(p)==review['privateInputHashes']['preparedInputs'],'INGESTION_PREPARED_INPUT_DRIFT')
    old=p['postGrantRecovery'];base.retained_bindings(old)
    require(old['retainedNumericGateway']==previous['retainedGatewayAttempt']['receipt'],
        'EXACT_RETAINED_APISIX_LINEAGE_REQUIRED')
    claim=read(evidence.PARENT/retained.CLAIM)
    require(claim.get('authorityHash')==AUTHORITY and claim.get('proofHash')==digest(old)
        and claim.get('state')=='CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY'
        and claim.get('priorControlledGrantAttempts')==8,'INGESTION_PREDECESSOR_CLAIM_REQUIRED')
    dirs=process['directoryPlan'];owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    require(str(owner)==p['postGrantWorkerDirectory'],'EXACT_INGESTION_WORKER_REQUIRED')
    worker=read(owner/'recovery.json',WORKER);session=read(owner/'owner-session.json',SESSION)
    admission=read(owner/'owner-admission.json',ADMISSION)
    require(read(owner/'owner-first-grant.json',FIRST_HASH)==previous['firstGrant']
        and read(owner/'owner-predecessor-worker.json',base.WORKER_HASH)==previous['worker']
        and read(owner/'owner-predecessor-session.json',base.SESSION_HASH)==previous['session']
        and session==review['scopes']['policyTokenFiniteWorkerSession'], 'COMPLETE_NINE_GRANT_HISTORY_REQUIRED')
    validate_worker(previous['firstGrant'],worker,admission,session)
    containers=read(Path(dirs['containers'])/'recovery.json',CONTAINERS);validate_containers(p['cohortPlan'],containers)
    gateway=read(Path(dirs['gateway'])/'recovery.json',GATEWAY);validate_gateway(p['gatewayPlan'],gateway)
    require(p['cohortPlan']['replacements']==previous['prepared']['cohortPlan']['replacements']
        and p['databasePlan']==previous['prepared']['databasePlan']
        and p['gatewayRuntimePlan']==previous['retainedGatewayAttempt']['prepared']['gatewayRuntimePlan']
        and p['gatewayPlan']==previous['retainedGatewayAttempt']['prepared']['gatewayPlan']
        and containers['effects'][:10]==previous['containerJournal']['effects'], 'PHASES_ONE_TO_FIVE_PLAN_DRIFT')
    db=read(Path(dirs['databases'])/'recovery.json',DATABASE)
    require(db.get('planHash')==digest(p['databasePlan']) and db.get('authorityHash')==AUTHORITY
        and all(db[k]==previous['databaseJournal'][k]for k in ('backups','mcpMigration','mcpAuditRole')),
        'COMPLETED_DATABASE_CHECKPOINT_DRIFT')
    auth=read(Path(dirs['authorization'])/'recovery.json')
    require(auth.get('authorityHash')==AUTHORITY and auth.get('planHash')==digest(p['authorization']['plan'])
        and not auth.get('effects') and auth.get('observations',{}).get('AFTER_GATEWAY',{}).get('state')=='COMPLETE',
        'COMPLETED_READONLY_AUTHORIZATION_REQUIRED')
    runtime=read(Path(dirs['gatewayRuntime'])/'recovery.json')
    require(runtime.get('authorityHash')==AUTHORITY and runtime.get('nextStep')==8
        and runtime.get('planHash')==digest(p['gatewayRuntimePlan'])
        and runtime.get('effects')==previous['retainedGatewayAttempt']['journal']['effects']
        and runtime.get('retainedNumericGateway',{}).get('proofHash')==digest(old), 'COMPLETED_APISIX_ADOPTION_DRIFT')
    transition=read(Path(p['registry']['directoryPlan']['transition'])/'recovery.json')
    base.verify_successor_transition(transition,review['scopes']['applicationRegistryCutover'],AUTHORITY)
    require(transition.get('nextPhase')==10 and len(transition.get('effects',[]))==10,
        'PRODUCERS_MUST_REMAIN_UNRELEASED')
    receipt={'profile':PROFILE,'sourceCommit':SOURCE,'reviewHash':REVIEW,'authorityHash':AUTHORITY,
        'containerJournalHash':CONTAINERS,'gatewayJournalHash':GATEWAY,'databaseJournalHash':DATABASE,
        'cancelledWorkerHash':WORKER,'workerSessionHash':SESSION,'admissionHash':ADMISSION,
        'createdContainerId':CREATED,'nativeBindingHash':NATIVE,'finalRouteMapHash':ROUTES,
        'originalClaimHash':digest(claim),'newCreateAllowed':False,'newGatewayWritesAllowed':False,
        'retainedAppliedContainerEffects':11,'claimedCreateObservationRequired':True}
    return {**previous,'review':review,'worker':worker,'session':session,'admission':admission,
        'recordBindings':bindings,'ingestionAttempt':{'prepared':p,'containers':containers,'gateway':gateway,'receipt':receipt}}

def validate_proof(proof):
    r=proof.get('retainedCreatedIngestion',{})
    fixed={'profile':PROFILE,'sourceCommit':SOURCE,'reviewHash':REVIEW,'authorityHash':AUTHORITY,
        'containerJournalHash':CONTAINERS,'gatewayJournalHash':GATEWAY,'databaseJournalHash':DATABASE,
        'cancelledWorkerHash':WORKER,'workerSessionHash':SESSION,'admissionHash':ADMISSION,
        'createdContainerId':CREATED,'nativeBindingHash':NATIVE,'finalRouteMapHash':ROUTES,
        'newCreateAllowed':False,'newGatewayWritesAllowed':False,'retainedAppliedContainerEffects':11,
        'claimedCreateObservationRequired':True}
    require(type(r)is dict and set(r)==set(fixed)|{'originalClaimHash'}
        and all(r.get(k)==v for k,v in fixed.items()) and sha(r.get('originalClaimHash')),
        'EXACT_CREATED_INGESTION_PROOF_REQUIRED')
    return r

def native_readback(previous,engine):
    from tools.chatbot_file_cohort.containers import CohortContainers
    from tools.chatbot_file_cohort.migration_native import created
    row=next(r for r in previous['ingestionAttempt']['prepared']['cohortPlan']['replacements']if r['module']=='ingestion')
    reader=CohortContainers.__new__(CohortContainers);reader.engine=engine
    reader.retired(row,True);actual=reader.candidate(row)
    require(actual is not None and actual['Id']==CREATED and digest(Engine.runtime_binding(actual))==NATIVE,
        'EXACT_CREATED_INGESTION_NATIVE_REQUIRED')
    created(actual)
    require(reader.candidate(row)==actual,'CREATED_INGESTION_GENERATION_UNSTABLE')
    return actual

def adopt_containers(owner,previous,proof):
    from tools.chatbot_file_cohort import gateway_recovery as base
    from tools.chatbot_file_cohort.containers import CohortContainers
    require(type(owner)is CohortContainers,'CONCRETE_INGESTION_CONTAINER_OWNER_REQUIRED')
    owner.guard();base.retained_bindings(proof);receipt=validate_proof(proof)
    scope=json.loads(owner.action.raw)['applicationRegistryCutover']
    require(scope.get('postGrantRecovery')==proof,'EXACT_SIGNED_INGESTION_ADOPTION_REQUIRED')
    owner.action.guard('applicationRegistryCutover',scope)
    attempt=previous['ingestionAttempt'];require(receipt==attempt['receipt']
        and owner.plan['replacements']==attempt['prepared']['cohortPlan']['replacements'], 'INGESTION_ADOPTION_PLAN_DRIFT')
    validate_containers(attempt['prepared']['cohortPlan'],attempt['containers'])
    base.current_completed_containers(previous,owner.engine);native_readback(previous,owner.engine)
    with owner.journal.invocation():
        initial=owner.record();require(initial['version']==1 and not initial['effects'] and initial['nextStep']==0
            and not initial['gates'] and not initial['readiness'],'INGESTION_ADOPTION_ALREADY_CONSUMED')
        following=copy.deepcopy(initial);old=attempt['containers']
        following.update(effects=copy.deepcopy(old['effects']),nextStep=11,readiness=copy.deepcopy(old['readiness']))
        following['retainedCreatedIngestion']={'receiptHash':digest(receipt),'proofHash':digest(proof),
            'historicalAuthorityHash':AUTHORITY,'createReplayAllowed':False}
        owner.save(initial,following);owner.record()

def adopt_gateway(owner,proof):
    from tools.chatbot_file_cohort import gateway_recovery as base
    from tools.chatbot_file_cohort.gateway import GatewayRoutes
    require(type(owner)is GatewayRoutes,'CONCRETE_COMPLETED_GATEWAY_OWNER_REQUIRED')
    owner.guard();base.retained_bindings(proof);receipt=validate_proof(proof)
    scope=json.loads(owner.action.raw)['applicationRegistryCutover']
    require(scope.get('postGrantRecovery')==proof,'EXACT_SIGNED_GATEWAY_COMPLETION_REQUIRED')
    owner.action.guard('applicationRegistryCutover',scope)
    previous=base.read_predecessor();attempt=previous['ingestionAttempt']
    require(attempt['receipt']==receipt and owner.plan==attempt['prepared']['gatewayPlan'],
        'EXACT_COMPLETED_GATEWAY_PLAN_REQUIRED')
    validate_gateway(owner.plan,attempt['gateway'])
    require(owner.transport.routes()==owner.plan['proposedRoutes'],'COMPLETED_GATEWAY_MAP_DRIFT')
    require(not os.path.lexists(owner.journal.record),'COMPLETED_GATEWAY_ADOPTION_ALREADY_CONSUMED')
    row=copy.deepcopy(attempt['gateway']);row['authorityHash']=owner.action.authority_hash;row['version']+=1
    row['retainedCreatedIngestion']={'receiptHash':digest(receipt),'proofHash':digest(proof),'newWritesAllowed':False}
    owner.journal.initialize(row);owner.record();owner.guard();owner.verify()
