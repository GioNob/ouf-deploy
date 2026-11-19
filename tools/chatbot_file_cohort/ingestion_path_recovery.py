"""Governed phase-6 reprocessing: failed start, exact image PATH, retained history.

Incident pins bind retained evidence; they are not installation defaults.
"""
import copy,json,os,re
from pathlib import Path
import iam_binding_candidate as evidence
from engine_creation import Engine
from tools.chatbot_file_cohort.plan import digest,require,sha
from tools.chatbot_file_cohort.action_process import observed_private_json

PROFILE='ouf.chatbot-failed-ingestion-image-path-reprocessing.v1'
CONTEXT='chatbot-file-cohort-signed-1711f307b106011ee1bf1bf4a6dadf1379b40bda58a0299d39f0cf15d37a0bd6'
SOURCE='f6078a5ac07853b4abc13d310882f5a30086baba'
REVIEW='62c8837120f9079cbf2dd026105ccce7befbbbfbbd09b1c67fc813e6a468f91e'
AUTHORITY='b6335ae592c469d253a345c29352a6fe2180e1297a29146b98bf1048016b4fe4'
STATUS='e00e6c696f0a1ce92a55016ed7d483ff48eb7d354ea5916adce82729d2f43e8d'
CONTAINERS='4781c2c59cdd1075a4c1d5510a5fc91251a7350281a432d9a59dc59cdee7ecf1'
DATABASE='5a0068029d09dbcd4094ff698888acc3f24448fb56c4f38d4b9b84e47124c05b'
GATEWAY='d52c98d8e2858a80fda9ad26ba272497122d0b6c2327f1af6edb9967207785b4'
WORKER='ea7ad7a3af85d98131576bcf77e1c99a0b3235749c01431f68d916e2f1ee0b94'
SESSION='11273a3ffa869a072cbd8a0df82f5bfefe8ebc665084de237fa70f0aa3dda96e'
ADMISSION='6fe1cad32535c1a704885b149865436082ee5258d7b0ce1edd3ed36bd6759441'
CREATED='cbf3067d946cf21a8f4abbb03ed47a217f2f39624ed1a5fb23a642325129ee35'
NATIVE='e6244efad747d69b491347ae5f76332739d31678e527073dad6a593a84b1c1a4'
ROUTES='a6504c3d830019e84ca73e76fd62cb3a47ea6d07efe00d106a0e475fe770d574'
CLAIM='chatbot-file-cohort-failed-ingestion-path-'+AUTHORITY+'.claim.json'

def available():return os.path.lexists(evidence.PARENT/CONTEXT)

def validate_worker(first,worker,admission,session):
    from tools.chatbot_file_cohort import postgrant_recovery as original
    require(digest(first)==original.FIRST_HASH and digest(worker)==WORKER and digest(session)==SESSION
        and digest(admission)==ADMISSION and worker.get('state')=='CANCELLED'
        and worker.get('attempts')==worker.get('publicationCount')==1
        and worker.get('controlledPredecessorGrantAttempts')==9 and worker.get('controlledCumulativeGrantAttempts')==10
        and worker.get('workerSessionHash')==SESSION and worker.get('firstGrantReceiptHash')==digest(first)
        and admission.get('state')=='BLOCKED' and admission.get('version')==3
        and session.get('schema')=='ouf.policy-token-new-finite-worker-session.v9'
        and session.get('predecessorGrantAttempts')==9
        and session.get('predecessorFirstGrantOperation')==first['operation']
        and session.get('predecessorFirstGrantScopeHash')==first['scopeHash'],
        'INGESTION_CANCELLED_WORKER_CUMULATIVE_TEN_REQUIRED')

def validate_containers(plan,row):
    from tools.chatbot_file_cohort.containers import STAGES
    steps=[m+'.'+s for m in ('udp','onboarding','ingestion','mcp')for s in STAGES]
    require(digest(row)==CONTAINERS and row.get('planHash')==digest(plan) and row.get('authorityHash')==AUTHORITY
        and row.get('budgetReset')is False and row.get('nextStep')==12
        and len(row.get('effects',[]))==13 and [e.get('step')for e in row['effects']]==steps[:13]
        and all(e.get('state')=='APPLIED'for e in row['effects'][:12])
        and row['effects'][-1].get('state')=='CLAIMED','EXACT_INGESTION_FAILED_START_CLAIM_REQUIRED')
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
    from tools.chatbot_file_cohort import gateway_recovery as base,ingestion_recovery as retained
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
        and status.get('reason')=='COHORT_START_REQUIRES_RECONCILIATION','EXACT_INGESTION_START_PAUSE_REQUIRED')
    bundle=read(process['bundle']['path'],process['bundle']['sha256'],8388608);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']
        and digest(p)==review['privateInputHashes']['preparedInputs'],'INGESTION_PREPARED_INPUT_DRIFT')
    old=p['postGrantRecovery'];base.retained_bindings(old)
    require(old['retainedCreatedIngestion']==previous['ingestionAttempt']['receipt'],
        'EXACT_RETAINED_APISIX_LINEAGE_REQUIRED')
    claim=read(evidence.PARENT/retained.CLAIM)
    require(claim.get('authorityHash')==AUTHORITY and claim.get('proofHash')==digest(old)
        and claim.get('state')=='CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY'
        and claim.get('priorControlledGrantAttempts')==9,'INGESTION_PREDECESSOR_CLAIM_REQUIRED')
    dirs=process['directoryPlan'];owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    require(str(owner)==p['postGrantWorkerDirectory'],'EXACT_INGESTION_WORKER_REQUIRED')
    worker=read(owner/'recovery.json',WORKER);session=read(owner/'owner-session.json',SESSION)
    admission=read(owner/'owner-admission.json',ADMISSION)
    require(read(owner/'owner-first-grant.json',FIRST_HASH)==previous['firstGrant']
        and read(owner/'owner-predecessor-worker.json',retained.WORKER)==previous['worker']
        and read(owner/'owner-predecessor-session.json',retained.SESSION)==previous['session']
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
        'originalClaimHash':digest(claim),'proposedIngestionPlanHash':digest(corrected_row(p)),'newCreateAllowed':True,'newGatewayWritesAllowed':False,
        'retainedAppliedContainerEffects':12,'failedStartReplayAllowed':False}
    return {**previous,'review':review,'worker':worker,'session':session,'admission':admission,
        'recordBindings':bindings,'failedIngestionAttempt':{'prepared':p,'containers':containers,'gateway':gateway,'receipt':receipt}}

def validate_proof(proof):
    r=proof.get('retainedFailedIngestion',{})
    fixed={'profile':PROFILE,'sourceCommit':SOURCE,'reviewHash':REVIEW,'authorityHash':AUTHORITY,
        'containerJournalHash':CONTAINERS,'gatewayJournalHash':GATEWAY,'databaseJournalHash':DATABASE,
        'cancelledWorkerHash':WORKER,'workerSessionHash':SESSION,'admissionHash':ADMISSION,
        'createdContainerId':CREATED,'nativeBindingHash':NATIVE,'finalRouteMapHash':ROUTES,
        'newCreateAllowed':True,'newGatewayWritesAllowed':False,'retainedAppliedContainerEffects':12,
        'failedStartReplayAllowed':False}
    require(type(r)is dict and set(r)==set(fixed)|{'originalClaimHash','proposedIngestionPlanHash'}
        and all(r.get(k)==v for k,v in fixed.items()) and sha(r.get('originalClaimHash')) and sha(r.get('proposedIngestionPlanHash')),
        'EXACT_CREATED_INGESTION_PROOF_REQUIRED')
    return r

def corrected_row(prepared):
    from tools.chatbot_file_cohort.plan import environment
    from image_custody import runtime_image_id
    row=copy.deepcopy(next(r for r in prepared['cohortPlan']['replacements']if r['module']=='ingestion'))
    audit=next(r['audit']for r in prepared['imagePlan']['images']if r['module']=='ingestion')
    require(runtime_image_id(audit)==row['creationRequest']['Image'],'EXACT_PATH_IMAGE_AUDIT_REQUIRED')
    default=audit['imageConfig'];env=environment(row['creationRequest']['Env'])
    inherited=environment(default.get('Env')or[]);path=inherited.get('PATH');home=inherited.get('JAVA_HOME')
    require(type(path)is str and len(path)<=8192 and all(v.startswith('/')and '..'not in v.split('/')for v in path.split(':'))
        and type(home)is str and home.rstrip('/')+'/bin'in path.split(':')
        and row['creationRequest']['Entrypoint']==default['Entrypoint']
        and default['Entrypoint'][0]=='java' and env.get('PATH')!=path
        and env.get('JAVA_HOME',home)==home and home.rstrip('/')+'/bin'not in env.get('PATH','').split(':'),
        'EXACT_LEGACY_PATH_OVERRIDE_REQUIRES_REPROCESSING')
    env['PATH']=path;row['creationRequest']['Env']=[k+'='+v for k,v in sorted(env.items())]
    row['creationRequestHash']=digest(row['creationRequest'])
    row['environmentDelta']=copy.deepcopy(row['environmentDelta'])
    require('PATH'not in row['environmentDelta'].get('remove',[]),'PATH_REMOVAL_CONFLICT')
    row['environmentDelta'].setdefault('set',{})['PATH']=path
    return row

def renamed_networks(value):
    result=copy.deepcopy(value)
    for network in result.get('Networks',{}).values():
        for key in ('Aliases','DNSNames'):
            if type(network.get(key))is list:
                network[key]=sorted(set('$CURRENT_NAME'if v in ('ouf-ingestion','ouf-ingestion-failed-'+AUTHORITY[:24])else v
                    for v in network[key]))
    return result

def native_readback(previous,engine,renamed=False,baseline=None):
    from tools.chatbot_file_cohort.containers import CohortContainers
    from tools.chatbot_file_cohort.migration_native import created
    attempt=previous['failedIngestionAttempt']
    row=next(r for r in attempt['prepared']['cohortPlan']['replacements']if r['module']=='ingestion')
    reader=CohortContainers.__new__(CohortContainers);reader.engine=engine
    reader.retired(row,True)
    code,actual=engine.request('GET','/v1.44/containers/'+CREATED+'/json')
    require(code==200 and actual['Id']==CREATED,'EXACT_FAILED_INGESTION_NATIVE_REQUIRED')
    if not renamed:
        require(digest(Engine.runtime_binding(actual))==NATIVE,'EXACT_FAILED_INGESTION_NATIVE_REQUIRED')
    else:
        require(baseline is not None and digest(Engine.runtime_binding(baseline))==NATIVE
            and all(actual[k]==baseline[k]for k in ('Id','Image','Config','HostConfig','Mounts','State','RestartCount'))
            and renamed_networks(actual['NetworkSettings'])==renamed_networks(baseline['NetworkSettings']),
            'FAILED_INGESTION_RENAME_CHANGED_NATIVE_CONFIGURATION')
    created(actual)
    name='ouf-ingestion-failed-'+AUTHORITY[:24]if renamed else row['name']
    require(actual['Name']=='/'+name and actual['State']['ExitCode']==127
        and type(actual['State'].get('Error'))is str
        and re.search(r'executable file not found in \$PATH',actual['State']['Error'])
        and 'java'in actual['State']['Error'],'EXACT_FAILED_JAVA_PATH_START_REQUIRED')
    if not renamed:require(reader.candidate(row)==actual,'FAILED_INGESTION_CONFIG_DRIFT')
    require(digest(corrected_row(attempt['prepared']))==attempt['receipt']['proposedIngestionPlanHash'],
        'EXACT_NEW_PATH_INTENT_REQUIRED')
    return actual

def adopt_containers(owner,previous,proof):
    from tools.chatbot_file_cohort import gateway_recovery as base
    from tools.chatbot_file_cohort.containers import CohortContainers
    from urllib.parse import quote
    require(type(owner)is CohortContainers,'CONCRETE_INGESTION_CONTAINER_OWNER_REQUIRED')
    owner.guard();base.retained_bindings(proof);receipt=validate_proof(proof)
    require('failedIngestionRetirement'not in owner.record(),'INGESTION_PATH_ADOPTION_ALREADY_CONSUMED')
    scope=json.loads(owner.action.raw)['applicationRegistryCutover']
    require(scope.get('postGrantRecovery')==proof,'EXACT_SIGNED_INGESTION_ADOPTION_REQUIRED')
    owner.action.guard('applicationRegistryCutover',scope)
    attempt=previous['failedIngestionAttempt'];rows=copy.deepcopy(attempt['prepared']['cohortPlan']['replacements'])
    rows[2]=corrected_row(attempt['prepared'])
    require(receipt==attempt['receipt'] and owner.plan['replacements']==rows,'INGESTION_PATH_ADOPTION_PLAN_DRIFT')
    validate_containers(attempt['prepared']['cohortPlan'],attempt['containers'])
    base.current_completed_containers(previous,owner.engine);native_readback(previous,owner.engine)
    destination='ouf-ingestion-failed-'+AUTHORITY[:24]
    intent={'failedContainerId':CREATED,'failedRuntimeHash':NATIVE,'destination':destination,
        'failedStartIntentHash':attempt['containers']['effects'][-1]['intentHash'],
        'newModulePlanHash':receipt['proposedIngestionPlanHash']}
    with owner.journal.invocation():
        initial=owner.record();require(initial['version']==1 and not initial['effects'] and initial['nextStep']==0
            and not initial['gates'] and not initial['readiness'] and 'failedIngestionRetirement'not in initial,
            'INGESTION_PATH_ADOPTION_ALREADY_CONSUMED')
        require(owner.inspect(destination)is None,'FAILED_INGESTION_RETIREMENT_NAME_OCCUPIED')
        following=copy.deepcopy(initial)
        following['failedIngestionRetirement']={'state':'CLAIMED','intentHash':digest(intent),'intent':intent}
        claimed=owner.save(initial,following)
    owner.guard();baseline=native_readback(previous,owner.engine)
    status,_=owner.engine.request('POST','/v1.44/containers/'+CREATED+'/rename?name='+quote(destination,safe=''))
    require(status==204,'FAILED_INGESTION_RETIREMENT_REQUIRES_RECONCILIATION')
    retired=native_readback(previous,owner.engine,True,baseline);owner.guard()
    with owner.journal.invocation():
        initial=owner.record();require(initial==claimed,'FAILED_INGESTION_RETIREMENT_CLAIM_DRIFT')
        following=copy.deepcopy(initial);old=attempt['containers']
        following.update(effects=copy.deepcopy(old['effects'][:10]),nextStep=10,
            readiness=copy.deepcopy(old['readiness']))
        # The original producer is already renamed. Observe it under the new
        # module intent; never invoke that historical rename again.
        following['effects'].append({'step':'ingestion.rename','state':'CLAIMED',
            'intentHash':digest({'modulePlan':rows[2],'stage':'rename'})})
        pin=Engine.runtime_binding(retired)
        following['failedIngestionRetirement'].update(state='APPLIED',evidence=pin,evidenceHash=digest(pin))
        following['retainedFailedIngestion']={'receiptHash':digest(receipt),'proofHash':digest(proof),
            'historicalAuthorityHash':AUTHORITY,'failedStartReplayAllowed':False}
        owner.save(initial,following);owner.record()

def adopt_gateway(owner,proof):
    from tools.chatbot_file_cohort import gateway_recovery as base
    from tools.chatbot_file_cohort.gateway import GatewayRoutes
    require(type(owner)is GatewayRoutes,'CONCRETE_COMPLETED_GATEWAY_OWNER_REQUIRED')
    owner.guard();base.retained_bindings(proof);receipt=validate_proof(proof)
    scope=json.loads(owner.action.raw)['applicationRegistryCutover']
    require(scope.get('postGrantRecovery')==proof,'EXACT_SIGNED_GATEWAY_COMPLETION_REQUIRED')
    owner.action.guard('applicationRegistryCutover',scope)
    previous=base.read_predecessor();attempt=previous['failedIngestionAttempt']
    require(attempt['receipt']==receipt and owner.plan==attempt['prepared']['gatewayPlan'],
        'EXACT_COMPLETED_GATEWAY_PLAN_REQUIRED')
    validate_gateway(owner.plan,attempt['gateway'])
    require(owner.transport.routes()==owner.plan['proposedRoutes'],'COMPLETED_GATEWAY_MAP_DRIFT')
    require(not os.path.lexists(owner.journal.record),'COMPLETED_GATEWAY_ADOPTION_ALREADY_CONSUMED')
    row=copy.deepcopy(attempt['gateway']);row['authorityHash']=owner.action.authority_hash;row['version']+=1
    row['retainedFailedIngestion']={'receiptHash':digest(receipt),'proofHash':digest(proof),'newWritesAllowed':False}
    owner.journal.initialize(row);owner.record();owner.guard();owner.verify()
