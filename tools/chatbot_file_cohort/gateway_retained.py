"""Exact completed APISIX attempt: finite successor adoption, no lifecycle replay."""
import copy
import json
import os
from pathlib import Path

import iam_binding_candidate as evidence
from tools.chatbot_file_cohort.plan import digest,require,sha
from tools.chatbot_file_cohort.action_process import observed_private_json

PROFILE='ouf.chatbot-completed-numeric-gateway-adoption.v1'
CONTEXT='chatbot-file-cohort-signed-594c62d1be7fc0274bcd90097e014736dc4aac636ab34bd7f8be1920fc875081'
SOURCE='5d9c9b6b944e71b25cd006994c511397295b4f4f'
REVIEW='57e0e293fef4abbaac5e45d214f30b3a1e312780f441c04c7f8c008c9fcf3209'
AUTHORITY='08417d9c20401f26e5ea1223f753b016e1f35047e83d06e7aa8469af9432c852'
STATUS='f65c7fea429cfed14e8a6df43f006cbb17b895601fc886ce7f5016e542b889cd'
AUTHORIZATION='690865a6eddb01ddca3edf90c7e3502e14d7c74af1b2b214987deddc9c65ea36'
RUNTIME='1505050a950b8a9d9565eff9fb95301d5193baa55ad8fc76dbb3acac3f362b18'
NATIVE='456f99eb1c0d071d188194ba30c0cb1e73b9665e6a89ac03b21c9e2e3451e354'
CLAIM='chatbot-file-cohort-completed-gateway-'+AUTHORITY+'.claim.json'


def available():return os.path.lexists(evidence.PARENT/CONTEXT)


def validate_runtime(plan,row):
    from tools.chatbot_file_cohort.gateway_runtime import PROFILE as RUNTIME_PROFILE,STEPS
    require(plan.get('runtimeBindingProfile')=='ouf.apisix-runtime-binding.mount-set.v1'
        and row.get('schema')==RUNTIME_PROFILE and row.get('planHash')==digest(plan)
        and row.get('authorityHash')==AUTHORITY and digest(row)==RUNTIME
        and row.get('budgetReset')is False and row.get('nextStep')==len(STEPS)
        and len(row.get('effects',[]))==len(STEPS),'EXACT_COMPLETED_NUMERIC_GATEWAY_REQUIRED')
    for step,effect in zip(STEPS,row['effects']):
        require(effect.get('step')==step and effect.get('state')=='APPLIED'
            and effect.get('intentHash')==digest({'planHash':digest(plan),'step':step}),
            'COMPLETED_GATEWAY_EFFECT_HISTORY_DRIFT')
    pin=row['effects'][-1]['evidence']['runtimeBinding']
    require(digest(pin)==NATIVE and row['effects'][3]['evidence']['containerId']==pin['containerId']
        and all(pin[k]==v for k,v in row['effects'][5]['evidence']['runtimeBinding'].items()if k!='hostConfigHash'),
        'COMPLETED_GATEWAY_PROCESS_GENERATION_DRIFT')
    return pin


def enrich(previous):
    from tools.chatbot_file_cohort import gateway_recovery as base
    from tools.chatbot_file_cohort.postgrant_recovery import stopped_process
    root=evidence.PARENT/CONTEXT;bindings=copy.deepcopy(previous['recordBindings'])
    def read(path,expected=None,maximum=262144):
        value,binding=observed_private_json(path,maximum)
        require(expected is None or binding['sha256']==expected,'RETAINED_NUMERIC_GATEWAY_RECORD_DRIFT')
        bindings.append(binding);return value
    review=read(root/'review.json',REVIEW,8388608);authority=read(root/'authority.json',AUTHORITY)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and all(authority.get(k)==v for k,v in review['scopes'].items()),'RETAINED_NUMERIC_GATEWAY_AUTHORITY_DRIFT')
    decision=read(root/'decision.json')
    require(decision.get('approvedReviewHash')==REVIEW and decision.get('state')=='ACTIVE'
        and decision.get('approvedSourceClosureHash')==review['sourceClosureHash']
        and decision.get('expiresAt')==authority['expiresAt'],'RETAINED_NUMERIC_GATEWAY_DECISION_DRIFT')
    process=review['scopes']['finiteActionProcess']
    require(process['authorityDirectory']==str(root),'EXACT_COMPLETED_GATEWAY_CONTEXT_REQUIRED')
    stopped_process(process,review['sourceClosure']['executables']['systemctl'])
    status=read(root/'delivery-status.json',STATUS)
    require(status.get('authorityHash')==AUTHORITY and status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION'
        and status.get('reason')=='AuthorizationPaused','EXACT_POST_GATEWAY_AUTHORIZATION_PAUSE_REQUIRED')
    old_claim=read(evidence.PARENT/base.CLAIM)
    require(old_claim.get('authorityHash')==AUTHORITY and old_claim.get('schema')==base.PROFILE
        and old_claim.get('state')=='CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY'
        and old_claim.get('priorControlledGrantAttempts')==8,'ORIGINAL_GATEWAY_CONTINUATION_CLAIM_REQUIRED')
    b=process['bundle'];bundle=read(b['path'],b['sha256'],8388608);prepared=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']
        and digest(prepared)==review['privateInputHashes']['preparedInputs']
        and prepared['postGrantRecovery']['profile']==base.PROFILE
        and old_claim.get('proofHash')==digest(prepared['postGrantRecovery']),
        'EXACT_COMPLETED_GATEWAY_PREPARED_INPUTS_REQUIRED')
    directories=process['directoryPlan']
    auth=read(Path(directories['authorization'])/'recovery.json',AUTHORIZATION)
    require(auth.get('authorityHash')==AUTHORITY and not auth.get('effects')
        and auth.get('planHash')==digest(prepared['authorization']['plan'])
        and auth.get('budgetReset')is False,'NO_NEW_AUTHORIZATION_EFFECTS_REQUIRED')
    for name in ('containers','databases','gateway'):
        require(not os.path.lexists(Path(directories[name])/'recovery.json'),
            'UNEXPECTED_POST_GATEWAY_APPLICATION_EFFECTS')
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    require(str(owner)==prepared['postGrantWorkerDirectory'] and not os.path.lexists(owner/'recovery.json'),
        'UNEXPECTED_POST_GATEWAY_WORKER_REQUIRES_RECONCILIATION')
    plan=prepared['gatewayRuntimePlan'];row=read(Path(directories['gatewayRuntime'])/'recovery.json',RUNTIME)
    require(review['scopes']['gatewayRuntimeInstallation']['planHash']==digest(plan),
        'RETAINED_GATEWAY_SIGNED_RUNTIME_SCOPE_DRIFT')
    validate_runtime(plan,row)
    require(prepared['databasePlan']==previous['prepared']['databasePlan']
        and prepared['cohortPlan']['replacements']==previous['prepared']['cohortPlan']['replacements'],
        'COMPLETED_PHASES_ONE_TO_FOUR_PLAN_DRIFT')
    attempt={'review':review,'prepared':prepared,'journal':row,'recordBindings':bindings,
        'receipt':{'profile':PROFILE,'sourceCommit':SOURCE,'reviewHash':REVIEW,'authorityHash':AUTHORITY,
            'runtimeJournalHash':RUNTIME,'runtimeBindingHash':NATIVE,'runtimePlanHash':digest(plan),
            'gatewayPlanHash':digest(prepared['gatewayPlan']),'historicalEffects':8,
            'newLifecycleEffectsAllowed':False,'newWorkerPreviouslyInstalled':False,
            'originalContinuationClaimHash':digest(old_claim)}}
    return {**previous,'recordBindings':bindings,'retainedGatewayAttempt':attempt}


def validate_proof(proof):
    receipt=proof.get('retainedNumericGateway',{})
    require(type(receipt)is dict and set(receipt)=={'profile','sourceCommit','reviewHash','authorityHash',
        'runtimeJournalHash','runtimeBindingHash','runtimePlanHash','gatewayPlanHash','historicalEffects',
        'newLifecycleEffectsAllowed','newWorkerPreviouslyInstalled','originalContinuationClaimHash'}
        and all(sha(receipt.get(k))for k in ('runtimePlanHash','gatewayPlanHash','originalContinuationClaimHash'))
        and receipt.get('profile')==PROFILE and receipt.get('sourceCommit')==SOURCE
        and receipt.get('reviewHash')==REVIEW and receipt.get('authorityHash')==AUTHORITY
        and receipt.get('runtimeJournalHash')==RUNTIME and receipt.get('runtimeBindingHash')==NATIVE
        and receipt.get('historicalEffects')==8 and receipt.get('newLifecycleEffectsAllowed')is False
        and receipt.get('newWorkerPreviouslyInstalled')is False,'EXACT_RETAINED_NUMERIC_GATEWAY_PROOF_REQUIRED')
    return receipt


def current_transport(previous,engine):
    from tools.chatbot_file_cohort.gateway import NamespaceAdmin,apisix_runtime_binding
    from tools.chatbot_file_cohort.gateway_runtime import GatewayRuntime,validate_numeric_assets
    attempt=previous['retainedGatewayAttempt'];plan=attempt['prepared']['gatewayRuntimePlan']
    pin=validate_runtime(plan,attempt['journal'])
    reader=GatewayRuntime.__new__(GatewayRuntime);reader.plan=plan;reader.engine=engine
    reader.old(True);actual=reader.candidate(True,True,True)
    require(actual is not None and apisix_runtime_binding(actual,plan['runtimeBindingProfile'])==pin,
        'RETAINED_NUMERIC_GATEWAY_NATIVE_DRIFT')
    validate_numeric_assets(plan['oldRuntimeBinding']['imageId'],plan['numericCompatibility']['assets'])
    binding=NamespaceAdmin.observe(engine,plan['newConfigBinding']['path'],plan['runtimeBindingProfile'])
    require(binding['runtimeBinding']==pin and binding['adminKeyBinding']==plan['adminKeyBinding']
        and binding['pythonExecutable']==plan['pythonExecutable'],'RETAINED_NUMERIC_GATEWAY_TRANSPORT_DRIFT')
    return binding


def adopt_runtime(owner,proof):
    from tools.chatbot_file_cohort import gateway_recovery as base
    from tools.chatbot_file_cohort.gateway_runtime import GatewayRuntime
    require(type(owner)is GatewayRuntime,'CONCRETE_GATEWAY_RUNTIME_ADOPTION_REQUIRED')
    scope=json.loads(owner.action.raw)['applicationRegistryCutover']
    require(scope.get('postGrantRecovery')==proof,'EXACT_SIGNED_GATEWAY_ADOPTION_REQUIRED')
    owner.action.guard('applicationRegistryCutover',scope)
    owner.guard();base.retained_bindings(proof);receipt=validate_proof(proof)
    previous=base.read_predecessor();attempt=previous['retainedGatewayAttempt']
    require(receipt==attempt['receipt'] and owner.plan==attempt['prepared']['gatewayRuntimePlan'],
        'EXACT_COMPLETED_RUNTIME_PLAN_ADOPTION_REQUIRED')
    current_transport(previous,owner.engine)
    require(not os.path.lexists(owner.journal.record),'COMPLETED_RUNTIME_ADOPTION_ALREADY_CONSUMED')
    row=copy.deepcopy(attempt['journal']);row['authorityHash']=owner.action.authority_hash;row['version']+=1
    row['retainedNumericGateway']={'receiptHash':digest(receipt),'proofHash':digest(proof),
        'historicalAuthorityHash':AUTHORITY,'newLifecycleEffectsAllowed':False}
    owner.journal.initialize(row);owner.record();owner.guard();owner.generation()
    return row
