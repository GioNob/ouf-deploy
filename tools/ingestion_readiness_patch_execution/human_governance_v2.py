"""Separate finite 296->300 budget and one fresh HUMAN window for this patch.

The previous control/profile remain immutable. Budget review never opens a
credential journal. Window creation reads old public history internally, never
uses its bearer/refresh token, and delegates each request to the frozen operator.
"""
import copy
import json
import os
from pathlib import Path
import time
import uuid
from engine_creation import Engine
from tools.ingestion_readiness_patch_execution import entry_v2 as e, custody, operator_control_v2 as runtime
from tools.ingestion_readiness_patch_execution import runtime_guard, runtime_bindings
from tools.ingestion_readiness_patch_execution.replacement import EngineReader
from tools.governed_human_successor import operator, contract, window
from tools.governed_human_successor.session import validate_consent

SCHEMA='ouf.ingestion-readiness-patch-human-governance-case.v2'
GRANT='ouf.ingestion-readiness-patch-human-budget.v2'


def validate(case):
    c=e.c
    c.require(type(case)is dict and set(case)=={'schema','purpose','runtimeCase','nativeDeclaration',
        'predecessorControlPath','predecessorReviewHash','humanOperatorTransportProfile','governanceSourceHash'}
        and case['schema']==SCHEMA and case['purpose']=='EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT',
        'EXACT_PATCH_HUMAN_GOVERNANCE_CASE_REQUIRED')
    c.require(c.hashed(case['governanceSourceHash'])and c.hashed(case['predecessorReviewHash'])
        and globals().get('__qualified_source_sha256__')==case['governanceSourceHash'],
        'EXACT_SEALED_PATCH_HUMAN_GOVERNANCE_SOURCE_REQUIRED')
    c.path(case['predecessorControlPath'])
    r=case['runtimeCase'];runtime.validate_case(e,case['nativeDeclaration'],r,r['controlSourceHash'],custody)
    c.require(getattr(runtime,'__qualified_source_sha256__',None)==r['controlSourceHash'],
        'EXACT_SAME_QUALIFIED_PATCH_RUNTIME_CONTROLLER_REQUIRED')
    operator.validate_transport(case)
    return r


def predecessor(case):
    """Root-private control/profile metadata only; do not read credential bytes."""
    c=e.c;folder=Path(case['predecessorControlPath'])
    config=custody.read(str(folder/'control.json'))
    c.require(c.digest(config['review'])==case['predecessorReviewHash'],
        'EXACT_RETAINED_READY296_CONTROL_REVIEW_REQUIRED')
    loaded,binding=operator.load_control(str(folder),config['case'],config['confirmedRead'],config['sourceClosureHash'])
    c.require(loaded==config,'RETAINED_HUMAN_CONTROL_CHANGED')
    p=e.human_reader.validate(custody.read(str(folder/'human-read-profile.json')))
    old=config['review'];now=time.time()
    c.require(old['priorOAuthAttempts']==292 and old['maximumCumulativeOAuthAttempts']==296
        and p['minimumCumulativeAttempts']==p['maximumCumulativeAttempts']==296
        and p['selection']==config['selection'] and p['expectedBinding']==binding
        and binding['retryProfile']['maximumAttempts']==296
        and binding['selectionHash']==c.digest(p['selection'])
        and binding['createdAt']==config['decision']['approvedAt']
        and binding['expiresAt']==config['decision']['expiresAt']<=now
        and p['journal']['path']==binding['sessionDirectory']+'/recovery.json'
        and p['governedWindowReceiptHash']==c.digest({'review':old,'decision':config['decision']})
        and p['expectedBootId']==window.boot_id()
        and p['expectedMonotonicDeadline']<=time.monotonic(),
        'EXACT_EXPIRED_READY296_METADATA_REQUIRED_NO_RESET_OR_OLD_LOGIN')
    e.authority.private_file.check_metadata(p['journal'])
    return config,p


def operation(case):
    r=case['runtimeCase'];c=e.c
    return {'runtimeCaseHash':c.digest(r),'nativeInputsHash':r['nativeInputsHash'],
        'logicalOperationRef':r['logicalOperationRef'],'controlSourceHash':r['controlSourceHash']}


def proposal(case,closure):
    c=e.c;r=validate(case);runtime.retained(e,r,custody);config,p=predecessor(case)
    c.require(c.hashed(closure),'EXACT_PATCH_HUMAN_SOURCE_CLOSURE_REQUIRED')
    return {'schema':GRANT,'kind':'FOUR_REQUEST_TECHNICAL_BUDGET_PROPOSAL_ONLY',
        'caseHash':c.digest(case),'sourceClosureHash':closure,'operationBinding':operation(case),
        'predecessorReviewHash':case['predecessorReviewHash'],'predecessorProfileHash':c.digest(p),
        'predecessorJournalSeal':copy.deepcopy(p['journal']),
        'lineageRef':c.digest({'binding':p['expectedBinding'],'priorOAuthAttempts':296}),
        'selectionHash':c.digest(p['selection']),'retainedOwnerHistory':copy.deepcopy(config['history']),
        'intendedProviderPrincipal':{k:p['selection'][k]for k in ('issuer','subject','tenant')},
        'reason':'INSTALL_EXACT_ONE_INGESTION_READINESS_PATCH_WITHOUT_COMPLETED_ACTION_REPLAY',
        'priorOAuthAttempts':296,'additionalOAuthAttempts':4,'maximumCumulativeOAuthAttempts':300,
        'nominalRequests':['DISCOVERY','DEVICE_START','DEVICE_POLL','USERINFO'],
        'automaticRetryReserve':0,'maximumFutureLoginWindowSeconds':7200,
        'separateWindowConsentRequired':True,'freshProviderIdentityRequired':True,
        'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}


def paths(case,p):
    root=Path(case['runtimeCase']['snapshotRoot'])
    # Global predecessor fence prevents another case/root from granting the
    # same exhausted session a second parallel four-request allowance.
    old=Path(p['predecessorJournalSeal']['path']).parent
    return root,old/'patch-oauth-budget-296.claim.json',root/('patch-human-budget-'+e.c.digest(p))


def publish(folder,name,value):
    journal=e.Journal(folder);journal.create(Path(folder)/name,e.c.encoded(value));journal.sync()


def live_preflight(case):
    """Twelve exact-ID GETs, no keys/bearers/API/SQL calls and no mutations."""
    r=case['runtimeCase'];result=runtime.preflight(e,case['nativeDeclaration'],r,custody)
    b=runtime.retained(e,r,custody);eb=b['engineBinding'];engine=Engine(eb['socketPath'],tuple(eb['socketBinding']))
    reader=EngineReader(engine);before=b['beforeIngestion'];db=b['databaseControlProfile']
    ids=[before['Id'],*[p['binding']['containerId']for p in b['unchangedApplications'].values()],
         db['postgresRuntimeBinding']['containerId']]
    e.c.require(len(ids)==len(set(ids))==6,'SIX_DISTINCT_RETAINED_PATCH_CONTAINERS_REQUIRED')
    first=None;count=0
    for _ in range(2):
        observed={}
        for cid in ids:
            count+=1;observed[cid]=reader.container(cid)
        current=observed[before['Id']]
        e.c.require(all(current[k]==before[k]for k in ('Id','Name','Image','Config','HostConfig','Mounts','NetworkSettings','RestartCount'))
            and all(current['State'][k]==before['State'][k]for k in ('Running','Paused','Restarting','Pid','StartedAt'))
            and current['State']['Running']is True,'PRE_LOGIN_RETAINED_INGESTION_GENERATION_CHANGED')
        for pin in b['unchangedApplications'].values():runtime_guard.unchanged(observed[pin['binding']['containerId']],pin)
        pg=observed[db['postgresRuntimeBinding']['containerId']]
        runtime_guard.unchanged(pg,{'binding':db['postgresRuntimeBinding'],'restartCount':db['postgresRestartCount'],
            'bindingProfile':db['runtimeBindingProfile']})
        # Compare only bound state, excluding volatile health/resource counters.
        stable={cid:{k:row[k]for k in ('Id','Name','Image','Config','HostConfig','Mounts','NetworkSettings','RestartCount')}
            |{'process':{k:row['State'][k]for k in ('Running','Paused','Restarting','Pid','StartedAt')}}
            for cid,row in observed.items()}
        e.c.require(first is None or first==stable,'PRE_LOGIN_GENERATION_CHANGED_BETWEEN_READS')
        first=stable
    return {**result,'status':'PATCH_HUMAN_RUNTIME_PREFLIGHT_NO_WINDOW_OR_BUDGET',
        'engineRequests':count,'maximumEngineRequests':12,'liveRuntimeMetadataMatched':True,
        'applicationReadinessReverified':False,'databaseAdmissionProven':False}


def grant(case,closure):
    c=e.c;p=proposal(case,closure);root,claim,target=paths(case,p)
    c.require(not os.path.lexists(claim)and not os.path.lexists(target),'PATCH_BUDGET_ALREADY_CLAIMED_RECONCILE_ONLY')
    probe=live_preflight(case)
    c.require(operator.terminal_confirm(
        'Concedo quattro richieste tecniche OAuth: cumulativo296->300, storico296 conservato.\n'
        'DISCOVERY, DEVICE_START, UN polling dopo login browser, USERINFO; nessuna riserva retry.\n'
        'Solo questa patch Ingestion; finestra7200secondi con consenso separato.\n'
        'Non apre login, non invia OAuth e non concede autorita runtime, fonti o pubblicazione.',
        'CONCEDO BUDGET OAUTH 296->300 '+c.digest(p))is True,'EXPLICIT_PATCH_BUDGET_CONSENT_REQUIRED')
    c.require(proposal(case,closure)==p,'PATCH_BUDGET_INPUT_CHANGED_AFTER_CONSENT')
    now=int(time.time())
    decision=budget_decision(case,p,now)
    fence={'schema':GRANT,'proposalHash':c.digest(p),'decisionHash':c.digest(decision),'contextPath':str(target),
        'caseHash':c.digest(case),'sourceClosureHash':closure,'automaticReplayAllowed':False,'budgetReset':False}
    publish(claim.parent,claim.name,fence)
    with e.authority.protected_directory(root)as fd:os.mkdir(target.name,0o700,dir_fd=fd);os.fsync(fd)
    publish(target,'proposal.json',p);publish(target,'decision.json',decision);publish(target,'claim.json',fence)
    return {**budget_status(case,closure),'engineRequests':probe['engineRequests'],'maximumEngineRequests':12}


def budget_decision(case,p,now):
    return {'schema':GRANT,'decision':'GRANT_FOUR_TECHNICAL_REQUESTS_ONLY','proposalHash':e.c.digest(p),
        'approvedAt':now,'decisionRef':'operator-patch-oauth-budget-'+e.c.digest(p)[:24]+'-'+str(now),
        'authorEvidence':'EXPLICIT_LOCAL_OPERATOR_TTY_FRESH_PROVIDER_IDENTITY_STILL_REQUIRED',
        'intendedProviderPrincipal':copy.deepcopy(p['intendedProviderPrincipal']),'reason':p['reason'],
        'caseHash':e.c.digest(case),'priorOAuthAttempts':296,'maximumCumulativeOAuthAttempts':300,
        'budgetReset':False,'runtimeAuthorityIssued':False}


def granted(case,closure):
    c=e.c;p=proposal(case,closure);_,claim,target=paths(case,p)
    fence=custody.read(str(claim));decision=custody.read(str(target/'decision.json'))
    c.require(custody.read(str(target/'proposal.json'))==p and custody.read(str(target/'claim.json'))==fence
        and decision==budget_decision(case,p,decision['approvedAt'])
        and type(decision['approvedAt'])is int and decision['approvedAt']<=time.time()
        and fence=={'schema':GRANT,'proposalHash':c.digest(p),'decisionHash':c.digest(decision),
            'contextPath':str(target),'caseHash':c.digest(case),'sourceClosureHash':closure,
            'automaticReplayAllowed':False,'budgetReset':False},'EXACT_COMPLETED_PATCH_BUDGET_GRANT_REQUIRED')
    return p,decision,target


def budget_status(case,closure):
    p,decision,target=granted(case,closure)
    return {'status':'PATCH_TECHNICAL_BUDGET_GRANTED_NO_LOGIN_OR_RUNTIME_AUTHORITY','complete':True,
        'contextPath':str(target),'proposalHash':e.c.digest(p),'decisionHash':e.c.digest(decision),
        'decisionRef':decision['decisionRef'],
        'priorOAuthAttempts':296,'additionalOAuthAttemptsGranted':4,'maximumCumulativeOAuthAttempts':300,
        'countsAsOfGrant':True,'subsequentConsumptionNotObserved':True,'newHumanWindowOpened':False,
        'oauthRequests':0,'humanCredentialJournalsRead':0,'runtimeEffectsDispatched':0}


def fresh_review(case,closure):
    c=e.c;p,decision,target=granted(case,closure);config,profile=predecessor(case)
    # Credential journal read is internal only. Public history deliberately
    # excludes access/refresh/device values; no token file is opened or reused.
    row=json.loads(e.authority.private_file.read(profile['journal']))
    old=config['review'];binding=profile['expectedBinding']
    c.require(row['binding']==binding and row['state']=='READY'and type(row['attempts'])is int and row['attempts']==296
        and row['bootId']==profile['expectedBootId']==window.boot_id()
        and row['monotonicDeadline']==profile['expectedMonotonicDeadline']
        and row['budgetReset']is False and row['accessExpiresAt']<=time.time()
        and row['lastObservedAt']<=time.time()
        and row['governedWindowRenewal']=={'review':old,'decision':config['decision']},
        'EXACT_EXPIRED_READY296_PUBLIC_HISTORY_REQUIRED')
    history=copy.deepcopy(config['history']);history.update(minimumRetainedOAuthAttempts=296,maximumCumulativeOAuthAttempts=300)
    review=contract.validate_review({'schema':contract.SCHEMA,'predecessorDirectory':binding['sessionDirectory'],
        'predecessorPublicHistoryHash':c.digest(contract.public_history(row)),'predecessorBindingHash':c.digest(binding),
        'selectionHash':c.digest(profile['selection']),'bootId':row['bootId'],'priorOAuthAttempts':296,
        'maximumCumulativeOAuthAttempts':300,'maximumRemainingOAuthAttempts':4,'requestedScopes':copy.deepcopy(binding['scopes']),
        'newWindowSeconds':7200,'retainedOwnerHistory':history,'operationBinding':operation(case),
        'sourceClosureHash':closure,'predecessorWindowExpiresAt':binding['expiresAt'],
        'freshIssuerAuthenticationRequired':True,'oldCredentialsReusable':False,'oldRefreshReplayAllowed':False,
        'browserConfirmationPerPollRequired':True,'automaticRenewalAllowed':False,'automaticReplayAllowed':False,
        'budgetReset':False,'runtimeAuthorityIssued':False})
    return review,profile,row,decision,target


def open_window(case,closure):
    c=e.c;review,profile,old,grant_decision,root=fresh_review(case,closure)
    ctl=operator.control_path(review);dest=operator.successor_path(review);claim=root/'human-window.claim.json'
    original=Path(review['predecessorDirectory'])/'successor-window.claim.json'
    c.require(not any(os.path.lexists(p)for p in (claim,original,ctl,dest)),
        'PATCH_HUMAN_WINDOW_ALREADY_CLAIMED_RECONCILE_ONLY')
    probe=live_preflight(case)
    c.require(operator.terminal_confirm(
        'Apro UNA finestra HUMAN7200secondi per questa patch; budget concesso296/300.\n'
        'Ogni richiesta provider richiede un comando e conferma distinta; zero polling automatico o refresh.\n'
        'Sessione e credenziali precedenti non riutilizzate. Nessuna autorita runtime o attivazione fonte.',
        'APRO FINESTRA HUMAN '+c.digest(review))is True,'EXPLICIT_PATCH_WINDOW_CONSENT_REQUIRED')
    c.require(fresh_review(case,closure)[0]==review,'PATCH_HUMAN_HISTORY_CHANGED_AFTER_WINDOW_CONSENT')
    now=int(time.time());decision={'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':c.digest(review),
        'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}
    validate_consent(review,decision,time.time())
    binding=copy.deepcopy(old['binding']);binding.update(sessionId=str(uuid.UUID(c.digest(decision)[:32])),
        sessionDirectory=str(dest),tokenPath=str(dest/'human-access.jwt'),createdAt=now,expiresAt=decision['expiresAt'])
    binding['retryProfile'].update(id='ouf.human.ingestion-readiness-patch-budget-successor.v1',maximumAttempts=300)
    confirmed={'budgetDecisionHash':c.digest(grant_decision)}
    config={'schema':operator.CONFIG_SCHEMA,'review':review,'decision':decision,'selection':profile['selection'],
        'history':review['retainedOwnerHistory'],'predecessorJournal':profile['journal'],'sourceClosureHash':closure,
        'controlDirectory':str(ctl),'case':copy.deepcopy(case),'confirmedRead':confirmed}
    original_fence={'schema':'ouf.human-explicit-successor-claim.v1','reviewHash':c.digest(review),
        'decisionHash':c.digest(decision),'destination':str(dest),'priorOAuthAttempts':296,
        'maximumCumulativeOAuthAttempts':300,'expiresAt':decision['expiresAt'],'automaticReplayAllowed':False,
        'budgetReset':False,'runtimeAuthorityIssued':False}
    publish(original.parent,original.name,original_fence)
    publish(root,claim.name,{'schema':GRANT,'reviewHash':c.digest(review),'controlPath':str(ctl),
        'budgetDecisionHash':c.digest(grant_decision),'caseHash':c.digest(case),'automaticReplayAllowed':False})
    with e.authority.protected_directory(ctl.parent)as fd:
        os.mkdir(ctl.name,0o700,dir_fd=fd);os.mkdir(dest.name,0o700,dir_fd=fd);os.fsync(fd)
    operator.write_new(ctl,'control.json',config);operator.write_new(ctl,'binding.json',binding)
    e.Journal(dest).initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':binding,
        'bootId':review['bootId'],'monotonicDeadline':time.monotonic()+decision['expiresAt']-time.time(),
        'lastObservedAt':time.time(),'attempts':296,'state':'NEW','budgetReset':False,
        'governedWindowRenewal':{'review':review,'decision':decision}})
    return {'state':'NEW','complete':False,'attempts':296,'remainingAttempts':4,'maximumCumulativeOAuthAttempts':300,
        'controlPath':str(ctl),'windowExpiresAt':decision['expiresAt'],'newHumanWindowOpened':True,
        'oauthRequestsReservedThisInvocation':0,'engineRequests':probe['engineRequests'],'maximumEngineRequests':12}


def load(selected,case,closure):
    c=e.c;_,decision,root=granted(case,closure)
    confirmed={'budgetDecisionHash':c.digest(decision)}
    config,binding=operator.load_control(selected,case,confirmed,closure)
    c.require(custody.read(str(root/'human-window.claim.json'))=={'schema':GRANT,
        'reviewHash':c.digest(config['review']),'controlPath':selected,'budgetDecisionHash':c.digest(decision),
        'caseHash':c.digest(case),'automaticReplayAllowed':False}
        and config['review']['operationBinding']==operation(case)
        and config['review']['priorOAuthAttempts']==296 and config['review']['maximumCumulativeOAuthAttempts']==300,
        'SAME_PATCH_CONSUMED_GRANT_AND_BOUND_HUMAN_WINDOW_REQUIRED')
    return confirmed,config,binding


def execute(mode,selected,case,confirmed_read,closure):
    validate(case);c=e.c
    c.require(confirmed_read=={} and mode in ('prepare','grant-budget','budget-status','open-window','step','status','reconcile-read'),
        'ONE_EXPLICIT_PATCH_HUMAN_GOVERNANCE_MODE_REQUIRED')
    c.require((selected is None)==(mode in ('prepare','grant-budget','budget-status','open-window')),
        'EXACT_PATCH_HUMAN_CONTROL_ARGUMENT_REQUIRED')
    if mode=='prepare':
        p=proposal(case,closure);result={**live_preflight(case),'proposalHash':c.digest(p),
            'proposedAdditionalOAuthAttempts':4,'proposedCumulativeCeiling':300,'newBudgetGranted':False,
            'newHumanWindowOpened':False}
    elif mode=='grant-budget':result=grant(case,closure)
    elif mode=='budget-status':result=budget_status(case,closure)
    elif mode=='open-window':result=open_window(case,closure)
    else:
        confirmed,_,_=load(selected,case,closure)
        result={'step':operator.step,'status':operator.status,'reconcile-read':operator.reconcile_read}[mode](
            selected,case,confirmed,closure)
        if result.get('state')=='READY':result['productionTokenMarginCovered']=result.get('tokenSecondsRemaining',0)>930
    return {'schema':'ouf.ingestion-readiness-patch-human-governance-result.v1','complete':False,
        'runtimeAuthorityIssued':False,'budgetReset':False,'automaticReplayAllowed':False,'notReleaseAcceptance':True,
        'completedTechnicalPhases':8,'functionalMilestonesProven':4,**result}
