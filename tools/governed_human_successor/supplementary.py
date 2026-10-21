"""Explicit HUMAN successor carrying two immutable administrative ledgers.

Preparation is offline and authority-free. Opening a window is a separate tty
decision; each provider request remains an explicit foreground invocation.
Neither prior HUMAN tokens nor administrative tokens are reused.
"""
import copy
import os
from pathlib import Path
import time
import uuid
from tools.governed_human_successor import contract,operator,window,inspection
from tools.governed_human_successor.session import ExplicitFreshSession,validate_consent
from tools.ingestion_rollout_preparation import iam_lifetime_policy as lifetime
from tools.ingestion_rollout_preparation import iam_explicit_api as admin
from tools.ingestion_rollout_preparation import iam_policy_read as api
from tools.ingestion_rollout_preparation import human_timing as files
from tools.ingestion_rollout_execution.contract import require,digest,encoded,path
from tools.ingestion_rollout_execution import private_file
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import protected_directory

SCHEMA='ouf.human-supplementary-ledger-control.v1'
CHECKPOINT={'phase':'NOT_STARTED','controlPath':None}


def retained(case,closure):
    require(case.get('schema')=='ouf.human-supplementary-ledger-case.v1'
        and case.get('purpose')=='EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT'
        and case.get('expectedAttempts')==284 and case.get('maximumCumulativeOAuthAttempts')==288
        and case.get('requiredTokenMarginSeconds')==930,
        'EXACT_SUPPLEMENTARY_HUMAN_INSTALLATION_AND_BUDGET_REQUIRED')
    values,parent,prior,policy_review=lifetime.retained(case['lifetimeCase'],api,admin,files)
    old,context,session,selection,owner,prepared,endpoint,seals=values
    target=parent/'lifetime-policy-successor'
    row,seal=files.selected(str(target/'recovery.json'));seals.append(seal)
    claim,cseal=files.selected(str(parent/'provider-budget-successor.claim.json'));seals.append(cseal)
    require(row.get('schema')==lifetime.SCHEMA and row.get('caseHash')==digest(case['lifetimeCase'])
        and row.get('state')=='COMPLETE' and row.get('complete')is True
        and row.get('attempts')==284 and row.get('oauthRequestsReserved')==1
        and row.get('engineRequestsReserved')==2 and row.get('adminGetsReserved')==5
        and row.get('clientPutsReserved')==1 and row.get('grant')==claim
        and claim.get('destination')==str(target) and claim.get('review')==policy_review
        and claim.get('reviewHash')==digest(policy_review)
        and claim.get('priorAttempts')==283 and claim.get('maximumCumulativeOAuthAttempts')==288
        and claim.get('budgetReset')is claim.get('runtimeAuthorityIssued')is False
        and digest(row.get('result'))==case.get('lifetimeResultHash')
        and type(row.get('readbackComparison'))is dict and row['readbackComparison']
        and all(v is True for v in row['readbackComparison'].values()),
        'EXACT_COMPLETED_LIFETIME_LEDGER_CLAIM_AND_FULL_READBACK_REQUIRED')
    result=row['result']
    require(result.get('schema')=='ouf.iam-client-lifetime-result.v1'
        and result.get('status')=='CLIENT_LIFETIME_OVERRIDE_READBACK_NO_RUNTIME_AUTHORITY'
        and result.get('complete')is True and result.get('attempts')==284
        and result.get('remainingAttempts')==4 and result.get('maximumCumulativeOAuthAttempts')==288
        and result.get('publishedClientLifetimeSeconds')==1200
        and result.get('revocationFreshnessAllowanceApprovedSeconds')==1200
        and all(result.get(k)is True for k in ('realmLifetimeUnchanged','unrelatedClientFieldsUnchanged',
            'authenticationFlowFlagsUnchanged','priorContextsAndClaimsRetained','futureHumanMustConsumeSupplementaryLedger'))
        and all(result.get(k)is False for k in ('rolesChanged','runtimeAuthorityIssued','budgetReset',
            'newHumanWindowOpened','refreshPerformed'))
        and {k:result.get(k)for k in ('realm','clientId','clientUuid')}==policy_review['target'],
        'EXACT_SUCCESSFUL_SCOPED_LIFETIME_RESULT_REQUIRED')
    config,configseal=files.selected(old['humanControlPath']+'/control.json');seals.append(configseal)
    human,humans=files.selected(str(session/'recovery.json'));seals.append(humans)
    require(human.get('governedWindowRenewal')=={'review':config['review'],'decision':config['decision']},
        'EXACT_RETAINED_HUMAN_CONSENT_AND_CONTROL_REQUIRED')
    history=copy.deepcopy(config['history'])
    require(history['ownerPlanHash']==old['ownerPlanBinding']['sha256'],
        'SAME_ORIGINAL_COMPLETED_OWNER_HISTORY_REQUIRED')
    operations={**config['review']['operationBinding'],
        'administrative283CaseHash':digest(case['lifetimeCase']['originalApiCase']),
        'administrative283ResultHash':digest(prior),
        'administrative284CaseHash':digest(case['lifetimeCase']),
        'administrative284ResultHash':digest(result),
        'supplementarySuccessorCaseHash':digest(case)}
    review=contract.compile_review(selection,human,history,operations,closure,
        now=time.time(),monotonic=time.monotonic(),boot_id=window.boot_id())
    # The old journal stays at282. Carry283 and284 through the pinned ledger
    # chain rather than fabricating a rewritten predecessor public history.
    review['priorOAuthAttempts']=284;review['maximumRemainingOAuthAttempts']=4
    review['retainedOwnerHistory']['minimumRetainedOAuthAttempts']=284
    contract.validate_review(review)
    production=Path(old['productionContextPath'])
    ready,readyseal=files.selected(str(production/'operator-control/recovery.json'));seals.append(readyseal)
    require(ready.get('schema')=='ouf.ingestion-rollout-explicit-production-control.v1'
        and ready.get('state')=='PRIVATE_READY' and ready.get('complete')is False
        and ready.get('caseHash')==old['productionCaseHash']
        and ready.get('controlSourceHash')==old['productionControlSourceHash']
        and ready.get('preparationHash')==digest(prepared)
        and ready.get('runtimeAuthorityIssued')is ready.get('budgetReset')is False
        and not os.path.lexists(production/'recovery.json'),
        'UNCONSUMED_RETAINED_PRODUCTION_PREPARATION_REQUIRED_BEFORE_NEW_HUMAN')
    for seal in seals:files.recheck(seal)
    return review,{'selection':selection,'predecessorJournal':humans,'history':history,
        'ledgerDirectory':str(target),'seals':seals}


def prepare(case,closure):
    CHECKPOINT['phase']='RETAINED_FULL_LEDGER_CHAIN_AND_PRODUCTION_READINESS'
    operator.validate_transport(case)
    review,private=retained(case,closure)
    require(not os.path.lexists(Path(private['ledgerDirectory'])/'provider-budget-successor.claim.json')
        and not os.path.lexists(operator.control_path(review)),
        'SUPPLEMENTARY_SUCCESSOR_ALREADY_CONSUMED_STATUS_ONLY')
    return {'status':'SUPPLEMENTARY_HUMAN_REVIEW_READY_NO_AUTHORITY','complete':True,
        'readOnly':True,'reviewHash':digest(review),'attempts':284,'remainingAttempts':4,
        'oldHumanJournalAttempts':282,'administrativeLedgerAttempts':[283,284],
        'newHumanWindowOpened':False,'runtimePreparationRetained':True}


def claim_value(review,decision,private):
    return {'schema':SCHEMA,'reviewHash':digest(review),'decisionHash':digest(decision),
        'destination':str(operator.successor_path(review)),
        'controlPath':str(operator.control_path(review)),
        'priorOAuthAttempts':284,'maximumCumulativeOAuthAttempts':288,
        'ledgerDirectory':private['ledgerDirectory'],'expiresAt':decision['expiresAt'],
        'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'budgetReset':False}


def open_window(case,closure):
    operator.validate_transport(case)
    review,private=retained(case,closure)
    control=operator.control_path(review);destination=operator.successor_path(review)
    parent=Path(private['ledgerDirectory']);claim=parent/'provider-budget-successor.claim.json'
    CHECKPOINT.update(phase='EXPLICIT_SUPPLEMENTARY_HUMAN_WINDOW_CONSENT',controlPath=str(control))
    require(not any(os.path.lexists(v)for v in (control,destination,claim)),
        'SUPPLEMENTARY_SUCCESSOR_ALREADY_CONSUMED_STATUS_ONLY')
    require(operator.terminal_confirm('Apro UNA finestra HUMAN di7200secondi, senza richieste OAuth.\n'
        'Storico282+admin283+admin284 conservato:284/288, quattro richieste nominali senza riserva retry.\n'
        'Ogni richiesta successiva richiede un comando manuale e consenso distinto.\n'
        'Non modifico IAM, non riuso credenziali e non autorizzo runtime, fonti o THS.',
        'APRO FINESTRA HUMAN '+digest(review))is True,'FRESH_EXPLICIT_WINDOW_CONSENT_REQUIRED')
    now=int(time.time());decision={'schema':'ouf.human-login-window-terminal-consent.v1',
        'reviewHash':digest(review),'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY',
        'approvedAt':now,'expiresAt':now+7200}
    validate_consent(review,decision,time.time())
    with Journal(parent).invocation():
        for seal in private['seals']:files.recheck(seal)
        Journal(parent).create(claim,encoded(claim_value(review,decision,private)));Journal(parent).sync()
        # Any failure after claim consumes the operation. Never delete/reopen.
        with protected_directory(control.parent)as fd:
            os.mkdir(control.name,0o700,dir_fd=fd);os.mkdir(destination.name,0o700,dir_fd=fd);os.fsync(fd)
        previous=window.predecessor_row(private['predecessorJournal'])
        binding=copy.deepcopy(previous['binding'])
        binding.update(sessionId=str(uuid.UUID(digest(decision)[:32])),sessionDirectory=str(destination),
            tokenPath=str(destination/'human-access.jwt'),createdAt=now,expiresAt=decision['expiresAt'])
        binding['retryProfile']['id']='ouf.human.supplementary-ledger-successor.v1'
        config={'schema':SCHEMA,'review':review,'decision':decision,'selection':private['selection'],
            'predecessorJournal':private['predecessorJournal'],'sourceClosureHash':closure,
            'controlDirectory':str(control),'case':copy.deepcopy(case),'ledgerDirectory':str(parent)}
        operator.write_new(control,'control.json',config);operator.write_new(control,'binding.json',binding)
        Journal(destination).initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':binding,
            'bootId':review['bootId'],'monotonicDeadline':time.monotonic()+decision['expiresAt']-time.time(),
            'lastObservedAt':time.time(),'attempts':284,'state':'NEW','budgetReset':False,
            'governedWindowRenewal':{'review':review,'decision':decision}})
        for seal in private['seals']:files.recheck(seal)
    return {'state':'NEW','attempts':284,'remainingAttempts':4,'controlPath':str(control),
        'windowExpiresAt':decision['expiresAt'],'newHumanWindowOpened':True}


def load(control,case,closure):
    path(control);review,private=retained(case,closure)
    require(Path(control)==operator.control_path(review),'EXACT_SUPPLEMENTARY_CONTROL_PATH_REQUIRED')
    config,cseal=inspection.read_selected(control+'/control.json')
    require(config.get('schema')==SCHEMA and config.get('review')==review
        and config.get('case')==case and config.get('selection')==private['selection']
        and config.get('sourceClosureHash')==closure and config.get('controlDirectory')==control
        and config.get('ledgerDirectory')==private['ledgerDirectory']
        and config.get('predecessorJournal')==private['predecessorJournal'],
        'EXACT_SUPPLEMENTARY_CONTROL_SOURCE_SELECTION_AND_LEDGER_REQUIRED')
    validate_consent(review,config['decision'],config['decision']['approvedAt'])
    claim,seal=files.selected(private['ledgerDirectory']+'/provider-budget-successor.claim.json')
    require(claim==claim_value(review,config['decision'],private),
        'EXACT_CONSUMED_SUPPLEMENTARY_WINDOW_CLAIM_REQUIRED')
    binding,bseal=inspection.read_selected(control+'/binding.json')
    previous=window.predecessor_row(private['predecessorJournal']);expected=copy.deepcopy(previous['binding'])
    expected.update(sessionId=str(uuid.UUID(digest(config['decision'])[:32])),
        sessionDirectory=str(operator.successor_path(review)),
        tokenPath=str(operator.successor_path(review)/'human-access.jwt'),
        createdAt=config['decision']['approvedAt'],expiresAt=config['decision']['expiresAt'])
    expected['retryProfile']['id']='ouf.human.supplementary-ledger-successor.v1'
    require(binding==expected,'EXACT_SUPPLEMENTARY_PREPARED_SESSION_BINDING_REQUIRED')
    for s in (cseal,bseal,seal):files.recheck(s)
    return config,binding


def step(control,case,closure):
    config,binding=load(control,case,closure);operator.validate_transport(case)
    session=ExplicitFreshSession(config['selection'],binding,config['review'],config['decision'])
    row=session.journal.read();state=row['state'];effective=row.get('resumeState')if state=='RETRY_WAIT'else state
    if state=='RETRY_WAIT'and time.time()<row['nextAttemptAt']:
        return {**session.public_status(row),'controlPath':control,'status':'WAIT_EXPLICIT_STEP',
            'nextAttemptAt':row['nextAttemptAt']}
    confirmation=None;CHECKPOINT['phase']='ONE_EXPLICIT_PROVIDER_CONFIRMATION'
    if effective=='DEVICE_POLL':
        if time.time()<row['nextPollAt']:
            return {**session.public_status(row),'controlPath':control,'status':'WAIT_EXPLICIT_STEP',
                'nextAttemptAt':row['nextPollAt']}
        challenge=session.browser_challenge(row)
        operator.terminal_notice('Apri nel browser del cellulare '+challenge['verificationUri']+
            '\nInserisci il codice '+challenge['userCode']+
            '\nCompleta tutta l\'autenticazione e autorizzazione. Non serve la console amministrativa.')
        require(operator.terminal_confirm('Solo dopo conferma positiva nel browser autorizza UNA richiesta token.\n'
            'Un esito pending consuma budget: nessun polling automatico.',
            'LOGIN COMPLETATO '+digest(challenge))is True,'CURRENT_BROWSER_CONFIRMATION_FOR_ONE_POLL_REQUIRED')
        confirmation={'challengeHash':digest(challenge),'confirmedAt':time.time()}
    elif effective in ('NEW','DEVICE_START','VERIFYING'):
        operation={'NEW':'DISCOVERY','DEVICE_START':'DEVICE_START','VERIFYING':'USERINFO'}[effective]
        require(operator.terminal_confirm('Autorizzi UNA richiesta '+operation+' al provider selezionato.\n'
            'Conteggio '+str(row['attempts'])+'/288; nessun refresh o autorita runtime.',
            'ESEGUI '+operation+' '+digest(config['review']))is True,'EXPLICIT_PROVIDER_REQUEST_CONFIRMATION_REQUIRED')
    else:require(effective=='READY','STOP_RECONCILE_NO_AMBIGUOUS_AUTHENTICATION_REPLAY')
    result=session.step(confirmation);following=session.journal.read()
    result.update(controlPath=control,oauthRequestsReservedThisInvocation=following['attempts']-row['attempts'])
    if following['state']=='DEVICE_POLL':
        operator.terminal_notice('ORA apri '+following['verificationUri']+' nel browser del cellulare.\n'
            'Codice: '+following['userCode']+'\nCompleta il login prima del prossimo comando step.')
    if following['state']=='READY':
        remaining=int(following['accessExpiresAt']-time.time())
        result.update(providerVerificationCompleted=True,tokenSecondsRemaining=max(0,remaining),
            productionTokenMarginCovered=remaining>case['requiredTokenMarginSeconds'],
            privateHumanReadProfilePath=operator.publish_private_reader(control,session,following),
            nativeClientProfilePublished=False,complete=True)
    return result


def status(control,case,closure):
    config,binding=load(control,case,closure);row=Journal(Path(binding['sessionDirectory'])).read()
    require(row.get('binding')==binding and row.get('budgetReset')is False
        and type(row.get('attempts'))is int and 284<=row['attempts']<=288,
        'EXACT_SUPPLEMENTARY_STATUS_HISTORY_REQUIRED')
    return {'status':'SUPPLEMENTARY_STATUS_METADATA_ONLY','readOnly':True,'controlPath':control,
        'state':row['state'],'attempts':row['attempts'],'remainingAttempts':288-row['attempts'],
        'windowExpiresAt':binding['expiresAt'],'windowOpen':time.time()<binding['expiresAt']
        and time.monotonic()<row['monotonicDeadline'] and row['bootId']==window.boot_id()}


def execute(mode,control,case,confirmed_read,closure):
    started=time.time();clock=time.monotonic()
    require(confirmed_read=={},'SUPPLEMENTARY_CHAIN_REPLACES_OLD_SUCCESSFUL_READ_SELECTION')
    CHECKPOINT.update(phase='LOAD_SUPPLEMENTARY_CHAIN',controlPath=control)
    require(mode in ('prepare','open-window','step','status'),'ONE_EXPLICIT_SUPPLEMENTARY_MODE_REQUIRED')
    if mode in ('prepare','open-window'):
        require(control is None,'SUPPLEMENTARY_CONTROL_DERIVED_FROM_REVIEW')
        result=prepare(case,closure)if mode=='prepare'else open_window(case,closure)
    else:
        require(type(control)is str,'EXACT_SUPPLEMENTARY_CONTROL_ARGUMENT_REQUIRED')
        result=step(control,case,closure)if mode=='step'else status(control,case,closure)
    return {'schema':'ouf.human-supplementary-ledger-result.v1','complete':False,
        'oauthRequestsReservedThisInvocation':0,'maximumCumulativeOAuthAttempts':288,
        'runtimeAuthorityIssued':False,'budgetReset':False,'automaticReplayAllowed':False,
        'completedOwnerActionReplayed':False,'completedPublicationReplayed':False,
        'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True,
        'startedAtUnix':started,'finishedAtUnix':time.time(),'elapsedSeconds':time.monotonic()-clock,**result}
