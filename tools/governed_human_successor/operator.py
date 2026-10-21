"""Explicit operator modes for one approved fresh HUMAN window.

Opening a window and each network request are separate invocations with a
controlling-terminal confirmation. Never starts a retry/poll/refresh loop.
The private HUMAN read profile is not a published native client profile.
"""
import copy
import json
import os
from pathlib import Path
import select
import stat
import termios
import time
from tools.ingestion_rollout_execution.contract import require,digest,encoded,path
from tools.ingestion_rollout_execution import human_reader,private_file
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.governed_human_successor import inspection,window
from tools.governed_human_successor.contract import validate_review
from tools.governed_human_successor.session import ExplicitFreshSession,validate_consent

CONFIG_SCHEMA='ouf.human-explicit-successor-control.v1'
CONFIG_FIELDS={'schema','review','decision','selection','history','predecessorJournal',
    'sourceClosureHash','controlDirectory','case','confirmedRead'}
CHECKPOINT={'phase':'NOT_STARTED','controlPath':None}
TRANSPORT={'schema':'ouf.human-operator-platform-tls-direct.v1',
    'platformSystemTrust':True,'httpsProxyAllowed':False,'environmentTrustOverridesAllowed':False}

def validate_transport(case):
    require(case.get('humanOperatorTransportProfile')==TRANSPORT,
            'EXPLICIT_QUALIFIED_PLATFORM_TLS_DIRECT_PROFILE_REQUIRED')
    forbidden=('SSL_CERT_FILE','SSL_CERT_DIR','HTTPS_PROXY','HTTP_PROXY','ALL_PROXY',
        'https_proxy','http_proxy','all_proxy')
    require(not any(os.environ.get(k)for k in forbidden),
            'UNREVIEWED_TLS_OR_PROXY_ENVIRONMENT_OVERRIDE_FORBIDDEN')

def terminal_confirm(summary,phrase):
    """No piped approval, prefetched answer, secret input or automatic retry."""
    require(type(summary)is str and len(summary)<=8192 and type(phrase)is str
        and len(phrase)<=200,'BOUNDED_OPERATOR_TERMINAL_PROMPT_REQUIRED')
    fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode)and os.isatty(fd),'CONTROLLING_HUMAN_TERMINAL_REQUIRED')
        termios.tcflush(fd,termios.TCIFLUSH)
        os.write(fd,('\n'+summary+'\nScrivi esattamente: '+phrase+'\n> ').encode())
        require(bool(select.select([fd],[],[],60)[0]),'HUMAN_TERMINAL_CONFIRMATION_TIMEOUT_NO_EFFECT')
        answer=os.read(fd,1024)
        require(answer==phrase.encode('ascii')+b'\n','EXACT_HUMAN_TERMINAL_CONFIRMATION_REQUIRED')
        return True
    finally:os.close(fd)

def terminal_notice(summary):
    require(type(summary)is str and len(summary)<=8192,'BOUNDED_OPERATOR_TERMINAL_NOTICE_REQUIRED')
    fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode)and os.isatty(fd),'CONTROLLING_HUMAN_TERMINAL_REQUIRED')
        os.write(fd,('\n'+summary+'\n').encode())
    finally:os.close(fd)

def control_path(review):
    return Path(review['predecessorDirectory']).parent/('human-successor-control-'+digest(review))

def successor_path(review):
    return Path(review['predecessorDirectory']).parent/('human-successor-'+digest(review))

def write_new(directory,name,value):
    require(name in('control.json','binding.json','human-read-profile.json'),
            'EXACT_PRIVATE_SUCCESSOR_CONTROL_MEMBER_REQUIRED')
    journal=Journal(directory);journal.create(Path(directory)/name,encoded(value));journal.sync()

def prepare_review(case,confirmed_read,source_closure_hash):
    require(type(confirmed_read)is dict and set(confirmed_read)=={'reviewHash','sourceClosureHash'},
            'EXACT_PREDECESSOR_SUCCESSFUL_READ_REQUIRED')
    review,private=inspection.inspect_retained(case,source_closure_hash)
    # Inspection reviews contain no observation timestamp. Bind the same public
    # history and operation to the prior successful read without executing it.
    prior={**copy.deepcopy(review),'sourceClosureHash':confirmed_read['sourceClosureHash']}
    require(digest(prior)==confirmed_read['reviewHash'],
            'SUCCESSFUL_READ_HISTORY_CHANGED_RECONCILE_BEFORE_WINDOW')
    return review,private

def open_window(case,confirmed_read,source_closure_hash):
    CHECKPOINT.update(phase='RECONCILE_SUCCESSFUL_READ',controlPath=None)
    validate_transport(case)
    review,private=prepare_review(case,confirmed_read,source_closure_hash)
    control=control_path(review)
    CHECKPOINT.update(phase='EXPLICIT_TERMINAL_WINDOW_CONSENT',controlPath=str(control))
    require(not os.path.lexists(control)and not os.path.lexists(
        Path(review['predecessorDirectory'])/'successor-window.claim.json'),
        'EXISTING_SUCCESSOR_OR_CONTROL_REQUIRES_RECONCILIATION_NO_REOPEN')
    summary=('Apro UNA nuova finestra HUMAN di7200secondi. Storico '+str(review['priorOAuthAttempts'])+
        '/'+str(review['maximumCumulativeOAuthAttempts'])+' conservato; massimo '+
        str(review['maximumRemainingOAuthAttempts'])+' richieste residue, nessun reset.\n'
        'Credenziali precedenti non riutilizzate. Nessuna richiesta OAuth in questa apertura.\n'
        'Ogni successiva richiesta richiede un comando e una conferma distinti.\n'
        'Non autorizza Owner, THS, DB, Gateway, runtime, fonti/job o pubblicazione profili.\n'
        'Revisione: '+digest(review))
    require(terminal_confirm(summary,'APRO FINESTRA HUMAN '+digest(review))is True,
            'FRESH_EXPLICIT_WINDOW_CONSENT_REQUIRED')
    now=int(time.time());decision={'schema':'ouf.human-login-window-terminal-consent.v1',
        'reviewHash':digest(review),'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY',
        'approvedAt':now,'expiresAt':now+review['newWindowSeconds']}
    config={'schema':CONFIG_SCHEMA,'review':review,'decision':decision,
        'selection':private['selection'],'history':private['history'],
        'predecessorJournal':private['predecessorJournal'],'sourceClosureHash':source_closure_hash,
        'controlDirectory':str(control),'case':copy.deepcopy(case),'confirmedRead':copy.deepcopy(confirmed_read)}
    # A partial control is retained. Never remove/recreate it or replay open.
    CHECKPOINT['phase']='PRIVATE_CONTROL_PREPARATION_AFTER_CONSENT'
    with protected_directory(control.parent)as parent:
        os.mkdir(control.name,0o700,dir_fd=parent);os.fsync(parent)
    write_new(control,'control.json',config)
    CHECKPOINT['phase']='ONE_WINDOW_CLAIM_AND_SESSION_INITIALIZATION'
    binding=window.initialize(review,decision,private['predecessorJournal'],private['selection'],private['history'])
    write_new(control,'binding.json',binding)
    CHECKPOINT['phase']='COMPLETE_WINDOW_OPEN_NO_OAUTH'
    return {'state':'NEW','attempts':review['priorOAuthAttempts'],
        'remainingAttempts':review['maximumRemainingOAuthAttempts'],
        'maximumCumulativeOAuthAttempts':review['maximumCumulativeOAuthAttempts'],
        'controlPath':str(control),'windowExpiresAt':decision['expiresAt'],
        'newWindowOpened':True,'oauthRequestsReservedThisInvocation':0}

def load_control(control,case,confirmed_read,source_closure_hash):
    CHECKPOINT.update(phase='LOAD_EXACT_PRIVATE_CONTROL',controlPath=control)
    control=Path(path(control));config,seal=inspection.read_selected(str(control/'control.json'))
    require(type(config)is dict and set(config)==CONFIG_FIELDS and config['schema']==CONFIG_SCHEMA
        and config['sourceClosureHash']==source_closure_hash
        and config['case']==case and config['confirmedRead']==confirmed_read,
        'EXACT_APPROVED_SUCCESSOR_CONTROL_SOURCE_AND_CASE_REQUIRED')
    review=validate_review(config['review'])
    validate_consent(review,config['decision'],config['decision']['approvedAt'])
    require(control==control_path(review)and str(control)==config['controlDirectory']
        and review['sourceClosureHash']==source_closure_hash
        and digest(config['selection'])==review['selectionHash']
        and config['history']==review['retainedOwnerHistory'],
        'EXACT_CONTROL_REVIEW_SELECTION_AND_HISTORY_REQUIRED')
    binding,binding_seal=inspection.read_selected(str(control/'binding.json'))
    require(binding.get('sessionDirectory')==str(successor_path(review)),
            'EXACT_PREPARED_SUCCESSOR_DESTINATION_REQUIRED')
    claim,claim_seal=inspection.read_selected(str(Path(review['predecessorDirectory'])/'successor-window.claim.json'))
    expected={'schema':'ouf.human-explicit-successor-claim.v1','reviewHash':digest(review),
        'decisionHash':digest(config['decision']),'destination':str(successor_path(review)),
        'priorOAuthAttempts':review['priorOAuthAttempts'],
        'maximumCumulativeOAuthAttempts':review['maximumCumulativeOAuthAttempts'],
        'expiresAt':config['decision']['expiresAt'],'automaticReplayAllowed':False,
        'budgetReset':False,'runtimeAuthorityIssued':False}
    require(claim==expected,'EXACT_CONSUMED_WINDOW_CLAIM_REQUIRED')
    for selected in(seal,binding_seal,claim_seal,config['predecessorJournal']):private_file.check_metadata(selected)
    return config,binding

def publish_private_reader(control,session,row):
    require(row['state']=='READY','VERIFIED_READY_HUMAN_REQUIRED')
    read_row,seal=inspection.read_selected(str(session.journal.record))
    require(read_row==row,'READY_JOURNAL_CHANGED_BEFORE_PRIVATE_READER_BINDING')
    profile={'schema':human_reader.SCHEMA,'selection':copy.deepcopy(session.selection),
        'expectedBinding':copy.deepcopy(row['binding']),'journal':seal,
        'minimumCumulativeAttempts':row['attempts'],'maximumCumulativeAttempts':session.maximum,
        'expectedBootId':row['bootId'],'expectedMonotonicDeadline':row['monotonicDeadline'],
        'governedWindowReceiptHash':digest(row['governedWindowRenewal']),
        'readOnly':True,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    human_reader.open_existing(profile).current()
    selected=Path(control)/'human-read-profile.json'
    if os.path.lexists(selected):
        previous,_=inspection.read_selected(str(selected))
        require(previous==profile,'PRIVATE_HUMAN_READER_ALREADY_PUBLISHED_DIFFERENT_BINDING')
    else:write_new(control,'human-read-profile.json',profile)
    return str(selected)

def step(control,case,confirmed_read,source_closure_hash):
    config,binding=load_control(control,case,confirmed_read,source_closure_hash)
    validate_transport(case)
    session=ExplicitFreshSession(config['selection'],binding,config['review'],config['decision'])
    row=session.journal.read();state=row['state'];effective=row.get('resumeState')if state=='RETRY_WAIT'else state
    if state=='RETRY_WAIT'and time.time()<row['nextAttemptAt']:
        return {**session.public_status(row),'controlPath':control,'status':'WAIT_EXPLICIT_STEP',
            'nextAttemptAt':row['nextAttemptAt'],'oauthRequestsReservedThisInvocation':0}
    confirmation=None
    CHECKPOINT['phase']='EXPLICIT_TERMINAL_PROVIDER_CONFIRMATION'
    if effective=='DEVICE_POLL':
        if time.time()<row['nextPollAt']:
            return {**session.public_status(row),'controlPath':control,'status':'WAIT_EXPLICIT_STEP',
                'nextAttemptAt':row['nextPollAt'],'oauthRequestsReservedThisInvocation':0}
        challenge=session.browser_challenge(row)
        summary=('LOGIN NEL BROWSER: apri URL '+json.dumps(challenge['verificationUri'])+
            '\nInserisci codice '+json.dumps(challenge['userCode'])+
            '\nCompleta il login; solo dopo conferma UNA richiesta token. Nessun polling automatico.')
        require(terminal_confirm(summary,'LOGIN COMPLETATO '+digest(challenge))is True,
                'CURRENT_BROWSER_CONFIRMATION_FOR_ONE_POLL_REQUIRED')
        confirmation={'challengeHash':digest(challenge),'confirmedAt':time.time()}
    elif effective in('NEW','DEVICE_START','VERIFYING'):
        operation={'NEW':'DISCOVERY','DEVICE_START':'DEVICE_START','VERIFYING':'USERINFO'}[effective]
        require(terminal_confirm('Autorizzi UNA richiesta '+operation+' al provider selezionato.\n'
            'Conteggio '+str(row['attempts'])+'/'+str(session.maximum)+'; nessun refresh o autorita runtime.',
            'ESEGUI '+operation+' '+digest(config['review']))is True,
            'EXPLICIT_PROVIDER_REQUEST_CONFIRMATION_REQUIRED')
    else:require(effective=='READY','STOP_RECONCILE_NO_AMBIGUOUS_AUTHENTICATION_REPLAY')
    CHECKPOINT['phase']='ONE_EXPLICIT_PROVIDER_STEP'
    result=session.step(confirmation);following=session.journal.read()
    result.update(controlPath=control,oauthRequestsReservedThisInvocation=following['attempts']-row['attempts'])
    if following['state']=='DEVICE_POLL':
        terminal_notice('LOGIN NEL BROWSER: URL '+json.dumps(following['verificationUri'])+
            '\nCodice '+json.dumps(following['userCode'])+
            '\nCompleta ora il login. Poi usa il prossimo comando manuale: richiedera conferma prima di UN polling.')
    if following['state']=='READY':
        CHECKPOINT['phase']='PRIVATE_HUMAN_READ_BINDING_NO_CLIENT_PUBLICATION'
        result.update(providerVerificationCompleted=True,
            tokenSecondsRemaining=max(0,int(following['accessExpiresAt']-time.time())),
            privateHumanReadProfilePath=publish_private_reader(control,session,following),
            nativeClientProfilePublished=False,complete=True)
    CHECKPOINT['phase']='COMPLETE_EXPLICIT_STEP'
    return result

def status(control,case,confirmed_read,source_closure_hash):
    config,binding=load_control(control,case,confirmed_read,source_closure_hash)
    row=Journal(Path(binding['sessionDirectory'])).read();review=config['review']
    require(row.get('binding')==binding and type(row.get('attempts'))is int
        and review['priorOAuthAttempts']<=row['attempts']<=review['maximumCumulativeOAuthAttempts']
        and row.get('budgetReset')is False,'RETAINED_SUCCESSOR_STATUS_HISTORY_REQUIRED')
    try:observed_boot=window.boot_id()
    except OSError:observed_boot=None
    return {'state':row['state'],'attempts':row['attempts'],
        'maximumCumulativeOAuthAttempts':review['maximumCumulativeOAuthAttempts'],
        'remainingAttempts':review['maximumCumulativeOAuthAttempts']-row['attempts'],
        'controlPath':control,'windowExpiresAt':binding['expiresAt'],
        'windowOpen':time.time()<binding['expiresAt']and time.monotonic()<row['monotonicDeadline']
            and observed_boot is not None and row['bootId']==observed_boot,
        'bootEvidenceAvailable':observed_boot is not None,
        'oauthRequestsReservedThisInvocation':0,'statusIsRuntimeAuthority':False}

def reconcile_read(control,case,confirmed_read,source_closure_hash):
    config,binding=load_control(control,case,confirmed_read,source_closure_hash)
    session=ExplicitFreshSession(config['selection'],binding,config['review'],config['decision'])
    require(terminal_confirm('Riconcilio soltanto una lettura persa, senza richiesta al provider o nuovo budget.',
        'RICONCILIO LETTURA '+digest(config['review']))is True,'EXPLICIT_LOST_READ_RECONCILIATION_REQUIRED')
    return {**session.reconcile_read(),'controlPath':control,'oauthRequestsReservedThisInvocation':0}

def execute(mode,control,case,confirmed_read,source_closure_hash):
    require(mode in('open-window','step','status','reconcile-read'),'ONE_EXPLICIT_HUMAN_OPERATOR_MODE_REQUIRED')
    if mode=='open-window':
        require(control is None,'OPEN_WINDOW_DERIVES_ONE_EXACT_CONTROL_PATH')
        result=open_window(case,confirmed_read,source_closure_hash)
    else:
        require(type(control)is str,'EXACT_RETAINED_CONTROL_PATH_REQUIRED')
        result={'step':step,'status':status,'reconcile-read':reconcile_read}[mode](
            control,case,confirmed_read,source_closure_hash)
    return {'schema':'ouf.human-explicit-successor-operator-result.v1','complete':False,**result,
        'runtimeAuthorityIssued':False,'budgetReset':False,'automaticReplayAllowed':False,
        'completedOwnerActionReplayed':False,'completedPublicationReplayed':False,
        'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}
