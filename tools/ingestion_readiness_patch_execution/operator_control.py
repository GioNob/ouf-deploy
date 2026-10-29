"""Explicit patch control around the immutable native entry. No authentication.

This stdlib-only bridge receives verified-memory native/custody namespaces.
Preflight/status never open HUMAN journals. All effects require exact separate
infrastructure consent, real role signatures and one explicit native invocation.
"""
import copy
import os
from pathlib import Path
import time

SCHEMA='ouf.ingestion-readiness-patch-control-case.v1'
ROW='ouf.ingestion-readiness-patch-operator-control.v1'
CUSTODY='tools.ingestion_readiness_patch_execution.custody'


def validate_case(e,manifest,case,control_hash,reader):
    c=e.c
    c.require(type(case)is dict and set(case)=={'schema','snapshotRoot','nativeInputsPath','nativeInputsHash',
        'nativeReceiptHash','parentInputsHash','logicalOperationRef','configurationImageId','nativeImageId',
        'nativeArchiveSha256','candidateSourceCommit','plannedStages','nativeDeclarationHash','qualification',
        'requiredCumulativeOAuthAttempts','maximumRuntimeSeconds','controlSourceHash'}
        and case['schema']==SCHEMA,'EXACT_PATCH_OPERATOR_CASE_REQUIRED')
    for k in ('nativeInputsHash','nativeReceiptHash','parentInputsHash','logicalOperationRef','nativeArchiveSha256',
              'nativeDeclarationHash','controlSourceHash'):c.require(c.hashed(case[k]),'EXACT_PATCH_CASE_HASHES_REQUIRED')
    c.require(control_hash==case['controlSourceHash'] and c.digest(manifest)==case['nativeDeclarationHash']
        and manifest.get('entryModule')==e.__name__ and manifest.get('moduleCount')==139
        and getattr(e,'__qualified_source_sha256__',None)==manifest['sourceHashes'].get(e.__name__)
        and c.hashed(getattr(e,'__qualified_source_sha256__',None))
        and getattr(reader,'__qualified_source_sha256__',None)==manifest['sourceHashes'].get(CUSTODY)
        and c.hashed(getattr(reader,'__qualified_source_sha256__',None)),
        'EXACT_SEALED_PATCH_ENTRY_CUSTODY_AND_OPERATOR_REQUIRED')
    c.path(case['snapshotRoot']);c.path(case['nativeInputsPath'])
    path=Path(case['nativeInputsPath'])
    c.require(path.name=='native-inputs.json'and path.parent.parent==Path(case['snapshotRoot'])
        and type(case['plannedStages'])is int and 12<=case['plannedStages']<=19
        and type(case['requiredCumulativeOAuthAttempts'])is int and case['requiredCumulativeOAuthAttempts']==296
        and type(case['maximumRuntimeSeconds'])is int and case['maximumRuntimeSeconds']==900,
        'FINITE_PATCH_INPUT_PATH_STAGES_AND_RETAINED292_HISTORY_REQUIRED')
    return case


def retained(e,case,reader):
    c=e.c;bundle=reader.read(case['nativeInputsPath'],case['nativeInputsHash'])
    receipt=reader.read(str(Path(case['nativeInputsPath']).parent/'complete.json'),case['nativeReceiptHash'])
    c.require(receipt.get('schema')=='ouf.ingestion-readiness-native-archive-result.v1'
        and receipt.get('status')=='NATIVE_ARCHIVE_INPUTS_PREPARED_NO_AUTHORITY'and receipt.get('complete')is True
        and receipt.get('bundleHash')==case['nativeInputsHash']
        and receipt.get('parentInputsHash')==case['parentInputsHash']
        and receipt.get('logicalOperationRef')==case['logicalOperationRef']
        and receipt.get('configurationImageId')==case['configurationImageId']
        and receipt.get('nativeImageId')==case['nativeImageId']
        and receipt.get('nativeArchiveSha256')==case['nativeArchiveSha256']
        and receipt.get('plannedStages')==case['plannedStages']
        and receipt.get('contextPath')==str(Path(case['nativeInputsPath']).parent)
        and all(receipt.get(k)is False for k in ('automaticReplayAllowed','budgetReset','runtimeAuthorityIssued',
            'nativeRuntimeExecutorQualified','targetApplyAuthorized','releaseAcceptance','imageRebuilt','liveRuntimeReverified'))
        and all(type(receipt.get(k))is int and receipt[k]==0 for k in ('imagesImported','engineRequests',
            'oauthRequests','credentialFilesOpened','runtimeEffectsDispatched')),
        'EXACT_COMPLETED_NATIVE_ARCHIVE_RECEIPT_REQUIRED_NO_REPLAY')
    c.require(bundle['candidate']['Id']==case['configurationImageId']
        and bundle['candidate']['Config']['Labels']['org.opencontainers.image.revision']==case['candidateSourceCommit']
        and bundle['nativeArchiveAudit']['nativeIdentity']['nativeImageId']==case['nativeImageId']
        and bundle['nativeArchiveAudit']['archiveSha256']==case['nativeArchiveSha256']
        and bundle['nativeArchivePreparation']['parentNativeInputsHash']==case['parentInputsHash']
        and bundle['finiteIntentContract']['logicalOperationRef']==case['logicalOperationRef']
        and len(c.stages(bundle))==case['plannedStages'],'SAME_NATIVE_ARCHIVE_LOGICAL_OPERATION_AND_INTENTS_REQUIRED')
    archive=bundle['imageImportProfile']['archive']
    e.authority.private_file.check_metadata(archive,maximum=2147483648)
    return bundle


def closure(e,manifest,bundle):
    a=e.authority;c=e.c
    python=copy.deepcopy(bundle['ownerControlProfile']['pythonExecutable'])
    c.require(all(bundle[k]['pythonExecutable']==python for k in ('unchangedGatewayTransportProfile','ingestionReadinessProfile')),
              'SAME_REVIEWED_PATCH_TRANSPORT_PYTHON_REQUIRED')
    programs={'python':python,'docker':copy.deepcopy(bundle['databaseControlProfile']['dockerExecutable']),
              'openssl':copy.deepcopy(bundle['historicalSourceClosure']['executables']['openssl'])}
    library=a.stdlib_binding()
    result={'declaration':copy.deepcopy(manifest),'executables':programs,
            'stdlibHash':c.digest(library),'stdlibFileCount':len(library['fileHashes'])}
    a.verify_closure(result)
    return result


def preflight(e,manifest,case,reader):
    b=retained(e,case,reader);sealed=closure(e,manifest,b)
    candidate={'nativeImageId':case['nativeImageId'],'sourceCommit':case['candidateSourceCommit']}
    e.authority.qualification_valid(case['qualification'],sealed,candidate)
    e.authority.current_issuer(b['retainedIssuerProfile'],int(time.time())+900)
    return {'status':'PATCH_RUNTIME_PREFLIGHT_NO_AUTHORITY','complete':True,'readOnly':True,
        'plannedStages':case['plannedStages'],'nativeInputBundleHash':case['nativeInputsHash'],
        'humanCredentialJournalsRead':0,'engineRequests':0,'databaseCalls':0,'runtimeEffectsDispatched':0,
        'runtimeAuthorityIssued':False,'oauthRequests':0,'newLoginPerformed':False,'refreshPerformed':False}


def human(e,case,profile):
    c=e.c;p=e.human_reader.validate(profile);ceiling=case['requiredCumulativeOAuthAttempts']
    c.require(p['minimumCumulativeAttempts']==p['maximumCumulativeAttempts']==ceiling
        and p['governedWindowReceiptHash']is not None,
        'NEW_GOVERNED_HUMAN296_HISTORY_REQUIRED_NO_RESET_OR_AUTHENTICATION_FALLBACK')
    h=e.human_reader.open_existing(p);renewal=h._read()['governedWindowRenewal'];review=renewal['review']
    c.require(review.get('priorOAuthAttempts')==292 and review.get('maximumCumulativeOAuthAttempts')==296
        and review.get('operationBinding')=={'runtimeCaseHash':c.digest(case),'nativeInputsHash':case['nativeInputsHash'],
            'logicalOperationRef':case['logicalOperationRef'],'controlSourceHash':case['controlSourceHash']},
        'CURRENT_HUMAN_WINDOW_MUST_BIND_THIS_EXACT_PATCH_AND_RETAIN292_HISTORY')
    return h


def context(e,case):
    return Path(case['snapshotRoot'])/('ingestion-readiness-execution-'+e.c.digest(case))


def publish(e,target,name,value):
    journal=e.Journal(target);journal.create(Path(target)/name,e.c.encoded(value));journal.sync()


def update(journal,**changes):
    row=journal.read();journal.compare_and_save(row,{**row,**changes});return journal.read()


def operator_binding(e,case):
    return {'caseHash':e.c.digest(case),'controlSourceHash':case['controlSourceHash'],
            'nativeInputsHash':case['nativeInputsHash'],'modeContract':'EXPLICIT_ONE_PATCH_STAGE_NO_REPLAY_V1'}


def action_review(e,manifest,case,bundle,profile,sealed):
    h=human(e,case,profile);c=e.c;a=e.authority
    native,packet=a.native_review.compile_review(bundle,{'path':case['nativeInputsPath'],'sha256':case['nativeInputsHash']},
        h.current(),str(context(e,case)),human_read_profile=profile)
    review=a.compile_action_review(native,packet,sealed,bundle['retainedIssuerProfile'],case['qualification'],900)
    review['absoluteExpiresAt']=min(h.expires_at-5,int(h._read()['accessExpiresAt'])-30)
    review['operatorControlBinding']=operator_binding(e,case)
    a.validate_action_review(review)
    return review,packet,h


def review(e,manifest,case,reader,profile_path):
    c=e.c;target=context(e,case)
    claim=Path(case['snapshotRoot'])/('ingestion-readiness-review-'+case['logicalOperationRef']+'.claim.json')
    c.require(not os.path.lexists(target)and not os.path.lexists(claim),'PATCH_REVIEW_ALREADY_CLAIMED_RECONCILE_ONLY')
    b=retained(e,case,reader);profile=reader.read(c.path(profile_path));h=human(e,case,profile)
    c.require(h._read()['accessExpiresAt']>time.time()+930,'CURRENT_PATCH_HUMAN_TOKEN_MARGIN930_REQUIRED_NO_REFRESH')
    sealed=closure(e,manifest,b);e.authority.current_issuer(b['retainedIssuerProfile'],int(time.time())+900)
    selected,packet,h=action_review(e,manifest,case,b,profile,sealed)
    material={'caseHash':c.digest(case),'sourceClosure':sealed,'nativeInputsHash':case['nativeInputsHash'],
              'humanProfileHash':c.digest(profile),'operatorControlBinding':operator_binding(e,case)}
    # Atomic one-use global claim precedes context publication. Partial results
    # remain visible and block another review; no replacement of expired claims.
    root=Path(case['snapshotRoot'])
    with e.authority.protected_directory(root)as fd:
        e.Journal(root).create(claim,c.encoded({'schema':ROW,'caseHash':c.digest(case),
            'logicalOperationRef':case['logicalOperationRef'],'contextPath':str(target),
            'reviewHash':c.digest(selected),'automaticReplayAllowed':False,'budgetReset':False}))
        e.Journal(root).sync();os.mkdir(target.name,0o700,dir_fd=fd);os.fsync(fd)
    with e.authority.protected_directory(target)as fd:os.mkdir('operator-control',0o700,dir_fd=fd);os.fsync(fd)
    journal=e.Journal(target/'operator-control');journal.initialize({'schema':ROW,'caseHash':c.digest(case),
        'state':'REVIEW_COMPILING','reviewHash':c.digest(selected),'packetHash':c.digest(packet),
        'materialHash':c.digest(material),'complete':False,'budgetReset':False,'runtimeAuthorityIssued':False})
    for name,value in (('material.json',material),('human-profile.json',profile),('packet.json',packet),('review.json',selected)):
        publish(e,target,name,value)
    update(journal,state='REVIEW_READY')
    return {'status':'PATCH_RUNTIME_REVIEW_READY_EXPLICIT_APPROVAL_REQUIRED','contextPath':str(target),'complete':False,
        'plannedStages':case['plannedStages'],'maximumRuntimeSeconds':900,'runtimeAuthorityIssued':False,
        'oauthRequests':0,'freshTerminalInfrastructureConsentRequired':True,'sourceActivationAllowed':False}


def opened(e,case,reader):
    target=context(e,case);journal=e.Journal(target/'operator-control');row=journal.read();c=e.c
    c.require(row.get('schema')==ROW and row.get('caseHash')==c.digest(case)and row.get('budgetReset')is False
        and row.get('state')in ('REVIEW_COMPILING','REVIEW_READY','ISSUING','ISSUED','DISPATCHING',
            'INITIALIZED','RUNNING','RECONCILE_REQUIRED','COMPLETE')and type(row.get('complete'))is bool,
        'EXACT_RETAINED_PATCH_OPERATOR_STATE_REQUIRED')
    claim=reader.read(str(Path(case['snapshotRoot'])/('ingestion-readiness-review-'+case['logicalOperationRef']+'.claim.json')))
    c.require(claim=={'schema':ROW,'caseHash':c.digest(case),'logicalOperationRef':case['logicalOperationRef'],
        'contextPath':str(target),'reviewHash':row['reviewHash'],'automaticReplayAllowed':False,'budgetReset':False},
        'EXACT_PERSISTENT_PATCH_REVIEW_FENCE_REQUIRED')
    return target,journal,row


def load_review(e,manifest,case,reader,target,row):
    c=e.c;b=retained(e,case,reader);material=reader.read(str(target/'material.json'),row['materialHash'])
    c.require(material.get('caseHash')==c.digest(case)and material.get('nativeInputsHash')==case['nativeInputsHash']
        and material.get('operatorControlBinding')==operator_binding(e,case)
        and material['sourceClosure']['declaration']==manifest,'SAME_RETAINED_PATCH_EXECUTION_MATERIAL_REQUIRED')
    e.authority.verify_closure(material['sourceClosure'])
    profile=reader.read(str(target/'human-profile.json'),material['humanProfileHash'])
    expected,packet,h=action_review(e,manifest,case,b,profile,material['sourceClosure'])
    selected=reader.read(str(target/'review.json'),row['reviewHash'])
    c.require(c.encoded(selected)==c.encoded(expected)and c.digest(packet)==row['packetHash']
        and reader.read(str(target/'packet.json'),row['packetHash'])==packet,
        'EXACT_RECONSTRUCTED_PATCH_REVIEW_PACKET_AND_HUMAN_REQUIRED')
    return selected,packet,h


def approve(e,manifest,case,reader,target,journal,row):
    c=e.c;a=e.authority;c.require(row['state']=='REVIEW_READY','PATCH_ISSUANCE_ALREADY_CLAIMED_NO_REPLAY')
    selected,packet,h=load_review(e,manifest,case,reader,target,row)
    c.require(h._read()['accessExpiresAt']>time.time()+930,'CURRENT_PATCH_HUMAN_TOKEN_MARGIN930_REQUIRED_NO_REFRESH')
    a.current_issuer(selected['issuerProfile'],int(time.time())+900)
    decision=a.terminal_consent(selected,
        'Patch infrastrutturale Ingestion: massimo900secondi, '+str(case['plannedStages'])+'stadi manuali.\n'
        'Importo solo il manifest e archivio gia verificati; sostituisco soltanto Ingestion preservando configurazione, reti e MAC osservati.\n'
        'Gateway e tutte le82route invariati; zero nuove chiavi, modifiche IAM/Owner o migrazioni SQL.\n'
        'Avvio del sostituto: il normale lavoro configurato puo riprendere. Nessuna nuova attivazione fonte o dispatch esplicito.\n'
        'HUMAN/Owner/DB/runtime correnti obbligatori prima degli effetti; un comando per stadio, nessun replay o rinnovo automatico.\n'
        'Questa decisione non approva semantica, fonti o pubblicazione del profilo client.\nRevisione privata: '+str(target/'review.json'))
    update(journal,state='ISSUING',decisionHash=c.digest(decision))
    a.issue_action(selected,decision,h,c.digest(decision))
    mandate=reader.read(str(target/'human.json'));mandate_hash=c.digest(mandate)
    update(journal,state='ISSUED',mandateHash=mandate_hash,runtimeAuthorityIssued=True)
    return {'status':'PATCH_AUTHORITY_ISSUED_EXPLICIT_INITIALIZE_REQUIRED','contextPath':str(target),'complete':False,
        'runtimeAuthorityIssued':True,'runtimeEffectsDispatched':0,'newLoginPerformed':False,'oauthRequests':0}


def native_checkpoint(e,target):
    if not os.path.lexists(target/'recovery.json'):return None
    row=e.Journal(target).read();n=row['nextStage']
    return {'rowHash':e.c.digest(row),'nextStage':n,'effectCount':len(row['effects']),
            'prefixHash':e.c.digest(row['effects'][:n]),'readAttempts':row['readAttempts'],'version':row['version']}


def reconcile_dispatch(e,case,target,journal,row,review,packet,human,action):
    """Reconcile a missing control reply using the durable native journal only.

    No native request is sent here. A still-CLAIMED effect stays with the core
    observation reconciler; an unclaimed interrupted read is rescheduled with
    the core's existing finite backoff and unchanged cumulative read attempts.
    """
    c=e.c;before=row.get('nativeBefore');last=row.get('lastExplicitMode')
    record=e.Journal(target)
    if not os.path.lexists(record.record):
        fence=Path(case['snapshotRoot'])/('ingestion-readiness-patch-'+case['logicalOperationRef']+'.claim.json')
        if last=='initialize'and before is None and not os.path.lexists(fence):
            update(journal,state='ISSUED');return {'reconciledControlOnly':True,'runtimeEffectsDispatched':0,'complete':False}
        return None
    ports=e.NativePorts(action,record,review['executionReview'],packet,human)
    runner=e.Runner(action,record,review['executionReview'],ports)
    try:
        with record.invocation():
            native=runner.guard();n=native['nextStage'];effects=native['effects']
            state=None;completed=False
            if last=='initialize'and before is None and n==len(effects)==0:state='INITIALIZED'
            elif type(before)is dict and last in ('step','reconcile'):
                c.require(native['version']>=before['version'] and native['readAttempts']>=before['readAttempts']
                    and c.digest(effects[:before['nextStage']])==before['prefixHash'],
                    'DISPATCH_RECONCILIATION_CANNOT_RESET_OR_REPLACE_NATIVE_PREFIX')
                if n==before['nextStage']+1 and len(effects)==n:state='RUNNING'
                elif n==before['nextStage']==len(review['executionReview']['stages'])and len(effects)==n:
                    completed=native['incidentState']=='RECOVERED';state='COMPLETE'if completed else'RUNNING'
                elif n==before['nextStage'] and len(effects)==n:
                    if native['readState']=='ATTEMPTING':
                        try:runner.retry_read(native,{'retryAfterSeconds':0})
                        except c.Paused:pass
                    state='RUNNING'
            if state is None:return None
            update(journal,state=state,complete=completed)
            return {'reconciledControlOnly':True,'complete':completed,'runtimeEffectsDispatched':0,
                    'effectReplayed':False,'nextStage':n}
    finally:ports.close()


def runtime(e,manifest,case,reader,target,journal,row,mode):
    allowed={'initialize':{'ISSUED'},'step':{'INITIALIZED','RUNNING'},
        'reconcile':{'DISPATCHING','RECONCILE_REQUIRED'}}
    e.c.require(row['state']in allowed[mode],'PATCH_EXPLICIT_RUNTIME_STATE_REQUIRES_RECONCILIATION')
    selected,packet,h=load_review(e,manifest,case,reader,target,row)
    decision=reader.read(str(target/'decision.json'),row['decisionHash'])
    action=e.load_action(selected,decision,h,row['decisionHash'],row['mandateHash'])
    if mode=='reconcile':
        recovered=reconcile_dispatch(e,case,target,journal,row,selected,packet,h,action)
        if recovered is not None:return {'status':'PATCH_CONTROL_DISPATCH_RECONCILED','contextPath':str(target),**recovered}
    update(journal,state='DISPATCHING',lastExplicitMode=mode,nativeBefore=native_checkpoint(e,target))
    try:result=e.execute(mode,selected,packet,h,action,manifest)
    except BaseException:update(journal,state='RECONCILE_REQUIRED');raise
    state='COMPLETE'if result.get('complete')is True else'INITIALIZED'if mode=='initialize'else'RUNNING'
    update(journal,state=state,complete=state=='COMPLETE')
    return {'status':'PATCH_EXPLICIT_NATIVE_INVOCATION_COMPLETED','contextPath':str(target),'controlState':state,**result}


def status(e,target,row):
    result={'status':'PATCH_RETAINED_OPERATOR_METADATA_ONLY','contextPath':str(target),'state':row['state'],
        'complete':row['complete'],'readOnly':True,'humanCredentialJournalsRead':0,'engineRequests':0,
        'databaseCalls':0,'oauthRequests':0,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0}
    if os.path.lexists(target/'recovery.json'):
        native=e.Journal(target).read();result.update(nextStage=native['nextStage'],readAttempts=native['readAttempts'],
            readState=native['readState'],nextReadAt=native['nextReadAt'],recordedExpiresAt=native['expiresAt'],
            runtimeEffectsRecorded=len(native['effects']))
    return result


def execute(e,manifest,case,control_hash,reader,args):
    validate_case(e,manifest,case,control_hash,reader);c=e.c
    c.require(type(args)is list and args,'ONE_EXPLICIT_PATCH_OPERATOR_MODE_REQUIRED')
    mode=args[0];shapes={'preflight':1,'review':2,'approve':1,'initialize':1,'step':1,'reconcile':1,'status':1}
    c.require(mode in shapes and len(args)==shapes[mode],'EXACT_PATCH_OPERATOR_MODE_ARGUMENTS_REQUIRED')
    if mode=='preflight':result=preflight(e,manifest,case,reader)
    elif mode=='review':result=review(e,manifest,case,reader,args[1])
    else:
        target,journal,row=opened(e,case,reader)
        if mode=='status':result=status(e,target,row)
        else:
            with journal.invocation():
                row=journal.read()
                if mode=='approve':result=approve(e,manifest,case,reader,target,journal,row)
                else:result=runtime(e,manifest,case,reader,target,journal,row,mode)
    return {'schema':'ouf.ingestion-readiness-patch-operator-result.v1','completedTechnicalPhases':8,
        'functionalMilestonesProven':4,'automaticReplayAllowed':False,'budgetReset':False,'notReleaseAcceptance':True,**result}
