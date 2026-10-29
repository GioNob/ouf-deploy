"""Distinct four-stage continuation of an exactly reconciled patch prefix.

Never initialize at zero, renew authority, authenticate, or rewrite a predecessor.
The imported prefix is mandatory before the unchanged native runner may step.
"""
import copy
import json
import os
from pathlib import Path
import time
from engine_creation import Engine
from tools.ingestion_readiness_patch_execution import entry_v2 as e, custody
from tools.ingestion_readiness_patch_execution import stage8_live_inputs as live
from tools.ingestion_readiness_patch_execution import operator_control_v2 as old_control
from tools.ingestion_readiness_patch_execution.unissued_successor import Directory

SCHEMA='ouf.ingestion-readiness-stage8-continuation-case.v1'
ROW='ouf.ingestion-readiness-stage8-continuation-control.v1'
RESIDUAL=['ingestion.READINESS','VERIFY_FINAL','ingestion.RESTORE_RESTART','VERIFY_RESTORED_FINAL']


def boot_id():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def validate_case(manifest,case):
    c=e.c
    c.require(type(case)is dict and set(case)=={'schema','capturePath','captureHash','expectedCaptureReceipt',
        'nativeDeclarationHash','controlSourceHash','qualification','requiredCumulativeOAuthAttempts',
        'maximumRuntimeSeconds'} and case['schema']==SCHEMA,'EXACT_STAGE8_CONTINUATION_CASE_REQUIRED')
    c.path(case['capturePath'])
    c.require(all(c.hashed(case[k])for k in ('captureHash','nativeDeclarationHash','controlSourceHash'))
        and case['nativeDeclarationHash']==c.digest(manifest)
        and getattr(e,'__qualified_source_sha256__',None)==manifest['sourceHashes'].get(e.__name__)
        and globals().get('__qualified_source_sha256__')==case['controlSourceHash']
        ==manifest['sourceHashes'].get(__name__)
        and case['requiredCumulativeOAuthAttempts']==304 and case['maximumRuntimeSeconds']==900,
        'EXACT_SEALED_STAGE8_CONTROLLER_AND_FINITE304_HISTORY_REQUIRED')


def retained(case):
    c=e.c;folder=Path(case['capturePath'])
    directory=Directory(str(folder))
    try: capture,_,_=directory.read('capture.json',8388608)
    finally:directory.close()
    c.require(c.digest(capture)==case['captureHash']
        and capture['schema']=='ouf.ingestion-readiness-stage8-private-live-inputs.v1'
        and capture['runtimeAuthorityIssued']is False and capture['runtimeEffectsDispatched']==0,
        'EXACT_PRIVATE_STAGE8_CAPTURE_REQUIRED')
    receipt=custody.read(str(folder/'complete.json'))
    c.require(receipt==case['expectedCaptureReceipt'] and receipt['complete']is True
        and receipt['status']=='STAGE8_LIVE_METADATA_MATCHED_NO_AUTHORITY'
        and receipt['contextPath']==str(folder) and receipt['privateCaptureHash']==case['captureHash']
        and receipt['engineGets']==receipt['maximumEngineGets']==14
        and receipt['priorOAuthAttempts']==300 and receipt['remainingStages']==4,
        'EXACT_COMPLETED_STAGE8_LIVE_RECEIPT_REQUIRED')
    review,packet,row,created,process=live.retained(capture['case'])
    c.require(capture['review']==review and capture['packet']==packet and capture['nativeJournal']==row
        and capture['stoppedSnapshot']==capture['case']['expectedSnapshot']
        and capture['replacementFirstProcess']==process
        and receipt['predecessorJournalHash']==c.digest(row)
        and receipt['prefixHash']==c.digest(row['effects'])
        and receipt['appliedStageCount']==row['nextStage']
        and receipt['logicalOperationRef']==review['executionReview']['logicalOperationRef'],
        'EXACT_UNCHANGED_CAPTURE_AND_STOPPED_PREFIX_REQUIRED')
    c.require(live.verify_rows(review,packet,row,created,process,capture['containers'])==capture['stableMetadata'],
        'EXACT_RETAINED_CAPTURE_GENERATIONS_REQUIRED')
    native=review['executionReview'];n=row['nextStage']
    c.require([s['name']for s in native['stages'][n:]]==RESIDUAL
        and row['bootId']==boot_id()
        and row['readState']=='IDLE' and row['stageReadAttempts']==0 and row['readAttempts']<128,
        'SAME_BOOT_IDLE_UNEXHAUSTED_FOUR_STAGE_PREFIX_REQUIRED')
    return capture,review,packet,row


def root(case):return Path(case['capturePath']).parent
def context(case):return root(case)/('ingestion-readiness-stage8-execution-'+e.c.digest(case))
def fence(case):
    return root(case)/('ingestion-readiness-stage8-continuation-'+case['expectedCaptureReceipt']['logicalOperationRef']+'.claim.json')


def binding(case):
    r=case['expectedCaptureReceipt']
    return {'schema':ROW,'caseHash':e.c.digest(case),'captureHash':case['captureHash'],
        'predecessorJournalHash':r['predecessorJournalHash'],'prefixHash':r['prefixHash'],
        'controlSourceHash':case['controlSourceHash'],'residualStages':RESIDUAL,
        'automaticReplayAllowed':False,'budgetReset':False}


def human_operation(case):
    return {'stage8CaseHash':e.c.digest(case),'privateCaptureHash':case['captureHash'],
        'continuationBindingHash':e.c.digest(binding(case)),'controlSourceHash':case['controlSourceHash']}


def preflight(manifest,case):
    capture,review,packet,row=retained(case)
    sealed=old_control.closure(e,manifest,review['executionReview']['preparedInputs'])
    e.authority.qualification_valid(case['qualification'],sealed,packet['candidate'])
    e.authority.current_issuer(review['issuerProfile'],int(time.time())+900)
    return {'status':'STAGE8_CONTINUATION_PREFLIGHT_NO_AUTHORITY','complete':True,'readOnly':True,
        'appliedStageCount':row['nextStage'],'remainingStages':4,'privateCaptureHash':case['captureHash'],
        'humanCredentialJournalsRead':0,'engineRequests':0,'databaseCalls':0,'oauthRequests':0,
        'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0}


def live_probe(case):
    """Fourteen exact-ID GETs only, before any new HUMAN work or prefix import."""
    capture,review,packet,row=retained(case)
    _,_,_,created,process=live.retained(capture['case'])
    ids=live.identifiers(review,packet,created);selected=review['executionReview']['engineBinding']
    engine=Engine(selected['socketPath'],tuple(selected['socketBinding']));original=engine.request
    allowed={'/v1.44/containers/'+v+'/json'for v in ids};count=0
    def request(method,path,body=None):
        nonlocal count
        e.c.require(method=='GET'and path in allowed and body is None and count<14,'BOUNDED_GET_ONLY_STAGE8_PROBE')
        count+=1;return original(method,path,body)
    engine.request=request;reader=live.replacement.EngineReader(engine)
    for _ in range(2):
        observed={cid:reader.container(cid)for cid in ids}
        stable=live.verify_rows(review,packet,row,created,process,observed)
        e.c.require(stable==capture['stableMetadata'],'STAGE8_LIVE_GENERATION_DRIFT_RECONCILE_ONLY')
    retained(case);e.c.require(count==14,'EXACT_STAGE8_PROBE_GET_COUNT_REQUIRED')
    return count


def human(case,profile):
    c=e.c;p=e.human_reader.validate(profile)
    c.require(p['minimumCumulativeAttempts']==p['maximumCumulativeAttempts']==304
        and p['governedWindowReceiptHash']is not None,'FRESH_GOVERNED304_HUMAN_REQUIRED_NO_REUSE')
    h=e.human_reader.open_existing(p);renewal=h._read()['governedWindowRenewal'];r=renewal['review']
    c.require(r['priorOAuthAttempts']==300 and r['maximumCumulativeOAuthAttempts']==304
        and r['operationBinding']==human_operation(case),'NEW_HUMAN_MUST_BIND_EXACT_STAGE8_CONTINUATION')
    return h


def action_review(manifest,case,profile,sealed):
    capture,old,old_packet,row=retained(case);h=human(case,profile);c=e.c;a=e.authority
    before=old['executionReview']
    native,packet=a.native_review.compile_review(before['preparedInputs'],before['preparedInputsBinding'],
        h.current(),str(context(case)),human_read_profile=profile)
    c.require(native['stages']==before['stages']and packet==old_packet,'UNCHANGED_PATCH_INTENTS_AND_PACKET_REQUIRED')
    selected=a.compile_action_review(native,packet,sealed,old['issuerProfile'],case['qualification'],900)
    selected['absoluteExpiresAt']=min(h.expires_at-5,int(h._read()['accessExpiresAt'])-30)
    selected['operatorControlBinding']=binding(case)
    selected['predecessorHistoryHash']=c.digest({'previous':old['predecessorHistoryHash'],'continuation':binding(case)})
    a.validate_action_review(selected)
    return selected,packet,h


def update(journal,**changes):return old_control.update(journal,**changes)
def publish(target,name,value):return old_control.publish(e,target,name,value)


def prepare_review(manifest,case,profile_path):
    c=e.c;target=context(case);claim=fence(case)
    c.require(not os.path.lexists(target)and not os.path.lexists(claim),'STAGE8_CONTINUATION_REVIEW_ALREADY_CLAIMED')
    preflight(manifest,case);profile=custody.read(c.path(profile_path));h=human(case,profile)
    c.require(h._read()['accessExpiresAt']>time.time()+930,'CURRENT_STAGE8_TOKEN_MARGIN930_REQUIRED')
    live_probe(case);capture,old,packet,row=retained(case)
    sealed=old_control.closure(e,manifest,old['executionReview']['preparedInputs'])
    selected,packet,h=action_review(manifest,case,profile,sealed)
    with e.authority.protected_directory(root(case))as fd:
        publish(root(case),claim.name,{**binding(case),'contextPath':str(target),'reviewHash':c.digest(selected)})
        os.mkdir(target.name,0o700,dir_fd=fd);os.fsync(fd)
    with e.authority.protected_directory(target)as fd:os.mkdir('operator-control',0o700,dir_fd=fd);os.fsync(fd)
    control=e.Journal(target/'operator-control');control.initialize({'schema':ROW,'caseHash':c.digest(case),
        'state':'REVIEW_COMPILING','complete':False,'budgetReset':False,'runtimeAuthorityIssued':False,
        'reviewHash':c.digest(selected),'packetHash':c.digest(packet),'profileHash':c.digest(profile)})
    for name,value in (('review.json',selected),('packet.json',packet),('human-profile.json',profile)):
        publish(target,name,value)
    update(control,state='REVIEW_READY')
    return {'status':'STAGE8_CONTINUATION_REVIEW_READY_EXPLICIT_APPROVAL_REQUIRED','complete':False,
        'contextPath':str(target),'remainingStages':4,'maximumRuntimeSeconds':900,'runtimeAuthorityIssued':False}


def opened(case):
    c=e.c;target=context(case);control=e.Journal(target/'operator-control');row=control.read()
    c.require(row['schema']==ROW and row['caseHash']==c.digest(case)and row['budgetReset']is False
        and row['state']in('REVIEW_COMPILING','REVIEW_READY','ISSUING','ISSUED','IMPORTING','IMPORTED',
            'DISPATCHING','RUNNING','RECONCILE_REQUIRED','COMPLETE'),'EXACT_STAGE8_OPERATOR_CONTROL_REQUIRED')
    claim=custody.read(str(fence(case)))
    c.require(claim=={**binding(case),'contextPath':str(target),'reviewHash':row['reviewHash']},
        'EXACT_STAGE8_GLOBAL_CONTINUATION_FENCE_REQUIRED')
    return target,control,row


def load_review(manifest,case,target,row):
    c=e.c;selected=custody.read(str(target/'review.json'),row['reviewHash'])
    profile=custody.read(str(target/'human-profile.json'),row['profileHash'])
    expected,packet,h=action_review(manifest,case,profile,selected['sourceClosure'])
    c.require(expected==selected and selected['sourceClosure']['declaration']==manifest
        and c.digest(packet)==row['packetHash']and custody.read(str(target/'packet.json'),row['packetHash'])==packet,
        'EXACT_RECONSTRUCTED_STAGE8_REVIEW_AND_PACKET_REQUIRED')
    e.authority.verify_closure(selected['sourceClosure'])
    return selected,packet,h


def approve(manifest,case,target,control,row):
    c=e.c;a=e.authority;c.require(row['state']=='REVIEW_READY','STAGE8_ISSUANCE_ALREADY_CONSUMED')
    selected,packet,h=load_review(manifest,case,target,row)
    c.require(h._read()['accessExpiresAt']>time.time()+930,'CURRENT_STAGE8_TOKEN_MARGIN930_REQUIRED')
    a.current_issuer(selected['issuerProfile'],int(time.time())+900)
    decision=a.terminal_consent(selected,
        'Continuazione infrastrutturale Ingestion: massimo900secondi e quattro stadi residui.\n'
        'Importo il prefisso APPLIED e tutti i contatori senza rieseguirli. Nessun initialize a zero.\n'
        'Solo readiness, verifica finale, ripristino restart Ingestion, verifica ripristino.\n'
        'Nessuna importazione immagine, sostituzione/avvio container, modifica Gateway/route/IAM/SQL o nuova chiave.\n'
        'HUMAN/Owner/DB/runtime correnti obbligatori; un comando per stadio.\n'
        'Nessuna approvazione o attivazione fonte, pubblicazione profilo o rinnovo automatico.\n'
        'Revisione privata: '+str(target/'review.json'))
    retained(case);update(control,state='ISSUING',decisionHash=c.digest(decision))
    a.issue_action(selected,decision,h,c.digest(decision))
    update(control,state='ISSUED',mandateHash=c.digest(custody.read(str(target/'human.json'))),runtimeAuthorityIssued=True)
    return {'status':'STAGE8_AUTHORITY_ISSUED_EXPLICIT_PREFIX_IMPORT_REQUIRED','complete':False,
        'contextPath':str(target),'runtimeAuthorityIssued':True,'runtimeEffectsDispatched':0}


def imported_record(case,old,native,action,wall,mono,boot):
    c=e.c;n=old['nextStage'];expiry=min(wall+900,json.loads(action.raw)['expiresAt'])
    c.require(old['bootId']==boot and old['expiresAt']<=wall and expiry>wall+30
        and old['lastWall']<=wall and old['lastMonotonic']<=mono and old['expiresMonotonic']<=mono
        and len(old['effects'])==n and old['readState']=='IDLE'and old['stageReadAttempts']==0
        and old['readAttempts']<128 and old['incidentState']=='OPEN'
        and old['budgetReset']is False and old['acceptanceGranted']is False
        and [s['name']for s in native['stages'][n:]]==RESIDUAL
        and all(v['stage']==native['stages'][i]['name']and v['intentHash']==native['stages'][i]['intentHash']
            and v['state']=='APPLIED'for i,v in enumerate(old['effects'])),
        'EXACT_EXPIRED_IDLE_PREFIX_AND_NEW_FINITE_AUTHORITY_REQUIRED')
    following=copy.deepcopy(old)
    following.update(scopeHash=c.digest(c.scope(native)),authorityHash=action.authority_hash,
        expiresAt=expiry,expiresMonotonic=mono+expiry-wall,lastWall=wall,lastMonotonic=mono,
        version=old['version']+1)
    # Preserve next-read/backoff values, read/native counters, createdAt and all
    # APPLIED resources verbatim. The new finite clock is separately consented.
    return following


def verify_import(case,old,native,action,current):
    c=e.c;n=old['nextStage']
    c.require(current['effects'][:n]==old['effects']and current['nextStage']>=n
        and current['createdAt']==old['createdAt']and current['bootId']==old['bootId']
        and current['scopeHash']==c.digest(c.scope(native))and current['authorityHash']==action.authority_hash
        and current['budgetReset']is False and current['readAttempts']>=old['readAttempts']
        and current['version']>old['version']
        and all(k in current and type(current[k])is int and current[k]>=v
            for k,v in old.items()if k.startswith('native')and type(v)is int),
        'IMPORTED_STAGE8_PREFIX_COUNTER_OR_AUTHORITY_DRIFT')
    proof=custody.read(str(context(case)/'prefix-import.json'))
    initial=imported_record(case,old,native,action,proof['wall'],proof['monotonic'],old['bootId'])
    c.require(proof['binding']==binding(case)and proof['oldJournalHash']==c.digest(old)
        and proof['newScopeHash']==c.digest(c.scope(native))and proof['authorityHash']==action.authority_hash
        and proof['importedRecordHash']==c.digest(initial)
        and current['expiresAt']==initial['expiresAt']and current['expiresMonotonic']==initial['expiresMonotonic'],
        'EXACT_STAGE8_IMPORT_PROOF_REQUIRED')
    return current


def import_prefix(manifest,case,target,control,row):
    c=e.c;c.require(row['state']=='ISSUED','STAGE8_PREFIX_IMPORT_ALREADY_CLAIMED_RECONCILE_ONLY')
    selected,packet,h=load_review(manifest,case,target,row)
    decision=custody.read(str(target/'decision.json'),row['decisionHash'])
    action=e.load_action(selected,decision,h,row['decisionHash'],row['mandateHash'])
    c.require(not os.path.lexists(target/'recovery.json')and not os.path.lexists(target/'prefix-import.json'),
        'STAGE8_NATIVE_PREFIX_ALREADY_EXISTS_RECONCILE_ONLY')
    live_probe(case);capture,old_review,old_packet,old=retained(case)
    wall,mono=time.time(),time.monotonic();native=selected['executionReview']
    action.guard(c.AUTHORITY_KEY,c.scope(native));c.require(h.current()==selected['authenticatedHuman'],'CURRENT_STAGE8_HUMAN_REQUIRED')
    record=imported_record(case,old,native,action,wall,mono,boot_id())
    proof={'schema':ROW,'binding':binding(case),'oldJournalHash':c.digest(old),'newScopeHash':c.digest(c.scope(native)),
        'authorityHash':action.authority_hash,'importedRecordHash':c.digest(record),'wall':wall,'monotonic':mono}
    update(control,state='IMPORTING');publish(target,'prefix-import.json',proof)
    e.Journal(target).initialize(record)
    verify_import(case,old,native,action,e.Journal(target).read());update(control,state='IMPORTED')
    return {'status':'STAGE8_PREFIX_IMPORTED_NO_RUNTIME_EFFECTS','complete':False,'appliedStageCount':old['nextStage'],
        'nextStage':old['nextStage'],'retainedReadAttempts':old['readAttempts'],'remainingStages':4,'runtimeEffectsDispatched':0}


def reconcile_import(manifest,case,target,control,row):
    """Only adopt a fully published import; never complete a partial publication."""
    c=e.c;c.require(row['state']=='IMPORTING','EXPLICIT_INTERRUPTED_STAGE8_IMPORT_REQUIRED')
    selected,packet,h=load_review(manifest,case,target,row)
    decision=custody.read(str(target/'decision.json'),row['decisionHash'])
    action=e.load_action(selected,decision,h,row['decisionHash'],row['mandateHash'])
    capture,previous,old_packet,old=retained(case)
    current=e.Journal(target).read()
    verify_import(case,old,selected['executionReview'],action,current)
    c.require(current['nextStage']==old['nextStage']and current['effects']==old['effects']
        and current['readAttempts']==old['readAttempts'],'UNEXECUTED_COMPLETE_STAGE8_IMPORT_REQUIRED')
    update(control,state='IMPORTED')
    return {'status':'STAGE8_IMPORT_RECONCILED_NO_REPLAY','complete':False,'runtimeEffectsDispatched':0,
        'nextStage':old['nextStage']}


def runtime(manifest,case,target,control,row,mode):
    c=e.c;c.require(row['state']in({'IMPORTED','RUNNING'}if mode=='step'else{'DISPATCHING','RECONCILE_REQUIRED'}),
        'EXPLICIT_IMPORTED_STAGE8_STATE_REQUIRED')
    selected,packet,h=load_review(manifest,case,target,row)
    decision=custody.read(str(target/'decision.json'),row['decisionHash'])
    action=e.load_action(selected,decision,h,row['decisionHash'],row['mandateHash'])
    capture,previous,old_packet,old=retained(case)
    verify_import(case,old,selected['executionReview'],action,e.Journal(target).read())
    if mode=='reconcile':
        recovered=old_control.reconcile_dispatch(e,case,target,control,row,selected,packet,h,action)
        if recovered is not None:return {'status':'STAGE8_DISPATCH_RECONCILED_NO_REPLAY',**recovered}
    update(control,state='DISPATCHING',lastExplicitMode=mode,nativeBefore=old_control.native_checkpoint(e,target))
    try:result=e.execute(mode,selected,packet,h,action,manifest)
    except BaseException:update(control,state='RECONCILE_REQUIRED');raise
    update(control,state='COMPLETE'if result.get('complete')is True else'RUNNING',complete=result.get('complete')is True)
    return {'status':'STAGE8_EXPLICIT_RESIDUAL_STAGE_COMPLETED',**result}


def execute(manifest,case,args):
    validate_case(manifest,case);c=e.c
    shapes={'preflight':1,'review':2,'approve':1,'import-prefix':1,'reconcile-import':1,'step':1,'reconcile':1,'status':1}
    c.require(type(args)is list and args and args[0]in shapes and len(args)==shapes[args[0]],
        'ONE_EXPLICIT_STAGE8_CONTINUATION_MODE_REQUIRED')
    mode=args[0]
    if mode=='preflight':result=preflight(manifest,case)
    elif mode=='review':result=prepare_review(manifest,case,args[1])
    else:
        target,control,row=opened(case)
        if mode=='status':result=old_control.status(e,target,row)
        else:
            with control.invocation():
                row=control.read()
                if mode=='approve':result=approve(manifest,case,target,control,row)
                elif mode=='import-prefix':result=import_prefix(manifest,case,target,control,row)
                elif mode=='reconcile-import':result=reconcile_import(manifest,case,target,control,row)
                else:result=runtime(manifest,case,target,control,row,mode)
    return {'schema':'ouf.ingestion-readiness-stage8-continuation-result.v1','complete':False,
        'runtimeAuthorityIssued':False,'oauthRequests':0,'newLoginPerformed':False,'refreshPerformed':False,
        'budgetReset':False,'automaticReplayAllowed':False,'notReleaseAcceptance':True,
        'completedTechnicalPhases':8,'functionalMilestonesProven':4,**result}

