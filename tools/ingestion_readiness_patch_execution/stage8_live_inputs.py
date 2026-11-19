"""One-use bounded live metadata capture before any continuation authentication.

No old journal updates, private key/token reads, readiness/Owner/SQL requests,
Engine writes, authority issuance, budget/window opening or runtime dispatch.
"""
import copy
import os
from pathlib import Path
import time
from engine_creation import Engine
from tools.ingestion_readiness_patch_execution import entry_v2 as e,custody,stopped_patch_snapshot
from tools.ingestion_readiness_patch_execution import runtime_guard,replacement

SCHEMA='ouf.ingestion-readiness-stage8-live-input-case.v1'


def retained(case):
    c=e.c
    c.require(type(case)is dict and set(case)=={'schema','snapshotCase','expectedSnapshot','readerSourceHash'}
        and case['schema']==SCHEMA and globals().get('__qualified_source_sha256__')==case['readerSourceHash'],
        'EXACT_SEALED_STAGE8_LIVE_READER_CASE_REQUIRED')
    c.require(stopped_patch_snapshot.inspect(case['snapshotCase'])==case['expectedSnapshot'],
        'EXACT_RECONCILED_STAGE8_METADATA_REQUIRED')
    target=Path(case['snapshotCase']['contextPath'])
    review=custody.read(str(target/'review.json'),case['expectedSnapshot']['reviewHash'])
    packet=custody.read(str(target/'packet.json'),review['packetHash'])
    row=custody.read(str(target/'recovery.json'),case['expectedSnapshot']['nativeJournalHash'])
    native=review['executionReview'];e.authority.native_review.validate_review(native,packet)
    c.require(native['stages'][row['nextStage']]['name']=='ingestion.READINESS'
        and len(native['stages'])-row['nextStage']==4 and row['expiresAt']<=time.time()
        and row['effects'][-1]['stage']=='ingestion.START_REPLACEMENT'
        and native['logicalOperationRef']==case['expectedSnapshot']['logicalOperationRef'],
        'EXACT_EXPIRED_PREFIX_BEFORE_FOUR_RESIDUAL_STAGES_REQUIRED')
    effects={v['stage']:v for v in row['effects']}
    created=effects['ingestion.CREATE_REPLACEMENT']['nativeResource']['containerId']
    process=effects['ingestion.START_REPLACEMENT']['nativeResource']
    c.require(c.hashed(created)and process['containerId']==created,'EXACT_DURABLE_REPLACEMENT_AND_FIRST_PROCESS_REQUIRED')
    return review,packet,row,created,process


def identifiers(review,packet,created):
    native=review['executionReview'];db=native['databaseControlProfile']
    ids=[packet['expectedRuntimeBindings']['ingestion']['containerId'],created,
        *[p['binding']['containerId']for p in native['runtimeGuardProfile']['unchangedApplications'].values()],
        db['postgresRuntimeBinding']['containerId']]
    e.c.require(len(ids)==len(set(ids))==7 and all(e.c.hashed(v)for v in ids),'SEVEN_EXACT_RETAINED_STAGE8_CONTAINERS_REQUIRED')
    return ids


def verify_rows(review,packet,row,created,process,rows):
    native=review['executionReview'];guard=native['runtimeGuardProfile'];db=native['databaseControlProfile']
    for pin in guard['unchangedApplications'].values():runtime_guard.unchanged(rows[pin['binding']['containerId']],pin)
    old=packet['expectedRuntimeBindings']['ingestion']['containerId']
    runtime_guard.predecessor('ingestion',rows[old],guard,packet,native,row)
    replacement.validate(packet['frames']['ingestion'],rows[created],packet['candidate']['imageConfig'],old,
        created_id=created,process=process,phase='RUNNING',restart_restored=False)
    runtime_guard.unchanged(rows[db['postgresRuntimeBinding']['containerId']],
        {'binding':db['postgresRuntimeBinding'],'restartCount':db['postgresRestartCount'],'bindingProfile':db['runtimeBindingProfile']})
    # Exclude volatile health/resource/error timestamps; bind all configuration,
    # process generation, network allocation, mounts and restart counts.
    return {cid:{k:v[k]for k in ('Id','Name','Image','Config','HostConfig','Mounts','NetworkSettings','RestartCount')}
        |{'process':{k:v['State'][k]for k in ('Running','Paused','Restarting','Pid','StartedAt')}}for cid,v in rows.items()}


def publish(folder,name,value):
    j=e.Journal(folder);j.create(Path(folder)/name,e.c.encoded(value));j.sync()


def prepare(case):
    c=e.c;review,packet,row,created,process=retained(case);ids=identifiers(review,packet,created)
    root=Path(case['snapshotCase']['contextPath']).parent
    claim=root/('ingestion-readiness-stage8-live-'+case['snapshotCase']['runtimeCaseHash']+'.claim.json')
    target=root/('ingestion-readiness-stage8-live-inputs-'+c.digest(case))
    c.require(not os.path.lexists(claim)and not os.path.lexists(target),'STAGE8_LIVE_CAPTURE_ALREADY_CLAIMED_RECONCILE_ONLY')
    selected=review['executionReview']['engineBinding'];engine=Engine(selected['socketPath'],tuple(selected['socketBinding']))
    reader=replacement.EngineReader(engine);original=engine.request
    # The global one-use fence is created before ANY Engine call.
    publish(root,claim.name,{'schema':SCHEMA,'caseHash':c.digest(case),'contextPath':str(target),
        'predecessorJournalHash':case['expectedSnapshot']['nativeJournalHash'],'maximumEngineGets':14,
        'automaticReplayAllowed':False,'runtimeAuthorityIssued':False})
    with e.authority.protected_directory(root)as fd:os.mkdir(target.name,0o700,dir_fd=fd);os.fsync(fd)
    journal=e.Journal(target);journal.initialize({'schema':SCHEMA,'caseHash':c.digest(case),'state':'READING',
        'engineGets':0,'maximumEngineGets':14,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False})
    allowed={'/v1.44/containers/'+v+'/json'for v in ids}
    def get(method,path,body=None):
        c.require(method=='GET'and path in allowed and body is None,'EXACT_ID_GET_ONLY_STAGE8_CAPTURE')
        current=journal.read();c.require(current['state']=='READING'and current['engineGets']<14,'FINITE_STAGE8_GET_BUDGET_REQUIRED')
        journal.compare_and_save(current,{**current,'engineGets':current['engineGets']+1})
        return original(method,path,body)
    engine.request=get
    first=None;observations=None
    for _ in range(2):
        rows={cid:reader.container(cid)for cid in ids}
        stable=verify_rows(review,packet,row,created,process,rows)
        c.require(first is None or first==stable,'STAGE8_GENERATION_CHANGED_BETWEEN_READS')
        first=stable;observations=rows
    retained(case)
    capture={'schema':'ouf.ingestion-readiness-stage8-private-live-inputs.v1','case':case,
        'stoppedSnapshot':case['expectedSnapshot'],'review':review,'packet':packet,'nativeJournal':row,
        'containers':observations,'stableMetadata':first,'replacementFirstProcess':process,
        'observedAt':time.time(),'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0}
    c.require(len(c.encoded(capture))<=8388608,'BOUNDED_PRIVATE_STAGE8_CAPTURE_REQUIRED')
    publish(target,'capture.json',capture)
    current=journal.read();c.require(current['engineGets']==14,'EXACT_FOURTEEN_STAGE8_GETS_REQUIRED')
    journal.compare_and_save(current,{**current,'state':'COMPLETE','captureHash':c.digest(capture)})
    result={'schema':'ouf.ingestion-readiness-stage8-live-input-result.v1',
        'status':'STAGE8_LIVE_METADATA_MATCHED_NO_AUTHORITY','complete':True,'contextPath':str(target),
        'privateCaptureHash':c.digest(capture),'predecessorJournalHash':case['expectedSnapshot']['nativeJournalHash'],
        'prefixHash':case['expectedSnapshot']['prefixHash'],'logicalOperationRef':case['expectedSnapshot']['logicalOperationRef'],
        'appliedStageCount':row['nextStage'],'remainingStages':4,'engineGets':14,'maximumEngineGets':14,
        'readOnlyRuntime':True,'privateSnapshotWritten':True,'privateValuesPrinted':False,
        'replacementGenerationMatched':True,'retainedPredecessorMatched':True,'unchangedApplicationsMatched':True,
        'postgresGenerationMatched':True,'applicationReadinessReverified':False,'databaseAdmissionProven':False,
        'gatewayRoutesReverified':False,'ownerControlReverified':False,'bearerFilesOpened':0,'privateKeysRead':0,
        'humanCredentialJournalsRead':0,'oauthRequests':0,'runtimeEffectsDispatched':0,'runtimeAuthorityIssued':False,
        'automaticReplayAllowed':False,'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4,
        'priorOAuthAttempts':300,'newBudgetGranted':False,'newHumanWindowOpened':False,'notReleaseAcceptance':True}
    publish(target,'complete.json',result)
    return result


def execute(mode,selected,case,confirmed_read,closure):
    e.c.require(mode=='prepare'and selected is None and confirmed_read=={},'ONE_EXPLICIT_STAGE8_CAPTURE_MODE_REQUIRED')
    return prepare(case)
