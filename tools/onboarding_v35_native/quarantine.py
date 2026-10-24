"""Ephemeral negative lease: stop only a created, owned, still-unproven candidate.

No old-container operations, start, restore, signing, SQL or recovery replay.
Runs in a single fork of the already source-verified, single-threaded controller.
The original public policy snapshot can verify ONLY this signed negative scope;
positive execution always requires the live original policy.
"""
import copy,json,os,re,signal,time
from pathlib import Path

def parent_pin(pid):
    try:
        raw=Path('/proc/'+str(pid)+'/stat').read_text();return raw[raw.rfind(')')+2:].split()[19]
    except (OSError,IndexError):return None

def cas(journal,mutate):
    for attempt in range(8):
        try:
            row=journal.read();following=mutate(copy.deepcopy(row))
            if following is None:return None
            following['version']=row['version']+1;journal.compare_and_save(row,following);return following
        except (BlockingIOError,ValueError)as error:
            if isinstance(error,ValueError)and str(error)!='RECOVERY_CAS_CONFLICT':raise
            if attempt==7:raise
            time.sleep(.02)

def check(ctx,review,raw):
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
    core=ctx.core;core.validate_review(review);authority=json.loads(raw);v=review['verification'];context=v['context']
    core.require(authority['scope']==core.scope(review)and authority['schema']==core.AUTHORITY_SCHEMA
        and authority['expiresAt']-authority['issuedAt']==900 and authority['cleanupExpiresAt']==authority['expiresAt']+30
        and authority['issuedAt']<=time.time()<authority['cleanupExpiresAt']
        and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==review['bootId'],'FINITE_SIGNED_V35_NEGATIVE_LEASE_REQUIRED')
    ctx.check_sources()
    copied={'path':str(ctx.root/'authority/issued-trust-policy.json'),'sha256':v['trustPolicy']['sha256']}
    verifier=DetachedAuthenticator(copied,str(ctx.root/'authority'),v['openssl'])
    for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
        core.require(verifier(raw,role,context[key],context['installationRef'],context['entityRef'])is True,'SIGNED_V35_NEGATIVE_LEASE_REQUIRED')
    return authority

def stop_unproven(ctx,review,raw,journal,reason):
    from engine_creation import Engine,requested_host_config_matches
    core=ctx.core;authority=check(ctx,review,raw);plan=review['nativePlan'];replacement=plan['replacement'];request=replacement['request']
    def claim(row):
        core.require(row['reviewHash']==core.digest(review)and row['authorityHash']==core.sha(raw),'SAME_V35_NEGATIVE_JOURNAL_REQUIRED')
        if row['state']=='COMPLETE'or row['nextStage']>=11 or row.get('quarantine')is not None:return None
        if not row['createdId']or row['createdConfigurationVerified']is not True:return None
        core.require(re.fullmatch('[a-f0-9]{64}',row['createdId'])is not None,'KNOWN_CREATED_V35_CANDIDATE_REQUIRED')
        row['quarantine']={'state':'CLAIMED','reason':reason,'candidateId':row['createdId'],'claimedAt':time.time()};return row
    row=cas(journal,claim)
    if row is None:return
    cid=row['createdId'];generation=row['createdGeneration'];engine=Engine(plan['engine']['socketPath'],tuple(plan['engine']['socketBinding']))
    def reserve(kind):
        def apply(row):
            core.require(row['quarantine']['state']=='CLAIMED'and row['quarantine']['candidateId']==cid
                and time.time()<authority['cleanupExpiresAt'],'CURRENT_V35_QUARANTINE_CLAIM_REQUIRED')
            core.require(row['counts'][kind]<review['maximums'][kind],'V35_NEGATIVE_BUDGET_EXHAUSTED')
            row['counts'][kind]+=1;return row
        cas(journal,apply)
    def inspect():
        reserve('engineGets');status,actual=engine.request('GET','/v1.44/containers/'+cid+'/json')
        core.require(status==200 and actual['Id']==cid and actual['Name']=='/'+replacement['name']
            and actual['Image']==request['Image']and actual['RestartCount']==0,'OWNED_V35_QUARANTINE_CANDIDATE_REQUIRED')
        for key,value in request.items():
            if key not in('HostConfig','NetworkingConfig'):core.require(actual['Config'].get(key)==value,'V35_QUARANTINE_CONFIGURATION_CHANGED')
        started=actual['State']['Running']is True
        core.require(requested_host_config_matches(request['HostConfig'],actual['HostConfig'],started=started)
            and core.digest(sorted(actual['Mounts'],key=lambda v:v['Destination']))==replacement['oldRuntimeBinding']['mountsHash'],
            'V35_QUARANTINE_HOST_OR_MOUNTS_CHANGED')
        if started and generation:core.require(ctx.m.process(actual)==generation,'V35_QUARANTINE_GENERATION_CHANGED')
        core.require(actual['State']['Paused']is False and actual['State']['Restarting']is False,'V35_QUARANTINE_STATE_CHANGED')
        return actual
    actual=inspect();dispatched=actual['State']['Running']is True
    if dispatched:
        check(ctx,review,raw);reserve('quarantineStops');reserve('engineWrites')
        status,_=engine.request('POST','/v1.44/containers/'+cid+'/stop?t=10')
        core.require(status==204,'V35_QUARANTINE_STOP_OUTCOME_UNPROVEN')
    actual=inspect();core.require(actual['State']['Running']is False and actual['State']['Pid']==0,'V35_QUARANTINE_STOP_UNPROVEN')
    def complete(row):
        row['quarantine'].update(state='APPLIED',stopDispatched=dispatched,candidateStopped=True,completedAt=time.time());return row
    cas(journal,complete)
    ctx.m.new_file(ctx.root,'quarantine-result.json',{'schema':'ouf.onboarding-v35-negative-lease-result.v1','status':'OWNED_UNPROVEN_CANDIDATE_STOPPED',
        'candidateStopDispatched':dispatched,'oldContainerRestarted':False,'databaseRestorePerformed':False,'automaticReplayAllowed':False,'budgetReset':False})

def monitor(ctx,review,raw,journal,parent_pid,pin):
    authority=json.loads(raw);deadline=time.monotonic()+max(0,authority['cleanupExpiresAt']-time.time())
    while time.monotonic()<deadline and time.time()<authority['cleanupExpiresAt']:
        try:row=journal.read()
        except BlockingIOError:time.sleep(.02);continue
        if row['state']=='COMPLETE'or row['nextStage']>=11 or row.get('quarantine')is not None:return
        lost=parent_pin(parent_pid)!=pin
        startup=row['startupDeadline']is not None and time.time()>=row['startupDeadline']and row['nextStage']<=9
        expiring=time.time()>=authority['expiresAt']-60
        if lost or startup or expiring:
            stop_unproven(ctx,review,raw,journal,'PARENT_LOST'if lost else'STARTUP_WINDOW_EXHAUSTED'if startup else'POSITIVE_LEASE_EXPIRING');return
        time.sleep(1)

def launch(ctx,review,gate,journal):
    ctx.check_sources();parent=os.getpid();pin=parent_pin(parent);ctx.core.require(pin is not None,'BOUND_V35_CONTROLLER_PROCESS_REQUIRED')
    ctx.m.new_file(ctx.root,'watchdog-parent.json',{'pid':parent,'startTicks':pin,'maximumAdditionalSeconds':30,'persistentServiceInstalled':False})
    log=os.open(ctx.root/'watchdog.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:child=os.fork()
    except BaseException:os.close(log);raise
    if child:
        os.close(log);return child
    try:
        os.setsid()
        null=os.open('/dev/null',os.O_RDONLY);os.dup2(null,0);os.close(null);os.dup2(log,1);os.dup2(log,2);os.close(log)
        # A hangup of the operator terminal must not cancel the negative lease.
        signal.signal(signal.SIGHUP,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
        monitor(ctx,review,gate.raw,journal,parent,pin);os._exit(0)
    except BaseException:
        # Keep the durable claim; unknown effects are never retried by another child.
        try:ctx.m.new_file(ctx.root,'watchdog-stop.json',{'status':'STOP_RECONCILE','negativeEffectMayBePartial':True,'automaticReplayAllowed':False})
        finally:os._exit(2)
