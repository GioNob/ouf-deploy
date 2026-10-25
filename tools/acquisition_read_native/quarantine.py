"""One ephemeral negative-only lease for this execution's3owned candidates."""
import copy,os,re,select,signal,time
from pathlib import Path
def pin(pid):
    try:
        raw=Path('/proc/'+str(pid)+'/stat').read_text();fields=raw[raw.rfind(')')+2:].split();return None if fields[0]in('Z','X','x')else fields[19]
    except (OSError,IndexError):return None
def read(journal):
    for attempt in range(8):
        try:return journal.read()
        except BlockingIOError:
            if attempt==7:raise
            time.sleep(.02)
def cas(journal,fn):
    for i in range(8):
        try:
            row=read(journal);next_row=fn(copy.deepcopy(row))
            if next_row is None:return None
            next_row['version']=row['version']+1;journal.compare_and_save(row,next_row);return next_row
        except (ValueError,BlockingIOError)as e:
            if isinstance(e,ValueError)and str(e)!='RECOVERY_CAS_CONFLICT':raise
            if i==7:raise
            time.sleep(.02)
def negative(ctx,review,raw,journal,reason):
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
    negative_started=time.monotonic();negative_wall=time.time()
    core=ctx.core;core.validate_review(review);authority=ctx.p.decode(raw);v=review['verification'];context=v['context'];policy={'path':str(ctx.root/'authority/issued-trust-policy.json'),'sha256':v['trustPolicy']['sha256']};verifier=DetachedAuthenticator(policy,str(ctx.root/'authority'),v['openssl']);ctx.check_sources()
    core.require(authority['schema']==core.AUTHORITY_SCHEMA and authority['scope']==core.scope(review)and authority['expiresAt']-authority['issuedAt']==900 and authority['cleanupExpiresAt']==authority['expiresAt']+30,'EXACT_SIGNED_NEGATIVE_SCOPE_REQUIRED')
    for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):core.require(verifier(raw,role,context[key],context['installationRef'],context['entityRef'])is True,'CURRENT_SIGNED_NEGATIVE_LEASE_REQUIRED')
    def claim(row):
        core.require(row['reviewHash']==core.digest(review)and row['authorityHash']==core.sha(raw),'SAME_NEGATIVE_AUTHORITY_JOURNAL_REQUIRED')
        if row['state']=='COMPLETE'or row['quarantine']is not None:return None
        row['quarantine']={'state':'CLAIMED','reason':reason,'candidates':{},'claimedAt':negative_wall,'deadlineMonotonic':min(row['expiresMonotonic']+30,negative_started+30),'deadlineWall':min(authority['cleanupExpiresAt'],negative_wall+30)};return row
    row=cas(journal,claim)
    if row is None:return
    ctx.engine.timeout=2
    def check():
        current=read(journal);core.require(time.time()>=authority['issuedAt']and time.time()<authority['cleanupExpiresAt']and time.monotonic()<current['quarantine']['deadlineMonotonic']and time.time()<current['quarantine']['deadlineWall']and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==review['bootId'],'FINITE_NEGATIVE_LEASE_REQUIRED');ctx.check_sources()
    def reserve(kind):
        check()
        def change(row):
            core.require(row['quarantine']['state']=='CLAIMED'and row['counts'][kind]<review['maximums'][kind],'NEGATIVE_CLAIM_AND_BUDGET_REQUIRED');row['counts'][kind]+=1;return row
        cas(journal,change)
    for role,candidate in row['candidates'].items():
        if candidate.get('configurationVerified')is not True:continue
        cid=candidate['id'];core.require(cid not in{v['containerId']for v in ctx.proposal['existingApplications'].values()},'ONLY_NEW_OWNED_CANDIDATE_QUARANTINE')
        def inspect():
            reserve('engineGets');s,v=ctx.engine.request('GET','/v1.44/containers/'+cid+'/json');core.require(s==200 and v['Id']==cid,'EXACT_NEGATIVE_CANDIDATE_REQUIRED');restored=v['HostConfig'].get('RestartPolicy')==ctx.restore_policy(role);ctx.candidate_configuration(role,v,v['State']['Running']is True,restored,quarantine=True)
            if v['State']['Running']and candidate.get('generation'):core.require(ctx.p.process_pin(v['State']['Pid'])==candidate['generation'],'SAME_NEGATIVE_CANDIDATE_GENERATION_REQUIRED')
            return v
        actual=inspect();reserve('quarantineStops');reserve('engineWrites');s,_=ctx.engine.request('POST','/v1.44/containers/'+cid+'/update',{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}});core.require(s==200,'NEGATIVE_CANDIDATE_RESTART_DISABLE_UNPROVEN')
        if actual['State']['Running']:
            reserve('engineWrites');s,_=ctx.engine.request('POST','/v1.44/containers/'+cid+'/stop?t=2');core.require(s==204,'NEGATIVE_CANDIDATE_STOP_OUTCOME_UNPROVEN')
        reserve('engineGets');s,after=ctx.engine.request('GET','/v1.44/containers/'+cid+'/json');core.require(s==200 and after['Id']==cid and after['State']['Running']is False and after['State']['Pid']==0 and after['HostConfig']['RestartPolicy']=={'Name':'no','MaximumRetryCount':0},'OWNED_CANDIDATE_QUARANTINE_UNPROVEN')
        def saved(row):row['quarantine']['candidates'][role]={'id':cid,'stopped':True,'restartDisabled':True};return row
        cas(journal,saved)
    def done(row):row['quarantine']['state']='APPLIED';row['state']='STOP_RECONCILE';return row
    cas(journal,done);ctx.write(ctx.root,'quarantine-result.json',{'schema':'ouf.acquisition-negative-lease-result.v1','status':'OWNED_CANDIDATES_QUARANTINED','releaseAcceptance':False,'automaticReplayAllowed':False})
def ensure_alive(ctx):
    pid=getattr(ctx,'watchdog_pid',None);expected=getattr(ctx,'watchdog_pin',None);ctx.core.require(pid is not None and pin(pid)==expected,'LIVE_BOUND_NEGATIVE_WATCHDOG_REQUIRED')
    raw=Path('/proc/'+str(pid)+'/stat').read_text();ctx.core.require(raw[raw.rfind(')')+2:].split()[0]not in('Z','X','x'),'NEGATIVE_WATCHDOG_EXITED')
def launch(ctx,review,gate,journal):
    parent=os.getpid();parent_pin=pin(parent);ctx.core.require(parent_pin is not None,'BOUND_CONTROLLER_PROCESS_REQUIRED');log=os.open(ctx.root/'watchdog.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400);r,w=os.pipe2(os.O_CLOEXEC);child=os.fork()
    if child:
        os.close(log);os.close(w)
        try:
            ready,_,_=select.select([r],[],[],10);ctx.core.require(bool(ready)and os.read(r,32)==b'READY','WATCHDOG_READY_BEFORE_ANY_EFFECT_REQUIRED')
        finally:os.close(r)
        ctx.watchdog_pid,ctx.watchdog_pin=child,pin(child);ensure_alive(ctx);return child
    try:
        os.close(r);os.setsid();signal.signal(signal.SIGHUP,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN);null=os.open('/dev/null',os.O_RDONLY);os.dup2(null,0);os.close(null);os.dup2(log,1);os.dup2(log,2);os.close(log);os.write(w,b'READY');os.close(w);last=time.time()
        while True:
            row=read(journal)
            if row['state']=='COMPLETE'or row['quarantine']is not None:os._exit(0)
            now=time.time();startup_expired=any(not v.get('readinessProven')and v.get('startupDeadlineMonotonic')is not None and(time.monotonic()>=v['startupDeadlineMonotonic']or now>=v['startupDeadlineWall'])for v in row['candidates'].values());reason='STARTUP_LEASE_EXPIRED'if startup_expired else'CONTROLLER_LOST'if pin(parent)!=parent_pin else'FINITE_LEASE_EXPIRED'if now>=row['expiresAt']or time.monotonic()>=row['expiresMonotonic']else'WALL_CLOCK_REGRESSION'if now<last else None;last=now
            if reason:negative(ctx,review,gate.raw,journal,reason);os._exit(0)
            time.sleep(.25)
    except BaseException:
        try:ctx.write(ctx.root,'watchdog-unproven.json',{'status':'STOP_RECONCILE','negativeEffectMayBePartial':True,'automaticReplayAllowed':False})
        finally:os._exit(2)
