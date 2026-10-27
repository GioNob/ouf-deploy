"""Four NEW, reviewed operational SQL attempts; no diagnostic/domain bypass.

The V35 profile provides only transport identity. Its authority and counters are
never executed or adopted. Dispatch is gated by the new signed stage claim.
"""
import hashlib,os,stat,subprocess,time
from pathlib import Path

def retained_transport(core,profile,captured,expected):
    """One observed format enrichment; retain both original hashes unchanged.

    The historical profile lacks peerCredentials. Every other field must be
    byte-equivalent to the authenticated capture, whose ROOT peer is still
    checked live by Engine.connection on every request. No missing-current-peer,
    arbitrary field exclusion, socket drift or historical hash rewriting.
    """
    core.require(profile['schema']=='ouf.current-onboarding-database-snapshot-profile.v1'
                 and profile['runtimeBindingProfile']=='ouf.runtime-binding.native-mount-order.v1',
                 'EXACT_RETAINED_DATABASE_SCHEMA_AND_NATIVE_PROFILE_REQUIRED')
    retained=profile['engineBinding']
    core.require(type(retained)is dict and type(captured)is dict and 'peerCredentials'not in retained
                 and set(captured)==set(retained)|{'peerCredentials'},'EXACT_HISTORICAL_ABSENT_CURRENT_PRESENT_PEER_PROFILE_REQUIRED')
    core.require(all(core.encoded(captured[k])==core.encoded(v)for k,v in retained.items()),'EVERY_RETAINED_ENGINE_FIELD_MUST_REMAIN_EXACT')
    peer=captured['peerCredentials'];socket=captured.get('socketBinding');path=captured.get('socketPath')
    core.require(type(peer)is list and len(peer)==3 and all(type(v)is int for v in peer)
                 and peer[0]>0 and peer[1]==0 and peer[2]>=0,'EXACT_CURRENT_ROOT_ENGINE_PEER_CREDENTIALS_REQUIRED')
    core.require(type(path)is str and path.startswith('/')and'..'not in path.split('/')and '\x00'not in path
                 and type(socket)is list and len(socket)==5 and all(type(v)is int for v in socket)
                 and socket[0]>=0 and socket[1]>0 and socket[2]==0 and socket[3]>=0 and socket[4]in(0o600,0o660),
                 'EXACT_CURRENT_ROOT_ENGINE_SOCKET_CUSTODY_REQUIRED')
    hashes={'retainedEngineBindingHash':core.digest(retained),'capturedEngineBindingHash':core.digest(captured),
            'peerCredentialsHash':core.digest(peer)}
    core.require(hashes==expected,'EXACT_RECONCILED_RETAINED_AND_CAPTURED_TRANSPORT_HASHES_REQUIRED')
    return {'profile':'HISTORICAL_ENGINE_BINDING_WITHOUT_PEER_TO_EXACT_AUTHENTICATED_ROOT_PEER_CAPTURE_V1',
            **hashes,'historicalMetadataRewritten':False,'sameSocketPathAndCustody':True,
            'liveCapturedPeerVerificationOnEveryEngineRequestRequired':True}

def check_postgres(ctx,actual):
    p=ctx.database_profile;core=ctx.core
    core.require(p['runtimeBindingProfile']=='ouf.runtime-binding.native-mount-order.v1'
                 and ctx.engine_helpers.Engine.runtime_binding(actual)==p['postgresRuntimeBinding']
                 and actual['State']['Running']is True and actual['State']['Paused']is False
                 and actual['State']['Restarting']is False,'SAME_RETAINED_POSTGRES_NATIVE_GENERATION_REQUIRED')

def check_docker(ctx):
    binding=ctx.database_profile['dockerExecutable'];path=Path(binding['path']);ctx.p.ancestry(path.parent)
    info=path.lstat();ctx.core.require(path.resolve()==path and stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0
          and info.st_mode&0o111 and not info.st_mode&0o022 and 0<info.st_size<=128*1024*1024
          and hashlib.sha256(path.read_bytes()).hexdigest()==binding['sha256'],'EXACT_NATIVE_SQL_DOCKER_EXECUTABLE_REQUIRED')

def observe(ports,stage):
    ctx=ports.ctx;c=ctx.core;row=ports.execution.record();i=row['nextStage']
    c.require(stage in('VERIFY_CURRENT_ADMISSION','VERIFY_PRESTOP_STATE','VERIFY_PRESTART_STATE','VERIFY_FINAL_STATE')
              and ports.stages[i]==stage and len(row['effects'])==i+1 and row['effects'][-1]['state']=='CLAIMED'
              and ctx.review['maintenanceSqlAuthorized']is True
              and ctx.review['operationalSqlHash']==c.sha(ctx.fence.query().encode()),'NEW_CLAIMED_OPERATIONAL_SQL_AUTHORITY_REQUIRED')
    pg=ctx.database_profile['postgresRuntimeBinding']['containerId'];actual=ports.container(pg);check_postgres(ctx,actual)
    # Freeze both the retained native generation and the fresh process namespace.
    pin=ctx.p.process_pin(actual['State']['Pid']);role='peer-'+pg[:16]
    c.require(pin==ctx.inputs['currentProcessPins'][role],'CURRENT_BOUND_POSTGRES_PROCESS_REQUIRED');check_docker(ctx)
    config=ctx.root/'empty-docker-config'
    if not config.exists():config.mkdir(mode=0o700);ctx.sync(ctx.root)
    s=config.lstat();c.require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
                             and not any(config.iterdir()),'EMPTY_PRIVATE_DOCKER_CONFIG_REQUIRED')
    args=ctx.fence.arguments(ctx.database_profile,config,ctx.fence.query())
    ports.reserve('sqlSessions');ctx.evidence('operational-sql-dispatch-claim',{'stage':stage,'sqlSha256':ctx.review['operationalSqlHash'],'attemptNotCompletion':True})
    ctx.gate.check();ctx.check_sources();started=time.monotonic();paths=[];streams=[];proc=None
    try:
        for suffix in('stdout','stderr'):
            path=ctx.root/(stage.lower()+'-'+suffix+'.log');paths.append(path)
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400);os.fchmod(fd,0o400);streams.append(os.fdopen(fd,'wb'))
        proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=streams[0],stderr=streams[1],cwd='/',env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},start_new_session=True)
        while proc.poll()is None:
            ctx.gate.check();ctx.watch.ensure_alive(ctx)
            c.require(time.monotonic()-started<20,'FINITE_OPERATIONAL_SQL_SESSION_REQUIRED')
            c.require(all(path.stat().st_size<=262144 for path in paths),'BOUNDED_OPERATIONAL_SQL_RECEIPT_REQUIRED');time.sleep(.05)
    finally:
        if proc is not None and proc.poll()is None:
            import signal
            os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=3)
        for stream in streams:stream.flush();os.fsync(stream.fileno());stream.close()
        ctx.sync(ctx.root)
    def receipt(path):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd);c.require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o400 and info.st_size<=262144,'PRIVATE_SQL_RECEIPT_CUSTODY_REQUIRED')
            raw=os.read(fd,262145);c.require(len(raw)==info.st_size and ctx.p.frame(info)==ctx.p.frame(os.fstat(fd))==ctx.p.frame(path.lstat()),'PRIVATE_SQL_RECEIPT_CHANGED');return raw
        finally:os.close(fd)
    raw=receipt(paths[0]);err=receipt(paths[1])
    # Protected raw files survive before any decoding, return-code or shape guard.
    ctx.evidence('operational-sql-receipt',{'stage':stage,'returnCode':proc.returncode,'stdoutSha256':c.sha(raw),'stderrSha256':c.sha(err)})
    c.require(proc.returncode==0 and 0<len(raw)<=131072,'READ_ONLY_OPERATIONAL_SQL_RESULT_REQUIRED')
    facts=ctx.p.decode(raw);baseline=getattr(ctx,'operational_baseline',None)
    proof=ctx.fence.validate(facts,ctx.database_profile,ctx.migrations,baseline)
    if baseline is None:
        c.require(stage=='VERIFY_CURRENT_ADMISSION','INITIAL_OWNER_STATE_FENCE_REQUIRED');ctx.operational_baseline=facts
    else:c.require(stage!='VERIFY_CURRENT_ADMISSION','NO_OPERATIONAL_BASELINE_RESET')
    after=ports.container(pg);check_postgres(ctx,after);c.require(ctx.p.process_pin(after['State']['Pid'])==pin,'POSTGRES_GENERATION_CHANGED_DURING_SQL')
    ctx.evidence('operational-state-proof',{'stage':stage,**proof});return proof
