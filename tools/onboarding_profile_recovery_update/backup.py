"""Reuse V35 quiescent native pg_dump and offline pg_restore parser, no restore."""
import hashlib,os,resource,signal,subprocess,time
from pathlib import Path

def perform(ports):
    ctx=ports.ctx;c=ctx.core;stage='VERIFY_QUIESCED_BACKUP';row=ports.execution.record()
    c.require(ports.stages[row['nextStage']]==stage and row['effects'][-1]['state']=='CLAIMED','EXACT_CLAIMED_BACKUP_STAGE_REQUIRED')
    old=ports.container(ports.plan['onboardingReplacement']['oldBinding']['containerId'])
    c.require(old['State']['Running']is False and old['State']['Pid']==0,'OWNER_MUST_BE_QUIESCED_FOR_BACKUP')
    ctx.database.observe(ports,stage,sample='BEFORE');profile=ctx.database_profile;identity=profile['identity'];program=profile['containerPrograms']
    config=ctx.root/'empty-docker-config';c.require(not any(config.iterdir()),'BACKUP_DOCKER_CONFIG_MUST_REMAIN_EMPTY')
    prefix=[profile['dockerExecutable']['path'],'--host','unix://'+profile['engineBinding']['socketPath'],'--config',str(config),'exec']
    common=[profile['postgresRuntimeBinding']['containerId'],program['env'],'-i','LC_ALL=C','PGPASSFILE=/dev/null','PGSERVICEFILE=/dev/null','PGSYSCONFDIR=/nonexistent',
        'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=60000 -c lock_timeout=1000']
    dump=str(Path(program['psql']).with_name('pg_dump'));restore=str(Path(program['psql']).with_name('pg_restore'))
    target=ctx.root/'onboarding.dump';maximum=ctx.review['maximumBackupBytes']
    def command(args,name,*,stdin=None,maximum=262144):
        ctx.database.check_docker(ctx);pg=ports.container(profile['postgresRuntimeBinding']['containerId']);ctx.database.check_postgres(ctx,pg)
        pin=ctx.p.process_pin(pg['State']['Pid']);c.require(pin==ctx.inputs['currentProcessPins']['peer-'+pg['Id'][:16]],'SAME_POSTGRES_BACKUP_PROCESS_REQUIRED')
        # Every Docker CLI connection is preceded by the authenticated root Engine peer check.
        ports.reserve('backupProcesses');ctx.evidence('backup-dispatch-claim',{'operation':name,'argumentHash':c.digest(args),'attemptNotCompletion':True})
        output=target if name=='dump'else ctx.root/'backup-parse.out';error=ctx.root/('backup-'+name+'.err');streams=[];proc=None;started=time.monotonic()
        try:
            for path in(output,error):
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400);os.fchmod(fd,0o400);streams.append(os.fdopen(fd,'wb'))
            def finite_child():
                resource.setrlimit(resource.RLIMIT_FSIZE,(maximum,maximum));resource.setrlimit(resource.RLIMIT_CPU,(90,90))
            proc=subprocess.Popen(args,stdin=stdin if stdin is not None else subprocess.DEVNULL,stdout=streams[0],stderr=streams[1],cwd='/',env={'LC_ALL':'C','PATH':'/usr/bin:/bin'},start_new_session=True,preexec_fn=finite_child)
            while proc.poll()is None:
                ctx.gate.check();ctx.watch.ensure_alive(ctx);c.require(time.monotonic()-started<ctx.review['maximumBackupSeconds'],'FINITE_BACKUP_PROCESS_REQUIRED')
                c.require(output.stat().st_size<=maximum and error.stat().st_size<=65536,'BOUNDED_BACKUP_OUTPUT_REQUIRED');time.sleep(.05)
        finally:
            if proc is not None and proc.poll()is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=3)
            for stream in streams:stream.flush();os.fsync(stream.fileno());stream.close()
            ctx.sync(ctx.root)
        ctx.evidence('backup-process-receipt',{'operation':name,'returnCode':proc.returncode,'stderrSha256':hashlib.sha256(error.read_bytes()).hexdigest()})
        c.require(proc.returncode==0 and output.stat().st_size<=maximum and error.stat().st_size<=65536,'BACKUP_OUTCOME_UNPROVEN')
        pg_after=ports.container(profile['postgresRuntimeBinding']['containerId']);ctx.database.check_postgres(ctx,pg_after);c.require(ctx.p.process_pin(pg_after['State']['Pid'])==pin,'POSTGRES_CHANGED_DURING_BACKUP')
    command(prefix+common+[program['timeout'],'-s','KILL','85',dump,'-h',profile['unixSocketDirectory'],'-p',str(identity['postgresPort']),'-U',identity['adminRole'],'-d',identity['database'],
        '--format=custom','--no-owner','--no-acl','--lock-wait-timeout=5s'],'dump',maximum=maximum)
    c.require(target.stat().st_size>100 and target.read_bytes()[:5]==b'PGDMP','CUSTOM_BACKUP_FORMAT_REQUIRED')
    with target.open('rb')as source:command(prefix+['-i']+common+[program['timeout'],'-s','KILL','85',restore,'--file=/dev/null'],'parse',stdin=source)
    ctx.database.observe(ports,stage,sample='AFTER')
    ctx.backup_proof={'path':str(target),'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'bytes':target.stat().st_size,'quiesced':True,'payloadParsed':True,'databaseRestorePerformed':False,'metadata':list(ctx.p.frame(target.lstat()))}
    ctx.evidence('verified-backup',ctx.backup_proof);return ctx.backup_proof
