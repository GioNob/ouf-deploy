"""Exact local Engine/backup/read-only SQL ports for one reviewed V35 update."""
import copy,errno,hashlib,http.client,json,os,re,signal,stat,subprocess,time
from pathlib import Path
from urllib.parse import quote

class NativePorts:
    def __init__(self,core,ctx,root,review,gate):
        self.core,self.ctx,self.root,self.review,self.gate=core,ctx,Path(root),review,gate
        self.plan=review['nativePlan'];self.row=self.plan['replacement'];self.execution=None
        from engine_creation import Engine
        self.engine=Engine(self.plan['engine']['socketPath'],tuple(self.plan['engine']['socketBinding']))
        self.request_count=0;self.process_count=0;self.last_readiness=None;self.last_sql=None
    def require(self,ok,code):self.core.require(ok,code)
    def reserve(self,kind):
        self.ctx.ports_module.quarantine.ensure_alive(self.ctx,self.execution.read_journal())
        self.execution.reserve(kind)
    def record(self):return self.execution.record()
    def request(self,method,path,body=None):
        self.require(method in('GET','POST'),'V35_ONLY_EXACT_GET_AND_POST_ALLOWED')
        self.reserve('engineGets'if method=='GET'else'engineWrites');self.request_count+=1
        status,value=self.engine.request(method,path,body)
        self.ctx.m.new_file(self.root,'engine-response-%03d.json'%self.request_count,{'status':status,'body':value})
        return status,value
    def container(self,cid):
        row=self.record();allowed={self.row['oldRuntimeBinding']['containerId'],*[v['containerId']for v in self.plan['unchangedApplications'].values()]}
        if row['createdId']:allowed.add(row['createdId'])
        self.require(cid in allowed and re.fullmatch('[a-f0-9]{64}',cid),'ONLY_BOUND_V35_CONTAINER_IDS_ALLOWED')
        status,value=self.request('GET','/v1.44/containers/'+cid+'/json')
        self.require(status==200 and value['Id']==cid,'BOUND_V35_CONTAINER_READ_REQUIRED');return value
    def image(self):
        status,value=self.request('GET','/v1.44/images/'+quote(self.plan['candidate']['nativeImageId'],safe='')+'/json')
        if status==404:return None
        self.require(status==200,'EXACT_V35_IMAGE_READ_REQUIRED');self.ctx.importer.matched(self.plan['candidate'],value);return value
    def network(self):
        selected=self.row['network']['id']
        self.require(re.fullmatch('[a-f0-9]{64}',selected),'ONE_EXACT_V35_NETWORK_ID_REQUIRED')
        status,value=self.request('GET','/v1.44/networks/'+selected)
        self.require(status==200 and value['Id']==selected and value['Name']==self.row['network']['name'],'EXACT_RETAINED_V35_NETWORK_REQUIRED')
        return value
    def check_sources_and_configuration(self):
        self.ctx.check_sources();self.reserve('ownerConfigurationReads')
        from tools.chatbot_file_cohort.gateway import private_config
        binding=self.plan['nativeFlywayConfiguration']['ownerOverlays'][0]['binding']
        self.require(binding['path']==self.ctx.n.OWNER_OVERLAY,'ONLY_RETAINED_NAMED_V35_CONFIGURATION')
        private_config(binding['path'],binding)
    def guard(self,stage):
        from tools.ingestion_readiness_patch_execution import runtime_bindings
        self.require(stage in self.core.STAGES,'EXACT_V35_STAGE_REQUIRED');self.gate.check();self.check_sources_and_configuration()
        for name,binding in self.plan['unchangedApplications'].items():
            actual=self.container(binding['containerId'])
            self.require(actual['State']['Running']is True and runtime_bindings.observed(actual,runtime_bindings.NATIVE)==binding
                and self.ctx.m.process(actual)==self.ctx.inputs['currentProcessIdentities'][name],'UNCHANGED_V35_PEER_GENERATION_REQUIRED')
        self.old_guard(stage)
        row=self.record()
        if row['createdId']:self.candidate_guard(row['createdId'],stage)
    def old_guard(self,stage):
        old=self.container(self.row['oldRuntimeBinding']['containerId']);pin=self.row['oldRuntimeBinding'];i=self.core.STAGES.index(stage)
        self.require(old['Image']==pin['imageId']and self.core.digest(old['Config'])==pin['configHash']
            and self.core.digest(sorted(old['Mounts'],key=lambda v:v['Destination']))==pin['mountsHash']
            and old['State']['StartedAt']==pin['startedAt'],'RETAINED_V35_OLD_CONFIGURATION_REQUIRED')
        host=copy.deepcopy(self.row['oldNativeHostConfig'])
        if i>self.core.STAGES.index('DISABLE_OLD_RESTART'):host['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
        self.require(old['HostConfig']==host,'V35_OLD_HOST_CONFIGURATION_CHANGED')
        if i<=self.core.STAGES.index('STOP_OLD_ONBOARDING'):
            self.require(old['State']['Running']is True and old['State']['Pid']==pin['pid'],'V35_OLD_PROCESS_CHANGED_BEFORE_STOP')
            self.require(self.core.digest(old['NetworkSettings'])==pin['networkSettingsHash'],'V35_OLD_ENDPOINT_CHANGED_BEFORE_STOP')
        else:self.require(old['State']['Running']is False and old['State']['Pid']==0,'OLD_ONBOARDING_MUST_REMAIN_STOPPED')
        expected_name=self.row['name']if i<=self.core.STAGES.index('RENAME_OLD')else self.row['retiredName']
        self.require(old['Name']=='/'+expected_name,'OLD_V35_NAME_CHANGED')
        networks=old['NetworkSettings']['Networks']
        if i>self.core.STAGES.index('DETACH_OLD_ENDPOINT'):
            self.require(old['Id']not in(self.network().get('Containers')or{}),'OLD_V35_ENDPOINT_NOT_RELEASED')
            self.require(set(networks)in(set(),{self.row['network']['name']}),'OLD_V35_CONFIGURED_NETWORK_SELECTION_CHANGED')
        else:
            self.require(set(networks)=={self.row['network']['name']},'OLD_V35_NETWORK_SELECTION_CHANGED')
            self.require(networks[self.row['network']['name']]['NetworkID']==self.row['network']['id'],'OLD_V35_NETWORK_ID_CHANGED')
        return old
    def candidate_guard(self,cid,stage,*,started=None,restored=None):
        from engine_creation import requested_host_config_matches
        actual=self.container(cid);request=self.row['request'];row=self.record();i=self.core.STAGES.index(stage)
        if started is None:started=i>self.core.STAGES.index('START_REVIEWED_V35_REPLACEMENT')
        if restored is None:restored=i>self.core.STAGES.index('RESTORE_RESTART_POLICY')
        self.require(actual['Name']=='/'+self.row['name']and actual['Image']==request['Image'],'EXACT_V35_REPLACEMENT_IDENTITY_REQUIRED')
        for key,value in request.items():
            if key not in('HostConfig','NetworkingConfig'):
                expected=self.plan['runtimeLabelProjection']['expectedLabels']if key=='Labels'else value
                self.require(actual['Config'].get(key)==expected,'EXACT_V35_REPLACEMENT_CONFIG_REQUIRED')
        host=copy.deepcopy(request['HostConfig'])
        if restored:host['RestartPolicy']=copy.deepcopy(self.row['restoreRestartPolicy'])
        self.require(requested_host_config_matches(host,actual['HostConfig'],started=started),'EXACT_V35_REPLACEMENT_HOST_REQUIRED')
        self.require(self.core.digest(sorted(actual['Mounts'],key=lambda v:v['Destination']))==self.row['oldRuntimeBinding']['mountsHash'],
            'V35_REPLACEMENT_MOUNTS_MUST_BE_RETAINED')
        networks=actual['NetworkSettings']['Networks'];self.require(set(networks)=={self.row['network']['name']},'ONE_EXACT_V35_REPLACEMENT_NETWORK')
        endpoint=networks[self.row['network']['name']]
        self.require(endpoint['NetworkID']==self.row['network']['id'],'SAME_V35_NETWORK_ID_REQUIRED')
        if started:
            self.require(actual['State']['Running']is True and actual['State']['Paused']is False and actual['State']['Restarting']is False
                and actual['RestartCount']==0 and endpoint['IPAddress']==self.row['network']['ip']
                and endpoint['MacAddress'].lower()==self.row['network']['mac'].lower(),'V35_RUNNING_PROCESS_AND_ENDPOINT_REQUIRED')
            aliases=request['NetworkingConfig']['EndpointsConfig'][self.row['network']['name']].get('Aliases')or[]
            self.require(all(v in(endpoint.get('Aliases')or[])for v in aliases),'V35_RETAINED_NETWORK_ALIASES_REQUIRED')
            if row['createdGeneration']:self.require(self.ctx.m.process(actual)==row['createdGeneration'],'V35_NEW_PROCESS_GENERATION_CHANGED')
        else:self.require(actual['State']['Running']is False and actual['State']['Pid']==0,'V35_CANDIDATE_MUST_NOT_ALREADY_BE_STARTED')
        return actual
    def docker_prefix(self):
        p=self.plan['databaseProfile'];self.ctx.m.raw(p['dockerExecutable']['path'],67108864,p['dockerExecutable']['sha256'],private=False)
        self.require(not os.listdir(self.root/'empty-docker-config'),'V35_DOCKER_CONFIG_MUST_REMAIN_EMPTY')
        return [p['dockerExecutable']['path'],'--host','unix://'+p['engineBinding']['socketPath'],'--config',str(self.root/'empty-docker-config')]
    def command(self,argv,*,maximum=524288,seconds=20,stdin=None,output=None):
        self.process_count+=1;prefix='process-%02d'%self.process_count;errpath=self.root/(prefix+'.err')
        outpath=Path(output)if output else self.root/(prefix+'.out')
        ofd=os.open(outpath,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        efd=os.open(errpath,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        proc=None;deadline=time.monotonic()+min(seconds,max(.01,self.gate.remaining()-3));last=time.monotonic()
        try:
            proc=subprocess.Popen(argv,stdin=stdin if stdin is not None else subprocess.DEVNULL,stdout=ofd,stderr=efd,
                env={'LC_ALL':'C','PATH':'/usr/bin:/bin'},start_new_session=True)
            while proc.poll()is None:
                self.require(time.monotonic()<deadline,'V35_NATIVE_PROCESS_DEADLINE')
                self.require(os.fstat(ofd).st_size<=maximum and os.fstat(efd).st_size<=65536,'V35_NATIVE_PROCESS_OUTPUT_BOUND')
                if time.monotonic()-last>=15:
                    print(self.core.encoded({'schema':'ouf.onboarding-v35-progress.v1','stage':self.core.STAGES[self.record()['nextStage']],
                        'counts':self.record()['counts'],'automaticReplayAllowed':False}).decode(),flush=True);last=time.monotonic()
                time.sleep(.1)
            os.fsync(ofd);os.fsync(efd)
            self.require(time.monotonic()<=deadline and proc.returncode==0 and os.fstat(ofd).st_size<=maximum and os.fstat(efd).st_size<=65536,'V35_NATIVE_PROCESS_OUTCOME_UNPROVEN')
        finally:
            if proc is not None and proc.poll()is None:os.killpg(proc.pid,signal.SIGKILL)
            if proc is not None:proc.wait(timeout=5)
            os.close(ofd);os.close(efd)
        if output:
            h=hashlib.sha256();size=0
            with outpath.open('rb')as stream:
                for block in iter(lambda:stream.read(1048576),b''):h.update(block);size+=len(block)
            return {'path':str(outpath),'sha256':h.hexdigest(),'bytes':size}
        return outpath.read_bytes()
    def snapshot(self,*,after=False):
        self.reserve('sqlSessions');p=self.plan['databaseProfile'];argv=self.ctx.q.arguments(self.ctx.d,p,self.root/'empty-docker-config')
        argv[-1]=self.ctx.sql(after=after)
        self.require(hashlib.sha256(argv[-1].encode()).hexdigest()==self.review['sqlQueryHashes']['after'if after else'before'],'EXACT_SIGNED_READ_ONLY_V35_SQL_REQUIRED')
        raw=self.command(argv,seconds=20);facts=self.ctx.m.decode(raw)
        self.ctx.validate_sql(facts,after=after,before=self.ctx.before);self.last_sql=facts
        return facts
    def backup(self):
        self.require(self.container(self.row['oldRuntimeBinding']['containerId'])['State']['Running']is False,'QUIESCED_V35_BACKUP_REQUIRED')
        self.snapshot();p=self.plan['databaseProfile'];identity=p['identity'];program=p['containerPrograms']
        common=self.docker_prefix()+['exec',p['postgresRuntimeBinding']['containerId'],program['env'],'-i','LC_ALL=C',
            'PGPASSFILE=/dev/null','PGSERVICEFILE=/dev/null','PGSYSCONFDIR=/nonexistent',
            'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=60000 -c lock_timeout=1000']
        dump=str(Path(program['psql']).with_name('pg_dump'));restore=str(Path(program['psql']).with_name('pg_restore'))
        self.reserve('backupProcesses');proof=self.command(common+[dump,'-h',p['unixSocketDirectory'],'-p',str(identity['postgresPort']),
            '-U',identity['adminRole'],'-d',identity['database'],'--format=custom','--no-owner','--no-acl','--lock-wait-timeout=5s'],
            seconds=90,maximum=self.review['maximumBackupBytes'],output=self.root/'onboarding.dump')
        with (self.root/'onboarding.dump').open('rb')as source:self.require(source.read(5)==b'PGDMP'and proof['bytes']>100,'CUSTOM_V35_BACKUP_FORMAT_REQUIRED')
        self.reserve('backupProcesses')
        with (self.root/'onboarding.dump').open('rb')as source:
            argv=self.docker_prefix()+['exec','-i',p['postgresRuntimeBinding']['containerId'],program['env'],'-i','LC_ALL=C',restore,'--file=/dev/null']
            self.command(argv,stdin=source,maximum=1048576,seconds=90)
        self.snapshot();row=self.record();self.execution.save(row,backup={**proof,'payloadParsed':True,'restorePerformed':False})
        return {'backupVerified':True,'backupHash':proof['sha256'],'backupBytes':proof['bytes'],'databaseRestorePerformed':False}
    def readiness(self):
        stage=self.core.STAGES[self.record()['nextStage']]
        while True:
            self.gate.check();row=self.record();self.require(row['startupDeadline']is not None and time.time()<row['startupDeadline'],'V35_STARTUP_WINDOW_EXHAUSTED');self.require(row['readinessInFlight']is False,'INTERRUPTED_V35_READINESS_REQUIRES_RECONCILIATION')
            if time.time()<row['readinessNextWall']or time.monotonic()<row['readinessNextMonotonic']:
                self.require(self.gate.remaining()>5 and time.time()<row['startupDeadline'],'V35_READINESS_WINDOW_EXHAUSTED');time.sleep(min(1,max(0,row['readinessNextWall']-time.time())));continue
            self.require(row['readinessAttempts']<128,'V35_READINESS_BUDGET_EXHAUSTED');self.reserve('readinessGets');row=self.record()
            self.execution.save(row,readinessAttempts=row['readinessAttempts']+1,readinessInFlight=True)
            self.candidate_guard(row['createdId'],stage,started=True)
            connection=http.client.HTTPConnection(self.row['network']['ip'],self.row['readiness']['readinessPort'],timeout=3)
            retry_after=0;transient=False;status=None;raw=b''
            try:
                connection.request('GET',self.row['readiness']['readinessPath'],headers={'Connection':'close','Accept':'application/json'})
                response=connection.getresponse();status=response.status;raw=response.read(262145)
                self.require(len(raw)<=262144,'BOUNDED_V35_READINESS_BODY_REQUIRED')
                retry=response.getheader('Retry-After','')
                if retry:self.require(re.fullmatch('[0-9]{1,4}',retry)is not None,'V35_RETRY_AFTER_REQUIRES_RECONCILIATION');retry_after=int(retry)
                transient=status in(429,502,503,504)
            except OSError as error:
                self.require(error.errno in(errno.ECONNREFUSED,errno.ECONNRESET,errno.ETIMEDOUT,errno.EHOSTUNREACH,errno.ENETUNREACH)
                    or isinstance(error,TimeoutError),'UNKNOWN_V35_READINESS_TRANSPORT');transient=True
            finally:connection.close()
            row=self.record();self.execution.save(row,readinessInFlight=False)
            if status==200:
                body=self.ctx.m.decode(raw);self.require(body.get('status')=='UP','V35_READINESS_NOT_UP')
                self.last_readiness={'status':200,'bodyHash':self.core.sha(raw),'attempts':row['readinessAttempts']};return self.last_readiness
            self.require(transient,'PERMANENT_OR_UNKNOWN_V35_READINESS_FAILURE')
            row=self.record();attempt=row['readinessAttempts'];base=(5,15,60,300,900)[min(attempt-1,4)]
            jitter=int(self.core.digest({'reviewHash':self.core.digest(self.review),'attempt':attempt})[:4],16)/65535*.2
            delay=max(retry_after,base*(1+jitter));self.require(delay+10<min(self.gate.remaining(),row['startupDeadline']-time.time()),'V35_READINESS_WINDOW_EXHAUSTED')
            self.execution.save(row,readinessNextWall=time.time()+delay,readinessNextMonotonic=time.monotonic()+delay)
    def execute(self,stage):
        self.gate.check();oldid=self.row['oldRuntimeBinding']['containerId'];row=self.record()
        self.require(row['nextStage']<len(self.core.STAGES)and self.core.STAGES[row['nextStage']]==stage
            and len(row['effects'])==row['nextStage']+1 and row['effects'][-1]['state']=='CLAIMED'
            and row['effects'][-1]['stage']==stage,'EXACT_CLAIMED_ORDERED_V35_STAGE_REQUIRED')
        self.guard(stage);row=self.record()
        if stage=='VERIFY_CURRENT_ADMISSION_AND_SIGNED_REVIEW':
            self.snapshot();return {'freshDatabaseAdmissionProven':True,'signedReviewHash':self.core.digest(self.review)}
        if stage=='IMPORT_EXACT_IMAGE':
            if self.image()is not None:return {'existingExactImageAdopted':True,'loadAttempts':0}
            self.reserve('imageLoadAttempts')
            self.ctx.check_native_archive()
            with self.ctx.native_archive.open('rb')as source:self.ctx.importer.load(self.docker_prefix()+['load'],source)
            self.require(self.image()is not None,'EXACT_V35_IMAGE_LOAD_UNPROVEN');return {'nativeImageLoaded':True,'loadAttempts':1}
        if stage=='DISABLE_OLD_RESTART':
            self.snapshot()
            status,_=self.request('POST','/v1.44/containers/'+oldid+'/update',{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}})
            self.require(status==200 and self.container(oldid)['HostConfig']['RestartPolicy']=={'Name':'no','MaximumRetryCount':0},'OLD_V35_RESTART_DISABLE_UNPROVEN')
            return {'oldRestartDisabled':True}
        if stage=='STOP_OLD_ONBOARDING':
            status,_=self.request('POST','/v1.44/containers/'+oldid+'/stop?t=10');actual=self.container(oldid)
            self.require(status==204 and actual['State']['Running']is False and actual['State']['Pid']==0,'OLD_V35_STOP_UNPROVEN');return {'oldStopped':True}
        if stage=='VERIFY_QUIESCED_BACKUP':return self.backup()
        if stage=='DETACH_OLD_ENDPOINT':
            observed=self.network();dispatched=oldid in(observed.get('Containers')or{})
            if dispatched:
                status,_=self.request('POST','/v1.44/networks/'+self.row['network']['id']+'/disconnect',{'Container':oldid,'Force':False})
                self.require(status==200,'OLD_V35_ENDPOINT_RELEASE_UNPROVEN')
            self.require(oldid not in(self.network().get('Containers')or{}),'OLD_V35_ENDPOINT_RELEASE_UNPROVEN')
            return {'oldEndpointReleased':True,'disconnectNeededAndDispatched':dispatched}
        if stage=='RENAME_OLD':
            status,_=self.request('POST','/v1.44/containers/'+oldid+'/rename?name='+quote(self.row['retiredName'],safe=''))
            self.require(status==204 and self.container(oldid)['Name']=='/'+self.row['retiredName'],'OLD_V35_RENAME_UNPROVEN');return {'oldRetainedStopped':True}
        if stage=='CREATE_REPLACEMENT':
            status,value=self.request('POST','/v1.44/containers/create?name='+quote(self.row['name'],safe=''),self.row['request'])
            self.require(status==201 and type(value)is dict and re.fullmatch('[a-f0-9]{64}',value.get('Id','')),'V35_CREATION_OUTCOME_UNPROVEN')
            row=self.record();self.execution.save(row,createdId=value['Id']);self.candidate_guard(value['Id'],stage,started=False)
            row=self.record();self.execution.save(row,createdConfigurationVerified=True)
            return {'createdContainerId':value['Id']}
        if stage=='START_REVIEWED_V35_REPLACEMENT':
            self.require(row['createdConfigurationVerified']is True,'V35_CREATED_CONFIG_PROOF_REQUIRED_BEFORE_START')
            self.execution.save(row,startupDeadline=time.time()+self.review['negativeCleanup']['startupSeconds'])
            status,_=self.request('POST','/v1.44/containers/'+row['createdId']+'/start');self.require(status==204,'V35_START_OUTCOME_UNPROVEN')
            actual=self.candidate_guard(row['createdId'],stage,started=True);row=self.record();self.execution.save(row,createdGeneration=self.ctx.m.process(actual))
            return {'reviewedV35ApplicationStarted':True,'newProcessGenerationBound':True}
        if stage=='VERIFY_READINESS_AND_EXACT_V35_HISTORY':return {'applicationReadiness':self.readiness()}
        if stage=='VERIFY_RETAINED_SOURCE_COUNTERS_AND_ZERO_BUDGET_SESSIONS':
            self.snapshot(after=True);return {'exactV35HistoryAndSchemaVerified':True,'sourceAttempts':3,'sourceGeneration':4,'budgetSessions':0}
        if stage=='RESTORE_RESTART_POLICY':
            status,_=self.request('POST','/v1.44/containers/'+row['createdId']+'/update',{'RestartPolicy':self.row['restoreRestartPolicy']})
            self.require(status==200,'V35_RESTART_POLICY_RESTORE_UNPROVEN');self.candidate_guard(row['createdId'],stage,started=True,restored=True)
            return {'restartPolicyRestored':True,'workerRestartPerformed':False}
        self.require(stage=='VERIFY_FINAL','UNKNOWN_V35_STAGE')
        self.require(self.last_sql is not None and self.last_readiness is not None,'V35_FINAL_DB_AND_READINESS_PROOFS_REQUIRED')
        self.candidate_guard(row['createdId'],stage,started=True,restored=True)
        return {'applicationReady':True,'onboardingSqlVersion':35,'retainedSourceAttempts':3,'retainedSourceGeneration':4,'budgetSessions':0}
    def final_result(self):
        row=self.record();self.require(row['state']=='COMPLETE'and row['nextStage']==len(self.core.STAGES),'COMPLETE_V35_JOURNAL_REQUIRED')
        return {'schema':'ouf.onboarding-v35-native-update-result.v1','status':'ONBOARDING_V35_APPLIED_SOURCE_PRESERVED','complete':True,
            'contextPath':str(self.root),'reviewHash':self.core.digest(self.review),'authorityHash':self.core.sha(self.gate.raw),
            'frozenPlanHash':self.review['frozenPlanHash'],'nativePlanHash':self.review['nativePlanHash'],'journalVersion':row['version'],
            'counts':row['counts'],'databaseMigrationVersion':35,'databaseMigrationChecksum':1095739786,'databaseMigrations':1,
            'applicationReadinessProven':True,'nativeFlywayHistoryVerified':True,'backupVerified':True,'databaseRestorePerformed':False,
            'oldOnboardingRetainedStopped':True,'existingLabelsPreserved':True,'exactInheritedImageLabelsProven':True,'sourceReadinessAttempts':3,'sourceReadinessGeneration':4,'sourceReadinessPhase':'PAUSED',
            'budgetSessionCount':0,'humanBudgetsGranted':0,'sourceActivations':0,'registryWorkerTouched':False,'oauthRequests':0,
            'credentialValuesPrinted':False,'addressesPrinted':False,'originalRequestRepeated':False,'applicationE2EProven':False,
            'runtimeAuthorityIssued':True,'installationSigningKeysRead':True,'installationSigningOperations':3,
            'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False,'automaticRollbackPerformed':False}
