"""Closed two-READ replacement stages; no MCP, worker, route, IAM or data port."""
import copy,hashlib,os,re,time
from urllib.parse import quote
class NativePorts:
    def __init__(self,ctx,review,gate):
        self.ctx,self.root,self.review,self.gate=ctx,ctx.root,review,gate;self.core=ctx.core;self.plan=review['nativePlan']['proposal'];self.execution=None;self.stages=tuple(review['stages'])
    def require(self,ok,code):self.core.require(ok,code)
    def reserve(self,kind):self.ctx.watch.ensure_alive(self.ctx);self.execution.reserve(kind)
    def proposal(self,role):
        self.require(role in self.core.ROLES,'ONLY_TWO_READ_PORTS');return self.plan['readReplacements'][role]
    def parse(self,stage):
        for role in self.core.ROLES:
            suffix='_'+role.upper()+'_READ'
            if stage.endswith(suffix):return stage[:-len(suffix)],role
        self.require(stage in('VERIFY_CURRENT_ADMISSION','VERIFY_FINAL'),'UNKNOWN_TWO_READ_STAGE');return stage,None
    def assert_write(self,path,body):
        row=self.execution.record();i=row['nextStage'];self.require(i<len(self.stages)and len(row['effects'])==i+1 and row['effects'][-1]['state']=='CLAIMED','CLAIMED_SIGNED_STAGE_BEFORE_WRITE_REQUIRED')
        action,role=self.parse(self.stages[i]);self.require(role is not None,'NO_WRITE_IN_GLOBAL_READ_STAGE');old=self.proposal(role);cid=old['oldBinding']['containerId'];expected=None
        if action=='CREATE':expected=('/v1.44/containers/create?name='+quote(old['name'],safe=''),old['request'])
        elif action=='START':expected=('/v1.44/containers/'+row['candidates'][role]['id']+'/start',None)
        elif action=='DISABLE_OLD_RESTART':expected=('/v1.44/containers/'+cid+'/update',{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}})
        elif action=='STOP_OLD':expected=('/v1.44/containers/'+cid+'/stop?t=10',None)
        elif action=='DETACH_OLD':expected=('/v1.44/networks/'+old['network']['id']+'/disconnect',{'Container':cid,'Force':False})
        elif action=='RENAME_OLD':expected=('/v1.44/containers/'+cid+'/rename?name='+quote(old['retiredName'],safe=''),None)
        elif action=='RESTORE_RESTART':expected=('/v1.44/containers/'+row['candidates'][role]['id']+'/update',{'RestartPolicy':self.ctx.restore_policy(role)})
        self.require(expected==(path,body),'EXACT_SIGNED_TWO_READ_STAGE_COMMAND_REQUIRED')
    def request(self,method,path,body=None):
        self.ctx.closed_path(method,path,body)
        if method!='GET':self.assert_write(path,body)
        self.reserve('engineGets'if method=='GET'else'engineWrites');return self.ctx.engine.request(method,path,body)
    def container(self,cid):
        ids={v['containerId']for v in self.plan['existingApplications'].values()}|{v['id']for v in self.execution.record()['candidates'].values()}
        self.require(cid in ids and re.fullmatch('[a-f0-9]{64}',cid),'ONLY_FROZEN_OR_CREATED_CANDIDATE_IDS');s,v=self.request('GET','/v1.44/containers/'+cid+'/json');self.require(s==200 and v['Id']==cid,'EXACT_BOUND_CONTAINER_GET_REQUIRED');return v
    def network(self,role):
        net=self.proposal(role)['network'];s,v=self.request('GET','/v1.44/networks/'+net['id']);self.require(s==200 and v['Id']==net['id']and v['Name']==net['name']and v['Driver']=='bridge'and v['Scope']=='local','EXACT_RETAINED_BRIDGE_REQUIRED')
        excluded={v['oldBinding']['containerId']for v in self.plan['readReplacements'].values()}|{v['id']for v in self.execution.record()['candidates'].values()}
        self.require({k:r for k,r in(v.get('Containers')or{}).items()if k not in excluded}=={k:r for k,r in self.ctx.network_baseline[net['id']].items()if k not in excluded},'ALL_OTHER_NETWORK_ENDPOINTS_UNCHANGED_REQUIRED');return v
    def guard(self,stage):
        self.gate.check();self.ctx.check_sources()
        for role,b in self.plan['existingApplications'].items():
            if role in('ingestion-read','udp-read'):continue
            v=self.container(b['containerId']);self.require(v['State']['Running']is True and v['State']['Paused']is False and v['State']['Restarting']is False and self.ctx.p.stable_binding(v)==b and self.ctx.p.process_pin(v['State']['Pid'])==self.ctx.inputs['currentProcessPins'][role],'EXACT_UNCHANGED_WORKER_MCP_GATEWAY_POSTGRES_REQUIRED')
        for role in self.core.ROLES:self.old_guard(role,stage)
        for role in self.execution.record()['candidates']:self.candidate_guard(role,stage=stage)
    def old_guard(self,role,stage):
        row=self.proposal(role);b=row['oldBinding'];v=self.container(b['containerId']);i=self.stages.index(stage);at=lambda s:self.stages.index(s+'_'+role.upper()+'_READ')
        expected_name='/'+(row['name']if i<=at('RENAME_OLD')else row['retiredName']);config_matches=self.core.digest(v['Config'])==b['configHash']
        if i>at('DETACH_OLD'):
            history=self.execution.record()['effects'];detached=history[at('DETACH_OLD')];stopped=history[at('STOP_OLD')]
            self.require(detached['state']==stopped['state']=='APPLIED'and detached['proof'].get('oldDetached')is True and stopped['proof'].get('oldStopped')is True,'PROVEN_STOP_DETACH_PREFIX_REQUIRED')
            original=self.ctx.inputs['currentObservations'][role+'-read'];policy=row['legacyConfigMacDetachPolicy']
            self.require(self.core.digest(original['Config'])==b['configHash']and v['NetworkSettings']['Networks']=={},'EXACT_ORIGINAL_AND_NO_RETAINED_ENDPOINT_REQUIRED')
            if policy['profile']=='LEGACY_CONFIG_MAC_ABSENT_ONLY_AFTER_PROVEN_STOP_AND_DETACH_V1':
                self.require(policy==self.ctx.mac.policy(original),'EXACT_SIGNED_LEGACY_MAC_POLICY_REQUIRED')
                try:proof=self.ctx.mac.verify_detached(original,v,expected_name=expected_name)
                except self.ctx.mac.MacTransitionDenied as error:self.require(False,str(error))
                self.ctx.evidence('old-read-mac-transition',{'role':role,'proof':proof});config_matches=True
            else:
                state='ABSENT'if'MacAddress'not in original['Config']else'NULL'if original['Config']['MacAddress']is None else'EMPTY_STRING'if original['Config']['MacAddress']==''else'INVALID'
                self.require(policy=={'profile':'ENDPOINT_ONLY_CONFIG_EXACT_AFTER_STOP_AND_DETACH_V1','configurationMacState':state,'originalConfigHash':b['configHash'],'detachedConfigHash':b['configHash'],'originalEndpointSetHash':self.core.digest(original['NetworkSettings']['Networks']),'originalHashesRewritten':False}and state!='INVALID'and config_matches,'EXACT_ENDPOINT_ONLY_CONFIG_NO_NORMALIZATION_REQUIRED')
        self.require(v['Image']==b['imageId']and config_matches and self.core.digest(sorted(v['Mounts'],key=lambda x:x['Destination']))==b['mountsHash']and v['State']['StartedAt']==b['startedAt'],'OLD_READ_CONFIG_GENERATION_REQUIRED')
        host=copy.deepcopy(row['oldNativeHostConfig'])
        if i>at('DISABLE_OLD_RESTART'):host['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
        self.require(v['HostConfig']==host and v['Name']==expected_name,'OLD_READ_HOST_CONFIG_OR_NAME_CHANGED')
        if i<=at('STOP_OLD'):
            self.require(v['State']['Running']is True and v['State']['Paused']is False and v['State']['Restarting']is False and self.ctx.p.process_pin(v['State']['Pid'])==self.ctx.inputs['currentProcessPins'][role+'-read']and self.core.digest(v['NetworkSettings'])==b['networkSettingsHash'],'SAME_OLD_READ_BEFORE_STOP_REQUIRED')
        else:self.require(v['State']['Running']is False and v['State']['Pid']==0,'OLD_READ_MUST_REMAIN_STOPPED')
        if i>at('DETACH_OLD'):self.require(v['Id']not in(self.network(role).get('Containers')or{}),'OLD_READ_ENDPOINT_NOT_RELEASED')
        return v
    def candidate_guard(self,role,stage=None,started=None,restored=None,actual=None):
        row=self.execution.record()['candidates'][role];v=actual or self.container(row['id']);i=self.stages.index(stage)if stage else -1
        if started is None:started=i>self.stages.index('START_'+role.upper()+'_READ')
        if restored is None:restored=i>self.stages.index('RESTORE_RESTART_'+role.upper()+'_READ')
        self.ctx.candidate_configuration(role,v,started,restored)
        if started:
            pin=self.ctx.p.process_pin(v['State']['Pid']);self.require(row.get('generation')is None or pin==row['generation'],'CREATED_PROCESS_GENERATION_CHANGED')
            if row.get('generation')is None:self.execution.candidate(role,generation=pin)
        return v
    def image(self,role):
        fact=self.ctx.facts[role];s,v=self.request('GET','/v1.44/images/'+quote(fact['identity']['nativeImageId'],safe='')+'/json')
        if s==404:return None
        self.require(s==200,'EXACT_NATIVE_IMAGE_GET_REQUIRED');return self.ctx.images.loaded(fact['audit'],v)
    def create(self,role):
        old=self.proposal(role);self.require(role not in self.execution.record()['candidates'],'NO_CANDIDATE_CREATION_REPLAY')
        self.require(old['oldBinding']['containerId']not in(self.network(role).get('Containers')or{}),'OLD_READ_ENDPOINT_MUST_BE_RELEASED_BEFORE_CREATE')
        s,v=self.request('POST','/v1.44/containers/create?name='+quote(old['name'],safe=''),old['request']);self.require(s==201 and type(v)is dict and re.fullmatch('[a-f0-9]{64}',v.get('Id','')),'CANDIDATE_CREATE_OUTCOME_UNPROVEN')
        self.execution.candidate(role,id=v['Id'],configurationVerified=False,generation=None,readinessProven=False);self.candidate_guard(role,started=False,restored=False);self.execution.candidate(role,configurationVerified=True);return {'role':role,'createdId':v['Id'],'configurationVerified':True}
    def start(self,role):
        row=self.execution.record()['candidates'][role];self.candidate_guard(role,started=False,restored=False);self.execution.candidate(role,startupDeadlineWall=time.time()+180,startupDeadlineMonotonic=time.monotonic()+180)
        s,_=self.request('POST','/v1.44/containers/'+row['id']+'/start');self.require(s==204,'CANDIDATE_START_OUTCOME_UNPROVEN');self.candidate_guard(role,started=True,restored=False);return {'started':True,'role':role}
    def healthy(self,role):
        row=self.execution.record()['candidates'][role];last=time.monotonic()
        while True:
            self.gate.check();self.require(time.time()<row['startupDeadlineWall']and time.monotonic()<row['startupDeadlineMonotonic'],'FINITE_CANDIDATE_STARTUP_DEADLINE');self.candidate_guard(role,started=True,restored=False);self.reserve('readinessGets')
            pin=self.execution.record()['candidates'][role]['generation'];response=self.ctx.http.health(self.ctx.p,pin);self.ctx.evidence('health',{'role':role,**response});self.require(response['status']in(0,200,502,503,504),'PERMANENT_OR_UNKNOWN_READINESS_DENIAL')
            good=self.readiness(response)
            self.require(time.time()<row['startupDeadlineWall']and time.monotonic()<row['startupDeadlineMonotonic'],'READINESS_PROOF_WITHIN_STARTUP_LEASE_REQUIRED')
            if good:self.execution.candidate(role,readinessProven=True);return {'readinessProven':True,'role':role}
            if time.monotonic()-last>=10:print('Attendo readiness READ '+role+'; limite startup180secondi invariato.',flush=True);last=time.monotonic()
            self.require(self.gate.remaining()>35,'INSUFFICIENT_TIME_FOR_READINESS');time.sleep(2*(.8+.4*os.urandom(1)[0]/255))
    def readiness(self,response):
        if response['status']in(0,502,503,504):return False
        self.require(response['status']==200,'PERMANENT_OR_UNKNOWN_READINESS_DENIAL')
        try:value=self.ctx.p.decode(bytes.fromhex(response['rawBodyHex']))
        except(ValueError,TypeError):self.require(False,'MALFORMED_READINESS_RESPONSE')
        self.require(type(value)is dict and value.get('status')in('UP','DOWN'),'UNKNOWN_READINESS_STATE')
        return value['status']=='UP'
    def execute(self,stage):
        row=self.execution.record();i=row['nextStage'];self.require(self.stages[i]==stage and len(row['effects'])==i+1 and row['effects'][-1]['state']=='CLAIMED','EXACT_CLAIMED_TWO_READ_STAGE_REQUIRED');action,role=self.parse(stage)
        if action=='VERIFY_CURRENT_ADMISSION':self.ctx.admission();return {'currentCohortGuarded':True}
        if action=='VERIFY_FINAL':
            proofs={}
            for role in self.core.ROLES:
                candidate=row['candidates'][role];self.require(candidate['readinessProven']is True,'BOTH_READINESS_PROOFS_REQUIRED');actual=self.candidate_guard(role,started=True,restored=True)
                self.reserve('readinessGets');response=self.ctx.http.health(self.ctx.p,candidate['generation']);self.ctx.evidence('final-readiness',{'role':role,**response})
                good=self.readiness(response)
                self.require(good,'FRESH_FINAL_READINESS_REQUIRED');proofs[role]={'nativeBindingHash':self.core.digest(self.ctx.p.stable_binding(actual)),'generation':candidate['generation'],'readinessProven':True,'oldRetainedStopped':True}
            return {'readProofs':proofs}
        old=self.proposal(role);cid=old['oldBinding']['containerId']
        if action=='IMPORT':
            proof=self.image(role)
            if proof:return {'alreadyExactImagePresent':True,'proof':proof}
            self.reserve('imageLoadAttempts');self.reserve('engineWrites');self.ctx.import_claim(role)
            s,raw,unchanged=self.ctx.engine.load_raw(self.ctx.archives[role],self.gate.remaining());self.ctx.retained('POST','/v1.44/images/load?quiet=1',s,raw)
            self.require(s==200 and unchanged,'EXACT_NATIVE_IMPORT_RECEIPT_REQUIRED');records=[self.ctx.p.decode(line)for line in raw.splitlines()if line.strip()]
            self.require(records and all(type(r)is dict and not r.get('error')and not r.get('errorDetail')for r in records),'NATIVE_IMAGE_IMPORT_FAILED');return {'loadReceiptHash':hashlib.sha256(raw).hexdigest(),'image':self.image(role)}
        if action=='DISABLE_OLD_RESTART':self.ctx.admission();s,_=self.request('POST','/v1.44/containers/'+cid+'/update',{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}});self.require(s==200,'OLD_READ_RESTART_DISABLE_UNPROVEN');return {'oldRestartDisabled':True}
        if action=='STOP_OLD':s,_=self.request('POST','/v1.44/containers/'+cid+'/stop?t=10');self.require(s==204,'OLD_READ_STOP_UNPROVEN');return {'oldStopped':True}
        if action=='DETACH_OLD':s,_=self.request('POST','/v1.44/networks/'+old['network']['id']+'/disconnect',{'Container':cid,'Force':False});self.require(s==200,'OLD_READ_DETACH_UNPROVEN');return {'oldDetached':True}
        if action=='RENAME_OLD':s,_=self.request('POST','/v1.44/containers/'+cid+'/rename?name='+quote(old['retiredName'],safe=''));self.require(s==204,'OLD_READ_RETAINED_RENAME_UNPROVEN');return {'oldRetainedStopped':True}
        if action=='CREATE':return self.create(role)
        if action=='START':return self.start(role)
        if action=='VERIFY_READINESS':return self.healthy(role)
        if action=='RESTORE_RESTART':
            candidate=row['candidates'][role];self.require(candidate['readinessProven']is True,'READINESS_BEFORE_RESTART_RESTORE');s,_=self.request('POST','/v1.44/containers/'+candidate['id']+'/update',{'RestartPolicy':self.ctx.restore_policy(role)});self.require(s==200,'READ_RESTART_RESTORE_UNPROVEN');self.candidate_guard(role,started=True,restored=True);return {'restartPolicyRestored':True}
        raise self.core.Stop('UNKNOWN_TWO_READ_ONLY_STAGE')
    def final_result(self):
        row=self.execution.record();proofs=row['effects'][-1]['proof']['readProofs'];result={'schema':'ouf.acquisition-redaction-update-result.v1','status':'ACQUISITION_REDACTION_READS_INSTALLED_E2E_NOT_ACCEPTED','complete':True,
            'contextPath':str(self.root),'preparedNativePlanHash':self.ctx.case['nativePlanHash'],'frozenPlanHash':self.ctx.case['frozenPlanHash'],'reviewHash':self.core.digest(self.review),'authorityHash':self.core.sha(self.gate.raw),'runtimeBindingHash':self.review['nativePlan']['runtimeBindingHash'],
            'candidateSourceCommits':self.ctx.case['sources'],'nativeImages':{r:v['identity']for r,v in self.ctx.facts.items()},'counts':row['counts'],'readProofs':proofs,'componentReadinessProven':True,'oldReadsRetainedStopped':2,'newReadReplicas':2,
            'fiveOtherComponentsUnchanged':True,'mcpUnchanged':True,'registryWorkerTouched':False,'gatewayRequests':0,'credentialFileReads':0,'oauthRequestsByRepair':0,'installationSigningKeysRead':True,'installationSigningOperations':3,'mountSourceContentIdentityProven':False,
            'acquisitionsExecuted':0,'sourceActivations':0,'sqlSessionsByRepair':0,'databaseMigrationsByRepair':0,'newGrantsGranted':0,'currentApplicationPolicyOrLabelsObserved':False,'runtimeAuthorityIssued':True,'applicationE2EProven':False,'releaseAcceptance':False,'budgetReset':False,'automaticReplayAllowed':False,'automaticRollbackPerformed':False}
        return self.ctx.finalize(result)
