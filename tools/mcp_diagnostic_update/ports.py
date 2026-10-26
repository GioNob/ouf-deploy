"""MCP-only closed stage commands; no owner route/credential/acquisition ports."""
import copy,hashlib,re,time
from urllib.parse import quote
class NativePorts:
    def __init__(self,ctx,review,gate):self.ctx,self.root,self.review,self.gate=ctx,ctx.root,review,gate;self.core=ctx.core;self.plan=review['nativePlan']['proposal'];self.execution=None;self.stages=tuple(review['stages'])
    def require(self,ok,code):self.core.require(ok,code)
    def reserve(self,kind):self.ctx.watch.ensure_alive(self.ctx);self.execution.reserve(kind)
    def assert_write(self,path,body):
        row=self.execution.record();i=row['nextStage'];self.require(i<len(self.stages)and len(row['effects'])==i+1 and row['effects'][-1]['state']=='CLAIMED','CLAIMED_SIGNED_STAGE_BEFORE_WRITE_REQUIRED');stage=self.stages[i];old=self.plan['mcpReplacement'];cid=old['oldBinding']['containerId'];expected=None
        if stage.startswith('CREATE_'):
            role='mcp'if stage=='CREATE_MCP'else stage.split('_')[1].lower();proposal=self.proposal(role);expected=('/v1.44/containers/create?name='+quote(proposal['name'],safe=''),proposal['request'])
        elif stage.startswith('START_'):
            role='mcp'if stage=='START_MCP'else stage.split('_')[1].lower();expected=('/v1.44/containers/'+row['candidates'][role]['id']+'/start',None)
        elif stage=='DISABLE_OLD_MCP_RESTART':expected=('/v1.44/containers/'+cid+'/update',{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}})
        elif stage=='STOP_OLD_MCP':expected=('/v1.44/containers/'+cid+'/stop?t=10',None)
        elif stage=='DETACH_OLD_MCP':expected=('/v1.44/networks/'+old['network']['id']+'/disconnect',{'Container':cid,'Force':False})
        elif stage=='RENAME_OLD_MCP':expected=('/v1.44/containers/'+cid+'/rename?name='+quote(old['retiredName'],safe=''),None)
        elif stage.startswith('RESTORE_'):
            role=stage.split('_')[1].lower();expected=('/v1.44/containers/'+row['candidates'][role]['id']+'/update',{'RestartPolicy':self.ctx.restore_policy(role)})
        self.require(expected==(path,body),'EXACT_SIGNED_STAGE_COMMAND_REQUIRED')
    def request(self,method,path,body=None):
        self.ctx.closed_path(method,path,body);
        if method!='GET':self.assert_write(path,body)
        self.reserve('engineGets'if method=='GET'else'engineWrites');status,value=self.ctx.engine.request(method,path,body);return status,value
    def container(self,cid):
        ids={v['containerId']for v in self.plan['existingApplications'].values()}|{v['id']for v in self.execution.record()['candidates'].values()}
        self.require(cid in ids and re.fullmatch('[a-f0-9]{64}',cid),'ONLY_FROZEN_OR_CREATED_CANDIDATE_IDS');status,value=self.request('GET','/v1.44/containers/'+cid+'/json');self.require(status==200 and value['Id']==cid,'EXACT_BOUND_CONTAINER_GET_REQUIRED');return value
    def proposal(self,role):self.require(role=='mcp','MCP_ONLY_PORT_REQUIRED');return self.plan['mcpReplacement']
    def network(self,role):
        net=self.proposal(role)['network'];s,v=self.request('GET','/v1.44/networks/'+net['id']);self.require(s==200 and v['Id']==net['id']and v['Name']==net['name']and v['Driver']=='bridge'and v['Scope']=='local','EXACT_RETAINED_BRIDGE_REQUIRED')
        excluded={self.plan['mcpReplacement']['oldBinding']['containerId']}|{row['id']for row in self.execution.record()['candidates'].values()}
        self.require({k:r for k,r in(v.get('Containers')or{}).items()if k not in excluded}=={k:r for k,r in self.ctx.network_baseline.items()if k not in excluded},'ALL_OTHER_NETWORK_ENDPOINTS_UNCHANGED_REQUIRED')
        return v
    def guard(self,stage):
        self.gate.check();self.ctx.check_sources()
        for role,b in self.plan['existingApplications'].items():
            if role=='mcp':continue
            v=self.container(b['containerId']);self.require(v['State']['Running']is True and v['State']['Paused']is False and v['State']['Restarting']is False and self.ctx.p.stable_binding(v)==b and self.ctx.p.process_pin(v['State']['Pid'])==self.ctx.inputs['currentProcessPins'][role],'EXACT_UNCHANGED_ORIGINAL_WORKER_REQUIRED')
        self.old_guard(stage)
        for role in self.execution.record()['candidates']:self.candidate_guard(role,stage)
    def old_guard(self,stage):
        row=self.plan['mcpReplacement'];b=row['oldBinding'];v=self.container(b['containerId']);i=self.stages.index(stage);at=lambda s:self.stages.index(s)
        config_matches=self.core.digest(v['Config'])==b['configHash']
        if not config_matches and i>at('DETACH_OLD_MCP'):
            history=self.execution.record()['effects'];detached=history[at('DETACH_OLD_MCP')];stopped=history[at('STOP_OLD_MCP')]
            self.require(detached['state']==stopped['state']=='APPLIED'and detached['proof'].get('oldDetached')is True and stopped['proof'].get('oldStopped')is True,'PROVEN_STOP_DETACH_PREFIX_REQUIRED_FOR_MAC_TRANSITION')
            original=self.ctx.inputs['currentObservations']['mcp'];self.require(self.core.digest(original['Config'])==b['configHash']and self.ctx.mac is not None,'EXACT_ORIGINAL_CONFIG_AND_SHARED_MAC_PROFILE_REQUIRED')
            wanted=self.ctx.mac.policy(original);self.require(self.plan.get('legacyConfigMacDetachPolicy',self.review['nativePlan'].get('legacyConfigMacDetachPolicy'))==wanted,'SIGNED_LEGACY_MAC_TRANSITION_POLICY_REQUIRED')
            try:proof=self.ctx.mac.verify_detached(original,v,expected_name='/'+(row['name']if i<=at('RENAME_OLD_MCP')else row['retiredName']))
            except self.ctx.mac.MacTransitionDenied as error:self.require(False,str(error))
            self.ctx.evidence('old-mcp-mac-transition',proof);config_matches=True
        self.require(v['Image']==b['imageId']and config_matches and self.core.digest(sorted(v['Mounts'],key=lambda x:x['Destination']))==b['mountsHash']and v['State']['StartedAt']==b['startedAt'],'OLD_MCP_CONFIG_GENERATION_REQUIRED')
        expected=copy.deepcopy(row['oldNativeHostConfig'])
        if i>at('DISABLE_OLD_MCP_RESTART'):expected['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
        self.require(v['HostConfig']==expected,'OLD_MCP_HOST_CONFIG_CHANGED')
        if i<=at('STOP_OLD_MCP'):
            self.require(v['State']['Running']is True and v['State']['Paused']is False and v['State']['Restarting']is False and self.ctx.p.process_pin(v['State']['Pid'])==self.ctx.inputs['currentProcessPins']['mcp']and self.core.digest(v['NetworkSettings'])==b['networkSettingsHash'],'SAME_OLD_MCP_BEFORE_STOP_REQUIRED')
        else:self.require(v['State']['Running']is False and v['State']['Pid']==0,'OLD_MCP_MUST_REMAIN_STOPPED')
        self.require(v['Name']=='/'+(row['name']if i<=at('RENAME_OLD_MCP')else row['retiredName']),'OLD_MCP_EXACT_RETAINED_NAME_REQUIRED')
        if i>at('DETACH_OLD_MCP'):self.require(v['Id']not in(self.network('mcp').get('Containers')or{}),'OLD_MCP_ENDPOINT_NOT_RELEASED')
        return v
    def candidate_guard(self,role,stage=None,started=None,restored=None,actual=None):
        row=self.execution.record()['candidates'][role];proposal=self.proposal(role);v=actual or self.container(row['id']);i=self.stages.index(stage)if stage else -1
        if started is None:started=i>self.stages.index('START_MCP'if role=='mcp'else'START_'+role.upper()+'_READ')
        if restored is None:restored=i>self.stages.index('RESTORE_'+role.upper()+'_RESTART')
        self.ctx.candidate_configuration(role,v,started,restored)
        if started:
            pin=self.ctx.p.process_pin(v['State']['Pid']);self.require(row.get('generation')is None or pin==row['generation'],'CREATED_PROCESS_GENERATION_CHANGED')
            if row.get('generation')is None:self.execution.candidate(role,generation=pin)
        return v
    def image(self,role):
        self.require(role=='mcp','ONLY_MCP_IMAGE_PORT');fact={'nativeImageId':self.ctx.native['nativeImageId'],'audit':self.ctx.native['imageAudit']};s,v=self.request('GET','/v1.44/images/'+quote(fact['nativeImageId'],safe='')+'/json')
        if s==404:return None
        self.require(s==200,'EXACT_NATIVE_IMAGE_GET_REQUIRED');return self.ctx.images.loaded(fact['audit'],v)
    def create(self,role):
        proposal=self.proposal(role);self.require(role not in self.execution.record()['candidates'],'NO_CANDIDATE_CREATION_REPLAY')
        if role=='mcp':self.require(self.plan['mcpReplacement']['oldBinding']['containerId']not in(self.network('mcp').get('Containers')or{}),'OLD_MCP_ENDPOINT_MUST_BE_RELEASED_BEFORE_CREATE')
        s,v=self.request('POST','/v1.44/containers/create?name='+quote(proposal['name'],safe=''),proposal['request']);self.require(s==201 and type(v)is dict and re.fullmatch('[a-f0-9]{64}',v.get('Id','')),'CANDIDATE_CREATE_OUTCOME_UNPROVEN');self.execution.candidate(role,id=v['Id'],configurationVerified=False,generation=None,readinessProven=False);self.candidate_guard(role,started=False,restored=False);self.execution.candidate(role,configurationVerified=True);return {'role':role,'createdId':v['Id'],'configurationVerified':True}
    def start(self,role):
        row=self.execution.record()['candidates'][role];self.candidate_guard(role,started=False,restored=False);self.execution.candidate(role,startupDeadlineWall=time.time()+180,startupDeadlineMonotonic=time.monotonic()+180);s,_=self.request('POST','/v1.44/containers/'+row['id']+'/start');self.require(s==204,'CANDIDATE_START_OUTCOME_UNPROVEN');self.candidate_guard(role,started=True,restored=False);return {'started':True,'role':role}
    def healthy(self,role):
        row=self.execution.record()['candidates'][role];last=time.monotonic()
        while True:
            self.gate.check();self.require(time.time()<row['startupDeadlineWall']and time.monotonic()<row['startupDeadlineMonotonic'],'FINITE_CANDIDATE_STARTUP_DEADLINE');self.candidate_guard(role,started=True,restored=False);self.reserve('readinessGets');pin=self.execution.record()['candidates'][role]['generation'];response=self.ctx.http.health(self.ctx.p,pin);self.ctx.evidence('health',response);self.require(response['status']in(0,204,502,503,504),'PERMANENT_OR_UNKNOWN_READINESS_DENIAL')
            if role=='mcp':good=response['status']==204
            else:
                try:good=response['status']==200 and self.ctx.p.decode(response['body'].encode()).get('status')=='UP'
                except (ValueError,AttributeError):good=False
            self.require(time.time()<row['startupDeadlineWall']and time.monotonic()<row['startupDeadlineMonotonic'],'READINESS_PROOF_WITHIN_STARTUP_LEASE_REQUIRED')
            if good:self.execution.candidate(role,readinessProven=True);return {'readinessProven':True,'role':role}
            if time.monotonic()-last>=10:
                print('Attendo readiness del solo nuovo MCP; limite startup180secondi, scadenza invariata.',flush=True);last=time.monotonic()
            self.require(self.gate.remaining()>35,'INSUFFICIENT_TIME_FOR_READINESS');time.sleep(2)
    def execute(self,stage):
        row=self.execution.record();i=row['nextStage'];self.require(self.stages[i]==stage and len(row['effects'])==i+1 and row['effects'][-1]['state']=='CLAIMED','EXACT_CLAIMED_MCP_STAGE_REQUIRED')
        old=self.plan['mcpReplacement'];cid=old['oldBinding']['containerId']
        if stage=='VERIFY_CURRENT_ADMISSION':self.ctx.admission();return {'currentCohortGuarded':True}
        if stage=='IMPORT_MCP':
            proof=self.image('mcp')
            if proof:return {'alreadyExactImagePresent':True,'proof':proof}
            self.reserve('imageLoadAttempts');self.reserve('engineWrites');self.ctx.import_claim()
            status,raw,unchanged=self.ctx.engine.load_raw(self.ctx.archive,self.gate.remaining());self.ctx.retained('POST','/v1.44/images/load?quiet=1',status,raw)
            self.require(status==200 and unchanged,'EXACT_NATIVE_IMPORT_RECEIPT_REQUIRED')
            records=[self.ctx.p.decode(line)for line in raw.splitlines()if line.strip()]
            self.require(records and all(type(r)is dict and not r.get('error')and not r.get('errorDetail')for r in records),'NATIVE_IMAGE_IMPORT_FAILED')
            return {'loadReceiptHash':hashlib.sha256(raw).hexdigest(),'image':self.image('mcp')}
        if stage=='DISABLE_OLD_MCP_RESTART':
            self.ctx.admission();s,_=self.request('POST','/v1.44/containers/'+cid+'/update',{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}});self.require(s==200,'OLD_MCP_RESTART_DISABLE_UNPROVEN');return {'oldRestartDisabled':True}
        if stage=='STOP_OLD_MCP':s,_=self.request('POST','/v1.44/containers/'+cid+'/stop?t=10');self.require(s==204,'OLD_MCP_STOP_UNPROVEN');return {'oldStopped':True}
        if stage=='DETACH_OLD_MCP':s,_=self.request('POST','/v1.44/networks/'+old['network']['id']+'/disconnect',{'Container':cid,'Force':False});self.require(s==200,'OLD_MCP_DETACH_UNPROVEN');return {'oldDetached':True}
        if stage=='RENAME_OLD_MCP':s,_=self.request('POST','/v1.44/containers/'+cid+'/rename?name='+quote(old['retiredName'],safe=''));self.require(s==204,'OLD_MCP_RETAINED_RENAME_UNPROVEN');return {'oldRetainedStopped':True}
        if stage=='CREATE_MCP':return self.create('mcp')
        if stage=='START_MCP':return self.start('mcp')
        if stage=='VERIFY_MCP_READINESS':return self.healthy('mcp')
        if stage=='RESTORE_MCP_RESTART':
            candidate=row['candidates']['mcp'];self.require(candidate['readinessProven']is True,'READINESS_BEFORE_RESTART_RESTORE');s,_=self.request('POST','/v1.44/containers/'+candidate['id']+'/update',{'RestartPolicy':self.ctx.restore_policy('mcp')});self.require(s==200,'MCP_RESTART_RESTORE_UNPROVEN');self.candidate_guard('mcp',started=True,restored=True);return {'restartPolicyRestored':True}
        if stage=='VERIFY_FINAL':
            candidate=row['candidates']['mcp'];self.require(candidate['readinessProven']is True,'MCP_READINESS_REQUIRED');actual=self.candidate_guard('mcp',started=True,restored=True)
            self.reserve('readinessGets');response=self.ctx.http.health(self.ctx.p,candidate['generation']);self.ctx.evidence('final-readiness',response);self.require(response['status']==204,'FRESH_FINAL_MCP_READINESS_REQUIRED')
            return {'nativeBindingHash':self.core.digest(self.ctx.p.stable_binding(actual)),'generation':candidate['generation'],'readinessProven':True,'oldRetainedStopped':True}
        raise self.core.Stop('UNKNOWN_MCP_ONLY_STAGE')
    def final_result(self):
        row=self.execution.record();proof=row['effects'][-1]['proof']
        result={'schema':'ouf.mcp-diagnostic-update-result.v1','status':'MCP_DIAGNOSTIC_UPDATE_INSTALLED_E2E_NOT_ACCEPTED','complete':True,
                'contextPath':str(self.root),'preparedNativePlanHash':self.ctx.case['nativePlanHash'],'frozenPlanHash':self.ctx.case['frozenPlanHash'],
                'reviewHash':self.core.digest(self.review),'authorityHash':self.core.sha(self.gate.raw),'candidateSourceCommit':self.ctx.case['sourceCommit'],
                'nativeImageId':self.ctx.native['nativeImageId'],'counts':row['counts'],'originalsAndReadReplicasUnchanged':6,
                'newMcpManagers':1,'oldMcpRetainedStopped':True,'nativeBindingHash':proof['nativeBindingHash'],'componentReadinessProven':True,
                'registryWorkerTouched':False,'gatewayRequests':0,'credentialFileReads':0,'oauthRequestsByRepair':0,'normalMcpOAuthBootstrapMayHaveOccurred':True,
                'normalMcpManifestCatalogueUpdateMayHaveOccurred':True,'normalMcpOAuthRequestsCountNotObserved':True,
                'installationSigningKeysRead':True,'installationSigningOperations':3,'mountSourceContentIdentityProven':False,
                'acquisitionsExecuted':0,'sourceActivations':0,'sqlSessionsByRepair':0,'databaseMigrationsByRepair':0,'newGrantsGranted':0,
                'runtimeAuthorityIssued':True,'applicationE2EProven':False,'releaseAcceptance':False,'budgetReset':False,'automaticReplayAllowed':False,'automaticRollbackPerformed':False}
        return self.ctx.finalize(result)
