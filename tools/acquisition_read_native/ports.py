"""Closed stage ports for2READ replicas,1MCP replacement and2additive routes."""
import copy,hashlib,os,re,time
from pathlib import Path
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
        if method!='GET':self.assert_write(path,body)
        self.reserve('engineGets'if method=='GET'else'engineWrites');status,value=self.ctx.engine.request(method,path,body);self.ctx.evidence('engine-response',{'status':status,'body':value});return status,value
    def container(self,cid):
        ids={v['containerId']for v in self.plan['existingApplications'].values()}|{v['id']for v in self.execution.record()['candidates'].values()}
        self.require(cid in ids and re.fullmatch('[a-f0-9]{64}',cid),'ONLY_FROZEN_OR_CREATED_CANDIDATE_IDS');status,value=self.request('GET','/v1.44/containers/'+cid+'/json');self.require(status==200 and value['Id']==cid,'EXACT_BOUND_CONTAINER_GET_REQUIRED');return value
    def proposal(self,role):return self.plan['mcpReplacement']if role=='mcp'else self.plan['readComponents'][role]
    def network(self,role):
        net=self.proposal(role)['network'];s,v=self.request('GET','/v1.44/networks/'+net['id']);self.require(s==200 and v['Id']==net['id']and v['Name']==net['name']and v['Driver']=='bridge'and v['Scope']=='local','EXACT_RETAINED_BRIDGE_REQUIRED');return v
    def guard(self,stage):
        self.gate.check();self.ctx.check_sources();self.ctx.check_owner_configuration(self.reserve)
        for role,b in self.plan['existingApplications'].items():
            if role=='mcp':continue
            v=self.container(b['containerId']);self.require(v['State']['Running']is True and self.ctx.p.stable_binding(v)==b and self.ctx.p.process_pin(v['State']['Pid'])==self.ctx.inputs['currentProcessPins'][role],'EXACT_UNCHANGED_ORIGINAL_WORKER_REQUIRED')
        self.old_guard(stage)
        for role in self.execution.record()['candidates']:self.candidate_guard(role,stage)
    def old_guard(self,stage):
        row=self.plan['mcpReplacement'];b=row['oldBinding'];v=self.container(b['containerId']);i=self.stages.index(stage);at=lambda s:self.stages.index(s)
        config_matches=self.core.digest(v['Config'])==b['configHash']
        if not config_matches and i>at('DETACH_OLD_MCP'):
            history=self.execution.record()['effects'];detached=history[at('DETACH_OLD_MCP')];stopped=history[at('STOP_OLD_MCP')]
            self.require(detached['state']==stopped['state']=='APPLIED'and detached['proof'].get('oldDetached')is True and stopped['proof'].get('oldStopped')is True,'PROVEN_STOP_DETACH_PREFIX_REQUIRED_FOR_MAC_TRANSITION')
            ref=self.ctx.inputs['currentObservations']['mcp'];original=self.ctx.read(ref['path'],ref['sha256']);self.require(self.core.digest(original['Config'])==b['configHash']and self.ctx.mac is not None,'EXACT_ORIGINAL_CONFIG_AND_SHARED_MAC_PROFILE_REQUIRED')
            wanted=self.ctx.mac.policy(original);self.require(self.plan.get('legacyConfigMacDetachPolicy',self.review['nativePlan'].get('legacyConfigMacDetachPolicy'))==wanted,'SIGNED_LEGACY_MAC_TRANSITION_POLICY_REQUIRED')
            try:proof=self.ctx.mac.verify_detached(original,v,expected_name='/'+(row['name']if i<=at('RENAME_OLD_MCP')else row['retiredName']))
            except self.ctx.mac.MacTransitionDenied as error:self.require(False,str(error))
            self.ctx.evidence('old-mcp-mac-transition',proof);config_matches=True
        self.require(v['Image']==b['imageId']and config_matches and self.core.digest(sorted(v['Mounts'],key=lambda x:x['Destination']))==b['mountsHash']and v['State']['StartedAt']==b['startedAt'],'OLD_MCP_CONFIG_GENERATION_REQUIRED')
        expected=copy.deepcopy(row['oldNativeHostConfig'])
        if i>at('DISABLE_OLD_MCP_RESTART'):expected['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
        self.require(v['HostConfig']==expected,'OLD_MCP_HOST_CONFIG_CHANGED')
        if i<=at('STOP_OLD_MCP'):
            self.require(v['State']['Running']is True and self.ctx.p.process_pin(v['State']['Pid'])==self.ctx.inputs['currentProcessPins']['mcp']and self.core.digest(v['NetworkSettings'])==b['networkSettingsHash'],'SAME_OLD_MCP_BEFORE_STOP_REQUIRED')
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
        fact=self.ctx.native['candidateFacts'][role];s,v=self.request('GET','/v1.44/images/'+quote(fact['nativeImageId'],safe='')+'/json')
        if s==404:return None
        self.require(s==200,'EXACT_NATIVE_IMAGE_GET_REQUIRED');return self.ctx.images.loaded(fact['audit'],v)
    def create(self,role):
        proposal=self.proposal(role);self.require(role not in self.execution.record()['candidates'],'NO_CANDIDATE_CREATION_REPLAY')
        if role=='mcp':self.require(self.plan['mcpReplacement']['oldBinding']['containerId']not in(self.network('mcp').get('Containers')or{}),'OLD_MCP_ENDPOINT_MUST_BE_RELEASED_BEFORE_CREATE')
        s,v=self.request('POST','/v1.44/containers/create?name='+quote(proposal['name'],safe=''),proposal['request']);self.require(s==201 and type(v)is dict and re.fullmatch('[a-f0-9]{64}',v.get('Id','')),'CANDIDATE_CREATE_OUTCOME_UNPROVEN');self.execution.candidate(role,id=v['Id'],configurationVerified=False,generation=None,readinessProven=False);self.candidate_guard(role,started=False,restored=False);self.execution.candidate(role,configurationVerified=True);return {'role':role,'createdId':v['Id'],'configurationVerified':True}
    def start(self,role):
        row=self.execution.record()['candidates'][role];self.candidate_guard(role,started=False,restored=False);self.execution.candidate(role,startupDeadlineWall=time.time()+180,startupDeadlineMonotonic=time.monotonic()+180);s,_=self.request('POST','/v1.44/containers/'+row['id']+'/start');self.require(s==204,'CANDIDATE_START_OUTCOME_UNPROVEN');self.candidate_guard(role,started=True,restored=False);return {'started':True,'role':role}
    def healthy(self,role):
        row=self.execution.record()['candidates'][role]
        while True:
            self.gate.check();self.require(time.time()<row['startupDeadlineWall']and time.monotonic()<row['startupDeadlineMonotonic'],'FINITE_CANDIDATE_STARTUP_DEADLINE');self.candidate_guard(role,started=True,restored=False);self.reserve('readinessGets');pin=self.execution.record()['candidates'][role]['generation'];response=self.ctx.http.namespace(self.ctx.p,pin,'health','GET','/health/ready'if role=='mcp'else'/actuator/health/readiness');self.ctx.evidence('health',response)
            if role=='mcp':good=response['status']==204
            else:
                try:good=response['status']==200 and self.ctx.p.decode(response['body'].encode()).get('status')=='UP'
                except (ValueError,AttributeError):good=False
            self.require(time.time()<row['startupDeadlineWall']and time.monotonic()<row['startupDeadlineMonotonic'],'READINESS_PROOF_WITHIN_STARTUP_LEASE_REQUIRED')
            if good:self.execution.candidate(role,readinessProven=True);return {'readinessProven':True,'role':role}
            self.require(self.gate.remaining()>35,'INSUFFICIENT_TIME_FOR_READINESS');time.sleep(2)
    def admin(self,method,path,body=None):
        if method=='PUT':
            row=self.execution.record();i=row['nextStage'];self.require(len(row['effects'])==i+1 and row['effects'][-1]['state']=='CLAIMED'and self.stages[i]in('ADD_INGESTION_ROUTE','ADD_UDP_ROUTE'),'CLAIMED_SIGNED_ROUTE_STAGE_REQUIRED');index=0 if self.stages[i]=='ADD_INGESTION_ROUTE'else 1;route=self.plan['gateway']['newRoutes'][index];self.require(path=='/apisix/admin/routes/'+route['id']and body==route,'EXACT_SIGNED_ROUTE_BODY_REQUIRED')
        self.reserve('adminGets'if method=='GET'else'adminPuts');response=self.ctx.admin(method,path,body);self.ctx.evidence('admin',response);self.require(response['status']in((200,)if method=='GET'else(200,201)),'EXACT_ADMIN_RESPONSE_REQUIRED');return response
    def routes(self,added):
        response=self.admin('GET','/apisix/admin/routes');doc=self.ctx.p.decode(response['body'].encode());observed=self.ctx.route_rows(doc);wanted=self.plan['gateway']['previousRoutes']+self.plan['gateway']['newRoutes'][:added];self.require(self.ctx.route_map(observed)==self.ctx.route_map(wanted),'EXACT_ALL_RETAINED_AND_ADDED_ROUTES_REQUIRED');return {'routeCount':len(observed),'routeMapHash':self.core.digest(self.ctx.route_map(observed))}
    def execute(self,stage):
        row=self.execution.record();i=row['nextStage'];self.require(i<len(self.stages)and self.stages[i]==stage and len(row['effects'])==i+1 and row['effects'][-1]['state']=='CLAIMED','ONE_EXACT_CLAIMED_STAGE_REQUIRED')
        if stage=='LOAD_EXISTING_ADMIN_KEY':
            self.require('continuation'in self.review and self.ctx.key is None,'ONE_APPROVED_CONTINUATION_CREDENTIAL_READ_REQUIRED');self.ctx.load_admin_key();return {'additionalCredentialReadClaimed':True,'previousCredentialReadsRetained':1,'cumulativeCredentialReads':self.execution.record()['counts']['serviceCredentialFileReads']}
        if stage=='VERIFY_CURRENT_ADMISSION':self.ctx.admission();return self.routes(0)
        if stage.startswith('IMPORT_'):
            role=stage.removeprefix('IMPORT_').lower();proof=self.image(role)
            if proof:return {'alreadyExactImagePresent':True,'proof':proof}
            self.reserve('imageLoadAttempts');self.reserve('engineWrites');proof=self.ctx.engine.load(self.ctx.native['candidateFacts'][role]['nativeArchive'],self.gate.remaining());return {**proof,'nativeImage':self.image(role)}
        if stage in('CREATE_INGESTION_READ','CREATE_UDP_READ','CREATE_MCP'):return self.create('mcp'if stage=='CREATE_MCP'else stage.split('_')[1].lower())
        if stage in('START_INGESTION_READ','START_UDP_READ','START_MCP'):return self.start('mcp'if stage=='START_MCP'else stage.split('_')[1].lower())
        if stage=='VERIFY_READ_REPLICAS':return {r:self.healthy(r)for r in('ingestion','udp')}
        if stage=='VERIFY_MCP_READINESS':return self.healthy('mcp')
        old=self.plan['mcpReplacement'];cid=old['oldBinding']['containerId']
        if stage=='DISABLE_OLD_MCP_RESTART':self.ctx.admission();s,_=self.request('POST','/v1.44/containers/'+cid+'/update',{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}});self.require(s==200,'OLD_MCP_RESTART_DISABLE_UNPROVEN');return {'oldRestartDisabled':True}
        if stage=='STOP_OLD_MCP':s,_=self.request('POST','/v1.44/containers/'+cid+'/stop?t=10');self.require(s==204,'OLD_MCP_STOP_UNPROVEN');return {'oldStopped':True}
        if stage=='DETACH_OLD_MCP':s,_=self.request('POST','/v1.44/networks/'+old['network']['id']+'/disconnect',{'Container':cid,'Force':False});self.require(s==200,'OLD_MCP_ENDPOINT_DETACH_UNPROVEN');return {'oldDetached':True}
        if stage=='RENAME_OLD_MCP':s,_=self.request('POST','/v1.44/containers/'+cid+'/rename?name='+quote(old['retiredName'],safe=''));self.require(s==204,'OLD_MCP_RETAINED_RENAME_UNPROVEN');return {'oldRetainedStopped':True}
        if stage in('ADD_INGESTION_ROUTE','ADD_UDP_ROUTE'):
            index=0 if stage=='ADD_INGESTION_ROUTE'else 1;self.routes(index);route=self.plan['gateway']['newRoutes'][index];self.admin('PUT','/apisix/admin/routes/'+route['id'],route);return self.routes(index+1)
        if stage=='VERIFY_GATEWAY':return self.routes(2)
        if stage.startswith('RESTORE_'):
            role=stage.split('_')[1].lower();proposal=self.proposal(role);cid=self.execution.record()['candidates'][role]['id'];policy=proposal['restoreRestartPolicy']if role=='mcp'else proposal['restartPolicyAfterVerifiedReadiness'];s,_=self.request('POST','/v1.44/containers/'+cid+'/update',{'RestartPolicy':policy});self.require(s==200,'EXACT_CANDIDATE_RESTART_POLICY_RESTORE_UNPROVEN');self.candidate_guard(role,started=True,restored=True);return {'role':role,'restartPolicyRestored':True}
        if stage=='VERIFY_FINAL':
            for role in('ingestion','udp','mcp'):
                row=self.execution.record()['candidates'][role];self.require(row['readinessProven']is True,'ALL_CANDIDATE_READINESS_REQUIRED');self.candidate_guard(role,started=True,restored=True)
                self.reserve('readinessGets');response=self.ctx.http.namespace(self.ctx.p,row['generation'],'health','GET','/health/ready'if role=='mcp'else'/actuator/health/readiness');self.ctx.evidence('final-health',response)
                good=response['status']==204 if role=='mcp'else response['status']==200 and self.ctx.p.decode(response['body'].encode()).get('status')=='UP';self.require(good,'FRESH_FINAL_COMPONENT_READINESS_REQUIRED')
            return self.routes(2)
        raise self.core.Stop('UNKNOWN_ACQUISITION_STAGE')
    def final_result(self):
        row=self.execution.record();return {'schema':'ouf.acquisition-read-native-result.v1','status':'ACQUISITION_READ_PATH_INSTALLED_E2E_NOT_ACCEPTED','complete':True,'reviewHash':self.core.digest(self.review),'authorityHash':self.core.sha(self.gate.raw),'nativeInputsHash':self.ctx.NATIVE_HASH,'frozenPlanHash':self.ctx.native['frozenPlanHash'],'counts':row['counts'],'readComponents':2,'mcpManagers':1,'newGatewayRoutes':2,'oldGatewayRoutesPreserved':82,'originalWorkersUnchanged':True,'oldMcpRetainedStopped':True,'componentReadinessProven':True,'applicationE2EProven':False,'humanBudgetsGranted':0,'sourceActivations':0,'databaseMigrationsByRepair':0,'sqlSessionsByRepair':0,'oauthRequestsByRepair':0,'normalMcpOAuthBootstrapMayHaveOccurred':True,'normalMcpOAuthRequestsCountNotObserved':True,'registryWorkerTouched':False,'runtimeAuthorityIssued':True,'installationSigningKeysRead':True,'installationSigningOperations':3,'automaticReplayAllowed':False,'automaticRollbackPerformed':False,'budgetReset':False,'releaseAcceptance':False,**({'continuation':self.review['continuation']}if'continuation'in self.review else{})}
