"""Conditional APISIX key/config installation; same image, exact two networks.

Prepared secret bytes remain private. Each native effect is claimed once before
execution. Interrupted stop/create/start is read back, never automatically
retried or rolled back. The retained old container is not removed.
"""
import copy
import json
import time
from urllib.parse import quote

from engine_creation import Engine
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.plan import digest, encoded, environment, runtime_pin, require, sha, NO_RESTART, PlanDenied, creation_host_config, host_config_matches
from tools.chatbot_file_cohort.containers import CohortPaused, READINESS_POLICY
from tools.chatbot_file_cohort.gateway import NamespaceAdmin, private_config, namespace_program, apisix_runtime_binding, MOUNT_SET_BINDING

PROFILE='ouf.chatbot-file-cohort.gateway-runtime.v1'
APISIX_READINESS_POLICY={**READINESS_POLICY,'profile':'ouf.apisix-finite-readiness.v2',
    'respectRetryAfter':True,'readOnlyOnly':True,'crashRequiresReconciliation':True,
    'finiteProfileReason':'WITHIN_ONE_REVIEWED_3600_SECOND_HUMAN_ACTION'}
NUMERIC_IMAGE='sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d'
# Same qualified manifest/config pair: Docker image stores expose either identity.
NUMERIC_IMAGE_IDS=(NUMERIC_IMAGE,'sha256:b6fd21b8c341f3bf274ddabbad2e3c1bbb6a17566f0e41bf618166e63e4641e4')
NUMERIC_ASSETS={
 '/usr/local/apisix/deps/share/lua/5.1/jsonschema.lua':'f8c1fa8f9e8535467d4e8880312d769cdbf5e047d32593ab73d2fefb71e44364',
 '/usr/local/apisix/conf/ouf_json_precision.lua':'0444d8b4d6cab03ccc4b6cf47364d606b81ec11a843f7ab4714208d79dfb1eaa'}
NUMERIC_PROFILE='ouf.apisix-numeric-compatibility-mounts.v1'
STEPS=('disable_restart','stop','rename','create','connect','start','ready','restore_restart')


def compile_runtime(old, old_config_binding, new_config_binding, new_key_env, key, key_hash, cohort_id,
                    admin_key_binding=None, numeric_assets=None):
    pin=runtime_pin(old)
    require(old.get('Name')=='/ouf-apisix' and old['Config'].get('User')=='apisix'
            and set(old['NetworkSettings']['Networks'])=={'ouf-backend','ouf-gateway-control'}
            and old['HostConfig'].get('NetworkMode') in ('ouf-backend','ouf-gateway-control'),
            'EXACT_EXISTING_APISIX_TOPOLOGY_REQUIRED')
    require(sha(key_hash) and len(key)==64
            and all(c in '0123456789abcdef' for c in key), 'EXACT_PREPARED_PROPOSAL_KEY_REQUIRED')
    import hashlib
    require(hashlib.sha256(key.encode()).hexdigest()==key_hash, 'PROPOSAL_KEY_HASH_MISMATCH')
    if admin_key_binding is not None:
        from tools.chatbot_file_cohort.gateway import EXTERNAL_ADMIN_KEY
        require(admin_key_binding.get('path')==EXTERNAL_ADMIN_KEY,
                'EXACT_RETAINED_EXTERNAL_ADMIN_KEY_REQUIRED')
        private_config(EXTERNAL_ADMIN_KEY,admin_key_binding)
    host=creation_host_config(old['HostConfig']);config=copy.deepcopy(old['Config'])
    require(not host.get('Privileged') and not host.get('AutoRemove') and not host.get('Links')
            and not host.get('VolumesFrom') and not host.get('ContainerIDFile')
            and not str(host.get('PidMode','')).startswith('container:')
            and not str(host.get('IpcMode','')).startswith('container:'), 'INDEPENDENT_APISIX_GENERATION_REQUIRED')
    require(host.get('RestartPolicy') in (NO_RESTART,{'Name':'unless-stopped','MaximumRetryCount':0}),
            'REVIEWED_APISIX_RESTART_POLICY_REQUIRED')
    mounts=copy.deepcopy(old['Mounts'])
    selected=[m for m in mounts if m.get('Destination')=='/usr/local/apisix/conf/config.yaml']
    require(len(selected)==1 and selected[0].get('Type')=='bind' and selected[0].get('RW') is False
            and selected[0]['Source']==old_config_binding['path'], 'SELECTED_APISIX_CONFIG_MOUNT_DRIFT')
    replaced=False
    for m in host.get('Mounts') or []:
        if m.get('Target')=='/usr/local/apisix/conf/config.yaml':
            require(m.get('Source')==old_config_binding['path'] and m.get('ReadOnly') is True,
                    'APISIX_MOUNT_REQUEST_DRIFT')
            m['Source']=new_config_binding['path'];replaced=True
    for i,b in enumerate(host.get('Binds') or []):
        fields=b.split(':')
        if len(fields)==3 and fields[1]=='/usr/local/apisix/conf/config.yaml':
            require(not replaced and fields[0]==old_config_binding['path'] and fields[2]=='ro',
                    'EXACT_APISIX_BIND_REQUEST_REQUIRED')
            host['Binds'][i]=new_config_binding['path']+':'+fields[1]+':ro';replaced=True
    require(replaced,'EXPLICIT_APISIX_MOUNT_REQUEST_REQUIRED')
    selected[0]['Source']=new_config_binding['path']
    if numeric_assets is not None:
        validate_numeric_assets(old['Image'],numeric_assets)
        destinations={m['Destination'] for m in mounts}
        for asset in numeric_assets:
            destination=asset['destination'];binding=asset['binding']
            require(destination not in destinations,'NUMERIC_ASSET_MOUNT_ALREADY_PRESENT')
            require(':' not in binding['path'],'LITERAL_NUMERIC_ASSET_BIND_PATH_REQUIRED')
            host.setdefault('Binds',[]).append(binding['path']+':'+destination+':ro')
            mounts.append({'Type':'bind','Source':binding['path'],'Destination':destination,'RW':False})
            destinations.add(destination)
    values=environment(config.get('Env') or [])
    require(new_key_env not in values or values[new_key_env]==key,'PROPOSAL_ENV_KEY_CONFLICT')
    values[new_key_env]=key
    config['Env']=[k+'='+v for k,v in sorted(values.items())]
    config['Image']=old['Image']
    if config.get('Hostname')==old['Id'][:12]:config['Hostname']=''
    config['Labels']={**(config.get('Labels') or {}),'it.ouf.file-cohort':cohort_id}
    original_policy=copy.deepcopy(host['RestartPolicy']);host['RestartPolicy']=copy.deepcopy(NO_RESTART)
    networks={}
    for name,row in old['NetworkSettings']['Networks'].items():
        require(sha(row.get('NetworkID')) and not row.get('IPAMConfig'), 'APISIX_STATIC_ENDPOINT_REVIEW_REQUIRED')
        aliases=sorted((set(row.get('Aliases') or [])-{old['Id'],old['Id'][:12]})|{'ouf-apisix'})
        networks[name]={'NetworkID':row['NetworkID'],'Aliases':aliases}
    primary=host['NetworkMode'];secondary=next(n for n in networks if n!=primary)
    request={**config,'HostConfig':host,'NetworkingConfig':{'EndpointsConfig':{primary:networks[primary]}}}
    require(len(encoded(request))<=262144,'BOUNDED_APISIX_CREATION_REQUIRED')
    result={'schema':PROFILE,'pythonExecutable':namespace_program(),'oldRuntimeBinding':pin,'oldName':'ouf-apisix',
            'retiredName':'ouf-apisix-before-'+cohort_id,'oldConfigBinding':old_config_binding,
            'adminKeyBinding':copy.deepcopy(admin_key_binding),
            'newConfigBinding':new_config_binding,'oldHostConfig':copy.deepcopy(old['HostConfig']),
            'oldMounts':copy.deepcopy(old['Mounts']),'expectedMounts':mounts,
            'creationRequest':request,'networks':networks,'secondaryNetwork':secondary,
            'proposalKeyEnvironment':new_key_env,'proposalKeyHash':key_hash,
            'originalRestartPolicy':original_policy,'sameExistingImageRequired':True,
            'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False,
            'readinessPolicy':copy.deepcopy(APISIX_READINESS_POLICY),'runtimeAuthorityIssued':False}
    if numeric_assets is not None:
        result['numericCompatibility']={'profile':NUMERIC_PROFILE,'assets':copy.deepcopy(numeric_assets)}
        result['runtimeBindingProfile']=MOUNT_SET_BINDING
    return result


def validate_numeric_assets(image,assets):
    require(image in NUMERIC_IMAGE_IDS and type(assets)is list and len(assets)==2
        and {a.get('destination') for a in assets}==set(NUMERIC_ASSETS),
        'EXACT_QUALIFIED_NUMERIC_IMAGE_AND_ASSETS_REQUIRED')
    sources=[]
    for asset in assets:
        require(set(asset)=={'destination','binding','readOnly'} and asset['readOnly']is True,
            'NUMERIC_ASSET_MUST_BE_READ_ONLY')
        binding=asset['binding'];raw,observed=private_config(binding['path'],binding)
        require(observed['sha256']==NUMERIC_ASSETS[asset['destination']]
            and observed['metadata'][2:4]==[0,0] and observed['metadata'][4]&0o777==0o444,
            'QUALIFIED_ROOT_CUSTODIED_NUMERIC_ASSET_REQUIRED')
        sources.append(binding['path'])
    require(len(set(sources))==2,'DISTINCT_NUMERIC_ASSET_FILES_REQUIRED')


def runtime_scope(plan):
    require(plan.get('schema')==PROFILE and plan.get('sameExistingImageRequired') is True
            and plan.get('automaticRollbackAllowed') is False and plan.get('automaticWriteReplayAllowed') is False,
            'EXACT_GOVERNED_APISIX_RUNTIME_PLAN_REQUIRED')
    # Historical scope hashing must remain compatible with retained journals.
    # Current execution policy is enforced by GatewayRuntime.guard, never by a
    # read-only reconstruction of a previously completed owner's scope.
    return {'profile':PROFILE,'planHash':digest(plan),'oldContainerId':plan['oldRuntimeBinding']['containerId'],
            'sameImageId':plan['oldRuntimeBinding']['imageId'],'proposalKeyHash':plan['proposalKeyHash'],
            'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False}


def proposed_transport(plan):
    return {'transport':'JOURNAL_PROVEN_APISIX_REPLACEMENT_NETNS', 'runtimePlanHash':digest(plan),
            'creationRequestHash':digest(plan['creationRequest']), 'configBinding':plan['newConfigBinding'],
            'adminKeyBinding':plan['adminKeyBinding'],
            'pythonExecutable':plan['pythonExecutable']}


class GatewayRuntime:
    def __init__(self,action,engine,plan,journal,clock=time.time,monotonic=time.monotonic,boot=None):
        require(type(action) is AggregateAction and type(engine) is Engine and type(journal) is Journal,
                'CONCRETE_GOVERNED_APISIX_RUNTIME_REQUIRED')
        self.action,self.engine,self.journal,self.clock=action,engine,journal,clock
        self.monotonic=monotonic
        from pathlib import Path
        self.boot=boot or Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.plan=copy.deepcopy(plan);self.scope=runtime_scope(plan)
    def guard(self):
        require(runtime_scope(self.plan)==self.scope,'APISIX_RUNTIME_PLAN_DRIFT')
        require(self.plan.get('readinessPolicy')==APISIX_READINESS_POLICY,'EXACT_APISIX_READINESS_POLICY_REQUIRED')
        require(self.plan.get('runtimeBindingProfile')==(MOUNT_SET_BINDING if self.plan.get('numericCompatibility')is not None else None),
            'EXACT_APISIX_RUNTIME_BINDING_PROFILE_REQUIRED')
        self.action.guard('gatewayRuntimeInstallation',self.scope);self.engine.check_socket()
        private_config(self.plan['oldConfigBinding']['path'],self.plan['oldConfigBinding'])
        private_config(self.plan['newConfigBinding']['path'],self.plan['newConfigBinding'])
        numeric=self.plan.get('numericCompatibility')
        if numeric is not None:
            require(numeric.get('profile')==NUMERIC_PROFILE,'NUMERIC_COMPATIBILITY_PROFILE_DRIFT')
            validate_numeric_assets(self.plan['oldRuntimeBinding']['imageId'],numeric['assets'])
        if self.plan['adminKeyBinding'] is not None:
            from tools.chatbot_file_cohort.gateway import EXTERNAL_ADMIN_KEY
            private_config(EXTERNAL_ADMIN_KEY,self.plan['adminKeyBinding'])
    def initialize(self):
        self.guard()
        require(runtime_pin(self.inspect(self.plan['oldName']))==self.plan['oldRuntimeBinding'],
                'EXACT_CURRENT_APISIX_BEFORE_INSTALL_REQUIRED')
        self.journal.initialize({'schema':PROFILE,'planHash':self.scope['planHash'],
            'authorityHash':self.action.authority_hash,'version':1,'nextStep':0,'effects':[],
            'budgetReset':False,'readiness':None})
    def record(self):
        v=self.journal.read();n=v.get('nextStep');effects=v.get('effects')
        require(v.get('schema')==PROFILE and v.get('planHash')==self.scope['planHash']
                and v.get('authorityHash')==self.action.authority_hash and v.get('budgetReset') is False
                and type(n) is int and 0<=n<=len(STEPS) and type(effects) is list and len(effects) in (n,n+1)
                and [e['step'] for e in effects]==list(STEPS[:len(effects)])
                and all(e['intentHash']==digest({'planHash':self.scope['planHash'],'step':e['step']}) for e in effects)
                and all(e['state']=='APPLIED' for e in effects[:n])
                and (len(effects)==n or effects[-1]['state']=='CLAIMED'),'APISIX_EFFECT_HISTORY_DRIFT')
        return v
    def save(self,previous,value):
        value['version']=previous['version']+1;self.journal.compare_and_save(previous,value);return value
    def inspect(self,name):
        code,body=self.engine.request('GET','/v1.44/containers/'+quote(name,safe='')+'/json')
        if code==404:return None
        require(code==200 and type(body) is dict,'APISIX_INSPECT_FAILED');return body
    def old(self,renamed=False,stopped=True):
        p=self.plan;v=self.inspect(p['oldRuntimeBinding']['containerId']);pin=p['oldRuntimeBinding']
        require(v is not None and v['Id']==pin['containerId'] and v['Image']==pin['imageId']
                and digest(v['Config'])==pin['configHash'] and digest(v['Mounts'])==pin['mountsHash']
                and v['Name']=='/'+(p['retiredName'] if renamed else p['oldName']), 'RETAINED_APISIX_CHANGED')
        host=copy.deepcopy(p['oldHostConfig']);host['RestartPolicy']=NO_RESTART
        require(v['HostConfig']==host,'OLD_APISIX_RESTART_POLICY_NOT_DISABLED')
        if stopped:require(not v['State']['Running'] and v['State']['Pid']==0 and v['State']['Status']=='exited',
                           'OLD_APISIX_NOT_STOPPED')
        return v
    def candidate(self,connected=False,started=False,restored=False):
        p=self.plan;r=p['creationRequest'];v=self.inspect(p['oldName'])
        if v is None:return None
        require(v['Id']!=p['oldRuntimeBinding']['containerId'] and sha(v['Id']) and v['Image']==r['Image'],
                'APISIX_CANDIDATE_IDENTITY_DRIFT')
        for k,value in r.items():
            if k in ('HostConfig','NetworkingConfig') or (k=='Hostname' and not value):continue
            require(v['Config'].get(k)==value,'APISIX_CANDIDATE_PROCESS_DRIFT')
        host=copy.deepcopy(r['HostConfig'])
        if restored:host['RestartPolicy']=p['originalRestartPolicy']
        require(host_config_matches(host,v['HostConfig']),'APISIX_CANDIDATE_HOST_DRIFT')
        projection=lambda rows:{(m['Type'],m['Source'],m['Destination'],m['RW']) for m in rows}
        require(projection(v['Mounts'])==projection(p['expectedMounts']),'APISIX_CANDIDATE_MOUNT_DRIFT')
        networks=v['NetworkSettings']['Networks'];expected=p['networks'] if connected else r['NetworkingConfig']['EndpointsConfig']
        require(set(networks)==set(expected) and all(networks[n]['NetworkID']==e['NetworkID']
                and set(e['Aliases'])<=set(networks[n].get('Aliases') or []) for n,e in expected.items()),
                'APISIX_CANDIDATE_NETWORK_DRIFT')
        if started:require(v['State']['Running'] and not v['State']['Paused'] and v['State']['Pid']>1
                           and v['RestartCount']==0,'EXACT_FIRST_APISIX_GENERATION_REQUIRED')
        else:require(not v['State']['Running'] and v['State']['Status']=='created' and v['State']['Pid']==0,
                     'EXACT_CREATED_APISIX_REQUIRED')
        return v
    def generation(self):
        self.guard();v=self.record();require(v['nextStep']>=6,'APISIX_START_NOT_RECONCILED')
        self.old(True)
        restored=v['nextStep']==len(STEPS)
        actual=self.candidate(True,True,restored)
        require(actual is not None and v['effects'][3]['evidence']['containerId']==actual['Id'],
                'APISIX_CREATED_ID_NOT_JOURNAL_PROVEN')
        current=apisix_runtime_binding(actual,self.plan.get('runtimeBindingProfile'))
        started=v['effects'][5]['evidence'].get('runtimeBinding')
        require(type(started) is dict and set(started)==set(current)
                and all(current[k]==value for k,value in started.items() if k!='hostConfigHash'),
                'APISIX_STARTED_GENERATION_CHANGED')
        return actual
    def transport(self):
        self.generation()
        binding=NamespaceAdmin.observe(self.engine,self.plan['newConfigBinding']['path'],self.plan.get('runtimeBindingProfile'))
        require(binding['pythonExecutable']==self.plan['pythonExecutable']
                and binding['adminKeyBinding']==self.plan['adminKeyBinding'],
                'APPROVED_NAMESPACE_ADMIN_CREDENTIAL_CHANGED')
        return NamespaceAdmin(self.engine,binding,self)
    def mutation(self,step):
        self.guard();p=self.plan;old=p['oldRuntimeBinding']['containerId']
        if step=='disable_restart':
            require(runtime_pin(self.inspect(old))==p['oldRuntimeBinding'],'OLD_APISIX_BASELINE_DRIFT')
            self.engine.request('POST','/v1.44/containers/'+old+'/update',{'RestartPolicy':NO_RESTART})
        elif step=='stop':
            self.old(stopped=False);self.engine.request('POST','/v1.44/containers/'+old+'/stop?t=10')
        elif step=='rename':
            self.old();require(self.inspect(p['retiredName']) is None,'APISIX_RETIRED_NAME_EXISTS')
            self.engine.request('POST','/v1.44/containers/'+old+'/rename?name='+quote(p['retiredName'],safe=''))
        elif step=='create':
            self.old(True);require(self.inspect(p['oldName']) is None,'APISIX_LIVE_NAME_NOT_FREE')
            self.engine.request('POST','/v1.44/containers/create?name='+p['oldName'],p['creationRequest'])
        elif step=='connect':
            v=self.candidate();require(v is not None,'CREATED_APISIX_REQUIRED')
            n=p['secondaryNetwork'];self.engine.request('POST','/v1.44/networks/'+p['networks'][n]['NetworkID']+'/connect',
                {'Container':v['Id'],'EndpointConfig':p['networks'][n]})
        elif step=='start':
            v=self.candidate(True);require(v is not None,'NETWORK_BOUND_APISIX_REQUIRED')
            self.engine.request('POST','/v1.44/containers/'+v['Id']+'/start')
        elif step=='restore_restart':
            v=self.candidate(True,True);require(v is not None,'HEALTHY_APISIX_REQUIRED')
            self.engine.request('POST','/v1.44/containers/'+v['Id']+'/update',{'RestartPolicy':p['originalRestartPolicy']})
    def observe(self,step):
        if step=='disable_restart':v=self.old(stopped=False)
        elif step=='stop':v=self.old()
        elif step=='rename':v=self.old(True)
        else:
            self.old(True);v=self.candidate(step!='create',step in ('start','ready','restore_restart'),step=='restore_restart')
            require(v is not None,'APISIX_WRITE_OUTCOME_UNPROVEN_NO_REPLAY')
        return {'containerId':v['Id'],'imageId':v['Image'],'nativeHash':digest(v),
                'runtimeBinding':apisix_runtime_binding(v,self.plan.get('runtimeBindingProfile'))}
    def ready(self,record):
        self.guard();self.generation()
        now,mono=self.clock(),self.monotonic()
        expiry=json.loads(self.action.raw)['expiresAt']
        budget=copy.deepcopy(record['readiness'])
        if budget is None:
            remaining=min(3600,expiry-now)
            require(remaining>0,'APISIX_READINESS_AUTHORITY_EXPIRED')
            budget={'profile':APISIX_READINESS_POLICY['profile'],'bootId':self.boot,'state':'IDLE',
                'startedAt':now,'startedMonotonic':mono,'expiresAt':now+remaining,'expiresMonotonic':mono+remaining,
                'lastWall':now,'lastMonotonic':mono,'attempts':0,'nextAttemptAt':now,'nextAttemptMonotonic':mono}
        require(budget.get('profile')==APISIX_READINESS_POLICY['profile'] and budget.get('bootId')==self.boot
            and type(budget.get('attempts'))is int and 0<=budget['attempts']<=128
            and budget['startedAt']<=budget['lastWall']<=now and budget['startedMonotonic']<=budget['lastMonotonic']<=mono
            and 0<budget['expiresAt']-budget['startedAt']<=3600 and budget['expiresAt']<=expiry
            and 0<budget['expiresMonotonic']-budget['startedMonotonic']<=3600,
            'APISIX_READINESS_HISTORY_OR_CLOCK_DRIFT')
        def save(state,**changes):
            nonlocal record,budget
            budget.update(state=state,lastWall=self.clock(),lastMonotonic=self.monotonic(),**changes)
            following=copy.deepcopy(record);following['readiness']=copy.deepcopy(budget)
            record=self.save(record,following)
        def exhausted():
            return self.clock()>=budget['expiresAt'] or self.monotonic()>=budget['expiresMonotonic']
        def pause_exhausted(reason):
            save('PAUSED_EXHAUSTED');raise PlanDenied(reason)
        require(budget['state']in ('IDLE','RETRY_WAIT'),'APISIX_READINESS_IN_FLIGHT_OR_TERMINAL_NO_REPLAY')
        if budget['attempts']>=128 or exhausted():pause_exhausted('APISIX_READINESS_BUDGET_EXHAUSTED')
        wait=max(budget['nextAttemptAt']-now,budget['nextAttemptMonotonic']-mono,0)
        if wait:raise CohortPaused('APISIX_READINESS_WAIT',now+min(wait,budget['expiresAt']-now,budget['expiresMonotonic']-mono))
        save('ATTEMPTING',attempts=budget['attempts']+1)
        transport=self.transport()
        try:
            status,body=transport.request('GET','/apisix/admin/routes')
        except PlanDenied as error:
            if str(error)!='APISIX_OUTCOME_REQUIRES_RECONCILIATION':raise
            status,body=503,None
        self.guard()
        if exhausted():pause_exhausted('APISIX_READINESS_DEADLINE_EXCEEDED')
        if status in (429,502,503,504):
            if budget['attempts']>=128:pause_exhausted('APISIX_READINESS_BUDGET_EXHAUSTED')
            now,mono=self.clock(),self.monotonic()
            minimum=retry_after_seconds(getattr(transport,'retry_after',''),now)
            if minimum>=min(budget['expiresAt']-now,budget['expiresMonotonic']-mono):
                pause_exhausted('APISIX_READINESS_RETRY_AFTER_EXCEEDS_BUDGET')
            base=APISIX_READINESS_POLICY['backoffSeconds'][min(budget['attempts']-1,4)]
            fraction=int(digest({'planHash':self.scope['planHash'],'attempt':budget['attempts']})[:8],16)/0xffffffff
            delay=max(minimum,base*(1+.2*fraction))
            save('RETRY_WAIT',nextAttemptAt=now+delay,nextAttemptMonotonic=mono+delay)
            raise CohortPaused('APISIX_READINESS_TRANSIENT',now+min(delay,budget['expiresAt']-now,budget['expiresMonotonic']-mono))
        require(status==200 and type(body)is dict and type(body.get('list'))is list
            and body.get('total')==len(body['list']),'APISIX_ADMIN_READINESS_PERMANENT_FAILURE')
        save('COMPLETE')
        return record
    def apply(self):
        with self.journal.invocation():
            while True:
                self.guard();record=self.record();n=record['nextStep']
                if n==len(STEPS):return self.verify()
                step=STEPS[n]
                if len(record['effects'])==n:
                    following=copy.deepcopy(record);following['effects'].append({'step':step,'state':'CLAIMED',
                        'intentHash':digest({'planHash':self.scope['planHash'],'step':step})})
                    record=self.save(record,following)
                    if step!='ready':self.mutation(step)
                if step=='ready':record=self.ready(record)
                observed=self.observe(step);self.guard();following=copy.deepcopy(record)
                following['effects'][-1].update(state='APPLIED',evidence=observed);following['nextStep']=n+1
                self.save(record,following)
    def verify(self):
        require(self.record()['nextStep']==len(STEPS),'APISIX_INSTALLATION_INCOMPLETE')
        actual=self.generation();self.transport().routes()
        return {'schema':PROFILE,'planHash':self.scope['planHash'],'runtimeBinding':apisix_runtime_binding(actual,self.plan.get('runtimeBindingProfile')),
                'proposalKeyHash':self.plan['proposalKeyHash'],'oldContainerRetained':True,
                'automaticRollbackAllowed':False,'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}


def retry_after_seconds(value,now):
    """Only the bounded selected header is exposed; never shorten Retry-After."""
    import re
    from email.utils import parsedate_to_datetime
    require(type(value)is str and len(value)<=128,'APISIX_RETRY_AFTER_HEADER_INVALID')
    if not value:return 0
    if re.fullmatch(r'[0-9]{1,12}',value):return int(value)
    try:
        parsed=parsedate_to_datetime(value)
        require(parsed.tzinfo is not None,'APISIX_RETRY_AFTER_HEADER_INVALID')
        result=max(0,parsed.timestamp()-now)
    except (ValueError,TypeError,OverflowError):
        raise PlanDenied('APISIX_RETRY_AFTER_HEADER_INVALID') from None
    require(result<float('inf'),'APISIX_RETRY_AFTER_HEADER_INVALID')
    return result
