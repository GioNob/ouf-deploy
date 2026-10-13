"""One governed mapper creation, durable consumption and no automatic POST replay.

Component only: a sealed launcher must supply current CutoverAuthority, exact
source closure/plan and existing IAM-owner session. No signing, credentials,
grants, runtime journal/root initialization, exception disabling or R12 effects.
"""
import fcntl
import json
import os
import re
import stat
import subprocess
import time
import uuid
import iam_binding_candidate as binding
import iam_mapper_enrichment as metadata
from cutover_authority import CutoverAuthority

class MapperAdmin:
    def __init__(self,client):
        binding.require(type(client)is str and re.fullmatch('[0-9a-fA-F-]{36}',client),'EXACT_REGISTERED_CLIENT_REQUIRED')
        self.resource='clients/'+client+'/protocol-mappers/models'
        self.client=client;self.clock=time.monotonic;self.deadline=None
    def command(self,action,body=None,resource=None,fields=None):
        target=resource or self.resource
        binding.require(action in {'get','create'} and (action=='get' or target==self.resource),'EXACT_IAM_OPERATION_REQUIRED')
        timeout=15 if self.deadline is None else min(15,self.deadline-self.clock())
        binding.require(timeout>0,'FINITE_IAM_PREPARATION_DEADLINE')
        argv=['/usr/bin/docker','exec']
        if body is not None:argv.append('-i')
        argv+=['ouf-keycloak','/opt/keycloak/bin/kcadm.sh',action,target,'--server','http://localhost:8080','-r','ouf']
        if body is not None:argv+=['-f','-']
        if fields is not None:argv+=['--fields',fields]
        result=subprocess.run(argv,input=body,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout)
        binding.require(result.returncode==0,'SELECTED_IAM_OPERATION_UNAVAILABLE')
        binding.require(len(result.stdout)<=262144,'IAM_OPERATION_RESPONSE_UNBOUNDED')
        return result.stdout
    def models(self):
        value=binding.decode(self.command('get'))
        binding.require(type(value)is list and len(value)<=64 and all(type(m)is dict for m in value),'BOUNDED_CLIENT_MAPPER_SET_REQUIRED')
        return value
    def create(self,mapper):self.command('create',binding.encoded(mapper))
    def baseline(self,snapshot):
        admin=self
        class Reader:
            def get(self,resource,fields=None):
                binding.require(re.fullmatch(r'(clients/[0-9a-fA-F-]{36}(/(service-account-user|default-client-scopes|optional-client-scopes|protocol-mappers/models))?|client-scopes/[0-9a-fA-F-]{36}/protocol-mappers/models)',resource),
                    'EXACT_METADATA_RESOURCE_REQUIRED')
                return binding.decode(admin.command('get',resource=resource,fields=fields))
        reader=Reader();core=metadata.core(reader,self.client)
        binding.require(metadata.canonical(core)==metadata.canonical(metadata.anchor(snapshot)), 'CURRENT_CORE_AND_SCOPE_DRIFT')
        return metadata.enriched(snapshot,core,metadata.complete_mappers(reader,snapshot,core))

def equivalent(actual,desired):
    #Keycloak allocates the registration ID; the requested UUID is the durable
    #logical operation ID, not a claim that its POST preserves an object ID.
    return (type(actual)is dict and type(actual.get('id'))is str and re.fullmatch('[0-9a-fA-F-]{36}',actual['id'])
        and all(actual.get(k)==v for k,v in desired.items() if k!='id'))

class AudienceTransaction:
    """Exclusive invocation fence only; no shared service/lease lock or retry wait."""
    def __init__(self,plan,plan_hash,snapshot,authority,authority_raw,clock=time.monotonic):
        binding.require(type(authority)is CutoverAuthority and type(authority_raw)is bytes,'CURRENT_EXISTING_AUTHORITY_REQUIRED')
        binding.require(binding.sha(binding.encoded(plan))==plan_hash and plan.get('schema')=='ouf.policy-token-introspection-audience-review-plan.v1'
            and plan.get('runtimeAuthorityIssued')is False and plan.get('productionApplyReady')is False,'EXACT_PRIVATE_REVIEW_PLAN_REQUIRED')
        change=plan.get('changeProposal');binding.require(type(change)is dict and change.get('applyAuthorized')is False
            and change.get('operation')=='ADD_EXACT_CALLER_AUDIENCE_MAPPER' and change.get('introspectionCheckMustRemainEnabled')is True,
            'EXACT_CONDITIONAL_IAM_CHANGE_REQUIRED')
        match=re.fullmatch('clients/([0-9a-fA-F-]{36})/protocol-mappers/models',change['resource'])
        binding.require(match is not None,'EXACT_MAPPER_RESOURCE_REQUIRED')
        desired=change['proposedMapper'];cfg=desired.get('config',{})
        binding.require(type(snapshot)is dict and binding.sha(binding.encoded(snapshot))==plan['snapshotHash']
            and snapshot['client']['id']==match[1] and cfg.get('included.client.audience')==snapshot['client']['clientId'],
            'EXACT_RETAINED_CLIENT_AND_SNAPSHOT_REQUIRED')
        binding.require(set(desired)=={'id','name','protocol','protocolMapper','config'}
            and desired['name']=='ouf-policy-token-self-introspection-audience'
            and re.fullmatch('[0-9a-fA-F-]{36}',desired['id']) and desired['protocol']=='openid-connect'
            and desired['protocolMapper']=='oidc-audience-mapper' and set(cfg)=={'included.client.audience','access.token.claim','introspection.token.claim','id.token.claim'}
            and cfg['access.token.claim']==cfg['introspection.token.claim']=='true' and cfg['id.token.claim']=='false'
            and type(cfg['included.client.audience'])is str and 0<len(cfg['included.client.audience'])<=128,'EXACT_ADDITIVE_AUDIENCE_INTENT_REQUIRED')
        self.plan=json.loads(binding.encoded(plan));self.plan_hash=plan_hash;self.desired=binding.decode(binding.encoded(desired))
        self.snapshot=binding.decode(binding.encoded(snapshot))
        self.authority,self.raw,self.clock=authority,bytes(authority_raw),clock
        self.admin=MapperAdmin(match[1]);self.scope={'reviewPlanHash':plan_hash,'resource':change['resource'],
            'mapperHash':binding.sha(binding.encoded(desired)),'operation':'ADD_EXACT_CALLER_AUDIENCE_MAPPER',
            'maximumIamMutations':1,'introspectionCheckMustRemainEnabled':True,'runtimeAuthorityIssued':False}
        # Logical target/managed mapper identity stays stable across job/decision IDs.
        self.operation=binding.sha(binding.encoded({'resource':change['resource'],'mapperId':desired['id']}))
    def guard(self):
        binding.require(binding.sha(binding.encoded(self.plan))==self.plan_hash and binding.sha(binding.encoded(self.desired))==self.scope['mapperHash'],
            'IN_MEMORY_IAM_INTENT_DRIFT')
        binding.require(binding.decode(self.raw).get('policyTokenIamPreparation')==self.scope,'EXPLICIT_SIGNED_IAM_PREPARATION_SCOPE_REQUIRED')
        binding.require(self.authority(self.raw)is True,'CURRENT_HUMAN_AND_DUAL_ROLE_AUTHORITY_REQUIRED')
    def guard_reconciled_baseline(self,realized_id):
        current=self.admin.baseline(self.snapshot)
        current['client']['protocolMappers']=[m for m in current['client']['protocolMappers'] if m.get('id')!=realized_id]
        binding.require(current==self.snapshot,'CURRENT_COMPLETE_IAM_BASELINE_DRIFT')
    def run(self):
        self.guard();started=self.clock();name='policy-token-iam-transaction-'+self.operation+'.private.json'
        self.admin.clock=self.clock;self.admin.deadline=started+90
        report={'iamMutations':0,'runtimeAuthorityIssued':False,'productionApplyReady':False,'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
        with binding.protected_parent() as directory:
            lock=os.open(name+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
            row=None;owned=False
            try:
                s=os.fstat(lock);binding.require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0
                    and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1,'PRIVATE_INVOCATION_FENCE_REQUIRED')
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                binding.require(binding.identity(s)==binding.identity(os.stat(name+'.lock',dir_fd=directory,follow_symlinks=False)),'INVOCATION_FENCE_CHANGED')
                def save(row):
                    temporary='.'+name+'.'+uuid.uuid4().hex
                    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                    try:
                        with os.fdopen(os.dup(fd),'wb')as stream:stream.write(binding.encoded(row));stream.flush();os.fsync(stream.fileno())
                        os.replace(temporary,name,src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
                    finally:os.close(fd)
                try:row=binding.decode(binding.read_member(directory,name))
                except FileNotFoundError:
                    row={'schema':'ouf.policy-token-single-iam-mutation.v1','operation':self.operation,
                        'reviewPlanHash':self.plan_hash,'mapperHash':self.scope['mapperHash'],'postConsumed':False,'state':'PREPARED'}
                    save(row)
                binding.require(row.get('schema')=='ouf.policy-token-single-iam-mutation.v1' and row.get('operation')==self.operation
                    and row.get('reviewPlanHash')==self.plan_hash and row.get('mapperHash')==self.scope['mapperHash']
                    and type(row.get('postConsumed'))is bool,'RETAINED_IAM_INTENT_DRIFT')
                owned=True
                self.guard();models=self.admin.models();self.guard()
                matches=[m for m in models if m.get('id')==self.desired['id'] or m.get('name')==self.desired['name']]
                if matches:
                    binding.require(len(matches)==1 and equivalent(matches[0],self.desired),'MANAGED_MAPPER_CONFLICT_REQUIRES_REVIEW')
                    binding.require(row.get('realizedMapperId',matches[0]['id'])==matches[0]['id'],'REGISTERED_MAPPER_ID_DRIFT')
                    row['realizedMapperId']=matches[0]['id']
                    self.guard_reconciled_baseline(matches[0]['id']);self.guard()
                    row.update(state='APPLIED_RECONCILED');save(row);report['state']=row['state'];return report
                binding.require(row['state']=='PREPARED' and not row['postConsumed'],'CONSUMED_IAM_ATTEMPT_REQUIRES_RECONCILIATION')
                # A fresh complete metadata/core reconciliation is mandatory in
                # the independently signed intake; this component does not
                # manufacture it from mapper names or prior snapshot presence.
                proof=binding.decode(self.raw).get('policyTokenIamFreshReconciliation')
                binding.require(proof=={'reviewPlanHash':self.plan_hash,'observedClientMapperSetHash':binding.sha(binding.encoded(models)),
                    'metadataAndCoreDriftChecked':True,'callerAudienceReconciled':True},'INDEPENDENT_CURRENT_IAM_RECONCILIATION_REQUIRED')
                self.guard();binding.require(0<=self.clock()-started<90,'FINITE_IAM_PREPARATION_DEADLINE')
                binding.require(self.admin.baseline(self.snapshot)==self.snapshot,'CURRENT_COMPLETE_IAM_BASELINE_DRIFT')
                self.guard()
                row.update(postConsumed=True,state='POST_CONSUMED');save(row)
                try:
                    report['iamMutations']=1;self.admin.create(self.desired)
                    self.guard();models=self.admin.models();self.guard()
                    matches=[m for m in models if m.get('id')==self.desired['id'] or m.get('name')==self.desired['name']]
                    binding.require(len(matches)==1 and equivalent(matches[0],self.desired),'IAM_EFFECT_RECONCILIATION_REQUIRED')
                    row['realizedMapperId']=matches[0]['id']
                    self.guard_reconciled_baseline(matches[0]['id']);self.guard()
                    binding.require(0<=self.clock()-started<90,'FINITE_IAM_PREPARATION_DEADLINE')
                    row.update(state='APPLIED_RECONCILED');save(row);report['state']=row['state'];return report
                except Exception:
                    row.update(state='RECONCILE_REQUIRED');save(row);raise
            except Exception:
                if owned and row['state'] not in {'APPLIED_RECONCILED','RECONCILE_REQUIRED','BLOCKED'}:
                    row.update(state='RECONCILE_REQUIRED' if row['postConsumed'] else 'BLOCKED')
                    try:save(row)
                    except Exception:pass
                raise
            finally:os.close(lock)
