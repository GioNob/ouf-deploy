"""MCP-only finite ports reusing qualified replacement/OCI/readiness adapters."""
import copy,json,time
from pathlib import Path
from engine_creation import Engine
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory
from iam_owner_action import publish
from tools.semantic_mcp_update.native import private_file
from tools.ingestion_read_gateway_custody.owner import metadata_file
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,private_config
from tools.source_revision_update.native import NativePorts as ExistingPorts,runtime,NO_RESTART
from tools.mcp_read_transport_gateway82.owner import require,digest,scope,STAGES

class NativePorts(ExistingPorts):
 def __init__(self,action,engine,plan,human):
  require(type(action)is AggregateAction and type(engine)is Engine,'REAL_AUTHORITY_AND_ENGINE_REQUIRED')
  scope(plan);self.action,self.engine,self.plan,self.human=action,engine,copy.deepcopy(plan),human
  self.gateway=NamespaceAdmin(engine,plan['gateway']['transport'])
 def claim_logical_scope(self):
  with protected_directory(Path(self.plan['authorityDirectory']).parent)as directory:
   require(publish(directory,'mcp-ingestion-read-transport-'+self.plan['logicalUpdateRef']+'.claim.json',
    json.dumps({'planHash':digest(self.plan),'authorityHash':self.action.authority_hash,
     'context':self.plan['authorityDirectory'],'automaticReplayAllowed':False,'budgetReset':False},sort_keys=True).encode()),
    'MCP_TRANSPORT_LOGICAL_UPDATE_ALREADY_CLAIMED')
 def plan_scope(self):return scope(self.plan)
 def expected_routes(self,include_claim=False):return copy.deepcopy(self.plan['gateway']['beforeRoutes'])
 def route_inventory(self,after=False):
  actual=self.gateway.routes()
  require(actual==self.plan['gateway']['beforeRoutes']==self.plan['gateway']['afterRoutes'],
   'MCP_TRANSPORT_GATEWAY_ROUTES_CHANGED')
  return actual
 def guard_current(self,stage):
  require(stage in STAGES,'EXACT_MCP_ONLY_STAGE_REQUIRED');p=self.plan
  self.action.guard('mcpReadTransportUpdate',scope(p));self.engine.check_socket()
  private_file(p['privateReviewBinding']['path'],p['privateReviewBinding']['sha256'],8388608)
  private_config(p['gateway']['projectionBinding']['path'],p['gateway']['projectionBinding'])
  self.gateway.check();self.route_inventory()
  for binding in p['retainedMcpMetadata']:
   metadata_file(binding)
  require(self.human.current()==p['humanBinding'],'SAME_CURRENT_HUMAN_REQUIRED')
  for retained in p['unchangedApplications'].values():
   actual=self.inspect('containers',retained['containerId'])
   require(actual is not None and actual['State']['Running']is True and runtime(actual)==retained,
    'UNCHANGED_APPLICATION_GENERATION_REQUIRED')
  row=p['replacements']['mcp'];old=self.inspect('containers',row['oldRuntimeBinding']['containerId'])
  require(old is not None,'RETAINED_MCP_ABSENT');pin=row['oldRuntimeBinding']
  require(old['Image']==pin['imageId']and digest(old['Config'])==pin['configHash']
   and digest(sorted(old['Mounts'],key=lambda m:m['Destination']))==pin['mountsHash'],
   'RETAINED_MCP_CONFIG_CHANGED')
  host=copy.deepcopy(row['oldNativeHostConfig']);host['RestartPolicy']=copy.deepcopy(NO_RESTART)
  require(old['HostConfig']in(row['oldNativeHostConfig'],host),'RETAINED_MCP_HOST_CHANGED')
  n=STAGES.index(stage);stop=STAGES.index('mcp.STOP_OLD')
  if n<stop or n==stop and old['State']['Running']:
   observed=runtime(old);observed['hostConfigHash']=pin['hostConfigHash']
   require(old['State']['Running']is True and observed==pin,'OLD_MCP_GENERATION_CHANGED')
  require(old['State']['StartedAt']==pin['startedAt'],'OLD_MCP_PROCESS_REPLACED')
  if n>stop:require(old['State']['Running']is False and old['State']['Pid']==0,'OLD_MCP_RESTARTED')
  if n>STAGES.index('mcp.START_REPLACEMENT'):
   require(self.candidate('mcp',True)is not None,'STARTED_MCP_DISAPPEARED')
 def verify_inputs(self):
  self.route_inventory();row=self.plan['replacements']['mcp']
  private_file(row['imageArchive']['path'],row['imageArchive']['sha256'],1200000000)
  require(self.inspect('containers',row['retiredName'])is None,'RETIRED_MCP_NAME_ALREADY_EXISTS')
  return {'privateReviewHash':self.plan['privateReviewBinding']['sha256'],'databaseActions':0,'metadataWrites':0}
 def apply(self,stage):
  require(stage in STAGES,'EXACT_MCP_ONLY_STAGE_REQUIRED')
  if stage in ('VERIFY_INPUTS','VERIFY_FINAL'):
   if stage=='VERIFY_INPUTS':self.verify_inputs()
   return
  require(stage.startswith('mcp.'),'OTHER_APPLICATION_EFFECT_DENIED')
  return super().apply(stage)
 def observe(self,stage):
  require(stage in STAGES,'EXACT_MCP_ONLY_STAGE_REQUIRED')
  if stage=='VERIFY_INPUTS':return 'APPLIED',self.verify_inputs()
  if stage=='VERIFY_FINAL':
   actual=self.candidate('mcp',True);status,proof=self.health('mcp',actual)
   if status=='TRANSIENT':return status,proof
   require(status=='APPLIED','FINAL_MCP_READINESS_REQUIRED')
   return 'APPLIED',{'mcp':{'runtimeBinding':runtime(actual),'health':proof},
    'routeMapHash':digest(self.route_inventory()),'databaseMigrationsPerformed':0,'metadataChanged':False,
    'sourceActivationProven':False,'unchangedApplicationBindingsHash':digest(self.plan['unchangedApplications'])}
  return super().observe(stage)
