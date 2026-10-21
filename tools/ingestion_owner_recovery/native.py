"""Qualified HTTPS owner transport only:3POST,1export; no secret or runtime writes."""
import copy
from tools.installation_binding_apply.native import OwnerHttp,Ports as ExistingPorts,baseline_runtime
from tools.ingestion_owner_recovery.owner import require,scope,scope_key,STAGES,KIND
from tools.chatbot_file_cohort.gateway import private_config
from tools.ingestion_read_gateway_custody.owner import metadata_file
class Ports(ExistingPorts):
 def guard_current(self,stage,row):
  require(stage in STAGES[KIND],'CLOSED_OWNER_REFERENCE_STAGE_REQUIRED')
  self.action.guard(scope_key(self.plan['kind']),scope(self.plan))
  require(self.human.current()==self.plan['humanBinding'],'SAME_CURRENT_VERIFIED_HUMAN_REQUIRED')
  for name,pin in self.plan['currentApplications'].items():
   status,actual=self.engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
   require(status==200 and baseline_runtime(actual,name,self.plan)==pin,'CURRENT_INDEPENDENT_APPLICATION_DRIFT')
  for binding in self.plan['retainedMcpMetadata']:metadata_file(binding)
  activated=self.evidence(row,'ACTIVATE_EXPECTED');expected=activated['active']if activated else{**self.plan['bindingPlan']['expectedActive'],'etag':self.plan['bindingPlan']['expectedActiveETag']}
  require(self.http.active()==expected,'OWNER_ACTIVE_VERSION_GENERATION_DRIFT')
  private_config(self.plan['projectionBinding']['path'],self.plan['projectionBinding'])
  require(self.gateway.routes()==self.plan['gateway']['beforeRoutes'],'ALL82_GATEWAY_ROUTES_UNCHANGED_REQUIRED')
 def apply(self,stage,row):
  require(stage in STAGES[KIND],'CLOSED_OWNER_REFERENCE_EFFECT_REQUIRED')
  if stage=='VERIFY_FINAL':
   activated=self.evidence(row,'ACTIVATE_EXPECTED')['active'];revision,_=self.http.call('GET','/revisions/'+str(activated['revision']))
   require(revision.get('payload')==self.plan['bindingPlan']['candidatePayload']and revision.get('checksum')==self.plan['bindingPlan']['candidatePayloadChecksum']
    and revision.get('validationState')=='VALIDATED'and revision.get('validationFindings')==[],'FINAL_AUTHORITATIVE_OWNER_PAYLOAD_REQUIRED')
   return {'verified':True,'active':activated,'ownerPayloadReadbackProven':True}
  return super().apply(stage,row)
