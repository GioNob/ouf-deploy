"""Closed read-only installation owner plan. Never creates or activates revisions."""
import copy,hashlib,json,os,re,ssl,stat,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
from tools.installation_binding_plan import discovery
from iam_owner_action import stdlib_binding
from tools.chatbot_file_cohort.review import command_matches
from tools.ingestion_read_authorization.authorization import OwnerTransport,NoRedirect
from tools.linked_property_rollout.preparation import root_directory,read_file,write_new

def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
PARENT=Path('/etc/ouf/deploy-snapshots')
KEY='ouf-ingestion-runtime'
ONBOARDING='be388e1462778438a208c2e00e166370fee32189'
SCHEMAS={'login-review.json':'ouf.human-explicit-capability-scope-review.v4',
 'login-window-receipt.json':'ouf.installation-binding-scope-login-receipt.v1',
 'installation-plan.json':'ouf.installation-ingestion-binding-plan.v1',
 'planning-result.json':'ouf.installation-ingestion-binding-planning-result.v1'}
def publish_json(context,name,value):
 context=Path(context)
 require(context.parent==PARENT and re.fullmatch('installation-ingestion-binding-execution-[A-Za-z0-9_-]{8,64}',context.name)
  and name in SCHEMAS and type(value)is dict and value.get('schema')==SCHEMAS[name],'EXACT_INSTALLATION_PLAN_DOCUMENT_REQUIRED')
 root_directory(context);info=context.lstat()
 require(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700,'PRIVATE_INSTALLATION_PLANNING_CONTEXT_REQUIRED')
 raw=encoded(value);require(0<len(raw)<=8388608,'BOUNDED_PRIVATE_PLAN_REQUIRED');path=context/name;write_new(path,raw)
 fd=os.open(context,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 require(read_file(path,hashlib.sha256(raw).hexdigest())==raw,'PRIVATE_PLAN_READBACK_FAILED')

def canonical_owner(value):
 # Fail closed on JSON values with different Java/Python float or UTF16 ordering.
 def check(v):
  require(type(v)in(dict,list,str,int,bool,type(None)),'OWNER_CANONICAL_JSON_DOMAIN_REQUIRED')
  if type(v)is str:require(all(0x20<=ord(c)<=0xffff and not 0xd800<=ord(c)<=0xdfff for c in v),'OWNER_CANONICAL_STRING_DOMAIN_REQUIRED')
  if type(v)is int:require(-(2**63)<=v<2**63,'OWNER_CANONICAL_INTEGER_DOMAIN_REQUIRED')
  if type(v)is list:
   for item in v:check(item)
  if type(v)is dict:
   for key,item in v.items():require(type(key)is str,'OWNER_STRING_KEYS_REQUIRED');check(key);check(item)
 check(value)
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()

def candidate(payload,alias):
 require(type(payload)is dict and type(payload.get('networking'))is dict and type(alias)is str
  and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,252}',alias)and alias!=KEY,'VERIFIED_OWNER_ALIAS_AND_NETWORKING_REQUIRED')
 bindings=payload['networking'].get('serviceBindings',{})
 require(type(bindings)is dict and KEY not in bindings,'ONE_MISSING_INGESTION_BINDING_REQUIRED')
 require(all(type(k)is str and type(v)is str and v.strip()==v and v for k,v in bindings.items()),'EXISTING_BINDINGS_MUST_BE_LOSSLESS')
 out=copy.deepcopy(payload);out['networking']['serviceBindings']={**bindings,KEY:alias}
 return out

class InstallationReader:
 def __init__(self,selection,human,installation_id,revision):
  require(re.fullmatch('[A-Za-z0-9._-]{1,128}',installation_id)and type(revision)is int and revision>0,'EXACT_INSTALLATION_ID_AND_REVISION_REQUIRED')
  self.credentials=OwnerTransport(selection,human.token_path,human.token_path,human_session=human)
  self.base=selection['origin'].rstrip('/');self.calls=0;self.deadline=time.monotonic()+45
  root='/api/trusted-human/v1/installations/'+installation_id
  self.paths=[root+'/active',root+'/revisions/'+str(revision),root+'/active']
  self.opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()),NoRedirect())
 def get_next(self):
  require(self.calls<3 and time.monotonic()<self.deadline,'FINITE_THREE_OWNER_GETS_ONLY')
  path=self.paths[self.calls];token=self.credentials.token('admin')
  require(time.monotonic()<self.deadline,'INSTALLATION_OWNER_READ_DEADLINE')
  request=urllib.request.Request(self.base+path,headers={'Authorization':'Bearer '+token,'Accept':'application/json'},method='GET')
  self.calls+=1
  try:
   with self.opener.open(request,timeout=min(10,max(0.1,self.deadline-time.monotonic())))as response:
    require(response.status==200,'INSTALLATION_OWNER_GET_NOT_SUCCESSFUL');raw=response.read(1048577)
    require(0<len(raw)<=1048576,'BOUNDED_INSTALLATION_OWNER_RESPONSE_REQUIRED');return json.loads(raw)
  except (urllib.error.HTTPError,urllib.error.URLError,TimeoutError):raise ValueError('INSTALLATION_OWNER_READ_STOP_NO_RETRY')from None

def compile_plan(active,revision,active_after,projection,alias,bindings):
 require(type(projection)is dict and type(projection.get('revision'))is int and projection['revision']>0
  and type(projection.get('checksum'))is str and re.fullmatch('[0-9a-f]{64}',projection['checksum']),
  'PINNED_OWNER_PROJECTION_IDENTITY_REQUIRED')
 expected={k:projection[k]for k in('installationId','revision','checksum')}
 require(active==active_after==expected,'OWNER_ACTIVE_OR_APPROVED_PROJECTION_DRIFT')
 require(type(revision)is dict and all(revision.get(k)==v for k,v in expected.items())
  and revision.get('validationState')=='VALIDATED'and revision.get('validationFindings')==[]
  and type(revision.get('payload'))is dict,'EXACT_VALIDATED_OWNER_REVISION_REQUIRED')
 payload=revision['payload'];require(payload.get('installationId')==expected['installationId']
  and canonical_owner(payload)==expected['checksum'],'OWNER_PAYLOAD_CHECKSUM_MISMATCH')
 current=payload.get('networking',{}).get('serviceBindings',{})
 require(projection.get('services',{}).get('bindings')==current,'OWNER_AND_PROJECTION_BINDINGS_DISAGREE')
 derived=candidate(payload,alias)
 return {'schema':'ouf.installation-ingestion-binding-plan.v1','expectedActive':expected,
  'sourceRevisionViewHash':digest(revision),'sourcePayload':payload,'sourcePayloadChecksum':expected['checksum'],
  'candidatePayload':derived,'candidatePayloadChecksum':canonical_owner(derived),
  'onlyChange':'/networking/serviceBindings/ouf-ingestion-runtime','addedBindings':{KEY:alias},
  'bindings':bindings,'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,
  'ownerApplyAuthorized':False,'installationActivationAllowed':False,'projectionReplacementAllowed':False,
  'gatewayWritesAllowed':False,'sourceActivationAllowed':False,'jobDispatchAllowed':False,
  'atomicOwnerActivePreconditionSupportProven':False,'futureNativeConsentRequired':True,
  'requiredFutureOwnerLifecycle':['CREATE_IMMUTABLE_REVISION','VALIDATE_ENVIRONMENT','CONDITIONAL_ACTIVATE','EXPORT_ACTIVE_PROJECTION'],
  'requiredFutureGatewayDelta':{'capabilities':['ouf.ingestion.status','ouf.ingestion.history'],'maximumPutRequests':2,'retainedOtherRoutes':80}}

def inspect_current(plan,result):
 gateway_binding=plan['gateway']['transport']['runtimeBinding']
 expected={'gateway':gateway_binding,'ingestion':plan['unchangedApplications']['ingestion'],
  'onboarding':plan['unchangedApplications']['onboarding']}
 reader=discovery.Reader(plan['engine'],[v['containerId']for v in expected.values()])
 actual={k:reader.get('/v1.44/containers/'+v['containerId']+'/json')for k,v in expected.items()}
 for k,v in actual.items():
  ordered=k!='gateway'or plan['gateway']['transport'].get('runtimeBindingProfile')=='ouf.apisix-runtime-binding.mount-set.v1'
  require(discovery.runtime(v,ordered)==expected[k],'RETAINED_RUNTIME_GENERATION_DRIFT')
 require(actual['onboarding']['Config'].get('Labels',{}).get('org.opencontainers.image.revision')==ONBOARDING,'EXACT_RETAINED_INSTALLATION_OWNER_SOURCE_REQUIRED')
 return reader,expected,actual


def closure_valid(closure):
 require(type(closure)is dict and set(closure)=={'declaration','executables','stdlibHash','stdlibFileCount'}
  and closure['declaration']['entryModule']=='tools.installation_binding_plan.entry'
  and closure['declaration']['moduleCount']==209 and closure['declaration']['requiredPythonFlags']==['-I','-B','-S'],
  'EXACT_INSTALLATION_READ_ONLY_CLOSURE_REQUIRED')
 for program in closure['executables'].values():command_matches(program)
 library=stdlib_binding()
 require(digest(library)==closure['stdlibHash']and len(library['fileHashes'])==closure['stdlibFileCount'],
  'APPROVED_PYTHON_STDLIB_CHANGED')
