"""Compile only the existing Resolution THS contract from retained owner routes."""
import copy,json,re
from tools.chatbot_file_cohort.gateway import private_config
from tools.resolution_ths_update.owner import require,digest
PAGE='/trusted-human/resolution/*'
PACKAGE='/api/udp/v1/governance/resolution/issues/package'
ROUTES=('ths-resolution-package-read','ths-resolution-package-confirm','trusted-human-resolution-review')
THS_CONFIG='/opt/ouf/secrets/onboarding-ths.yaml'
def configuration(actual,origin,expected_sha):
 env={}
 for row in actual['Config'].get('Env')or[]:
  k,v=row.split('=',1);require(k not in env,'DUPLICATE_ONBOARDING_ENVIRONMENT_KEY');env[k]=v
 require(not any(env.get(k)for k in('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS'))and not any(a.startswith(('-D','--'))for a in(actual['Config'].get('Entrypoint')or[])+(actual['Config'].get('Cmd')or[])),'UNREVIEWED_THS_ARGUMENT_OVERRIDE')
 mounts=[m for m in actual['Mounts']if m.get('Source')==THS_CONFIG]
 require(len(mounts)==1 and mounts[0]['Type']=='bind'and mounts[0]['RW']is False,'EXACT_THS_READ_ONLY_SELECTION_REQUIRED')
 selectors=[v for k,v in env.items()if re.sub('[^a-z0-9]','',k.lower())in('springconfigimport','springconfiglocation','springconfigadditionallocation')]
 require(any(mounts[0]['Destination']in v for v in selectors),'MOUNTED_THS_CONFIG_NOT_SELECTED')
 raw,binding=private_config(THS_CONFIG);require(binding['sha256']==expected_sha,'REVIEWED_THS_CONFIG_BYTES_CHANGED')
 values={};stack=[]
 normal=lambda k:re.sub('[^a-z0-9]','',k.lower())
 def add(key,value):
  key=normal(key)
  if isinstance(value,list):value=','.join(str(v)for v in value)
  if isinstance(value,bool):value=str(value).lower()
  if isinstance(value,(str,int,float)):values.setdefault(key,set()).add(str(value).strip().strip("\"'"))
 def flatten(obj,prefix=''):
  require(type(obj)is dict,'LITERAL_THS_JSON_REQUIRED')
  for key,value in obj.items():
   full=prefix+'.'+key if prefix else key
   if type(value)is dict:flatten(value,full)
   else:add(full,value)
 for line in raw.decode().splitlines():
  if not line.strip()or line.lstrip().startswith('#'):continue
  require('\t'not in line,'THS_CONFIG_INDENTATION_UNPROVEN')
  indent=len(line)-len(line.lstrip());text=line.strip()
  if text.startswith('- '):add('.'.join(k for _,k in stack),text[2:]);continue
  match=re.fullmatch(r'([A-Za-z0-9_.-]+):(?:\s+(.*))?',text)
  if not match:continue
  while stack and stack[-1][0]>=indent:stack.pop()
  key='.'.join([k for _,k in stack]+[match[1]])
  if match[2]is None:stack.append((indent,match[1]))
  else:add(key,match[2])
 for key,value in env.items():add(key,value)
 if env.get('SPRING_APPLICATION_JSON'):flatten(json.loads(env['SPRING_APPLICATION_JSON']))
 require(values.get(normal('ouf.authorization.ths.enabled'))=={'true'},'EXPLICIT_THS_AUTHENTICATION_ENABLED_REQUIRED')
 require({v.rstrip('/')for v in values.get(normal('ouf.resolution.ths.gateway-base-url'),set())}=={origin.rstrip('/')},'EXACT_RESOLUTION_GATEWAY_ORIGIN_REQUIRED')
 scope_values=values.get(normal('spring.security.oauth2.client.registration.ouf-ths.scope'),set())
 scopes={v.strip("[]\"'")for value in scope_values for v in re.split(r'[,\s]+',value)}
 require({'resolution.issue.read','resolution.match.approve'}<=scopes,'EXPLICIT_THS_RESOLUTION_SCOPES_REQUIRED')
 return {'fileBinding':binding,'runtimeConfigHash':digest(actual['Config']),'resolutionGatewayEqualsReviewedOrigin':True,'thsAuthenticationEnabled':True,'requiredScopesDeclared':True,'loadedSnapshotProven':False}

def compile_routes(before):
 require(type(before)is dict and 0<len(before)<=256 and not set(ROUTES)&set(before),'RESOLUTION_ROUTES_ALREADY_EXIST_RECONCILE')
 templates=('trusted-human-onboarding-review','ths-identity-preflight-read','ths-identity-preflight-create')
 require(all(k in before for k in templates),'EXISTING_APPROVED_OWNER_ROUTE_TEMPLATES_REQUIRED')
 page=copy.deepcopy(before[templates[0]]);read=copy.deepcopy(before[templates[1]]);confirm=copy.deepcopy(before[templates[2]])
 require(page.get('uri')=='/trusted-human/onboarding/*'and page.get('methods')==['GET','POST']and 'openid-connect'not in page['plugins']and page['plugins'].get('serverless-pre-function'),'EXISTING_AUTHENTICATED_BROWSER_SESSION_BOUNDARY_REQUIRED')
 for row,method in((read,'GET'),(confirm,'POST')):
  require(row.get('uri')=='/api/udp/v1/governance/identity/preflight'and row.get('methods')==[method]
   and row['plugins']['openid-connect'].get('bearer_only')is True
   and row['plugins']['openid-connect'].get('ssl_verify')is True
   and row['plugins']['openid-connect'].get('required_scopes')==['urban.identity.preflight']
   and row['plugins'].get('serverless-pre-function')and row['plugins'].get('serverless-post-function')
   and row['upstream'].get('retries')==0,'EXACT_EXISTING_UDP_HUMAN_OIDC_BOUNDARY_REQUIRED')
 for row,rid,path,cap in((read,ROUTES[0],PACKAGE,'resolution.issue.read'),(confirm,ROUTES[1],PACKAGE+'/confirm','resolution.match.approve')):
  row.update(id=rid,uri=path);row.pop('uris',None)
  row.setdefault('labels',{}).update({'ouf-capability':cap,'ouf-surface':'TRUSTED_HUMAN_RESOLUTION'})
  row['plugins']['openid-connect']['required_scopes']=[cap]
  require(set(row['plugins'].get('proxy-rewrite',{}))<= {'uri'},'UNREVIEWED_UDP_REWRITE_CHANNEL')
  if 'proxy-rewrite'in row['plugins']:row['plugins']['proxy-rewrite']['uri']=path
  require('vars'not in row and 'filter_func'not in row,'UNREVIEWED_TEMPLATE_PATH_CONDITION')
  if row.get('methods')==['POST']:row['plugins'].setdefault('request-validation',{})['body_schema']=copy.deepcopy(CONFIRM_SCHEMA)
  row['plugins']['client-control']={'max_body_size':1048576}
  row['upstream']['timeout']={'connect':3,'send':3,'read':20}
 page.update(id=ROUTES[2],uri=PAGE);page.pop('uris',None)
 require('proxy-rewrite'not in page['plugins']and 'vars'not in page,'BROWSER_PATH_PRESERVATION_REQUIRED')
 page.setdefault('labels',{}).update({'ouf-capability':'resolution.issue.read','ouf-surface':'TRUSTED_HUMAN_RESOLUTION'})
 page['plugins']['client-control']={'max_body_size':1048576};page['upstream']['timeout']={'connect':3,'send':3,'read':30}
 for row in(read,confirm,page):
  for existing in before.values():
   paths=[existing['uri']]if'uri'in existing else existing.get('uris',[])
   require(row['uri']not in paths,'RESOLUTION_PATH_ALREADY_BOUND_RECONCILE')
 return {row['id']:row for row in(read,confirm,page)}


UUID_PATTERN='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
CONFIRM_SCHEMA={'type':'object','additionalProperties':False,'required':['snapshotHash','choices'],
 'properties':{'snapshotHash':{'type':'string','pattern':'^sha256:[0-9a-f]{64}$'},'choices':{'type':'array','items':{
  'type':'object','additionalProperties':False,'required':['issueId','expectedVersion','action'],'properties':{
   'issueId':{'type':'string','pattern':UUID_PATTERN},'expectedVersion':{'type':'integer','minimum':0},
   'action':{'type':'string','enum':['APPROVE','CREATE_NEW','DISMISS']},
   'reason':{'type':['string','null'],'maxLength':1000},
   'targetUrbanObjectId':{'type':['string','null'],'pattern':UUID_PATTERN},
   'expectedReviewHash':{'type':['string','null'],'pattern':'^sha256:[0-9a-f]{64}$'}}}}}}

