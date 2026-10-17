"""Exact additive browser scope request and retained-image Onboarding replacement."""
import copy,json,re
from tools.chatbot_file_cohort.gateway import private_config
from tools.resolution_ths_update.plan import compile_routes,THS_CONFIG,ROUTES
from tools.resolution_ths_configuration.owner import require,digest
NORMAL=lambda key:re.sub('[^a-z0-9]','',key.lower())
ENABLED='ouf.authorization.ths.enabled'
SCOPES='spring.security.oauth2.client.registration.ouf-ths.scope'
GATEWAY='ouf.resolution.ths.gateway-base-url'
REQUIRED=('resolution.issue.read','resolution.match.approve')
def unique(pairs):
 result={}
 for key,value in pairs:require(key not in result,'DUPLICATE_SPRING_JSON_KEY');result[key]=value
 return result

def selected(obj):
 result={}
 def walk(value,path=()):
  require(type(value)is dict,'SPRING_JSON_OBJECT_REQUIRED')
  for key,item in value.items():
   require(type(key)is str,'STRING_SPRING_JSON_KEY_REQUIRED');parts=path+(key,)
   if type(item)is dict:walk(item,parts)
   else:
    canonical=NORMAL('.'.join(parts));require(canonical not in result,'AMBIGUOUS_SPRING_JSON_PROPERTY');result[canonical]=(parts,item)
 walk(obj);return result

def patch_environment(actual,origin,expected_sha):
 values=actual['Config'].get('Env');require(type(values)is list,'RETAINED_ENVIRONMENT_REQUIRED');env={}
 for row in values:
  key,value=row.split('=',1);require(key not in env,'DUPLICATE_ENVIRONMENT_KEY');env[key]=value
 require(not any(env.get(k)for k in('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS'))and not any(a.startswith(('-D','--'))for a in(actual['Config'].get('Entrypoint')or[])+(actual['Config'].get('Cmd')or[])),'UNREVIEWED_THS_ARGUMENT_OVERRIDE')
 mounts=[m for m in actual['Mounts']if m.get('Source')==THS_CONFIG]
 require(len(mounts)==1 and mounts[0]['Type']=='bind'and mounts[0]['RW']is False,'EXACT_THS_READ_ONLY_SELECTION_REQUIRED')
 selectors=[v for k,v in env.items()if NORMAL(k)in('springconfigimport','springconfiglocation','springconfigadditionallocation')]
 require(any(mounts[0]['Destination']in v for v in selectors),'MOUNTED_THS_CONFIG_NOT_SELECTED')
 _,binding=private_config(THS_CONFIG);require(binding['sha256']==expected_sha,'REVIEWED_THS_CONFIG_BYTES_CHANGED')
 require(0<len(env.get('SPRING_APPLICATION_JSON',''))<=1048576,'BOUNDED_EXISTING_SPRING_JSON_REQUIRED')
 original=json.loads(env['SPRING_APPLICATION_JSON'],object_pairs_hook=unique);properties=selected(original)
 path,scopes=properties[NORMAL(SCOPES)];require(type(scopes)is list and 0<len(scopes)<=128 and all(type(s)is str and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',s)for s in scopes)and len(scopes)==len(set(scopes)),'EXACT_EXISTING_SCOPE_LIST_REQUIRED')
 require(properties.get(NORMAL(GATEWAY),(None,None))[1]in(origin,origin.rstrip('/')+'/'),'EXACT_EXISTING_JSON_RESOLUTION_GATEWAY_REQUIRED')
 for key,value in env.items():
  if NORMAL(key)==NORMAL(GATEWAY):require(value.rstrip('/')==origin.rstrip('/'),'EXACT_ENVIRONMENT_RESOLUTION_GATEWAY_REQUIRED')
 changed=copy.deepcopy(original)
 def put(path,value):
  cursor=changed
  for key in path[:-1]:cursor=cursor[key]
  cursor[path[-1]]=value
 added=[s for s in REQUIRED if s not in scopes];require(added,'RESOLUTION_SCOPES_ALREADY_REQUESTED_RECONCILE')
 put(path,scopes+added)
 enabled_path=properties.get(NORMAL(ENABLED),((ENABLED,),None))[0];put(enabled_path,True)
 following=selected(changed);require(following[NORMAL(ENABLED)][1]is True and following[NORMAL(SCOPES)][1]==scopes+added,'EXACT_ADDITIVE_RESOLUTION_SCOPE_PATCH_REQUIRED')
 require({k:v for k,v in following.items()if k not in(NORMAL(ENABLED),NORMAL(SCOPES))}=={k:v for k,v in properties.items()if k not in(NORMAL(ENABLED),NORMAL(SCOPES))},'UNRELATED_SPRING_PROPERTY_CHANGED')
 encoded=json.dumps(changed,sort_keys=True,separators=(',',':'),allow_nan=False)
 new=[key+'='+encoded if key=='SPRING_APPLICATION_JSON'else row for row in values for key in[row.split('=',1)[0]]]
 require([r for r in new if not r.startswith('SPRING_APPLICATION_JSON=')]==[r for r in values if not r.startswith('SPRING_APPLICATION_JSON=')],'UNRELATED_ENVIRONMENT_CHANGED')
 return new,{'fileBinding':binding,'beforeSpringJsonHash':digest(original),'afterSpringJsonHash':digest(changed),'preservedScopeCount':len(scopes),'addedScopes':added,'thsEnabledExplicitly':True,'gatewayPreserved':True}

def replacement(previous,actual,environment,context_ref):
 old=previous['replacements']['onboarding'];request=copy.deepcopy(old['request'])
 for key in('User','Entrypoint','Cmd','WorkingDir','Env','Labels','Healthcheck','StopSignal','StopTimeout'):
  if key in actual['Config']:request[key]=copy.deepcopy(actual['Config'][key])
 request['Image']=actual['Image'];request['Env']=copy.deepcopy(environment);request['HostConfig']['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
 from tools.onboarding_audit_update.native import runtime
 row={'name':old['name'],'retiredName':old['name']+'-resolution-retired-'+context_ref[:12],'request':request,'oldRuntimeBinding':runtime(actual),'oldNativeHostConfig':copy.deepcopy(actual['HostConfig']),'oldMounts':copy.deepcopy(actual['Mounts']),'restoreRestartPolicy':copy.deepcopy(actual['HostConfig']['RestartPolicy']),'imageAudit':copy.deepcopy(old['imageAudit']),'network':copy.deepcopy(old['network']),'readiness':copy.deepcopy(old['readiness'])}
 return row
