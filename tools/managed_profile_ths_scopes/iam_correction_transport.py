"""Closed supplemental IAM routes; no arbitrary client update or URL channel."""
import subprocess
from tools.managed_csv_recovery.retained_inputs import require,encoded,decode
from tools.managed_profile_ths_scopes.iam_read import dispatch,executable

EXTRA_CHILD=r'''import hashlib,http.client,ipaddress,json,os,re,signal,sys
signal.alarm(8)
def require(ok):
 if not ok:raise ValueError()
def unique(rows):
 result={}
 for k,v in rows:require(k not in result);result[k]=v
 return result
def sha(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
required=('ouf.managed-source.preview','ouf.managed-source.file.profile','ouf.onboarding.quarantine.release')
marker='ouf.provisioning.operation-ref'
try:
 raw=sys.stdin.buffer.read(32769);require(0<len(raw)<=32768);v=json.loads(raw,object_pairs_hook=unique)
 require(set(v)=={'host','port','adminRealm','clientId','expectedUser','targetRealm','targetClient','operation','credential','subject','clientUuid','scopeUuid','scopeName','operationRef'})
 require(ipaddress.ip_address(v['host']).is_loopback and type(v['port'])is int and 1<=v['port']<=65535)
 require(re.fullmatch('[A-Za-z0-9_.-]{1,128}',v['targetRealm'])and re.fullmatch('[a-f0-9]{64}',v['operationRef']))
 require(type(v['credential'])is str and 0<len(v['credential'])<=16384 and not any(c.isspace()for c in v['credential']))
 base='/admin/realms/'+v['targetRealm'];op=v['operation'];method='GET';body=None
 headers={'Accept':'application/json','Connection':'close','Authorization':'Bearer '+v['credential']}
 if op in ('ASSIGN_OPTIONAL','CLIENT_INTEGRITY'):require(re.fullmatch('[A-Za-z0-9_-]{1,128}',v['clientUuid']))
 if op in ('CREATE_SCOPE','ASSIGN_OPTIONAL','SCOPE_DETAIL'):require(re.fullmatch('[A-Za-z0-9_-]{1,128}',v['scopeUuid']))
 if op=='CREATE_SCOPE':
  require(v['scopeName']==required[2]);method='POST';path=base+'/client-scopes';headers['Content-Type']='application/json'
  body=json.dumps({'id':v['scopeUuid'],'name':v['scopeName'],'protocol':'openid-connect','attributes':{'include.in.token.scope':'true',marker:v['operationRef']},'protocolMappers':[]},sort_keys=True,separators=(',',':')).encode()
 elif op=='ASSIGN_OPTIONAL':require(v['scopeName']in required);method='PUT';path=base+'/clients/'+v['clientUuid']+'/optional-client-scopes/'+v['scopeUuid']
 elif op=='SCOPE_DETAIL':path=base+'/client-scopes/'+v['scopeUuid']
 elif op=='CLIENT_INTEGRITY':path=base+'/clients/'+v['clientUuid']
 elif op=='DEFINITIONS_INTEGRITY':path=base+'/client-scopes'
 elif op=='REALM_DEFAULTS':path=base+'/default-default-client-scopes'
 elif op=='REALM_OPTIONALS':path=base+'/default-optional-client-scopes'
 else:raise ValueError()
 fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd);c=http.client.HTTPConnection(v['host'],v['port'],timeout=6)
 try:
  c.request(method,path,body=body,headers=headers);r=c.getresponse();raw=r.read(1048577);require(len(raw)<=1048576)
  status=r.status;location=r.getheader('Location','');retry=r.getheader('Retry-After','')
  require(len(location)<=2048 and len(retry)<=128 and all(32<=ord(x)<127 for x in location+retry));value=None
  if status==200 and method=='GET':
   data=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(ValueError()))
   if op=='CLIENT_INTEGRITY':
    require(type(data)is dict)
    selected={k:item for k,item in data.items()if k not in ('secret','registrationAccessToken','defaultClientScopes','optionalClientScopes')}
    value={'id':data.get('id'),'clientId':data.get('clientId'),'nonCredentialNonBindingMetadataHash':sha(selected)}
   elif op=='DEFINITIONS_INTEGRITY':
    require(type(data)is list and len(data)<=1024);value={}
    for row in data:
     require(type(row)is dict and type(row.get('id'))is str and row['id']not in value);value[row['id']]={'name':row.get('name'),'metadataHash':sha(row)}
   elif op=='SCOPE_DETAIL':
    require(type(data)is dict and type(data.get('attributes',{}))is dict);attrs=data.get('attributes',{});mappers=data.get('protocolMappers')or[];require(type(mappers)is list)
    value={**{k:data.get(k)for k in ('id','name','protocol')},'attributes':{k:item for k,item in attrs.items()if k in ('include.in.token.scope',marker)},
           'otherAttributeCount':len(set(attrs)-{'include.in.token.scope',marker}),'protocolMappers':[]if not mappers else[{'unreviewed':True}]}
   elif op in ('REALM_DEFAULTS','REALM_OPTIONALS'):
    require(type(data)is list and len(data)<=1024);value=[{k:row[k]for k in ('id','name','protocol')if k in row}for row in data]
  result={'status':status,'body':value,'retryAfter':retry,'bytes':len(raw),'location':location}
 except (OSError,TimeoutError,http.client.RemoteDisconnected):result={'status':0,'body':None,'retryAfter':'','bytes':0,'location':''}
 finally:c.close()
 out=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode();require(len(out)<=1048576);sys.stdout.buffer.write(out);sys.stdout.buffer.flush()
except BaseException:os._exit(2)
os._exit(0)
'''

BASE_OPERATIONS=('PASSWORD_GRANT','IDENTITY','CLIENT_LIST','CLIENT','DEFAULTS','OPTIONALS','DEFINITIONS','SCOPE_ROLES')

def dispatch_correction(program,namespace,payload):
    operation=payload.get('operation')
    if operation in BASE_OPERATIONS:
        body={k:v for k,v in payload.items()if k not in ('scopeName','operationRef')}
        result=dispatch(program,namespace,body);return {**result,'location':''}
    require(operation in ('CREATE_SCOPE','ASSIGN_OPTIONAL','SCOPE_DETAIL','CLIENT_INTEGRITY','DEFINITIONS_INTEGRITY','REALM_DEFAULTS','REALM_OPTIONALS'),'CLOSED_SUPPLEMENTAL_IAM_OPERATION_REQUIRED')
    try:
        child=subprocess.run([executable(program),'-I','-S','-B','-c',EXTRA_CHILD,str(namespace)],input=encoded(payload),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                             timeout=10,pass_fds=(namespace,),env={'LC_ALL':'C','PATH':'/usr/bin:/bin'})
    except subprocess.TimeoutExpired:return {'status':0,'body':None,'retryAfter':'','bytes':0,'location':''}
    if child.returncode!=0:
        require(operation in ('CREATE_SCOPE','ASSIGN_OPTIONAL'),'CORRECTION_READ_CHILD_OUTCOME_UNPROVEN')
        # The durable write claim already exists. Reconcile this exact fixed ID
        # using GET in the same session; never infer nondispatch or repeat it.
        return {'status':0,'body':None,'retryAfter':'','bytes':0,'location':''}
    require(0<len(child.stdout)<=1048576,'BOUNDED_CORRECTION_RESPONSE_REQUIRED')
    value=decode(child.stdout)
    require(type(value)is dict and set(value)=={'status','body','retryAfter','bytes','location'}and type(value['status'])is int
            and type(value['bytes'])is int and 0<=value['bytes']<=1048576,'CLOSED_CORRECTION_HTTP_RECEIPT_REQUIRED')
    return value
