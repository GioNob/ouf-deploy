"""Narrow namespace-bound IAM reader, never a generic HTTP/admin executor.

One separately consented administrative authentication; no refresh, CLI cache,
automatic login or IAM mutation. GET-only retry claims are monotonic and bounded.
"""
import base64,http.client,ipaddress,json,os,random,re,select,stat,subprocess,termios,time
from pathlib import Path
from tools.managed_csv_recovery.retained_inputs import Stop,require,decode,digest,encoded,Capture,stable_binding

CLIENT_FIELDS=('id','clientId','enabled','protocol','standardFlowEnabled','publicClient','consentRequired','fullScopeAllowed','directAccessGrantsEnabled','serviceAccountsEnabled')

class IamCapture(Capture):
    def put(self,name,value):
        if name=='claim.json':
            self.maximums['privateMetadataReads']=2
        # Current Engine documents are needed in memory, but must not copy the
        # IAM process environment (possibly bootstrap credentials) into a new
        # diagnostic journal. Keep only the exact complete binding digest.
        if re.fullmatch('engine-get-[0-9]+-response.json',name):
            value={'schema':'ouf.ths-iam-engine-observation.v1','rawEnvironmentPersisted':False,
                   'binding':stable_binding(value)}if 'Id'in value else{'schema':'ouf.ths-iam-engine-info.v1','serverVersion':value.get('ServerVersion')}
        return super().put(name,value)

CHILD=r'''import http.client,ipaddress,json,os,re,signal,sys,urllib.parse
signal.alarm(8)
def require(ok):
 if not ok:raise ValueError()
def unique(rows):
 value={}
 for k,v in rows:require(k not in value);value[k]=v
 return value
def client(value):
 require(type(value)is dict)
 return {k:value[k]for k in ('id','clientId','enabled','protocol','standardFlowEnabled','publicClient','consentRequired','fullScopeAllowed','directAccessGrantsEnabled','serviceAccountsEnabled')if k in value}
def scopes(value):
 require(type(value)is list and len(value)<=1024)
 result=[]
 for row in value:
  require(type(row)is dict and type(row.get('attributes',{}))is dict)
  result.append({**{k:row[k]for k in ('id','name','protocol')if k in row},'attributes':{k:v for k,v in row.get('attributes',{}).items()if k in ('include.in.token.scope','is.dynamic.scope','is.parameterized.scope')}})
 return result
def roles(value):
 require(type(value)is list and len(value)<=2048 and all(type(row)is dict for row in value))
 return [{k:row[k]for k in ('id','name')if k in row}for row in value]
try:
 raw=sys.stdin.buffer.read(32769);require(0<len(raw)<=32768)
 v=json.loads(raw,object_pairs_hook=unique);require(set(v)=={'host','port','adminRealm','clientId','expectedUser','targetRealm','targetClient','operation','credential','subject','clientUuid','scopeUuid'})
 require(ipaddress.ip_address(v['host']).is_loopback and type(v['port'])is int and 1<=v['port']<=65535)
 for k in ('adminRealm','clientId','expectedUser','targetRealm','targetClient'):require(type(v[k])is str and re.fullmatch('[A-Za-z0-9._-]{1,128}',v[k]))
 op=v['operation'];cred=v['credential'];require(type(cred)is str and 0<len(cred)<=16384 and not any(c in cred for c in '\r\n\x00'))
 headers={'Accept':'application/json','Connection':'close'};body=None;method='GET';base='/admin/realms/'+v['targetRealm']
 if op=='PASSWORD_GRANT':
  method='POST';path='/realms/'+v['adminRealm']+'/protocol/openid-connect/token';headers['Content-Type']='application/x-www-form-urlencoded'
  body=urllib.parse.urlencode({'client_id':v['clientId'],'grant_type':'password','username':v['expectedUser'],'password':cred,'scope':'openid'})
 elif op=='IDENTITY':
  require(re.fullmatch('[A-Za-z0-9_-]{1,128}',v['subject']));path='/admin/realms/'+v['adminRealm']+'/users/'+v['subject'];headers['Authorization']='Bearer '+cred
 elif op=='CLIENT_LIST':path=base+'/clients?'+urllib.parse.urlencode({'clientId':v['targetClient'],'exact':'true','first':0,'max':2});headers['Authorization']='Bearer '+cred
 elif op in ('CLIENT','DEFAULTS','OPTIONALS'):
  require(re.fullmatch('[A-Za-z0-9_-]{1,128}',v['clientUuid']));path=base+'/clients/'+v['clientUuid']+{'CLIENT':'','DEFAULTS':'/default-client-scopes','OPTIONALS':'/optional-client-scopes'}[op];headers['Authorization']='Bearer '+cred
 elif op=='DEFINITIONS':path=base+'/client-scopes';headers['Authorization']='Bearer '+cred
 elif op=='SCOPE_ROLES':
  require(re.fullmatch('[A-Za-z0-9_-]{1,128}',v['scopeUuid']));path=base+'/client-scopes/'+v['scopeUuid']+'/scope-mappings';headers['Authorization']='Bearer '+cred
 else:raise ValueError()
 fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
 c=http.client.HTTPConnection(v['host'],v['port'],timeout=6)
 try:
  c.request(method,path,body=body,headers=headers);r=c.getresponse();raw=r.read(1048577);require(len(raw)<=1048576)
  status=r.status;retry=r.getheader('Retry-After','');require(len(retry)<=128 and all(32<=ord(x)<127 for x in retry))
  value=None
  if status==200:
   data=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(ValueError()))
   if op=='PASSWORD_GRANT':require(type(data)is dict);value={k:data[k]for k in ('access_token','id_token','token_type','expires_in')if k in data}
   elif op=='IDENTITY':require(type(data)is dict);value={k:data[k]for k in ('id','username','enabled')if k in data}
   elif op=='CLIENT_LIST':require(type(data)is list and len(data)<=2);value=[client(x)for x in data]
   elif op=='CLIENT':value=client(data)
   elif op in ('DEFAULTS','OPTIONALS','DEFINITIONS'):value=scopes(data)
   elif op=='SCOPE_ROLES':
    require(type(data)is dict and set(data)<={'realmMappings','clientMappings'});value={}
    if 'realmMappings'in data:value['realmMappings']=roles(data['realmMappings'])
    if 'clientMappings'in data:
     cm=data['clientMappings'];require(type(cm)is dict and len(cm)<=256);value['clientMappings']={}
     for key,row in cm.items():
      require(type(row)is dict);value['clientMappings'][key]={**{k:row[k]for k in ('id','client')if k in row},'mappings':roles(row.get('mappings',[]))}
  result={'status':status,'body':value,'retryAfter':retry,'bytes':len(raw)}
 except (OSError,TimeoutError,http.client.RemoteDisconnected):
  # Authentication dispatch is never replayed, including unknown completion.
  result={'status':0,'body':None,'retryAfter':'','bytes':0}
 finally:c.close()
 out=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode();require(len(out)<=1048576)
 sys.stdout.buffer.write(out);sys.stdout.buffer.flush()
except BaseException:os._exit(2)
os._exit(0)
'''

def executable(binding):
    path=Path(binding['path']);require(path.is_absolute()and path.resolve()==path,'EXACT_IAM_PROGRAM_PATH_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_IAM_PROGRAM_ANCESTRY_REQUIRED')
    s=path.lstat();require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and s.st_mode&0o111 and not s.st_mode&0o022
            and 0<s.st_size<=64000000 and __import__('hashlib').sha256(path.read_bytes()).hexdigest()==binding['sha256'],'EXACT_IAM_PROGRAM_BYTES_REQUIRED')
    return str(path)

def dispatch(program,namespace,payload):
    try:
        result=subprocess.run([executable(program),'-I','-S','-B','-c',CHILD,str(namespace)],input=encoded(payload),
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,pass_fds=(namespace,),env={'LC_ALL':'C','PATH':'/usr/bin:/bin'})
    except subprocess.TimeoutExpired:
        return {'status':0,'body':None,'retryAfter':'','bytes':0}
    require(result.returncode==0 and 0<len(result.stdout)<=1048576,'IAM_READ_CHILD_OUTCOME_UNPROVEN_NO_REPLAY')
    value=decode(result.stdout)
    require(type(value)is dict and set(value)=={'status','body','retryAfter','bytes'}and type(value['status'])is int
            and type(value['bytes'])is int and 0<=value['bytes']<=1048576,'CLOSED_IAM_READ_RESPONSE_REQUIRED')
    return value

class ReadLedger:
    def __init__(self,capture,*,clock=time.time,sleep=time.sleep):
        self.c,self.clock,self.sleep=capture,clock,sleep;self.serial=0;self.authenticated=False;self.identityVerified=False;self.deadline=None
        require(not any(k in self.c.counts for k in ('oauthRequestsReserved','adminGetsReserved','adminGetRetryReservations')),'IAM_LEDGER_ALREADY_INITIALIZED_NO_COUNTER_RESET')
        self.c.counts.update(oauthRequestsReserved=0,adminGetsReserved=0,adminGetRetryReservations=0)
    def event(self,stage,**metadata):
        require(re.fullmatch('[a-z0-9-]{1,160}',stage),'CLOSED_IAM_STAGE_REQUIRED')
        self.serial+=1;self.c.put('iam-step-'+str(self.serial)+'.json',{'stage':stage,'counts':dict(self.c.counts),'at':self.clock(),**metadata})
    def request(self,stage,operation,payload,send,guard,*,expiry=None):
        require(operation in ('PASSWORD_GRANT','IDENTITY','CLIENT_LIST','CLIENT','DEFAULTS','OPTIONALS','DEFINITIONS','SCOPE_ROLES')and payload.get('operation')==operation,'EXACT_COUNTED_IAM_OPERATION_REQUIRED')
        for attempt in range(3):
            guard()
            require(self.deadline is not None and self.clock()<self.deadline,'FINITE_ORIGINAL_IAM_OPERATION_WINDOW_REQUIRED')
            if operation=='PASSWORD_GRANT':
                require(attempt==0 and self.c.counts['oauthRequestsReserved']==0,'ONE_EXPLICIT_ADMIN_AUTHENTICATION_NO_REPLAY')
                self.c.counts['oauthRequestsReserved']=1
            else:
                require(self.authenticated and self.c.counts['adminGetsReserved']<20 and expiry is not None and expiry>self.clock()+8,'CURRENT_ADMIN_IDENTITY_TOKEN_AND_READ_BUDGET_REQUIRED')
                require(operation=='IDENTITY'or self.identityVerified,'PROTECTED_EFFECTIVE_IAM_IDENTITY_REQUIRED_BEFORE_CLIENT_READ')
                self.c.counts['adminGetsReserved']+=1
                if attempt:
                    require(self.c.counts['adminGetRetryReservations']<4,'FINITE_IAM_RETRY_BUDGET_EXHAUSTED');self.c.counts['adminGetRetryReservations']+=1
            self.event(stage,operation=operation,attempt=attempt+1,dispatchReserved=True)
            value=send(payload);self.c.counts['bytes']+=value['bytes'];require(self.c.counts['bytes']<=25165824,'FINITE_IAM_BYTE_BUDGET_REQUIRED')
            self.event(stage,operation=operation,status=value['status'],responseReceived=True)
            guard()
            if value['status']==200:return value['body']
            require(operation!='PASSWORD_GRANT','ADMIN_AUTHENTICATION_OUTCOME_STOP_NO_RETRY')
            require(value['status']in(0,429,502,503,504)and attempt<2,'IAM_DENIED_OR_UNKNOWN_RESPONSE_NO_RETRY')
            # Explicit transient GET only. Preserve the same stage/session and
            # finite token/deadline, never refresh or reserve another login.
            delay=(5,15)[attempt]*random.SystemRandom().uniform(.8,1.2)
            header=value['retryAfter']
            if header:
                if header.isdigit():retry=float(header)
                else:
                    from email.utils import parsedate_to_datetime
                    try:retry=parsedate_to_datetime(header).timestamp()-self.clock()
                    except (ValueError,TypeError,OverflowError):raise Stop('INVALID_RETRY_AFTER_STOP')from None
                delay=max(delay,max(0,retry))
            require(delay<=20 and self.clock()+delay+8<expiry,'IAM_TRANSIENT_WAIT_EXCEEDS_ORIGINAL_TOKEN_WINDOW')
            until=self.clock()+delay;self.event(stage,transient=True,nextAttemptAt=until)
            while self.clock()<until:guard();self.sleep(min(1,until-self.clock()))
        raise Stop('FINITE_IAM_STAGE_EXHAUSTED')


def terminal(summary, phrase=None):
    """Controlling tty only; password echo restored even on timeout/interrupt."""
    fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_NOFOLLOW)
    old = None
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode) and os.isatty(fd), 'CONTROLLING_ADMIN_TERMINAL_REQUIRED')
        termios.tcflush(fd, termios.TCIFLUSH)
        if phrase is None:
            old = termios.tcgetattr(fd)
            hidden = termios.tcgetattr(fd)
            hidden[3] &= ~(termios.ECHO | termios.ECHONL)
            termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
            os.write(fd, ('\n' + summary + '\n> ').encode())
        else:
            os.write(fd, ('\n' + summary + '\nScrivi esattamente: ' + phrase + '\n> ').encode())
        require(bool(select.select([fd], [], [], 90)[0]), 'ADMIN_TERMINAL_INPUT_TIMEOUT_NO_REPLAY')
        raw = os.read(fd, 4097)
        require(0 < len(raw) <= 4096 and raw.endswith(b'\n') and b'\x00' not in raw,
            'BOUNDED_ADMIN_TERMINAL_LINE_REQUIRED')
        value = raw[:-1].decode('utf-8')
        if phrase is not None:
            require(value == phrase, 'EXACT_ADMIN_API_TERMINAL_CONSENT_REQUIRED')
            return True
        require(value and not any(c in value for c in '\r\n'), 'NONEMPTY_SINGLE_ADMIN_PASSWORD_REQUIRED')
        return value
    finally:
        if old is not None:
            termios.tcsetattr(fd, termios.TCSANOW, old)
            os.write(fd, b'\n')
        os.close(fd)


def access(api, response, endpoint, issuer, requested_at):
    require(type(response) is dict and response.get('token_type', '').lower() == 'bearer'
        and type(response.get('expires_in')) is int and 0 < response['expires_in'] <= 3600,
        'EXACT_FRESH_ADMIN_TOKEN_RESPONSE_REQUIRED')
    token = response.get('access_token')
    require(type(token) is str and len(token) <= 16384 and len(token.split('.')) == 3,
        'BOUNDED_FRESH_ADMIN_ACCESS_TOKEN_REQUIRED')
    part = token.split('.')[1]
    require(re.fullmatch('[A-Za-z0-9_-]+', part) is not None, 'FRESH_ADMIN_JWT_PAYLOAD_REQUIRED')
    claims = api.decode(base64.b64decode(part + '=' * (-len(part) % 4), altchars=b'-_', validate=True))
    allowed = {issuer.rsplit('/realms/', 1)[0] + '/realms/' + endpoint['adminRealm'],
        endpoint['storedServerUrl'] + '/realms/' + endpoint['adminRealm']}
    require(type(claims) is dict and claims.get('iss') in allowed,
        'FRESH_ADMIN_ACCESS_ISSUER_MUST_MATCH_SELECTED_PROVIDER')
    require(claims.get('azp') == endpoint['adminClientId'], 'FRESH_ADMIN_ACCESS_CLIENT_MUST_MATCH')
    require(type(claims.get('exp')) is type(claims.get('iat')) is int
        and requested_at - 10 <= claims['iat'] <= time.time() + 5,
        'FRESH_ADMIN_ACCESS_TIMESTAMPS_REQUIRED')
    # A lightweight access token can omit BOTH preferred_username and sub.
    # Resolve the routing subject from the ID token returned in this same
    # fresh, directly received password-grant response (scope=openid). This is
    # provider-channel provenance, not independent JWT signature validation.
    # A protected Admin user lookup must then prove username/id/enabled state.
    id_token = response.get('id_token')
    require(type(id_token) is str and len(id_token) <= 16384 and len(id_token.split('.')) == 3,
        'FRESH_ADMIN_OIDC_ID_TOKEN_REQUIRED_FOR_SUBJECT')
    part = id_token.split('.')[1]
    require(re.fullmatch('[A-Za-z0-9_-]+', part) is not None, 'BOUNDED_ADMIN_ID_TOKEN_PAYLOAD_REQUIRED')
    identity = api.decode(base64.b64decode(part + '=' * (-len(part) % 4), altchars=b'-_', validate=True))
    require(type(identity) is dict and identity.get('iss') == claims['iss'], 'SAME_PROVIDER_ADMIN_ID_TOKEN_ISSUER_REQUIRED')
    audience = identity.get('aud')
    require(audience == endpoint['adminClientId'] or type(audience) is list
        and endpoint['adminClientId'] in audience and all(type(v) is str for v in audience),
        'ADMIN_ID_TOKEN_AUDIENCE_MUST_INCLUDE_SELECTED_CLIENT')
    require(identity.get('azp', endpoint['adminClientId']) == endpoint['adminClientId'],
        'ADMIN_ID_TOKEN_AUTHORIZED_PARTY_MUST_MATCH')
    require(type(identity.get('exp')) is type(identity.get('iat')) is int
        and requested_at - 10 <= identity['iat'] <= time.time() + 5 and identity['exp'] > time.time(),
        'FRESH_ADMIN_ID_TOKEN_TIMESTAMPS_REQUIRED')
    require(re.fullmatch('[A-Za-z0-9_-]{1,128}', identity.get('sub', '')),
        'BOUNDED_ADMIN_ID_TOKEN_SUBJECT_REQUIRED')
    require(claims.get('sub') is None or claims['sub'] == identity['sub'],
        'ADMIN_ACCESS_AND_ID_TOKEN_SUBJECTS_MUST_AGREE_WHEN_PRESENT')
    expiry = min(claims['exp'], requested_at + response['expires_in'])
    require(expiry > time.time() + 45, 'FRESH_ADMIN_TOKEN_TOO_SHORT_FOR_FOUR_BOUNDED_GETS')
    # This is routing metadata, never independent JWT signature verification.
    # The provider's protected user endpoint must establish subject identity.
    return token, expiry, identity['sub']
