"""Installation-specific issuer log read, no OAuth, exec, login or refresh."""
import hashlib,http.client,json,os,re,signal,socket,stat,struct,sys,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-mbbleugm')
PACKAGE='f4552fa8894c2050e67f025df9d6c14eb02b04a7c6d18d4a9019994d8bda1de9'
CLOSURE='6e2a0e4ec523c7de9c337ce71f18e3b1983205738a2aaccecf2c97319bb313ee'
SOURCE='f57728d2aa68dc9cf58b86a7f3fad04b45df82dc'
ARTIFACTS=('candidate-review.json','execution-plan.json','review.json','decision.json','human.json','authority.json','issuance.claim.json','recovery.json','update-result.json')
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  row=parent.lstat();require(stat.S_ISDIR(row.st_mode)and row.st_uid==0 and not row.st_mode&0o022,'PRIVATE_ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  row=os.fstat(fd);require(stat.S_ISREG(row.st_mode)and row.st_uid==row.st_gid==0
   and stat.S_IMODE(row.st_mode)==0o600 and row.st_nlink==1 and 0<row.st_size<=maximum,'PRIVATE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==row.st_size and pin(row)==pin(os.fstat(fd))==pin(path.lstat())
   and(expected is None or sha(raw)==expected),'PRIVATE_BYTES_CHANGED');return raw
 finally:os.close(fd)
def parsed(path,expected=None,maximum=8388608):return json.loads(read(path,expected,maximum))
SINCE=1792404450
UNTIL=1792404520
ERRORS={'invalid_token','invalid_grant','session_expired','user_disabled','user_not_found','client_disabled',
 'invalid_client','invalid_client_credentials','invalid_request','invalid_scope','not_allowed','expired_token',
 'token_expired','invalid_user_credentials','session_not_active','stale_token','consent_denied'}
REASONS={'session not active':'SESSION_NOT_ACTIVE','session expired':'SESSION_EXPIRED',
 'token is not active':'TOKEN_NOT_ACTIVE','token is not active anymore':'TOKEN_NO_LONGER_ACTIVE',
 'invalid refresh token':'INVALID_REFRESH_TOKEN','stale token':'STALE_TOKEN','user disabled':'USER_DISABLED',
 'client disabled':'CLIENT_DISABLED','session idle timeout':'SESSION_IDLE_TIMEOUT',
 'maximum allowed refresh token reuse exceeded':'REFRESH_TOKEN_REUSE_EXCEEDED'}
def unframe(raw,tty):
 if tty:return raw
 result=bytearray();offset=0
 while offset<len(raw):
  require(offset+8<=len(raw),'COMPLETE_DOCKER_LOG_HEADER_REQUIRED')
  header=raw[offset:offset+8];size=struct.unpack('>I',header[4:])[0]
  require(header[0]in(1,2)and header[1:4]==b'\x00\x00\x00'and size<=1048576 and offset+8+size<=len(raw),'BOUNDED_COMPLETE_DOCKER_LOG_FRAME_REQUIRED')
  result.extend(raw[offset+8:offset+8+size]);offset+=8+size
 return bytes(result)
def projection(raw,selection):
 require(len(raw)<=4194304,'BOUNDED_ISSUER_LOG_REQUIRED')
 rows=[];unattributed=0;relevant=0
 for line in raw.decode('utf-8',errors='replace').splitlines():
  if 'REFRESH_TOKEN_ERROR'not in line:continue
  fields=dict(re.findall(r'([A-Za-z_][A-Za-z0-9_]*)="([^"\r\n]{0,512})"',line))
  if fields.get('type')!='REFRESH_TOKEN_ERROR'or fields.get('clientId')!='ouf-human-admin':continue
  if fields.get('realmName')not in(None,selection['realm']):continue
  relevant+=1
  if fields.get('userId')!=selection['subject']:unattributed+=1;continue
  error=fields.get('error','');reason=fields.get('reason',fields.get('error_description','')).lower()
  row={'event':'REFRESH_TOKEN_ERROR','errorCode':error if error in ERRORS else'OTHER_REDACTED',
   'reasonCode':REASONS.get(reason,'NO_KNOWN_SAFE_REASON'),'subjectMatched':True,'clientMatched':True}
  if row not in rows:rows.append(row)
  require(len(rows)<=16,'BOUNDED_ISSUER_ERROR_CLASSES_REQUIRED')
 return {'matchedErrorClasses':rows,'matchedErrorClassCount':len(rows),'clientErrorCountInWindow':relevant,
  'clientErrorsWithoutExactSubject':unattributed,'matchingIssuerEventProven':bool(rows),'specificIssuerReasonProven':any(r['reasonCode']!='NO_KNOWN_SAFE_REASON'for r in rows),
  'rawLogLinesPrinted':0,'rawIdentifiersPrinted':0,'credentialValuesPrinted':False}
class Reader:
 def __init__(self,binding,container):
  self.path=Path(binding['socketPath']);self.binding=tuple(binding['socketBinding']);self.calls=0
  self.allowed={'/v1.44/containers/'+container+'/json',
   '/v1.44/containers/'+container+'/logs?stdout=1&stderr=1&follow=0&timestamps=1&tail=2000&since='+str(SINCE)+'&until='+str(UNTIL)}
 def check(self):
  require(self.path.is_absolute()and self.path.resolve()==self.path,'EXACT_ENGINE_SOCKET_PATH_REQUIRED')
  row=self.path.lstat();require(stat.S_ISSOCK(row.st_mode)and row.st_uid==0
   and stat.S_IMODE(row.st_mode)in(0o600,0o660)
   and(row.st_dev,row.st_ino,row.st_uid,row.st_gid,stat.S_IMODE(row.st_mode))==self.binding,'EXACT_RETAINED_ENGINE_SOCKET_REQUIRED')
 def get(self,path):
  require(path in self.allowed and self.calls<3,'EXACT_THREE_READ_ONLY_ENGINE_REQUESTS_REQUIRED')
  self.check();engine_path=str(self.path)
  class Connection(http.client.HTTPConnection):
   def connect(self):
    self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect(engine_path)
  connection=Connection('retained-engine',timeout=10)
  try:
   self.calls+=1;connection.request('GET',path);reply=connection.getresponse();raw=reply.read(4194305)
   require(reply.status==200 and len(raw)<=4194304,'BOUNDED_SUCCESSFUL_ENGINE_READ_REQUIRED');self.check();return raw
  finally:connection.close()
def generation(raw,container):
 value=json.loads(raw);state=value['State']
 require(value['Id']==container and state['Running']is True and state['Pid']>0
  and not state['Paused']and not state['Restarting'],'EXACT_RUNNING_ISSUER_REQUIRED')
 return {'containerId':container,'imageId':value['Image'],'pid':state['Pid'],'startedAt':state['StartedAt'],
  'tty':value['Config']['Tty']}
def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('ISSUER_READ_DEADLINE')));signal.alarm(60)
 package=parsed(CONTEXT/'package.json',PACKAGE)
 require(package['sourceCommit']==SOURCE and digest(package['closure'])==CLOSURE,'EXACT_STOPPED_PACKAGE_REQUIRED')
 case=parsed(CONTEXT/'case.json',package['fileHashes']['case.json'])
 require(not any(os.path.lexists(CONTEXT/n)for n in ARTIFACTS),'NO_LATER_AUTHORITY_OR_EFFECTS_REQUIRED')
 binding=case['originalBinding'];original=parsed(binding['path'],binding['sha256'])
 selection=original['authorization']['plan']['selection'];container=selection['keycloakContainer']
 require(re.fullmatch('[0-9a-f]{64}',container)and selection['subject']==case['humanBinding']['subject']
  and selection['tenant']==case['humanBinding']['tenant'],'EXACT_RETAINED_ISSUER_SELECTION_REQUIRED')
 reader=Reader(original['engine'],container);path='/v1.44/containers/'+container
 before=generation(reader.get(path+'/json'),container)
 logpath=next(p for p in reader.allowed if '/logs?'in p)
 result=projection(unframe(reader.get(logpath),before['tty']),selection)
 require(generation(reader.get(path+'/json'),container)==before,'ISSUER_GENERATION_CHANGED_DURING_READ')
 signal.alarm(0)
 return {'schema':'ouf.mcp-human-issuer-stop-read.v1','complete':True,'readOnly':True,
  'issuerGenerationVerified':True,'windowSince':SINCE,'windowUntil':UNTIL,'engineGetRequests':reader.calls,
  'issuerEvidence':result,'oauthRequests':0,'iamAdminRequests':0,'processDispatches':0,'credentialFilesOpened':0,
  'humanCredentialJournalsRead':0,'journalWrites':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,
  'budgetReset':False,'newHumanLoginAllowed':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 try:result=main()
 except(Exception,KeyboardInterrupt)as error:
  result={'schema':'ouf.mcp-human-issuer-stop-read.v1','complete':False,'exceptionClass':type(error).__name__,
   'reason':'PRIVATE_DETAILS_REDACTED','automaticReplayAllowed':False,'budgetReset':False}
 print(encoded(result).decode(),flush=True);raise SystemExit(0 if result['complete']else 2)
