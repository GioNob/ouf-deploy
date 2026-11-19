"""One local private G0 draft. No Engine, S3, SQL, grants or runtime admission.

Historical IDs are expected candidates, never current Docker attestations.
Only five pinned process generations and four process environments are read.
"""
import hashlib,json,os,re,stat,sys,time
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlsplit,parse_qsl
from tools.m2_discovery_installation_profile.custody_capture import decode,digest,encoded,process_pin,require,Stop,attrs
from tools.storage_migration.minio_input_observation import InputBinding

STAGING=Path('/var/lib/ouf-g0-network-preparation-20261106')
DRAFT='binding-draft-20261106'
ROLES_READ=('minio','postgres','onboarding','udp','ingestion')
DB_PREFIX={'onboarding':'OUF_ONB','udp':'OUF_UDP','ingestion':'OUF_ING'}
def sha(b):return hashlib.sha256(b).hexdigest()
def protected(p):
 for x in (p,*p.parents):
  st=x.lstat();require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,'INPUTS_PROTECTED_ROOT_ANCESTRY')
def read_private(p,limit):
 protected(p.parent);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and 0<st.st_size<=limit,'INPUTS_PRIVATE_BOUNDED_FILE')
  b=os.read(fd,limit+1);require(len(b)==st.st_size and attrs(st)==attrs(os.fstat(fd))==attrs(p.lstat()),'INPUTS_FILE_CHANGED');return b
 finally:os.close(fd)
def put(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def environment(raw):
 require(0<len(raw)<=131072 and raw.endswith(b'\0'),'INPUTS_BOUNDED_PROCESS_ENVIRONMENT');d={}
 for entry in raw[:-1].split(b'\0'):
  require(b'=' in entry,'INPUTS_TYPED_ENVIRONMENT');k,v=entry.split(b'=',1);k=k.decode();require(k not in d,'INPUTS_DUPLICATE_ENVIRONMENT');d[k]=v.decode()
 return d
def live_environment(pid):
 fd=os.open('/proc/'+str(pid)+'/environ',os.O_RDONLY|os.O_NOFOLLOW)
 try:return environment(os.read(fd,131073))
 finally:os.close(fd)
def bindings(seed,profile):
 require(digest(seed)==profile['seedCanonicalSha256'],'INPUTS_EXACT_HISTORICAL_SEED')
 require(seed.get('schema')=='ouf.m2-discovery-current-private-bindings.v1' and all(seed.get(k) is False for k in ('historicalAuthorityReused','runtimeAuthorityIssued','automaticReplayAllowed','budgetReset')),'INPUTS_UNADMITTED_SEED')
 observations=seed['observations'];pins=seed['processPins'];roster=profile['roster'];require(len(observations)==len(roster)==13 and set(observations)==set(pins),'INPUTS_THIRTEEN_ROLE_DOMAIN');index={v['Id']:k for k,v in observations.items()};require(len(index)==13,'INPUTS_UNIQUE_CONTAINER_IDS');selected={}
 for role,row in roster.items():
  alias=index.get(row['containerId']);require(alias is not None,'INPUTS_HISTORICAL_ROLE_MISSING');doc=observations[alias];pin=pins[alias];require(pin==row['generation'] and doc['State']['Pid']==pin['pid'] and re.fullmatch('sha256:[a-f0-9]{64}',doc['Image']),'INPUTS_EXACT_HISTORICAL_ROLE_PIN');selected[role]={'doc':doc,'pin':pin}
 return selected

def postgres_aliases(doc):
 values={doc.get('Name','').lstrip('/'),doc.get('Config',{}).get('Hostname','')}
 for n in (doc.get('NetworkSettings',{}).get('Networks') or {}).values():
  values.update(n.get('Aliases') or []);values.update(n.get('DNSNames') or [])
 return {v for v in values if isinstance(v,str) and re.fullmatch('[A-Za-z0-9_.-]+',v)}
def db_connection(role,env,aliases,operation,installation,password_path):
 prefix=DB_PREFIX[role];keys=[prefix+'_DB_URL',prefix+'_DB_USER',prefix+'_DB_PASSWORD'];require(all(env.get(k) for k in keys),'INPUTS_'+role.upper()+'_DB_ENV_REQUIRED')
 require(not any(k.startswith('SPRING_DATASOURCE_') or k in ('SPRING_APPLICATION_JSON','SPRING_CONFIG_LOCATION','SPRING_CONFIG_ADDITIONAL_LOCATION') for k in env) and not any('datasource' in env.get(k,'').lower() for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS')),'INPUTS_DATASOURCE_OVERRIDE_REQUIRES_REVIEW')
 url,user,password=(env[k] for k in keys);require(url.startswith('jdbc:postgresql://'),'INPUTS_EXPLICIT_JDBC_URL');u=urlsplit(url[5:]);require(u.scheme=='postgresql' and u.hostname in aliases and not u.username and not u.password and not u.fragment and (u.port or 5432)==5432,'INPUTS_POSTGRES_HOST_BINDING')
 pairs=parse_qsl(u.query,keep_blank_values=True,strict_parsing=True);require(len({k for k,v in pairs})==len(pairs) and all(k=='currentSchema' and re.fullmatch('[A-Za-z0-9_,]+',v) for k,v in pairs),'INPUTS_JDBC_OPTIONS_REQUIRE_REVIEW')
 database=u.path.removeprefix('/');require(re.fullmatch('[A-Za-z0-9_-]{1,128}',database) and re.fullmatch('[A-Za-z0-9_-]{1,128}',user),'INPUTS_DB_IDENTIFIERS')
 require(0<len(password.encode())<=3000 and not any(c in password for c in ('\0','\r','\n')),'INPUTS_BOUNDED_DATABASE_PASSWORD')
 escaped=password.replace('\\','\\\\').replace(':','\\:');passfile=('127.0.0.1:5432:'+database+':'+user+':'+escaped+'\n').encode()
 config={'schema':'ouf.storage-g0-db-input.v1','operationId':operation+'-'+role,'installationRef':installation,'profile':'onboarding-retained' if role=='onboarding' else role,'host':'127.0.0.1','hostaddr':'127.0.0.1','port':5432,'database':database,'user':user,'passwordFile':str(password_path),'sslmode':'disable','rootCertificateFile':''}
 return config,passfile

def owner_buckets(envs):
 onb=envs['onboarding'].get('OUF_ONBOARDING_STAGING_BUCKET');udp={envs['udp'][k] for k in ('OUF_UDP_S3_BUCKET','OUF_UDP_LAKE_S3_BUCKET') if envs['udp'].get(k)}
 require(onb and len(udp)==1,'INPUTS_OWNER_BUCKET_SELECTION_REQUIRED');mapping={'onboarding':onb,'udp':next(iter(udp))};require(all(re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',v) for v in mapping.values()),'INPUTS_OWNER_BUCKET_NAMES');return mapping

def prepare(staging,profile,*,env_reader=live_environment,pin_reader=process_pin,boot_reader=lambda:Path('/proc/sys/kernel/random/boot_id').read_text().strip(),minio_factory=InputBinding):
 require(os.geteuid()==os.getegid()==0,'INPUTS_ROOT_ONLY');protected(staging);root=staging/'inputs'/DRAFT
 # Repeating this local entry only reads its prior result, never credentials again.
 if root.exists():
  require((root/'result.json').is_file(),'INPUTS_PARTIAL_DRAFT_REVIEW_REQUIRED');r=decode(read_private(root/'result.json',65536));r['existingResultReadOnly']=True;return r
 prep=decode(read_private(staging/'preparation.json',16384));require(prep['manifestSha256']==profile['packageManifestSha256'] and prep['historyMatchesPreviousPreparation'] is True,'INPUTS_EXACT_STAGED_PACKAGE')
 manifest=(staging/'package/package-manifest.json').read_bytes();require(sha(manifest)==profile['packageManifestSha256'],'INPUTS_PACKAGE_MANIFEST');m=decode(manifest)
 for p,h in m['files'].items():
  rel=Path(p);require(not rel.is_absolute() and '..' not in rel.parts,'INPUTS_PACKAGE_MEMBER');f=staging/'package'/rel;protected(f.parent);require(not f.is_symlink() and f.is_file() and sha(f.read_bytes())==h,'INPUTS_STAGED_PACKAGE_CHANGED')
 original=read_private(staging/'inputs/package-input.json',65536);c=decode(original);require(c['schema']=='ouf.storage-g0-package-input.v2' and c['operationId'] is None and c['installationRef'] is None and c['collectionDecisionRef'] is None and all(v=={'containerId':None,'nativeImage':None} for v in c['roles'].values()),'INPUTS_UNTOUCHED_STAGING_DRAFT')
 require(len(c['priorReceiptFiles'])==17 and {v['control'] for v in c['priorReceiptFiles']}==set(range(1,18)),'INPUTS_HISTORY_DOMAIN')
 def history():
  for row in c['priorReceiptFiles']:require(sha(read_private(Path(row['path']),2<<20))==row['sha256'],'INPUTS_HISTORY_CHANGED')
 history();root.mkdir(mode=0o700);put(root/'preparation.claim.json',encoded({'schema':'ouf.storage-g0-input-draft-claim.v1','maximumAttempts':1,'maximumSeconds':30,'originalDraftSha256':sha(original),'providerRequests':0,'runtimeAuthorityIssued':False}));until=time.monotonic()+30
 report={'schema':'ouf.storage-g0-input-draft-result.v1','status':'HELD','historicalRolesPrepared':0,'processGenerationsChecked':0,'connectionDraftsPrepared':[],'processEnvironmentsRead':0,'credentialFilesRead':0,'credentialSourceBytesRead':0,'credentialFileWritesAttempted':0,'credentialFilesWritten':0,'credentialsMayBePresentInDraft':False,'missingInputs':[],'providerRequests':0,'collectionScopeCreated':False,'runtimeAuthorityIssued':False,'targetInputCheckPassed':False,'g0Complete':False,'acceptanceCreditAdded':0,'automaticReplayAllowed':False}
 def secret_file(name,value):
  report['credentialFileWritesAttempted']+=1;report['credentialsMayBePresentInDraft']=True;put(root/name,value);report['credentialFilesWritten']+=1
 try:
  seed_raw=read_private(Path(profile['seedPath']),2<<20);seed=decode(seed_raw);selected=bindings(seed,profile)
  def guard():
   require(time.monotonic()<until,'INPUTS_PREPARATION_DEADLINE');require(boot_reader()==seed['bootId'],'INPUTS_BOOT_CHANGED')
   for role in ROLES_READ:require(pin_reader(selected[role]['pin']['pid'])==selected[role]['pin'],'INPUTS_'+role.upper()+'_PROCESS_CHANGED')
  guard();report['processGenerationsChecked']=5;operation=profile['operationId'];installation=profile['installationRef'];c.update(operationId=operation,installationRef=installation);c['roles']={r:{'containerId':v['doc']['Id'],'nativeImage':v['doc']['Image']} for r,v in selected.items()};report['historicalRolesPrepared']=13
  network={'schema':'ouf.storage-g0-network-binding.v1','operationId':operation,'installationRef':installation,'bootId':seed['bootId'],'targets':{r:{**c['roles'][r],'process':selected[r]['pin']} for r in ('minio','postgres')}};put(root/'network.review.json',encoded(network));c['networkBindingFile']=str(root/'network.review.json')
  envs={}
  for role in ('minio','onboarding','udp','ingestion'):
   guard();report['processEnvironmentsRead']+=1;envs[role]=env_reader(selected[role]['pin']['pid']);guard()
  aliases=postgres_aliases(selected['postgres']['doc']);require(bool(aliases),'INPUTS_POSTGRES_ALIASES_REQUIRED')
  for role in ('onboarding','udp','ingestion'):
   try:
    config,password=db_connection(role,envs[role],aliases,operation,installation,root/(role+'.pass'));guard();secret_file(role+'.pass',password);put(root/(role+'.json'),encoded(config));c['connectionFiles'][role]=str(root/(role+'.json'));report['connectionDraftsPrepared'].append(role)
   except Stop as e:report['missingInputs'].append(str(e))
  guard();binding=None
  try:
   binding=minio_factory(selected['minio']['pin']['pid']);binding.preflight(envs['minio']);require(not binding.policy_blocked,'INPUTS_MINIO_DECLARED_INPUT_REVIEW');values,sources=binding.resolve(envs['minio']);guard();binding.stable()
   secret_file('s3-access',values[0]);secret_file('s3-secret',values[1]);conf={'schema':'ouf.storage-g0-collection-input.v1','operationId':operation+'-s3','installationRef':installation,'connection':{'endpoint':'http://127.0.0.1:9000','region':binding.region,'accessKeyFile':str(root/'s3-access'),'secretKeyFile':str(root/'s3-secret'),'allowLoopbackHttp':True}};put(root/'s3.json',encoded(conf));c['connectionFiles']['s3']=str(root/'s3.json');report['connectionDraftsPrepared'].append('s3')
  except Stop as e:report['missingInputs'].append('INPUTS_MINIO_'+str(e))
  finally:
   if binding is not None:report['credentialFilesRead']=binding.opened;report['credentialSourceBytesRead']=binding.bytes;binding.close()
  try:
   buckets=owner_buckets(envs);runtime={'schema':'ouf.storage-g0-operator-evidence.v1','installationRef':installation,'section':'RUNTIME','provenance':'TECHNICAL_OBSERVATION','ownerRef':'LOCAL_PINNED_PROCESS_ENVIRONMENT','capturedAt':datetime.now(timezone.utc).isoformat(),'evidenceRefs':['LOCAL_PROCESS_PINS_AND_ENVIRONMENT_NOT_DOCKER_CONFIG_ATTESTATION'],'storageBuckets':buckets};put(root/'runtime.review.json',encoded(runtime));c['operatorEvidenceFiles']['runtime']=str(root/'runtime.review.json')
  except Stop as e:report['missingInputs'].append(str(e))
  mounts=[x for x in selected['minio']['doc'].get('Mounts',[]) if x.get('Destination')=='/data'];require(len(mounts)==1 and isinstance(mounts[0].get('Source'),str) and Path(mounts[0]['Source']).is_absolute(),'INPUTS_MINIO_DATA_MOUNT_CANDIDATE');c['capacityPaths']={'source':mounts[0]['Source'],**profile['proposedPaths']}
  report['missingInputs']+=['CURRENT_DOCKER_ROLE_IMAGE_AND_MOUNT_REVIEW','EFFECTIVE_APPLICATION_CONFIGURATION_REVIEW','ONBOARDING_RETAINED_PROFILE_REVIEW','SOURCE_AND_PROPOSED_CAPACITY_PATH_CUSTODY_REVIEW','OPERATOR_ACCESS_WRITERS_CAPACITY_CUSTODY_WINDOW','SEPARATE_COLLECTION_DECISION']
  guard();history();require(read_private(staging/'inputs/package-input.json',65536)==original and read_private(Path(profile['seedPath']),2<<20)==seed_raw,'INPUTS_ORIGINAL_CHANGED')
  put(root/'package-input.review.json',encoded(c));put(root/'provenance.private.json',encoded({'historicalSeedCanonicalSha256':profile['seedCanonicalSha256'],'originalDraftSha256':sha(original),'historicalRoleBindingsOnly':True,'currentDockerConfigurationObserved':False,'processPinRoles':list(ROLES_READ),'installationRefKind':profile['installationRefKind'],'onboardingProfile':'RETAINED_CANDIDATE_SQL_WILL_DENY_IF_INCOMPATIBLE_NO_FALLBACK','capacityPathsAreCandidates':True,'dataOrBackupDirectoriesCreated':False,'independentBackupVerified':False,'runtimeAuthorityIssued':False}));report['status']='PRIVATE_INPUT_DRAFT_PREPARED_REVIEW_REQUIRED';report['networkBindingDraftPresent']=True;report['originalPreparationPreserved']=True
 except Exception as e:
  reason=str(e);report['reason']=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,180}',reason) else 'INPUTS_LOCAL_PREPARATION_UNPROVEN'
 put(root/'result.json',encoded(report));return report

def main(bundle):
 try:
  require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'INPUTS_ROOT_ISOLATED_ENTRY');os.umask(0o077)
  profile=decode((bundle/'releases/storage-g0-input-preparation-profile-20261106.json').read_bytes())
  report=prepare(STAGING,profile);print(json.dumps(report,sort_keys=True));return 0 if report['status']=='PRIVATE_INPUT_DRAFT_PREPARED_REVIEW_REQUIRED' else 1
 except Exception as e:
  reason=str(e);print(json.dumps({'status':'HELD','reason':reason if re.fullmatch('[A-Z][A-Z0-9_]{0,180}',reason) else 'INPUTS_ENTRY_UNPROVEN','providerRequests':0,'runtimeAuthorityIssued':False}));return 1
