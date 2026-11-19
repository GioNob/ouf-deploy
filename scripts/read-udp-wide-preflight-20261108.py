#!/usr/bin/env python3
"""Read current SeaweedFS UDP package, bindings, migration history and aggregate work.
No service mutation, migration, S3 request, token grant or business command.
"""
import copy,hashlib,importlib.util,io,json,os,re,shlex,signal,subprocess,sys,tempfile,zipfile
from pathlib import Path
from datetime import datetime,timezone
CID='ab0ce29e39cfd616e5eee4bff32c0babdd04a0efe5d918dcc85e9e363d488005'
IMAGE='sha256:ae78f604ef485dda3751222ce418e03027d2db87bc49d8cb1faf8de3e2b60b52'
SOURCE='c0cf1702b2eb971718996a959414caee004af494'
RESOURCE_SHA='01e35ca79b53ea15531f7ded57f76284f55353bb5f1e77625ac8790f57baa746'
TRUST_SHA='3c1a048732b8db22d785de8fd087459901ac6a79e16f3b904435c660b039c083'
JAR='/app/app.jar'
SELECTED=('PublishedIdentityPolicy.class','GovernedIdentityEngine.class','S3LakeConfiguration.class','S3LakeObjectStorageAdapter.class')
STATES={'handoff_intake':('DURABLE','PROCESSING','PROCESSED','FAILED'),
 'materialization_job':('READY','RUNNING','PAUSED','QUARANTINED','SUCCEEDED','FAILED'),
 'lake_object':('STAGED','DURABLE','VERIFIED','COMPACTED','COLD','QUARANTINED','DELETION_PENDING','DELETED','FAILED'),
 'lake_maintenance_schedule':('READY','RUNNING','PAUSED'),
 'lake_shadow_rebuild_plan':('DRAFT','BUILDING','READY','CUTOVER','FAILED')}
def need(ok,code):
 if not ok:raise RuntimeError(code)
def sha(b):return hashlib.sha256(b).hexdigest()
def helpers():
 f=Path(__file__).with_name('read-onboarding-wide-preflight-20261108.py');raw=f.read_bytes()
 need(sha(raw)=='fca0dccd2ed5e42904fa57a8c0d898eb537c233070653379971ef29d7b5498d6','PACKAGE_HELPER_CHANGED')
 spec=importlib.util.spec_from_file_location('udp_package_helper',f);p=importlib.util.module_from_spec(spec);exec(compile(raw,str(f),'exec'),p.__dict__)
 c,h=p.helpers();return p,c,h
def manifest():
 raw=Path(__file__).with_name('udp-wide-source-resources-20261108.json').read_bytes();need(sha(raw)==RESOURCE_SHA,'SOURCE_RESOURCE_RECORD_CHANGED');return json.loads(raw)
def query(p):
 parts=[]
 for table,states in STATES.items():
  allowed=','.join("'"+s+"'" for s in states)
  parts.append("'%s',(SELECT coalesce(json_object_agg(s,n),'{}'::json) FROM (SELECT CASE WHEN state IN (%s) THEN state ELSE 'OTHER' END s,count(*) n FROM ouf_udp.%s GROUP BY 1) x)"%(table,allowed,table))
 parts.append("'unexpiredLeases',json_build_object("+','.join("'%s',(SELECT count(*) FROM ouf_udp.%s WHERE lease_until>transaction_timestamp())"%(t,t) for t in ('materialization_job','lake_object','lake_maintenance_schedule','lake_shadow_rebuild_plan'))+")")
 parts.append("'maintenanceDue',(SELECT count(*) FROM ouf_udp.lake_maintenance_schedule WHERE state='READY' AND next_run_at<=transaction_timestamp())")
 return p.QUERY.replace('ouf_onboarding.','ouf_udp.').replace("'applicationRoleSuperuser'","'activity',json_build_object("+','.join(parts)+"),'applicationRoleSuperuser'")
def result(p,value,expected):
 value=p.database_result(value,expected);a=value.get('activity');need(isinstance(a,dict) and set(a)==set(STATES)|{'unexpiredLeases','maintenanceDue'},'ACTIVITY_SHAPE')
 for t,states in STATES.items():
  need(isinstance(a[t],dict) and set(a[t])<=set(states)|{'OTHER'} and all(type(x)is int and x>=0 for x in a[t].values()),'ACTIVITY_SHAPE')
 need(set(a['unexpiredLeases'])=={'materialization_job','lake_object','lake_maintenance_schedule','lake_shadow_rebuild_plan'} and all(type(x)is int and x>=0 for x in a['unexpiredLeases'].values()) and type(a['maintenanceDue'])is int and a['maintenanceDue']>=0,'LEASE_ACTIVITY_SHAPE')
 value['activityMeaning']='COUNTS_AT_READ_TIME_NOT_QUIESCENCE_OR_RESTART_AUTHORITY';return value
def db_binding(doc,pg,c,h):
 env=h.environment(doc);d=copy.deepcopy(doc);d['Config']['Env']=[x for x in doc['Config']['Env'] if not x.startswith(('OUF_SEM_DB_URL=','OUF_SEM_DB_USER='))]+['OUF_SEM_DB_URL='+env.get('OUF_UDP_DB_URL',''),'OUF_SEM_DB_USER='+env.get('OUF_UDP_DB_USER','')]
 return c.db_binding(d,pg,'semantic',h)
def declarations(env,args):
 expected={'endpoint':'https://ouf-seaweedfs-stage:9002','bucket':'ouf-udp','region':'us-east-1','path-style':'true'}
 declared={k:[] for k in expected}
 for i,a in enumerate(args):
  for k in expected:
   key='--ouf.udp.lake.s3.'+k
   if a.startswith(key+'='):declared[k].append(a.split('=',1)[1])
   elif a==key:
    need(i+1<len(args),'STORAGE_ARGUMENT_VALUE_MISSING');declared[k].append(args[i+1])
 matches={k:declared[k]==[v] for k,v in expected.items()}
 opts=list(args)
 for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'):opts.extend(shlex.split(env.get(k,'')))
 trust=[x.split('=',1)[1] for x in opts if x.startswith('-Djavax.net.ssl.trustStore=')]
 selected={}
 aliases={'OUF_UDP_LAKE_REQUIRED':'ouf.udp.lake.required','OUF_UDP_MATERIALIZATION_RECOVERY_ENABLED':'ouf.udp.materialization-recovery.enabled',
 'OUF_UDP_LAKE_MAINTENANCE_INITIAL_DELAY_MS':'ouf.udp.lake.maintenance.initial-delay-ms','OUF_UDP_LAKE_SHADOW_INITIAL_DELAY_MS':'ouf.udp.lake.shadow.initial-delay-ms'}
 canonical=lambda x:re.sub('[._-]','',x).lower()
 names=tuple(aliases.values())+('spring.flyway.enabled','spring.config.import','spring.config.additional-location','spring.config.location','ouf.udp.lake.maintenance.enabled','ouf.udp.lake.shadow.enabled')
 def add(k,v,origin):
  for n in names:
   if canonical(k)==canonical(n):
    val=str(v).lower();summary=val if (n.endswith('.enabled') or n.endswith('.required')) and val in ('true','false') else 'PRESENT' if val else 'EMPTY'
    selected.setdefault(n,[]).append({'origin':origin,'summary':summary})
 for k,v in env.items():add(aliases.get(k,k),v,'PACKAGED_YAML_VARIABLE' if k in aliases else 'ENV')
 for a in args:
  if a.startswith(('--','-D')) and '=' in a:add(*a[2:].split('=',1),'RUNNING_ARGUMENT')
 return {'scope':'DECLARED_ENV_AND_RUNNING_ARGUMENTS_NOT_EFFECTIVE_SPRING_CONFIGURATION','storageArgumentMatchesSeaweedfsSwitch':matches,
 'allStorageArgumentsMatchSeaweedfsSwitch':all(matches.values()),'storageEnvironmentMatchesSeaweedfsSwitch':{k:env.get('OUF_UDP_S3_'+k.upper().replace('-','_'))==v for k,v in expected.items()},
 'truststoreDeclarationMatchesSwitch':trust==['/run/ouf-seaweedfs/truststore.p12'],'sharedCredentialsFileMatchesSwitch':env.get('AWS_SHARED_CREDENTIALS_FILE')=='/run/ouf-seaweedfs/credentials',
 'profileMatchesSwitch':env.get('AWS_PROFILE')=='default','staticAwsCredentialEnvironmentPresent':any(env.get(k) for k in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN')),
 'springApplicationJsonPresent':bool(env.get('SPRING_APPLICATION_JSON')),'selectedProperties':selected,'externalConfigContentsRead':False,'rawArgumentsEmitted':False}
def package(p,raw,expected):
 value=p.package(raw,expected)
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  prefix='BOOT-INF/classes/it/comune/trieste/ouf/udp/'
  value['selectedInstalledClasses']={n:{'present':prefix+n in z.namelist(),'sha256':sha(z.read(prefix+n)) if prefix+n in z.namelist() else None} for n in SELECTED}
 value['comparisonScope']='SOURCE_MIGRATION_AND_YAML_RESOURCES_NOT_NEW_IMAGE_MEMBERSHIP';return value
def run(report):
 need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED');p,c,h=helpers();expected=manifest()
 raw=h.read(h.PLAN,1048576);need(sha(raw)==h.PLAN_SHA,'RETAINED_PLAN_CHANGED');roles=h.parse(raw)['roles']
 doc=h.inspect(CID);pg=h.inspect(roles['postgres']['containerId']);old=h.inspect(roles['udp']['containerId'])
 need(doc['Image']==IMAGE and doc['State']['Running'] and doc['State']['Pid']>0,'CURRENT_UDP_IDENTITY_STATE_CHANGED')
 need(pg['Image']==roles['postgres']['nativeImage'] and pg['State']['Running'],'POSTGRES_IDENTITY_CHANGED')
 need(old['Id']!=CID and not old['State']['Running'],'OLD_MINIO_WRITER_MUST_REMAIN_STOPPED')
 work=Path(tempfile.mkdtemp(prefix='udp-wide-preflight-',dir=h.ROOT));os.chmod(work,0o700)
 report.update(privateEvidenceDirectory=str(work),currentContainerId=CID,currentImageId=IMAGE,currentFrameSha256=h.digest(h.frame(doc)),
  primaryDockerApi='1.44',currentLegacyMac=h.mac_shape(doc),networks=sorted(doc['NetworkSettings']['Networks']),oldMinioWriterStopped=True)
 for n,d in [('udp.private.json',doc),('postgres.private.json',pg),('original.private.json',old)]:c.save_private(work,n,(json.dumps(d,sort_keys=True)+'\n').encode())
 args_raw=Path('/proc',str(doc['State']['Pid']),'cmdline').read_bytes();args=args_raw.rstrip(b'\0').decode().split('\0')
 need(Path(args[0]).name=='java' and args.count('-jar')==1 and args[args.index('-jar')+1]==JAR,'KNOWN_RUNNING_JAVA_JAR_REQUIRED')
 need(not any(JAR==m['Destination'] or JAR.startswith(m['Destination'].rstrip('/')+'/') for m in doc['Mounts']),'IMAGE_JAR_MUST_NOT_BE_MOUNTED')
 jar=Path('/proc',str(doc['State']['Pid']),'root'+JAR);report['package']=package(p,h.read(jar,192*1024*1024),expected)
 report['configuration']=declarations(h.environment(doc),args);report['mountCount']=len(doc['Mounts']);report['readOnlyMountCount']=sum(not m['RW'] for m in doc['Mounts'])
 _,meta=c.mount_file(doc,'/run/ouf-seaweedfs/credentials',False);report['storageCredentialFileMetadata']=meta
 trust,meta=c.mount_file(doc,'/run/ouf-seaweedfs/truststore.p12',True,4*1024*1024);report['truststoreFilesRead']+=1
 report['truststore']={**meta,'sha256':sha(trust) if trust else None,'matchesSwitch':trust is not None and sha(trust)==TRUST_SHA}
 user,name=db_binding(doc,pg,c,h);report['readOnlyDatabaseSessionsAttempted']+=1
 q=subprocess.run((*c.DOCKER,'exec','-i','-e','PGOPTIONS=-c default_transaction_read_only=on','-e','PGAPPNAME=ouf-udp-wide-preflight',pg['Id'],'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-h','/var/run/postgresql','-U',user,'-d',name),input=query(p).encode(),capture_output=True,timeout=12)
 c.save_private(work,'database.stderr.private',q.stderr[:65536]);need(q.returncode==0 and len(q.stdout)<=131072,'DATABASE_READ_FAILED')
 c.save_private(work,'database.private.json',q.stdout);report['database']=result(p,h.parse(q.stdout),expected)
 need(h.frame(h.inspect(CID))==h.frame(doc) and h.frame(h.inspect(pg['Id']))==h.frame(pg) and h.frame(h.inspect(old['Id']))==h.frame(old),'RUNTIME_CHANGED_DURING_READ')
 need(Path('/proc',str(doc['State']['Pid']),'cmdline').read_bytes()==args_raw and sha(h.read(jar,192*1024*1024))==report['package']['jarSha256'],'PACKAGE_CHANGED_DURING_READ')
 report.update(status='UDP_WIDE_PREFLIGHT_READ',runtimeUnchangedDuringRead=True,candidateStartupTested=False,sourceCommit=SOURCE)
def main():
 report={'schema':'ouf.udp-wide-preflight.v1','status':'READ_INCOMPLETE','credentialFileContentsRead':0,'credentialValuesEmitted':False,'truststoreFilesRead':0,
 'readOnlyDatabaseSessionsAttempted':0,'databaseWrites':0,'serviceStops':0,'serviceConfigurationChanged':False,'imageImports':0,'migrationDispatched':False,'businessRequestsIssued':0,'s3Requests':0,'tokenRequests':0,'identifiersPayloadsOrCheckpointsRead':False}
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(RuntimeError('READ_DEADLINE')));signal.alarm(55)
 try:run(report)
 except Exception as e:report['reason']=str(e) if type(e)is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(e)) else type(e).__name__
 finally:signal.alarm(0)
 report['observedAt']=datetime.now(timezone.utc).isoformat();print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
