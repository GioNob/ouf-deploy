#!/usr/bin/env python3
"""Read installed Ingestion code/history/activity before a bounded CSV update.

No start, migration, token, business or storage request. Aggregate activity is
an observation, not a guarantee that no worker will run during later startup.
"""
import copy, hashlib, importlib.util, io, json, os, re, signal, subprocess, sys, tempfile, zipfile
from pathlib import Path
from datetime import datetime, timezone

CID='d69c3f763d75f8c8f8db382fef0159a4dd5a3b99ee62ae8737a24421f4285c14'
IMAGE='sha256:d173aa8beeb9a1ac29c35a163e254a902e95fedad2871e328886a41831c10697'
FRAME='1a7e2cf521248433a0319681ca1c3739889ab876a7d3360056067c662048fe62'
JAR='/app/app.jar'
SOURCE='c85d9fd3be215e518dc6e7d075797720b5afbd91'
RESOURCE_SHA='6b53e6c008337e1acd5459a732e1c249fa843f4450b836e1d2b268e5b1644a2f'
PREVIOUS_SHA='fca0dccd2ed5e42904fa57a8c0d898eb537c233070653379971ef29d7b5498d6'
SELECTED=('ManagedTabularAdapter.class','ManagedTabularAdapter$CsvCursor.class',
          'ExecutionRuntimeConfiguration.class','ExecutionGatewayClient.class','IngestionReadinessHealthIndicator.class')

def need(ok,code):
    if not ok:raise RuntimeError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def helpers():
    path=Path(__file__).with_name('read-onboarding-wide-preflight-20261108.py');raw=path.read_bytes()
    need(sha(raw)==PREVIOUS_SHA,'QUALIFIED_HELPER_CHANGED')
    spec=importlib.util.spec_from_file_location('ing_package_helper',path);p=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),'exec'),p.__dict__)
    c,h=p.helpers();return p,c,h
def manifest():
    raw=Path(__file__).with_name('ingestion-wide-source-resources-20261108.json').read_bytes()
    need(sha(raw)==RESOURCE_SHA,'SOURCE_RESOURCE_RECORD_CHANGED');return json.loads(raw)
def query(p):
    base=p.QUERY.replace('ouf_onboarding.','ouf_ingestion.')
    return base.replace("'applicationRoleSuperuser'", """'activity',json_build_object(
      'runStates',(SELECT coalesce(json_object_agg(s,n),'{}'::json) FROM
        (SELECT CASE WHEN state IN ('READY','PREFLIGHT','RUNNING','DRAINING','SUCCEEDED','FAILED','PAUSED') THEN state ELSE 'OTHER' END s,count(*) n
         FROM ouf_ingestion.ing_run GROUP BY 1) x),
      'handoffStates',(SELECT coalesce(json_object_agg(s,n),'{}'::json) FROM
        (SELECT CASE WHEN state IN ('READY','DELIVERING','ACKED','FAILED_RETRYABLE','FAILED_TERMINAL') THEN state ELSE 'OTHER' END s,count(*) n
         FROM ouf_ingestion.handoff_outbox GROUP BY 1) x),
      'unexpiredPartitionLeases',(SELECT count(*) FROM ouf_ingestion.ing_partition WHERE lease_until>transaction_timestamp())),
      'applicationRoleSuperuser'""")
def db_binding(doc,pg,c,h):
    env=h.environment(doc);translated=copy.deepcopy(doc)
    translated['Config']['Env']=[x for x in doc['Config']['Env'] if not x.startswith(('OUF_SEM_DB_URL=','OUF_SEM_DB_USER='))]
    translated['Config']['Env']+=['OUF_SEM_DB_URL='+env.get('OUF_ING_DB_URL',''),'OUF_SEM_DB_USER='+env.get('OUF_ING_DB_USER','')]
    return c.db_binding(translated,pg,'semantic',h)
def declarations(env,args):
    # Only presence/origin and exact booleans; never emit arbitrary ENV/argument values.
    names=('ouf.ingestion.execution.enabled','ouf.ingestion.activation.gateway-url','ouf.ingestion.activation.token-file',
      'ouf.ingestion.gateway-read.enabled','ouf.ingestion.gateway-read.key-file','ouf.ingestion.iam.enabled',
      'ouf.authorization.registry-url','ouf.authorization.registry-token-file',
      'spring.config.additional-location','spring.config.import','spring.flyway.enabled')
    canonical=lambda s:re.sub('[._-]','',s).lower()
    result={}
    def add(k,v,origin):
        for n in names:
            if canonical(k)==canonical(n):
                summary=str(v).lower() if n.endswith('.enabled') and str(v).lower() in ('true','false') else 'PRESENT' if v not in ('',None) else 'EMPTY'
                result.setdefault(n,[]).append({'origin':origin,'summary':summary})
    for k,v in env.items():add(k,v,'ENV')
    aliases={'OUF_ING_GATEWAY_READ_ENABLED':'ouf.ingestion.gateway-read.enabled',
             'OUF_ING_GATEWAY_READ_KEY_FILE':'ouf.ingestion.gateway-read.key-file','OUF_ING_IAM_ENABLED':'ouf.ingestion.iam.enabled'}
    for k,n in aliases.items():
        if k in env:add(n,env[k],'PACKAGED_YAML_VARIABLE')
    for a in args:
        if a.startswith(('--','-D')) and '=' in a:add(*a[2:].split('=',1),'RUNNING_ARGUMENT')
    return {'scope':'DECLARATIONS_NOT_EFFECTIVE_SPRING_CONFIGURATION','selectedProperties':result,
            'springApplicationJsonPresent':bool(env.get('SPRING_APPLICATION_JSON')),
            'externalConfigContentsRead':False,'rawArgumentsEmitted':False}
def package(p,raw,expected):
    value=p.package(raw,expected)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        prefix='BOOT-INF/classes/it/comune/trieste/ouf/ingestion/'
        value['selectedInstalledClasses']={n:{'present':prefix+n in z.namelist(),
            'sha256':sha(z.read(prefix+n)) if prefix+n in z.namelist() else None} for n in SELECTED}
    value['comparisonScope']='SOURCE_MIGRATION_AND_YAML_RESOURCES_NOT_NEW_IMAGE_MEMBERSHIP'
    return value
def result(p,value,expected):
    value=p.database_result(value,expected);activity=value.get('activity')
    need(isinstance(activity,dict) and set(activity)=={'runStates','handoffStates','unexpiredPartitionLeases'},'ACTIVITY_METADATA_SHAPE')
    for k,states in [('runStates',{'READY','PREFLIGHT','RUNNING','DRAINING','SUCCEEDED','FAILED','PAUSED','OTHER'}),
                     ('handoffStates',{'READY','DELIVERING','ACKED','FAILED_RETRYABLE','FAILED_TERMINAL','OTHER'})]:
        rows=activity[k];need(isinstance(rows,dict) and set(rows)<=states and all(type(n)is int and n>=0 for n in rows.values()),'ACTIVITY_METADATA_SHAPE')
    need(type(activity['unexpiredPartitionLeases'])is int and activity['unexpiredPartitionLeases']>=0,'ACTIVITY_METADATA_SHAPE')
    value['activityMeaning']='COUNTS_AT_READ_TIME_NOT_QUIESCENCE_OR_RESTART_AUTHORITY';return value
def run(report):
    need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED')
    p,c,h=helpers();expected=manifest()
    plan=h.read(h.PLAN,1048576);need(sha(plan)==h.PLAN_SHA,'RETAINED_PLAN_CHANGED');roles=h.parse(plan)['roles']
    doc=h.inspect(CID);pg=h.inspect(roles['postgres']['containerId'])
    need(doc['Image']==IMAGE and doc['State']['Running'] and h.digest(h.frame(doc))==FRAME,'CURRENT_INGESTION_FRAME_CHANGED')
    need(pg['Image']==roles['postgres']['nativeImage'] and pg['State']['Running'],'POSTGRES_IDENTITY_CHANGED')
    work=Path(tempfile.mkdtemp(prefix='ingestion-wide-preflight-',dir=h.ROOT));os.chmod(work,0o700)
    report.update(privateEvidenceDirectory=str(work),currentContainerId=CID,currentImageId=IMAGE,
        currentFrameSha256=FRAME,currentLegacyMac=h.mac_shape(doc),networks=sorted(doc['NetworkSettings']['Networks']))
    for name,v in [('ingestion.private.json',doc),('postgres.private.json',pg)]:c.save_private(work,name,(json.dumps(v,sort_keys=True)+'\n').encode())
    args_raw=Path('/proc',str(doc['State']['Pid']),'cmdline').read_bytes();args=args_raw.rstrip(b'\0').decode().split('\0')
    need(Path(args[0]).name=='java' and args.count('-jar')==1 and args[args.index('-jar')+1]==JAR,'KNOWN_RUNNING_JAVA_JAR_REQUIRED')
    need(not any(JAR==m['Destination'] or JAR.startswith(m['Destination'].rstrip('/')+'/') for m in doc['Mounts']),'IMAGE_JAR_MUST_NOT_BE_MOUNTED')
    path=Path('/proc',str(doc['State']['Pid']),'root'+JAR);raw=h.read(path,192*1024*1024)
    report['package']=package(p,raw,expected);report['configuration']=declarations(h.environment(doc),args)
    report['processIsJava']=True;report['mountCount']=len(doc['Mounts']);report['readOnlyMountCount']=sum(not m['RW'] for m in doc['Mounts'])
    user,name=db_binding(doc,pg,c,h);report['readOnlyDatabaseSessionsAttempted']+=1
    q=subprocess.run((*c.DOCKER,'exec','-i','-e','PGOPTIONS=-c default_transaction_read_only=on','-e','PGAPPNAME=ouf-ingestion-wide-preflight',
        pg['Id'],'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-h','/var/run/postgresql','-U',user,'-d',name),
        input=query(p).encode(),capture_output=True,timeout=12)
    c.save_private(work,'database.stderr.private',q.stderr[:65536]);need(q.returncode==0 and len(q.stdout)<=131072,'DATABASE_READ_FAILED')
    c.save_private(work,'database.private.json',q.stdout);report['database']=result(p,h.parse(q.stdout),expected)
    need(h.frame(h.inspect(CID))==h.frame(doc) and h.frame(h.inspect(pg['Id']))==h.frame(pg),'RUNTIME_CHANGED_DURING_READ')
    need(Path('/proc',str(doc['State']['Pid']),'cmdline').read_bytes()==args_raw and sha(h.read(path,192*1024*1024))==report['package']['jarSha256'],'PACKAGE_CHANGED_DURING_READ')
    report.update(status='INGESTION_WIDE_PREFLIGHT_READ',runtimeUnchangedDuringRead=True,candidateStartupTested=False,sourceCommit=SOURCE)
def main():
    report={'schema':'ouf.ingestion-wide-preflight.v1','status':'READ_INCOMPLETE','credentialFileContentsRead':0,
      'credentialValuesEmitted':False,'readOnlyDatabaseSessionsAttempted':0,'databaseWrites':0,'serviceStops':0,
      'serviceConfigurationChanged':False,'imageImports':0,'migrationDispatched':False,'businessRequestsIssued':0,
      's3Requests':0,'tokenRequests':0,'identifiersPayloadsOrCheckpointsRead':False}
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(RuntimeError('READ_DEADLINE')));signal.alarm(55)
    try:run(report)
    except Exception as exc:report['reason']=str(exc) if type(exc)is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(exc)) else type(exc).__name__
    finally:signal.alarm(0)
    report['observedAt']=datetime.now(timezone.utc).isoformat();print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
