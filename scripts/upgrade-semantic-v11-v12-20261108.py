#!/usr/bin/env python3
"""Apply only the two missing packaged Semantic migrations using installed Flyway."""
import base64, hashlib, importlib.util, json, os, re, subprocess, sys, zipfile
from pathlib import Path
from datetime import datetime, timezone

HELPER='apply-gateway-analysis-delta-20261108.py'
HELPER_SHA='7064c8443bb323c12a56846267e4faa9cb25bf3e6dfb35455e753fbe71ce8b01'
JAVA_SHA='f973b61831e55831525939167d3e2114baf9a97635554d59d7a07c57baadfd4f'
SOURCE='c2dae77b42f1811b704465f6ab813c91d808ade4'
ROOT=Path('/var/lib/ouf-storage-migration')
WORK=ROOT/'semantic-v11-v12-20261108'
IMAGE='sha256:b61bc39c1593c28404a8258962008c024d13689d7e9b132e6a85619580003ca3'
CID='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'

def need(ok,code):
    if not ok: raise RuntimeError(code)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def load_helpers():
    path=Path(__file__).with_name(HELPER);raw=path.read_bytes()
    need(sha(raw)==HELPER_SHA,'HELPER_HASH_CHANGED')
    spec=importlib.util.spec_from_file_location('gateway_apply',path);a=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),'exec'),a.__dict__)
    c,h=a.helpers();return a,c,h

def package(doc,manifest):
    need(manifest['sourceCommit']==SOURCE,'EXACT_SOURCE_REQUIRED')
    path=Path('/proc')/str(doc['State']['Pid'])/'root/app/application.jar'
    need(path.stat().st_size<=268435456,'BOUNDED_JAR_REQUIRED')
    with zipfile.ZipFile(path) as z:
        names=z.namelist();need(len(names)==len(set(names)),'DUPLICATE_JAR_ENTRIES')
        sql={n.removeprefix('BOOT-INF/classes/db/migration/'):sha(z.read(n)) for n in names if n.startswith('BOOT-INF/classes/db/migration/') and n.endswith('.sql')}
        expected=manifest['files']
        need(sql==expected and len(sql)==12,'INSTALLED_MIGRATIONS_DIFFER_FROM_SOURCE')
        need(sha(z.read('BOOT-INF/classes/application.yml'))==manifest['applicationYamlSha256'],'PACKAGED_CONFIGURATION_CHANGED')
        libs=[Path(n).name for n in names if n.startswith('BOOT-INF/lib/') and re.fullmatch(r'(flyway-core|flyway-database-postgresql|postgresql)-[A-Za-z0-9.-]+\.jar',Path(n).name)]
        need(len(libs)==3 and 'org/springframework/boot/loader/launch/PropertiesLauncher.class' in names,'INSTALLED_FLYWAY_LAUNCHER_REQUIRED')
        return {'migrationCount':12,'migrationBytesMatchSource':True,'libraries':sorted(libs),'applicationYamlMatchesSource':True}

def selected_environment(env):
    need(env.get('OUF_SCHEMA_GOV_ENABLED')=='false' and env.get('OUF_DISCOVERY_WORKER_ENABLED')=='false','DISABLED_PROVIDER_WORKER_REQUIRED')
    need(not env.get('SPRING_APPLICATION_JSON'),'JSON_CONFIGURATION_UNSUPPORTED')
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'):
        need(not any(x in env.get(key,'') for x in ('spring.','ouf.','-agent','-javaagent','loader.')),'CUSTOM_JVM_CONFIGURATION_UNSUPPORTED')
    imports=env.get('SPRING_CONFIG_IMPORT','')
    need(imports and all(re.fullmatch(r'(?:optional:)?configtree:/[A-Za-z0-9_./-]+/',s) for s in imports.split(',')),'ONLY_DECLARED_CONFIGTREE_IMPORTS_SUPPORTED')

def stage_class(doc,bundle):
    need(bundle['sourceSha256']==JAVA_SHA and bundle['javaRelease']==21,'QUALIFIED_HELPER_SOURCE_REQUIRED')
    raw=base64.b64decode(bundle['classBase64'],validate=True)
    need(sha(raw)==bundle['classSha256'] and 1000<len(raw)<65536,'QUALIFIED_CLASS_BYTES_REQUIRED')
    root=Path('/proc')/str(doc['State']['Pid'])/'root/tmp'
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    name='ouf-semantic-v11-v12-20261108'
    try:
        os.mkdir(name,0o755,dir_fd=fd)
        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        try:
            for leaf,value in [('SemanticMigration.class',raw),('loader.properties',b'')]:
                out=os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444,dir_fd=child)
                with os.fdopen(out,'wb') as stream:stream.write(value);stream.flush();os.fsync(stream.fileno())
        finally:os.close(child)
    finally:os.close(fd)
    return root/name,'/tmp/'+name

def invoke(c,doc,path,url,user,oid):
    return subprocess.run((*c.DOCKER,'exec',doc['Id'],'java','-Xmx256m',
      '-Dloader.main=SemanticMigration','-Dloader.path='+path,
      '-Dloader.config.location=file:'+path+'/loader.properties','-cp','/app/application.jar',
      'org.springframework.boot.loader.launch.PropertiesLauncher',url,user,oid),capture_output=True,timeout=90)

def run(report):
    need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED')
    a,c,h=load_helpers()
    source=json.loads(Path(__file__).with_name('semantic-migration-source-20261108.json').read_bytes())
    bundle=json.loads(Path(__file__).with_name('semantic-migration-helper-20261108.json').read_bytes())
    WORK.mkdir(mode=0o700);report['privateEvidenceDirectory']=str(WORK)
    a.private(WORK,'attempt.json',{'sourceCommit':SOURCE,'versions':[11,12]})
    raw=h.read(h.PLAN,1048576);need(sha(raw)==h.PLAN_SHA,'RETAINED_PLAN_CHANGED')
    roles=h.parse(raw)['roles'];sem=h.inspect(CID);pg=h.inspect(roles['postgres']['containerId'])
    need(sem['Image']==IMAGE and pg['Image']==roles['postgres']['nativeImage'] and sem['State']['Running'] and pg['State']['Running'],'EXPECTED_RUNNING_IMAGES_REQUIRED')
    observed=h.parse(h.read(a.OBSERVED/'semantic.private.json',2*1024*1024))
    need(h.digest(h.frame(observed))==c.FRAME_PINS['semantic'],'OBSERVED_FRAME_EVIDENCE_CHANGED')
    need(a.stable_frame(h,sem)==a.stable_frame(h,observed),'SEMANTIC_FRAME_CHANGED')
    env=h.environment(sem);selected_environment(env)
    user,name=c.db_binding(sem,pg,'semantic',h)
    report['installedPackage']=package(sem,source)
    before=a.semantic_read(c,h,sem,pg,WORK,report)
    need(before['databaseOid']=='21558' and before['discoveryStates']==[] and not before['recoveryColumnPresent'],'DATABASE_BASELINE_CHANGED')
    report['before']=before
    host=None
    try:
        host,path=stage_class(sem,bundle);report['temporaryHelperStaged']=True
        need(a.stable_frame(h,h.inspect(CID))==a.stable_frame(h,sem) and a.stable_frame(h,h.inspect(pg['Id']))==a.stable_frame(h,pg),'RUNTIME_CHANGED_BEFORE_DISPATCH')
        a.private(WORK,'java-intent.json',{'versions':[11,12],'classSha256':bundle['classSha256'],'sourceCommit':SOURCE})
        report['javaExecutionDispatched']=True;report['databaseWrites']=None;report['migrationDispatched']=None
        result=invoke(c,sem,path,env['OUF_SEM_DB_URL'],user,'21558')
        c.save_private(WORK,'java.stdout.private',result.stdout);c.save_private(WORK,'java.stderr.private',result.stderr)
        rows=[json.loads(line[len(b'OUF_SEMANTIC_UPGRADE '):]) for line in result.stdout.splitlines() if line.startswith(b'OUF_SEMANTIC_UPGRADE ')]
        need(1<=len(rows)<=2,'JAVA_RESULT_UNPROVEN')
        report['javaResult']=rows[-1];report['migrationDispatched']=any(x['status']=='MIGRATION_DISPATCHED' for x in rows)
        if not report['migrationDispatched']:report['databaseWrites']=0
        need(result.returncode==0 and rows[-1]['status']=='SEMANTIC_V11_V12_MIGRATED_VALIDATED','MIGRATION_NOT_CONFIRMED')
        report['databaseWrites']=True
        need(a.stable_frame(h,h.inspect(CID))==a.stable_frame(h,sem) and a.stable_frame(h,h.inspect(pg['Id']))==a.stable_frame(h,pg),'RUNTIME_CHANGED_AFTER_MIGRATION')
        report['status']='SEMANTIC_V11_V12_MIGRATED_VALIDATED'
    finally:
        if host is not None:
            # Only files created by this attempt; retain the root-owned journal.
            for leaf in ('SemanticMigration.class','loader.properties'):(host/leaf).unlink()
            host.rmdir();report['temporaryHelperRemoved']=True

def main():
    report={'schema':'ouf.semantic-v11-v12-upgrade.v1','status':'HELD','credentialValuesEmitted':False,
      'readOnlyDatabaseSessionsAttempted':0,'databaseWrites':0,'migrationDispatched':False,'javaExecutionDispatched':False,
      'serviceStops':0,'containerConfigurationChanged':False,'providerEnableDispatched':False,
      'providerRequests':0,'tokenRequests':0,'businessRequestsIssued':0,'s3Requests':0,
      'springApplicationStarted':False,'temporaryHelperStaged':False,'temporaryHelperRemoved':False}
    try:run(report)
    except FileExistsError:report['reason']='EXISTING_ATTEMPT_DO_NOT_REPLAY'
    except (OSError,ValueError,RuntimeError,KeyError,TypeError,subprocess.TimeoutExpired) as e:
        report['reason']=str(e) if type(e) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(e)) else type(e).__name__
    report['observedAt']=datetime.now(timezone.utc).isoformat();print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
