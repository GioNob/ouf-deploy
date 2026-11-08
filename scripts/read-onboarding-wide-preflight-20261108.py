#!/usr/bin/env python3
"""Read the current SeaweedFS Onboarding before installing the wide candidate.

No stop, import, migration, token, provider, business or S3 request. Credential
files are stat-only. The existing truststore is hashed without exposing bytes.
"""
import copy, hashlib, importlib.util, io, json, os, re, shlex, signal, subprocess, sys, tempfile, zipfile
from pathlib import Path
from datetime import datetime, timezone

CID='d4f22ff3ed5f6dc20adaf58a7c9df4b13314f43c0d7e63e6773ad0a97ee0d859'
IMAGE='sha256:7b9d3e918beea500929cb9e3e88165b6c574cedac6067e56206fb2ffa1d65b51'
FRAME='3b9125c3a8d87a66da1a5992ef7188b3fd6b590f2055a32583acf6f8337f8758'
CONTRACT_SHA='468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277'
PACKAGE_SHA='3bc9191934011c52a682c4c509c2de60349d8ab9c2494e5a64348661db816fe2'
TRUST_SHA='231fc9855a1777705194fd93580fab1bff45d26483b2432f6678ea1bb934c187'
JAR='/app/application.jar'
QUERY="""BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s';
SELECT json_build_object(
 'readOnly',current_setting('transaction_read_only')='on',
 'databaseOid',(SELECT oid FROM pg_database WHERE datname=current_database()),
 'applicationRoleSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user),
 'migrations',(SELECT coalesce(json_agg(json_build_object(
   'version',version,'checksum',checksum,'success',success,'type',type,
   'installedRank',installed_rank,'installedOn',installed_on) ORDER BY installed_rank),'[]'::json)
   FROM ouf_onboarding.flyway_schema_history));
ROLLBACK;
"""

def need(ok,code):
    if not ok: raise RuntimeError(code)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def helpers():
    p=Path(__file__).with_name('read-discovery-contract-20261108.py');raw=p.read_bytes()
    need(sha(raw)==CONTRACT_SHA,'CONTRACT_HELPER_CHANGED')
    spec=importlib.util.spec_from_file_location('onb_contract',p);c=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(p),'exec'),c.__dict__)
    return c,c.helper()

def manifest():
    raw=Path(__file__).with_name('onboarding-wide-candidate-package-20261108.json').read_bytes()
    need(sha(raw)==PACKAGE_SHA,'CANDIDATE_PACKAGE_RECORD_CHANGED')
    return json.loads(raw)

def package(raw,expected):
    with zipfile.ZipFile(io.BytesIO(raw)) as jar:
        names=jar.namelist();need(len(names)==len(set(names)),'DUPLICATE_JAR_MEMBERS')
        paths=sorted(n for n in names if n.startswith('BOOT-INF/classes/db/migration/') and n.endswith('.sql'))
        need(len(paths)<=128,'MIGRATION_FILE_LIMIT')
        rows=[]
        for n in paths:
            need(jar.getinfo(n).file_size<=1048576,'MIGRATION_FILE_TOO_LARGE')
            rows.append({'name':n.rsplit('/',1)[-1],'sha256':sha(jar.read(n))})
        target=[{'name':x['name'],'sha256':x['sha256']} for x in expected['migrations']]
        yaml='BOOT-INF/classes/application.yml'
        need(yaml in names and jar.getinfo(yaml).file_size<=1048576,'PACKAGED_YAML_REQUIRED')
        libraries=[n.rsplit('/',1)[-1] for n in names if n.startswith('BOOT-INF/lib/') and
                   n.rsplit('/',1)[-1].startswith(('flyway-','minio-','spring-boot-','postgresql-'))]
        selected={}
        for n, pin in expected['selectedClasses'].items():
            present=n in names
            digest=sha(jar.read(n)) if present else None
            selected[n.rsplit('/',1)[-1]]={'present':present,'sha256':digest,'matchesCandidate':digest==pin}
        return {'jarBytes':len(raw),'jarSha256':sha(raw),'migrationCount':len(rows),
                'migrations':rows,'allMigrationFilesMatchCandidate':rows==target,
                'applicationYamlMatchesCandidate':sha(jar.read(yaml))==expected['applicationYaml']['sha256'],
                'selectedLibraries':libraries,'selectedClasses':selected,
                'classPresenceProvesRuntimeBehavior':False}

def selected_declarations(env,args):
    keys=('ouf.onboarding.staging.endpoint','ouf.onboarding.staging.bucket',
          'ouf.onboarding.staging.access-key-file','ouf.onboarding.staging.secret-key-file')
    result={k:[] for k in keys}
    for k in keys:
        for i,arg in enumerate(args):
            if arg=='--'+k:
                need(i+1<len(args),'ARGUMENT_VALUE_MISSING');result[k].append(args[i+1])
            elif arg.startswith('--'+k+'='):result[k].append(arg.split('=',1)[1])
    # These are the explicit arguments added by the successful SeaweedFS switch.
    expected=('https://ouf-seaweedfs-stage:9002','ouf-managed-files',
              '/run/ouf-seaweedfs/access-key','/run/ouf-seaweedfs/secret-key')
    matches={k:result[k]==[v] for k,v in zip(keys,expected)}
    opts=[]
    for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'):
        opts.extend(shlex.split(env.get(k,'')))
    opts.extend(args)
    stores=[a.split('=',1)[1] for a in opts if a.startswith('-Djavax.net.ssl.trustStore=')]
    return {'scope':'DECLARED_ENV_AND_RUNNING_ARGUMENTS_NOT_EFFECTIVE_SPRING_CONFIGURATION',
            'stagingArgumentMatchesSeaweedfsSwitch':matches,
            'allStagingArgumentsMatchSeaweedfsSwitch':all(matches.values()),
            'truststoreDeclarationMatchesSwitch':stores==['/run/ouf-seaweedfs/truststore.p12'],
            'springApplicationJsonPresent':bool(env.get('SPRING_APPLICATION_JSON')),
            'externalSpringConfigDeclared':any(env.get(k) for k in
                ('SPRING_CONFIG_IMPORT','SPRING_CONFIG_LOCATION','SPRING_CONFIG_ADDITIONAL_LOCATION')),
            'rawArgumentsEmitted':False}

def db_binding(doc,pg,c,h):
    env=h.environment(doc)
    # Reuse the qualified JDBC host/user parser, with the Onboarding ENV names.
    translated=copy.deepcopy(doc)
    translated['Config']['Env']=[x for x in doc['Config']['Env'] if not x.startswith(('OUF_SEM_DB_URL=','OUF_SEM_DB_USER='))]
    translated['Config']['Env'] += ['OUF_SEM_DB_URL='+env.get('OUF_ONB_DB_URL',''),
                                  'OUF_SEM_DB_USER='+env.get('OUF_ONB_DB_USER','')]
    return c.db_binding(translated,pg,'semantic',h)

def database_result(value,expected):
    need(value.get('readOnly') is True and str(value.get('databaseOid','')).isdigit(),'READ_ONLY_DATABASE_REQUIRED')
    rows=value.get('migrations');need(isinstance(rows,list) and len(rows)<=128,'BOUNDED_HISTORY_REQUIRED')
    need(all(isinstance(r,dict) and (r.get('version') is None or re.fullmatch(r'\d{1,3}',r.get('version',''))) and
             (r.get('checksum') is None or type(r['checksum']) is int) and type(r.get('success')) is bool and
             r.get('type') in ('SQL','BASELINE','SCHEMA') and type(r.get('installedRank')) is int and
             re.fullmatch(r'[0-9T:.+ -]{10,40}',r.get('installedOn','')) for r in rows),'HISTORY_METADATA_SHAPE_UNEXPECTED')
    versions=[r for r in rows if r['version'] is not None]
    target={str(int(r['name'].split('__',1)[0][1:])):r['flywayStyleCrc32Utf8'] for r in expected['migrations']}
    exact=(len(versions)==len(target) and {r['version']:r['checksum'] for r in versions}==target and
           all(r['success'] and r['type']=='SQL' for r in versions) and all(r['success'] for r in rows))
    value.update(exactCandidateMigrationHistory=exact,migrationExecuted=False,
                 scope='READ_ONLY_HISTORY_ON_DECLARED_APPLICATION_DATABASE_NOT_EFFECTIVE_SPRING_BINDING')
    return value

def run(report):
    need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED')
    c,h=helpers();expected=manifest()
    plan=h.read(h.PLAN,1048576);need(sha(plan)==h.PLAN_SHA,'RETAINED_PLAN_CHANGED');roles=h.parse(plan)['roles']
    doc=h.inspect(CID);pg=h.inspect(roles['postgres']['containerId']);original=h.inspect(roles['onboarding']['containerId'])
    need(doc['Image']==IMAGE and doc['State']['Running'] and h.digest(h.frame(doc))==FRAME,'CURRENT_ONBOARDING_FRAME_CHANGED')
    need(pg['Image']==roles['postgres']['nativeImage'] and pg['State']['Running'],'POSTGRES_IDENTITY_CHANGED')
    need(original['Id']!=CID and original['State']['Running'] is False,'OLD_MINIO_WRITER_MUST_REMAIN_STOPPED')
    work=Path(tempfile.mkdtemp(prefix='onboarding-wide-preflight-',dir=h.ROOT));os.chmod(work,0o700)
    report.update(privateEvidenceDirectory=str(work),currentContainerId=CID,currentImageId=IMAGE,
                  currentFrameSha256=FRAME,currentLegacyMac=h.mac_shape(doc),
                  networks=sorted(doc['NetworkSettings']['Networks']),oldMinioWriterStopped=True)
    for name,v in (('onboarding.private.json',doc),('postgres.private.json',pg),('original.private.json',original)):
        c.save_private(work,name,(json.dumps(v,sort_keys=True)+'\n').encode())
    report['phase']='READ_INSTALLED_PACKAGE'
    args_raw=Path('/proc',str(doc['State']['Pid']),'cmdline').read_bytes()
    args=args_raw.rstrip(b'\0').decode().split('\0')
    need(Path(args[0]).name=='java' and args.count('-jar')==1 and args[args.index('-jar')+1]==JAR,'KNOWN_RUNNING_JAVA_JAR_REQUIRED')
    need(not any(JAR==m['Destination'] or JAR.startswith(m['Destination'].rstrip('/')+'/') for m in doc['Mounts']),'IMAGE_JAR_MUST_NOT_BE_MOUNTED')
    jar_path=Path('/proc',str(doc['State']['Pid']),'root'+JAR)
    raw=h.read(jar_path,192*1024*1024);report['package']=package(raw,expected)
    report['phase']='READ_STORAGE_BINDINGS'
    env=h.environment(doc);report['configuration']=selected_declarations(env,args)
    files={}
    for name in ('access-key','secret-key'):
        _,files[name]=c.mount_file(doc,'/run/ouf-seaweedfs/'+name,False)
    trust,meta=c.mount_file(doc,'/run/ouf-seaweedfs/truststore.p12',True,4*1024*1024)
    report['truststoreFilesRead']+=1
    report['storageCredentialFileMetadata']=files
    report['truststore']={**meta,'sha256':sha(trust) if trust else None,'matchesSwitch':trust is not None and sha(trust)==TRUST_SHA}
    report['phase']='READ_DATABASE_HISTORY'
    user,name=db_binding(doc,pg,c,h)
    command=(*c.DOCKER,'exec','-i','-e','PGOPTIONS=-c default_transaction_read_only=on',
             '-e','PGAPPNAME=ouf-onboarding-wide-preflight',pg['Id'],'psql','-X','-w','-q','-A','-t',
             '-v','ON_ERROR_STOP=1','-h','/var/run/postgresql','-U',user,'-d',name)
    report['readOnlyDatabaseSessionsAttempted']+=1
    result=subprocess.run(command,input=QUERY.encode(),capture_output=True,timeout=12)
    c.save_private(work,'database.stderr.private',result.stderr[:65536])
    need(result.returncode==0 and len(result.stdout)<=131072,'DATABASE_HISTORY_READ_FAILED')
    report['database']=database_result(h.parse(result.stdout),expected)
    c.save_private(work,'database.private.json',result.stdout)
    report['phase']='VERIFY_UNCHANGED'
    need(h.frame(h.inspect(CID))==h.frame(doc) and h.frame(h.inspect(pg['Id']))==h.frame(pg) and
         h.frame(h.inspect(original['Id']))==h.frame(original),'RUNTIME_CHANGED_DURING_READ')
    need(Path('/proc',str(doc['State']['Pid']),'cmdline').read_bytes()==args_raw and
         sha(h.read(jar_path,192*1024*1024))==report['package']['jarSha256'],'RUNNING_PACKAGE_CHANGED_DURING_READ')
    report.update(status='ONBOARDING_WIDE_PREFLIGHT_READ',phase='COMPLETE',runtimeUnchangedDuringRead=True,
                  candidateStartupTested=False,sourceCommit=expected['sourceCommit'])

def main():
    report={'schema':'ouf.onboarding-wide-preflight.v1','status':'READ_INCOMPLETE','phase':'READ_CURRENT_FRAME',
            'credentialFileContentsRead':0,'credentialValuesEmitted':False,'truststoreFilesRead':0,
            'readOnlyDatabaseSessionsAttempted':0,'databaseWrites':0,'serviceStops':0,
            'serviceConfigurationChanged':False,'imageImports':0,'migrationDispatched':False,
            'businessRequestsIssued':0,'s3Requests':0,'tokenRequests':0}
    signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(RuntimeError('READ_DEADLINE')));signal.alarm(55)
    try: run(report)
    except Exception as exc:
        report['reason']=str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(exc)) else type(exc).__name__
    finally: signal.alarm(0)
    report['observedAt']=datetime.now(timezone.utc).isoformat();print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
