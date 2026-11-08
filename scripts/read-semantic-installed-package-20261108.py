#!/usr/bin/env python3
"""Read installed Semantic package metadata after a pre-dispatch migration hold.

Two Docker GETs; no exec, Java launch, SQL, token/provider calls or migration.
"""
import hashlib, importlib.util, json, os, re, signal, stat, sys, tempfile, zipfile, zlib
from pathlib import Path
from datetime import datetime, timezone

CID='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
IMAGE='sha256:b61bc39c1593c28404a8258962008c024d13689d7e9b132e6a85619580003ca3'
HELPER='apply-gateway-analysis-delta-20261108.py'
HELPER_SHA='7064c8443bb323c12a56846267e4faa9cb25bf3e6dfb35455e753fbe71ce8b01'
SOURCE_SHA='b1ae156656b6b89f4fb20e3a7611d23a46bbcda8bc05aa2c27c42becde21c438'
SOURCE='c2dae77b42f1811b704465f6ab813c91d808ade4'
PREFIX='BOOT-INF/classes/db/migration/'
CLASSES=('api/DiscoveryApi','api/SemanticDiscoveryMcpApi','api/SemanticDiscoveryDelegation',
         'application/DiscoveryJobService','application/DiscoveryService','application/DiscoveryWorker')

def need(ok,code):
    if not ok:raise RuntimeError(code)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def helpers():
    p=Path(__file__).with_name(HELPER);raw=p.read_bytes();need(sha(raw)==HELPER_SHA,'HELPER_HASH_CHANGED')
    spec=importlib.util.spec_from_file_location('gateway_apply',p);a=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(p),'exec'),a.__dict__);c,h=a.helpers();return a,c,h

def crc(raw):
    value=0
    for line in re.split(r'\r\n|\r|\n',raw.decode('utf-8-sig')):value=zlib.crc32(line.encode(),value)
    return value if value<2**31 else value-2**32

def summarize(z,expected):
    names=z.namelist();need(len(names)==len(set(names)) and len(names)<=20000,'UNIQUE_BOUNDED_PACKAGE_ENTRIES_REQUIRED')
    def selected(name,limit):
        info=z.getinfo(name);need(info.file_size<=limit,'SELECTED_PACKAGE_ENTRY_TOO_LARGE');return z.read(info)
    migrations=[];actual={}
    for name in sorted(n for n in names if n.startswith(PREFIX) and n.endswith('.sql')):
        leaf=name.removeprefix(PREFIX)
        need(re.fullmatch(r'V[0-9]{1,6}__[A-Za-z0-9_-]{1,120}\.sql',leaf),'UNEXPECTED_MIGRATION_NAME')
        raw=selected(name,2*1024*1024);digest=sha(raw);actual[leaf]=digest
        migrations.append({'name':leaf,'bytes':len(raw),'sha256':digest,
          'flywayStyleCrc32Utf8':crc(raw),'candidateSha256':expected['files'].get(leaf),
          'matchesCandidate':digest==expected['files'].get(leaf)})
    need(len(migrations)<=64,'BOUNDED_MIGRATION_COUNT_REQUIRED')
    classes={}
    for leaf in CLASSES:
        name='BOOT-INF/classes/it/comune/trieste/ouf/semantic/'+leaf+'.class'
        classes[leaf]={'present':name in names}
        if name in names:classes[leaf]['sha256']=sha(selected(name,1024*1024))
    libraries=[]
    pattern=r'(flyway-core|flyway-database-postgresql|postgresql|spring-boot|spring-boot-autoconfigure|spring-core|spring-context)-[0-9][A-Za-z0-9.+-]*\.jar'
    for name in names:
        if name.startswith('BOOT-INF/lib/') and re.fullmatch(pattern,name.removeprefix('BOOT-INF/lib/')):
            libraries.append({'name':Path(name).name,'sha256':sha(selected(name,32*1024*1024))})
    need(len(libraries)<=16,'BOUNDED_LIBRARY_COUNT_REQUIRED')
    yaml='BOOT-INF/classes/application.yml'
    yaml_sha=sha(selected(yaml,1024*1024)) if yaml in names else None
    fields={}
    if 'META-INF/MANIFEST.MF' in names:
        manifest=selected('META-INF/MANIFEST.MF',65536).decode('utf-8')
        for key,pattern in [('Start-Class',r'[A-Za-z0-9_.$]{1,200}'),('Spring-Boot-Version',r'[0-9][A-Za-z0-9.+-]{0,60}'),('Build-Jdk-Spec',r'[0-9]{1,3}')]:
            values=re.findall(r'^'+re.escape(key)+r': ([^\r\n]*)',manifest,re.M)
            fields[key]={'declared':bool(values)}
            if len(values)==1 and re.fullmatch(pattern,values[0]):fields[key]['value']=values[0]
    return {'migrations':migrations,'migrationCount':len(migrations),
      'missingCandidateFiles':sorted(set(expected['files'])-set(actual)),
      'additionalInstalledFiles':sorted(set(actual)-set(expected['files'])),
      'changedCandidateFiles':sorted(k for k in set(actual)&set(expected['files']) if actual[k]!=expected['files'][k]),
      'allMigrationFilesMatchCandidate':actual==expected['files'],
      'applicationYamlPresent':yaml in names,'applicationYamlSha256':yaml_sha,
      'applicationYamlMatchesCandidate':yaml_sha==expected['applicationYamlSha256'],
      'selectedLibraries':sorted(libraries,key=lambda x:x['name']),'selectedClasses':classes,
      'manifestFields':fields,'classPresenceProvesRuntimeBehavior':False}

def read_package(path,expected):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    pin=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and 0<before.st_size<=268435456,'BOUNDED_REGULAR_JAR_REQUIRED')
        with os.fdopen(os.dup(fd),'rb') as stream:
            digest=hashlib.sha256()
            for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
            stream.seek(0)
            with zipfile.ZipFile(stream) as z:result=summarize(z,expected)
        need(pin(before)==pin(os.fstat(fd))==pin(os.stat(path,follow_symlinks=False)),'PACKAGE_CHANGED_DURING_READ')
        result.update(jarSha256=digest.hexdigest(),jarBytes=before.st_size,unchangedDuringRead=True)
        return result
    finally:os.close(fd)

def declarations(env):
    out={}
    for key in ('SPRING_FLYWAY_ENABLED','SPRING_FLYWAY_TARGET','SPRING_FLYWAY_LOCATIONS','SPRING_PROFILES_ACTIVE'):
        value=env.get(key);row={'present':value is not None}
        if key.endswith('ENABLED') and value in ('true','false'):row['value']=value
        elif key.endswith('TARGET') and value is not None and re.fullmatch(r'[0-9]{1,6}(?:\.[0-9]{1,6})*',value):row['value']=value
        elif key.endswith('LOCATIONS') and value=='classpath:db/migration':row['value']=value
        elif key.endswith('ACTIVE') and value=='file-first':row['value']=value
        out[key]=row
    return {'scope':'SELECTED_ENV_DECLARATIONS_NOT_EFFECTIVE_SPRING_CONFIGURATION','properties':out}

def run(report):
    need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED');a,c,h=helpers()
    raw=h.read(Path(__file__).with_name('semantic-migration-source-20261108.json'),65536)
    need(sha(raw)==SOURCE_SHA,'CANDIDATE_SOURCE_MANIFEST_CHANGED');expected=h.parse(raw)
    need(expected['sourceCommit']==SOURCE,'EXPECTED_CANDIDATE_SOURCE_REQUIRED')
    attempt=h.ROOT/'semantic-v11-v12-20261108';first=sorted(p.name for p in attempt.iterdir())
    need(first==['attempt.json'],'HELD_PRE_DISPATCH_ATTEMPT_REQUIRED')
    old=h.read(attempt/'attempt.json',4096)
    need(h.parse(old)=={'sourceCommit':SOURCE,'versions':[11,12]},'HELD_ATTEMPT_CHANGED')
    report['heldAttemptContainsOnlyPreDispatchRecord']=True
    report['dockerGetAttempts']+=1;doc=h.inspect(CID)
    need(doc['Image']==IMAGE and doc['State']['Running'] and not doc['State'].get('Paused') and not doc['State'].get('Restarting'),'EXPECTED_RUNNING_IMAGE_REQUIRED')
    captured=h.parse(h.read(a.OBSERVED/'semantic.private.json',2*1024*1024))
    need(h.digest(h.frame(captured))==c.FRAME_PINS['semantic'],'OBSERVED_FRAME_EVIDENCE_CHANGED')
    need(a.stable_frame(h,doc)==a.stable_frame(h,captured),'SEMANTIC_FRAME_CHANGED')
    pid=str(doc['State']['Pid'])
    with open('/proc/'+pid+'/cmdline','rb') as inp:argv=inp.read(16385).split(b'\0')
    need(sum(map(len,argv))<16384 and Path(os.fsdecode(argv[0])).name=='java' and argv.count(b'-jar')==1 and argv[argv.index(b'-jar')+1]==b'/app/application.jar','RUNNING_JAVA_JAR_ARGUMENT_REQUIRED')
    report['runningJavaJarPathVerified']=True
    report['package']=read_package(Path('/proc')/pid/'root/app/application.jar',expected)
    report['declaredFlywayConfiguration']=declarations(h.environment(doc))
    mounts=[m for m in doc['Mounts'] if '/app/application.jar'==m['Destination'] or '/app/application.jar'.startswith(m['Destination'].rstrip('/')+'/')]
    report['jarCoveredByMount']=bool(mounts)
    report['jarCoveringMountTypes']=sorted({m['Type'] for m in mounts})
    revision=(doc['Config'].get('Labels') or {}).get('org.opencontainers.image.revision')
    report['containerRevisionLabel']={'present':revision is not None,'provesSourceMembership':False}
    if isinstance(revision,str) and re.fullmatch('[a-f0-9]{40}',revision):report['containerRevisionLabel']['value']=revision
    report['dockerGetAttempts']+=1
    need(a.stable_frame(h,h.inspect(CID))==a.stable_frame(h,doc),'SEMANTIC_CHANGED_DURING_READ')
    need(sorted(p.name for p in attempt.iterdir())==first and h.read(attempt/'attempt.json',4096)==old,'HELD_ATTEMPT_CHANGED_DURING_READ')
    report.update(status='SEMANTIC_INSTALLED_PACKAGE_READ',runtimeUnchangedDuringRead=True,heldAttemptUnchanged=True,candidateSourceCommit=SOURCE)
    work=Path(tempfile.mkdtemp(prefix='semantic-package-read-',dir=h.ROOT));os.chmod(work,0o700)
    report['privateEvidenceDirectory']=str(work);a.private(work,'package-read.json',report)

def main():
    report={'schema':'ouf.semantic-installed-package-read.v1','status':'READ_INCOMPLETE','dockerGetAttempts':0,
      'databaseRequests':0,'databaseWrites':0,'javaExecutionDispatched':False,'migrationDispatched':False,
      'serviceStops':0,'containerConfigurationChanged':False,'credentialFilesRead':0,'credentialValuesEmitted':False,
      'providerRequests':0,'tokenRequests':0,'businessRequestsIssued':0,'s3Requests':0,
      'observedAt':datetime.now(timezone.utc).isoformat()}
    signal.signal(signal.SIGALRM,lambda *_:need(False,'READ_DEADLINE'));signal.alarm(60)
    try:run(report)
    except (OSError,ValueError,RuntimeError,KeyError,TypeError,zipfile.BadZipFile) as e:
        report['reason']=str(e) if type(e) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(e)) else type(e).__name__
    finally:signal.alarm(0)
    print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
