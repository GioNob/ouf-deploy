"""Installation-specific, one-use private preparation; never invokes completed readback.

The bounded stage is hash-bound by the launcher. Retained completed artifacts
are read as history; no container/service/SQL readback or installer is replayed.
Native IAM/HUMAN decisions occur only in the fresh isolated execution process.
"""
import base64,hashlib,json,os,re,signal,stat,sys,tempfile,time
from pathlib import Path

def require(ok,reason):
    if not ok:raise ValueError(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))

FILES={'prepare.py','bootstrap.py','reader.py','entry.py','authority.py','authorization.py','login.py','iam.py','runtime.py','selection.json'}
MODULE_FILES={name:'tools.ingestion_read_authorization.'+name[:-3] for name in
    ('entry.py','authority.py','authorization.py','login.py','iam.py')}

def stage_read(path,expected,maximum=262144):
    path=Path(path);require(path.is_absolute() and path.resolve()==path,'EXACT_STAGE_PATH_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and 0<st.st_size<=maximum,'BOUNDED_STAGE_FILE_REQUIRED')
        raw=os.read(fd,maximum+1)
        pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        require(len(raw)==st.st_size and pin(st)==pin(os.fstat(fd))==pin(path.lstat()) and sha(raw)==expected,'STAGE_CHANGED')
        return raw
    finally:os.close(fd)

def write_new(directory,name,raw):
    require(Path(name).name==name,'SAFE_CAPSULE_MEMBER_REQUIRED')
    fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return {'path':str(directory/name),'sha256':sha(raw)}

def checked_stage(directory,manifest_sha):
    require(re.fullmatch('[0-9a-f]{64}',manifest_sha),'EXACT_STAGE_MANIFEST_HASH_REQUIRED')
    manifest=json.loads(stage_read(directory/'manifest.json',manifest_sha))
    require(manifest['schema']=='ouf.ingestion-read-administrative-code.v1' and set(manifest['files'])==FILES
        and re.fullmatch('[0-9a-f]{40}',manifest['sourceCommit']),'EXACT_STAGE_CLOSURE_REQUIRED')
    files={n:stage_read(directory/n,h)for n,h in manifest['files'].items()}
    require(sha(Path(__file__).read_bytes())==manifest['files']['prepare.py'],'PREPARER_SOURCE_CHANGED')
    return manifest,files

def run(directory,manifest_sha):
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
        'ISOLATED_ROOT_REQUIRED')
    os.umask(0o077)
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('PREPARATION_TIME_BOUND_EXHAUSTED')))
    signal.alarm(180);directory=Path(directory)
    manifest,files=checked_stage(directory,manifest_sha)
    reader={'__name__':'verified_retained_file_helpers'}
    exec(compile(files['reader.py'],'<verified-retained-file-helpers>','exec'),reader)
    read=reader['read'];doc=reader['document'];root=reader['ROOT'];execution=reader['EXECUTION']
    # Static frozen custody checks only; reader.main() is never called.
    result,old_case=reader['frozen_preparation']()
    require(digest(result)=='3eb2fd4fff1048accdb954322faa58979bb490250c8535c1dd8512253e603587',
        'EXACT_SUCCESSFUL_PREPARATION_RECEIPT_REQUIRED')
    old_review=doc(execution/'review.json');old_authority_raw=read(execution/'authority.json')
    old_authority=json.loads(old_authority_raw);old_plan=doc(execution/'execution-plan.json');history=doc(execution/'recovery.json')
    require(old_authority['scopedExecution']['reviewHash']==digest(old_review)
        and old_review['sourceClosureHash']==result['sourceClosureSha256']==old_authority['sourceClosureHash']
        and old_review['scopes']['sourceRevisionUpdate']['planHash']==digest(old_plan),'COMPLETED_HISTORY_BINDING_REQUIRED')
    reader['completed_history'](history,old_plan,old_review,old_authority_raw)
    auth=doc(execution/'authorization-plan.json',reader['AUTH_PLAN'])
    auth_history=doc(execution/'authorization/recovery.json')
    require(auth_history['planHash']==reader['AUTH_PLAN'] and auth_history['authorityHash']==sha(old_authority_raw)
        and auth_history['budgetReset']is False and all(e['state']=='APPLIED'for e in auth_history['effects'].values()),
        'COMPLETED_AUTHORIZATION_HISTORY_REQUIRED')
    original=doc(result['currentOriginalPreparationBinding']['path'],reader['ORIGINAL'])
    require(auth['selection']==original['authorization']['plan']['selection'],'RETAINED_INSTALLATION_SELECTION_CHANGED')
    boot=old_case['retainedBootstrap'];ns={'__name__':'retained_decode_helpers'}
    exec(compile(read(boot['path'],boot['sha256']),'<verified-retained-decode>','exec'),ns)
    prior=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW'])
    b=prior['scopes']['finiteActionProcess']['bundle'];bundle=ns['read'](b['path'],8388608,b['sha256'])
    require(digest(bundle['prepared'])==prior['privateInputHashes']['preparedInputs'],'ORIGINAL_PREPARED_INPUTS_CHANGED')
    _,sources=ns['decode_sources'](bundle)
    code=reader['PREPARED']/'executor-code';package=doc(code/'package.json',result['executorCodeBinding']['packageSha256'])
    for module,name in reader['FROZEN_NAMES'].items():sources[module]=read(code/name,package['sourceHashes'][module],262144)
    # Add a new sealed owner. No bytes in the installed/frozen capsule change.
    for name,module in MODULE_FILES.items():sources[module]=files[name]
    loader=files['runtime.py'];memory={'__name__':'new_private_closed_loader'}
    exec(compile(loader,'<new-private-closed-loader>','exec'),memory)
    memory['compile_sources'](sources)
    selection=json.loads(files['selection.json'])
    require(set(selection)=={'schema','sourceId','iamProfile'} and selection['schema']=='ouf.ingestion-read-administrative-selection.v1'
        and selection['sourceId']=='teatri-csv-6609b245','EXACT_INSTALLATION_SPECIFIC_ACTION_SELECTION_REQUIRED')
    iam=selection['iamProfile']
    require(set(iam)=={'schema','installationSpecific','adminServer','adminRealm','adminUser','maximumLoginAttempts',
        'maximumLoginSeconds','provenance','retainedProfileSource'}
        and iam['schema']=='ouf.ingestion-read-administrative-iam-gate.v1' and iam['installationSpecific']is True
        and iam['maximumLoginAttempts']==1 and iam['maximumLoginSeconds']==300
        and all(type(iam[k])is str and 0<len(iam[k])<512 for k in('adminServer','adminRealm','adminUser','provenance','retainedProfileSource')),
        'EXPLICIT_RETAINED_INSTALLATION_IAM_PROFILE_REQUIRED')
    # A durable logical-action fence prevents a second launcher from multiplying
    # budgets/effects, even if preparation crashes. Never remove on failure.
    claim='ingestion-read-authorization-'+digest({'sourceId':selection['sourceId'],'predecessor':reader['AUTH_PLAN']})+'.claim.json'
    context=Path(tempfile.mkdtemp(prefix='ingestion-read-authorization-execution-',dir=root))
    write_new(root,claim,encoded({'context':str(context),'sourceId':selection['sourceId'],
        'sourceCommit':manifest['sourceCommit'],'automaticReplayAllowed':False,'budgetReset':False}))
    case={**selection,'humanBinding':old_review['authenticatedHuman'],
        'preparationReceiptHash':digest(result),'predecessorHistoryHash':digest(history),
        'preparedPlanBinding':{'path':str(execution/'authorization-plan.json'),'sha256':reader['AUTH_PLAN']},
        'originalBinding':result['currentOriginalPreparationBinding']}
    write_new(context,'case.json',encoded(case));write_new(context,'bootstrap.py',files['bootstrap.py'])
    write_new(context,'runtime.py',loader);write_new(context,'reader.py',files['reader.py'])
    write_new(context,'sources.json',encoded({n:base64.b64encode(raw).decode('ascii')for n,raw in sorted(sources.items())}))
    pins={'ouf-deploy':manifest['sourceCommit'],'ouf-onboarding':old_case['candidateOwnerSourceCommit']}
    execution_pins={'executorSha256':sha(files['bootstrap.py']),'caseSha256':digest(case),'mode':'INGESTION_READ_AUTHORIZATION'}
    declaration=memory['declaration'](manifest['sourceCommit'],sources,loader,pins,execution_pins)
    closure={**old_review['sourceClosure'],'declaration':declaration}
    package={'schema':'ouf.ingestion-read-administrative-package.v1','sourceCommit':manifest['sourceCommit'],
        'sourcePins':pins,'executionPins':execution_pins,'closure':closure,'declarationHash':digest(declaration),
        'fileHashes':{n:sha(read(context/n))for n in('case.json','bootstrap.py','runtime.py','reader.py','sources.json')},
        'predecessorPackageHash':result['executorCodeBinding']['packageSha256'],'runtimeAuthorityIssued':False}
    write_new(context,'package.json',encoded(package))
    receipt={'schema':'ouf.ingestion-read-administrative-preparation.v1','contextPath':str(context),
        'packageHash':digest(package),'sourceClosureHash':digest(closure),'sourceCommit':manifest['sourceCommit'],
        'newHumanSessionOpened':False,'oauthRequests':0,'infrastructureCalls':0,'completedReadbackReplayed':False,
        'runtimeAuthorityIssued':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
    write_new(context,'preparation-result.json',encoded(receipt))
    # Check the entire source closure and qualified interpreter in this fresh
    # execution; the native entry independently checks current stdlib/authority.
    print('OUF_INGESTION_ADMIN_PREPARED='+encoded(receipt).decode(),flush=True)
    signal.alarm(0)
    os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(context/'bootstrap.py'),str(context),digest(package)])

if __name__=='__main__':
    try:
        require(len(sys.argv)==3,'EXACT_STAGE_AND_HASH_ARGUMENTS_REQUIRED');run(sys.argv[1],sys.argv[2])
    except (Exception,KeyboardInterrupt)as error:
        print(encoded({'schema':'ouf.ingestion-read-administrative-stop.v1','status':'STOP_RECONCILE',
            'exceptionClass':type(error).__name__,'reason':'PRIVATE_DETAILS_REDACTED',
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}).decode(),flush=True)
        raise SystemExit(2)
