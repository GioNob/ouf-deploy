#!/usr/bin/env python3
"""Installation-specific, retained evidence only. No runtime transport or executor."""
import hashlib,json,os,re,signal,stat,sys
from pathlib import Path

PARENT='/etc/ouf/deploy-snapshots'
FROZEN=PARENT+'/onboarding-budget-v35-54d86bbcd2ea47fd/native-plan-v1/execution-plan.json'
FROZEN_HASH='b17c2c99cc791cced8ee00ed190e30b75c518ae84e2dd4a9ae7eef521390c8bd'
REVIEW_HASH='828d9d6c5f04f8535801e45c2d284a71256232b778b3d6dc14afe6d468e5a94b'
AUTHORITY_HASH='af9a8fbd77a7d5d7caabb436360650eb9ab4ea126684ea15cc70c1fd42f37d63'
STAGES=('VERIFY_CURRENT_ADMISSION_AND_SIGNED_REVIEW','IMPORT_EXACT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD_ONBOARDING','VERIFY_QUIESCED_BACKUP','DETACH_OLD_ENDPOINT','RENAME_OLD','CREATE_REPLACEMENT')
LIMITS={'engineGets':300,'engineWrites':8,'sqlSessions':6,'imageLoadAttempts':1,'backupProcesses':2,'readinessGets':128,'ownerConfigurationReads':32,'quarantineStops':1}
SAFE_KEYS=set('Hostname Domainname User AttachStdin AttachStdout AttachStderr ExposedPorts Tty OpenStdin StdinOnce Env Cmd Healthcheck ArgsEscaped Image Volumes WorkingDir Entrypoint NetworkDisabled MacAddress OnBuild Labels StopSignal StopTimeout Shell'.split())
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def unique(pairs):
    result={}
    for k,v in pairs:
        require(k not in result,'DUPLICATE_PRIVATE_EVIDENCE_KEY');result[k]=v
    return result
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def directory(path):
    path=Path(path);require(path.is_absolute()and '..'not in path.parts,'EXACT_PRIVATE_PATH_REQUIRED')
    for p in (path,*path.parents):
        s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_PRIVATE_ANCESTRY_REQUIRED')
    return path
class Evidence:
    def __init__(self):self.files={};self.reads=0;self.bytes=0
    def read(self,path,expected=None):
        path=Path(path);directory(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)in(0o400,0o600)and 0<s.st_size<=2097152,'PRIVATE_EVIDENCE_CUSTODY_REQUIRED')
            self.reads+=1;self.bytes+=s.st_size;require(self.reads<=700 and self.bytes<=134217728,'FINITE_PRIVATE_EVIDENCE_READ_BOUND')
            raw=os.read(fd,2097153);require(len(raw)==s.st_size and pin(s)==pin(os.fstat(fd))==pin(path.lstat()),'PRIVATE_EVIDENCE_CHANGED')
        finally:os.close(fd)
        require(expected is None or sha(raw)==expected,'EXACT_RETAINED_EVIDENCE_HASH_REQUIRED')
        previous=self.files.get(str(path));require(previous is None or previous==(pin(s),sha(raw)),'PRIVATE_EVIDENCE_CHANGED_BETWEEN_PASSES')
        self.files[str(path)]=(pin(s),sha(raw));return json.loads(raw,object_pairs_hook=unique)
    def stable(self):
        for path,(_,expected)in list(self.files.items()):self.read(path,expected)
def persist(root,name,value):
    fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        raw=encoded(value);require(os.write(fd,raw)==len(raw),'PRIVATE_RESULT_WRITE_INCOMPLETE');os.fsync(fd)
    finally:os.close(fd)
def observe():
    evidence=Evidence();frozen=evidence.read(FROZEN,FROZEN_HASH);logical=frozen['logicalOperationRef']
    require(re.fullmatch('[a-f0-9]{64}',logical)is not None,'EXACT_LOGICAL_OPERATION_REQUIRED')
    root=directory(Path(PARENT)/('onboarding-v35-apply-'+logical))
    require(str(root)==frozen['proposedAuthorityDirectory'],'SAME_EXISTING_AUTHORITY_ROOT_REQUIRED')
    review=evidence.read(root/'review.json',REVIEW_HASH);authority=evidence.read(root/'authority/authority.json',AUTHORITY_HASH)
    require(review['frozenPlanHash']==FROZEN_HASH and review['executionRoot']==str(root)and review['logicalOperationRef']==logical and authority['scope']['reviewHash']==REVIEW_HASH and authority['scope']['nativePlanHash']==sha(encoded(review['nativePlan'])),'SAME_REVIEW_AUTHORITY_PLAN_REQUIRED')
    journal=evidence.read(root/'recovery.json');require(journal['reviewHash']==REVIEW_HASH and journal['authorityHash']==AUTHORITY_HASH and journal['schema']=='ouf.onboarding-v35-native-journal.v1','SAME_EXISTING_JOURNAL_REQUIRED')
    require(journal['nextStage']==7 and len(journal['effects'])==8 and journal['createdConfigurationVerified']is False and journal['createdGeneration']is None and journal['automaticReplayAllowed']is False and journal['budgetReset']is False,'EXACT_PRESTART_CLAIMED_CREATE_REQUIRED')
    for i,row in enumerate(journal['effects']):
        require(row['stage']==STAGES[i]and row['state']==('APPLIED'if i<7 else'CLAIMED')and row['intentHash']==sha(encoded({'reviewHash':REVIEW_HASH,'stage':STAGES[i]})),'RETAINED_ORDERED_EFFECTS_REQUIRED')
    counts=journal['counts'];require(set(counts)==set(LIMITS)and all(type(v)is int and 0<=v<=LIMITS[k]for k,v in counts.items()),'RETAINED_CUMULATIVE_COUNTS_REQUIRED')
    cid=journal['createdId'];require(type(cid)is str and re.fullmatch('[a-f0-9]{64}',cid)is not None,'PERSISTED_CREATED_ID_REQUIRED')
    names=sorted(p.name for p in root.iterdir());require(len(names)<=1024,'BOUNDED_PRIVATE_DIRECTORY_REQUIRED')
    responses=[n for n in names if re.fullmatch('engine-response-[0-9]{3}\\.json',n)]
    require(0<len(responses)<=308,'BOUNDED_RETAINED_ENGINE_RESPONSES_REQUIRED')
    candidates=[];creation=[]
    for name in responses:
        response=evidence.read(root/name);body=response.get('body')
        if type(body)is dict and body.get('Id')==cid:
            if response['status']==201:creation.append(name)
            if response['status']==200 and type(body.get('Config'))is dict:candidates.append((name,body))
    require(len(creation)==1 and len(candidates)==1 and creation[0]<candidates[0][0],'EXACT_RETAINED_CREATE_AND_INSPECT_REQUIRED')
    _,actual=candidates[0];plan=review['nativePlan'];replacement=plan['replacement'];request=replacement['request']
    require(actual['Name']=='/'+replacement['name']and actual['Image']==request['Image']and actual['State']['Running']is False and actual['State']['Pid']==0,'RETAINED_PRESTART_CANDIDATE_IDENTITY_REQUIRED')
    differences=[]
    for key,value in request.items():
        if key in('HostConfig','NetworkingConfig'):continue
        expected=plan['runtimeLabelProjection']['expectedLabels']if key=='Labels'else value
        observed=actual['Config'].get(key)
        if observed!=expected:
            differences.append({'field':key if key in SAFE_KEYS else 'UNRECOGNIZED_CONFIG_FIELD','expectedType':type(expected).__name__,'observedType':type(observed).__name__,'presentInObservedConfig':key in actual['Config']})
    require(differences,'RETAINED_CONFIG_STOP_NOT_REPRODUCED')
    # Re-read every evidence file. No Engine connection, SQL, credentials, keys,
    # owner overlay contents, authority verification at current time, or journal writes.
    evidence.stable()
    require(sorted(p.name for p in root.iterdir())==names,'PRIVATE_EVIDENCE_DIRECTORY_CHANGED')
    return {'schema':'ouf.onboarding-v35-retained-create-reconciliation.v1','status':'RETAINED_CREATED_CONFIG_DIFFERENCE_OBSERVED','complete':True,'reviewHash':REVIEW_HASH,'authorityHash':AUTHORITY_HASH,'retainedJournalHash':evidence.files[str(root/'recovery.json')][1],'retainedCandidateConfigDifferences':differences,'retainedEffectStates':[r['state']for r in journal['effects']],'retainedCumulativeCounts':counts,'retainedCandidateWasStopped':True,'currentRuntimeStateObserved':False,'historicalAuthorityReused':False,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,'engineGetAttempts':0,'sqlSessionAttempts':0,'containerExecAttempts':0,'credentialContentReads':0,'privateSigningKeysRead':0,'oldJournalWrites':0,'automaticReplayAllowed':False,'budgetReset':False,'originalRequestRepeated':False,'applicationReadinessProven':False,'releaseAcceptance':False,'credentialValuesPrinted':False,'addressesPrinted':False,'privateEvidenceReadPasses':2}
def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ONE_ISOLATED_ROOT_RETAINED_READER_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(Stop('FINITE_RETAINED_READER_DEADLINE')));signal.alarm(60)
        output=directory(Path(__file__).parent);persist(output,'reader-claim.json',{'reviewHash':REVIEW_HASH,'automaticReplayAllowed':False,'runtimeEffectsAuthorized':False})
        result=observe();persist(output,'reader-result.json',result)
    except Exception as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'RETAINED_RECONCILIATION_UNPROVEN'
        result={'schema':'ouf.onboarding-v35-retained-create-reconciliation.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    finally:signal.alarm(0)
    print(encoded(result).decode(),flush=True);return 0 if result.get('complete')is True else 2
if __name__=='__main__':raise SystemExit(main())
