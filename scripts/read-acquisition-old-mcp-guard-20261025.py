#!/usr/bin/env python3
"""Installation-specific retained-only diagnosis; no runtime ports or old entrypoints."""
import hashlib,json,os,re,signal,stat,sys,time
from pathlib import Path
NATIVE_HASH='5fa62e4f6869a6f40fb512878dcf65dcb6ffaf941be487e4189826f418046591'
ROOT=Path('/etc/ouf/deploy-snapshots/acquisition-read-apply-'+NATIVE_HASH+'/terminal-continuation-v1')
REVIEW_HASH='7fcbce1f43fd99b4add8db9913b3dc2fe215836f16eecd8e8191f9e344e54aa9'
AUTHORITY_HASH='496dda9a7057f67c4ffb10e6ae4606d101479c905cad6a731907eaf4010d56a4'
CODE=Path('/etc/ouf/deploy-snapshots/acquisition-read-continuation-code-dc2af88dfe0f1db2')
MANIFEST_HASH='dc2af88dfe0f1db2d54a0c3ed1a84a868f1b3b8e7ae5b1d6531d3aa27ec233b0'
INPUTS=Path('/etc/ouf/deploy-snapshots/acquisition-evidence-current-inputs-v1/inputs.json')
INPUTS_HASH='c40ba6dc86e8be72ddcda2eaef65fe3eb8aa9f24b8ec4b0d5758b0bfeacf1da6'
CHILD='retained-old-mcp-guard-v1'
STAGES=('LOAD_EXISTING_ADMIN_KEY','VERIFY_CURRENT_ADMISSION','IMPORT_INGESTION','IMPORT_UDP','IMPORT_MCP','CREATE_INGESTION_READ','CREATE_UDP_READ','START_INGESTION_READ','START_UDP_READ','VERIFY_READ_REPLICAS','DISABLE_OLD_MCP_RESTART','STOP_OLD_MCP','DETACH_OLD_MCP','RENAME_OLD_MCP','CREATE_MCP','START_MCP','VERIFY_MCP_READINESS','ADD_INGESTION_ROUTE','ADD_UDP_ROUTE','VERIFY_GATEWAY','RESTORE_INGESTION_RESTART','RESTORE_UDP_RESTART','RESTORE_MCP_RESTART','VERIFY_FINAL')
LIMITS={'adminGets':32,'adminPuts':2,'engineGets':500,'engineWrites':22,'imageLoadAttempts':3,'ownerConfigurationReads':64,'quarantineStops':3,'readinessGets':128,'serviceCredentialFileReads':2}
LAST_PROGRESS={'adminGets':2,'adminPuts':0,'engineGets':119,'engineWrites':10,'imageLoadAttempts':3,'ownerConfigurationReads':40,'quarantineStops':0,'readinessGets':2,'serviceCredentialFileReads':2}
SOURCE_NAMES=set('apply.py continuation.py protocol.py transport.py ports.py quarantine.py recovery_journal.py engine_creation.py plan_helper.py image_custody.py native_prepare.py authentication.py signing.py auth_protocol.py auth_preexec.py auth_producer.py runtime_binding.py'.split())
CONFIG_NAMES=set('Hostname Domainname User AttachStdin AttachStdout AttachStderr ExposedPorts Tty OpenStdin StdinOnce Env Cmd Healthcheck Image Volumes WorkingDir Entrypoint Labels StopSignal StopTimeout MacAddress Shell OnBuild ArgsEscaped NetworkDisabled'.split())
class Stop(RuntimeError):pass
def require(ok,reason):
    if not ok:raise Stop(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(v):return sha(encoded(v))
def unique(rows):
    result={}
    for k,v in rows:require(k not in result,'DUPLICATE_RETAINED_JSON_KEY');result[k]=v
    return result
def decode(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(Stop('NONFINITE_RETAINED_JSON')))
def frame(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def ancestry(path):
    require(path.is_absolute()and path.resolve()==path,'CANONICAL_RETAINED_PATH_REQUIRED')
    for p in(path,*path.parents):
        s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_RETAINED_ANCESTRY_REQUIRED')
def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def put(path,value):
    raw=encoded(value);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        with os.fdopen(os.dup(fd),'wb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
    finally:os.close(fd)
    sync(path.parent)
class Reader:
    def __init__(self):self.reads=0;self.bytes=0;self.started=time.monotonic();self.facts={}
    def read(self,path,expected=None):
        require(time.monotonic()-self.started<30,'OFFLINE_GUARD_READER_DEADLINE');require(self.reads<640,'OFFLINE_METADATA_READ_LIMIT');self.reads+=1;ancestry(path.parent)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)in(0o400,0o600)and 0<before.st_size<=8388608,'BOUNDED_PRIVATE_RETAINED_FILE_REQUIRED')
            require(self.bytes+before.st_size<=67108864,'OFFLINE_METADATA_BYTE_LIMIT');raw=os.read(fd,before.st_size+1);self.bytes+=len(raw)
            require(len(raw)==before.st_size and frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'RETAINED_FILE_CHANGED')
            require(expected is None or sha(raw)==expected,'EXACT_RETAINED_HASH_REQUIRED')
            previous=self.facts.get(str(path));require(previous is None or previous==(frame(before),sha(raw)),'RETAINED_SNAPSHOT_CHANGED');self.facts[str(path)]=(frame(before),sha(raw));return raw
        finally:os.close(fd)
    def stable(self):
        for path,(metadata,_)in self.facts.items():require(frame(Path(path).lstat())==metadata,'RETAINED_METADATA_CHANGED')

def compare(original,observed,binding):
    require(original['Id']==observed['Id']==binding['containerId'],'EXACT_RETAINED_OLD_MCP_ID_REQUIRED')
    def components(value):return {'image':value['Image']==binding['imageId'],'config':digest(value['Config'])==binding['configHash'],'mounts':digest(sorted(value['Mounts'],key=lambda m:m['Destination']))==binding['mountsHash'],'startedAt':value['State']['StartedAt']==binding['startedAt']}
    require(all(components(original).values()),'ORIGINAL_MCP_CAPTURE_BINDING_REQUIRED');checks=components(observed);differences=[]
    before,after=original['Config'],observed['Config'];require(type(before)is dict and type(after)is dict and len(set(before)|set(after))<=128,'BOUNDED_DOCKER_CONFIG_REQUIRED')
    for name in sorted(set(before)|set(after)):
        a,b=before.get(name),after.get(name)
        if(name in before)==(name in after)and encoded(a)==encoded(b):continue
        row={'field':name if name in CONFIG_NAMES else'UNKNOWN_SHA256_'+sha(name.encode()),'beforePresent':name in before,'afterPresent':name in after,'beforeType':type(a).__name__,'afterType':type(b).__name__,'beforeDefaultLike':a in(None,False,0,'',[],{}),'afterDefaultLike':b in(None,False,0,'',[],{})}
        if name=='MacAddress':
            nets=original['NetworkSettings']['Networks'];row['beforeMatchesOriginalSingleEndpointMac']=len(nets)==1 and type(a)is str and type(next(iter(nets.values())).get('MacAddress'))is str and a.lower()==next(iter(nets.values()))['MacAddress'].lower()
        differences.append(row)
    return {'guardChecks':checks,'failedGuardComponents':[k for k,v in checks.items()if not v],'configDifferences':differences,'oldMcpStoppedInRetainedResponse':observed['State']['Running']is False and observed['State']['Pid']==0,'retainedNetworkEndpointCount':len(observed['NetworkSettings']['Networks'])}

def inspect(reader,root=ROOT,code=CODE,inputs_path=INPUTS,review_hash=REVIEW_HASH,authority_hash=AUTHORITY_HASH,manifest_hash=MANIFEST_HASH,inputs_hash=INPUTS_HASH):
    # Alternate paths/hashes exist only for fixture construction; main has no arguments.
    ancestry(root);child=root/CHILD;require(not os.path.lexists(child),'GUARD_READER_SCOPE_CONSUMED_NO_REPLAY');child.mkdir(mode=0o700);sync(root)
    put(child/'claim.json',{'schema':'ouf.acquisition-old-mcp-guard-reader-claim.v1','reviewHash':review_hash,'authorityHash':authority_hash,'maximumSeconds':30,'maximumMetadataReads':640,'maximumMetadataBytes':67108864,'runtimeEffectsAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False})
    names={p.name for p in root.iterdir()};require(len(names)<=1024,'BOUNDED_RETAINED_SCOPE_REQUIRED');manifest=decode(reader.read(code/'sources.json',manifest_hash));require(type(manifest)is dict and set(manifest)==SOURCE_NAMES,'EXACT_CLOSED_CONTINUATION_SOURCE_MANIFEST_REQUIRED')
    for name,h in manifest.items():require(type(h)is str and re.fullmatch('[a-f0-9]{64}',h),'TYPED_RETAINED_SOURCE_HASH_REQUIRED');reader.read(code/name,h)
    review=decode(reader.read(root/'review.json',review_hash));authority=decode(reader.read(root/'authority/authority.json',authority_hash))
    require(review['schema']=='ouf.acquisition-read-continuation-review.v1'and review['executionRoot']==str(root)and review['stages']==list(STAGES)and review['maximums']==LIMITS and digest(review['nativePlan'])==review['nativePlanHash'],'EXACT_CONTINUATION_REVIEW_REQUIRED')
    require(authority['schema']=='ouf.acquisition-read-native-authority.v1'and authority['scope']['reviewHash']==review_hash and authority['scope']['nativePlanHash']==review['nativePlanHash']and authority['scope']['stages']==list(STAGES)and authority['scope']['maximums']==LIMITS,'EXACT_ISSUED_AUTHORITY_BINDING_REQUIRED')
    raw=reader.read(root/'recovery.json');journal=decode(raw);require(journal['schema']=='ouf.acquisition-read-native-journal.v1'and journal['reviewHash']==review_hash and journal['authorityHash']==authority_hash and journal['nextStage']==13 and journal['state']in('OPEN','STOP_RECONCILE')and journal['automaticReplayAllowed']is False and journal['budgetReset']is False,'EXACT_RENAME_GUARD_STOP_JOURNAL_REQUIRED')
    require(len(journal['effects'])==13,'NO_RENAME_OR_LATER_CLAIM_ALLOWED')
    for i,effect in enumerate(journal['effects']):require(effect['stage']==STAGES[i]and effect['state']=='APPLIED'and effect['intentHash']==digest({'reviewHash':review_hash,'stage':STAGES[i]})and type(effect.get('proof'))is dict and bool(effect['proof']),'ORDERED_RETAINED_APPLIED_PREFIX_REQUIRED')
    counts=journal['counts'];require(set(counts)==set(LIMITS)and all(type(v)is int and LAST_PROGRESS[k]<=v<=LIMITS[k]for k,v in counts.items())and counts['imageLoadAttempts']==3 and counts['adminPuts']==0 and counts['serviceCredentialFileReads']==2,'PRESERVED_CUMULATIVE_COUNTERS_REQUIRED')
    require(set(journal['candidates'])=={'ingestion','udp'}and all(c.get('configurationVerified')is True and c.get('readinessProven')is True for c in journal['candidates'].values()),'ONLY_TWO_VERIFIED_READ_CANDIDATES_NO_NEW_MCP_REQUIRED')
    proposal=review['nativePlan']['proposal'];binding=proposal['mcpReplacement']['oldBinding'];inputs=decode(reader.read(inputs_path,inputs_hash));require(proposal['capturedInputsHash']==inputs_hash,'EXACT_CAPTURED_INPUT_REFERENCE_REQUIRED');ref=inputs['currentObservations']['mcp'];original=decode(reader.read(Path(ref['path']),ref['sha256']))
    files=sorted((n for n in names if re.fullmatch(r'engine-response-[0-9]{4}\.json',n)),key=lambda n:int(n[-9:-5]));require(0<len(files)<=522,'BOUNDED_RETAINED_ENGINE_RESPONSES_REQUIRED');latest=None
    for name in files:
        value=decode(reader.read(root/name));body=value.get('body')
        if value.get('status')==200 and type(body)is dict and body.get('Id')==binding['containerId']:latest=(name,body)
    require(latest is not None,'RETAINED_OLD_MCP_GUARD_RESPONSE_REQUIRED');comparison=compare(original,latest[1],binding);require(bool(comparison['failedGuardComponents']),'ORIGINAL_MCP_GUARD_FAILURE_MUST_REPRODUCE')
    require(journal['effects'][-1]['proof'].get('oldDetached')is True and journal['effects'][-2]['proof'].get('oldStopped')is True,'RETAINED_STOP_AND_DETACH_PROOFS_REQUIRED')
    quarantine=journal['quarantine'];require(quarantine is None or type(quarantine)is dict and quarantine.get('state')in('CLAIMED','APPLIED'),'TYPED_RETAINED_NEGATIVE_STATE_REQUIRED')
    qrows={}if quarantine is None else quarantine.get('candidates',{});require(set(qrows)<={'ingestion','udp'},'ONLY_OWNED_READ_QUARANTINE_REQUIRED');stopped=[r for r,v in qrows.items()if v.get('stopped')is True and v.get('restartDisabled')is True and v.get('id')==journal['candidates'][r]['id']]
    markers={}
    for name in('quarantine-result.json','quarantine-unproven.json','watchdog-unproven.json'):
        if name in names:
            m=decode(reader.read(root/name));markers[name]={'present':True,'status':m.get('status')if m.get('status')in('OWNED_CANDIDATES_QUARANTINED','STOP_RECONCILE')else'UNKNOWN_RETAINED_STATUS'}
    reader.read(root/'recovery.json',sha(raw));reader.stable();require({p.name for p in root.iterdir()}==names,'RETAINED_SCOPE_ENTRY_SET_CHANGED')
    evidence={'reviewHash':review_hash,'authorityHash':authority_hash,'journalHash':sha(raw),'selectedOldMcpResponseFile':latest[0],'fileHashes':{p:h for p,(_,h)in reader.facts.items()},'comparison':comparison};put(child/'private-evidence.json',evidence)
    result={'schema':'ouf.acquisition-old-mcp-guard-retained-result.v1','status':'RETAINED_OLD_MCP_GUARD_DIFFERENCE_OBSERVED','complete':True,'reviewHash':review_hash,'authorityHash':authority_hash,'journalHash':sha(raw),'privateEvidenceHash':digest(evidence),'nextStage':'RENAME_OLD_MCP','appliedStages':13,'renameClaimed':False,'newMcpCreated':False,'currentRuntimeStateObserved':False,'recordedCounts':counts,'maximums':LIMITS,**comparison,'oldMcpNamePreservedInRetainedResponse':latest[1]['Name']=='/'+proposal['mcpReplacement']['name'],'oldMcpEndpointDetachedInRetainedResponse':proposal['mcpReplacement']['network']['name']not in latest[1]['NetworkSettings']['Networks'],'negativeJournalState':None if quarantine is None else quarantine['state'],'negativeCandidateStopsProvenInRetainedJournal':sorted(stopped),'negativeMarkers':markers,'privateMetadataReads':reader.reads,'maximumPrivateMetadataReads':640,'newEngineRequests':0,'newAdminRequests':0,'newCredentialReads':0,'newSigningKeyReads':0,'sqlSessions':0,'oauthRequests':0,'humanBudgetsGranted':0,'sourceActivations':0,'originalRetainedFileWrites':0,'automaticReplayAllowed':False,'budgetReset':False,'continuationAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False}
    put(child/'complete.json',result);reader.stable();return result
def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ONE_ISOLATED_ROOT_RETAINED_GUARD_READER_REQUIRED')
        def timeout(*_):raise Stop('OFFLINE_GUARD_READER_DEADLINE')
        signal.signal(signal.SIGALRM,timeout);signal.alarm(30);result=inspect(Reader())
    except Exception as error:
        reason=str(error)if type(error)is Stop and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'RETAINED_MCP_GUARD_DIFFERENCE_UNPROVEN'
        result={'schema':'ouf.acquisition-old-mcp-guard-retained-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,'automaticReplayAllowed':False,'budgetReset':False,'continuationAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False}
    print(encoded(result).decode(),flush=True);return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
