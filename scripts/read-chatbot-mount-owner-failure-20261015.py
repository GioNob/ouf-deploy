#!/usr/bin/env python3
"""Read only the fixed failed mount-owner action; never read bearer/secret files.

No source bodies are executed. No IAM/DB call, grant, signal, writer repair,
Docker mutation, budget change, admission, signature or runtime authority.
"""
import base64,hashlib,http.client,json,math,os,re,signal,socket,stat,subprocess,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-d3ef7a038a6b587dde883e802080cb393732be9c4399f98e43a1a3ff6b3b2c2f')
REVIEW='2380132af8e47de185894fde156470e162dab784942c8615778e7620e7f8fc60'
AUTHORITY='8c59697f46b3ce1b54d1cff1acf1f08dde6c4087062d28e379465d9a76ec570a'
SOURCE='b7d24c57d6e45e71994ac3f99f56f249d83cde22'
UNIT='ouf-file-cohort-d3ef7a038a6b587dde883e802080cb39.service'
CID='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
CLAIM='chatbot-file-cohort-paused-attestation-fa7bdc08f0c0ea048b064774648176cf54ce51279118ce1df0ff296fc8616d3b.claim.json'
OLD_TRANSITION='af9c88a9ca302cc69ec11b2a85035510eb03d7282d7409b46be88aa720ecbb8f'
PHASES=('STOP_REVOKE_OLD_LEASE','QUIESCE_PRODUCERS','FENCED_BACKUP','RELEASE_OLD_ENDPOINT','CREATE_REPLACEMENT','STAGE_PAUSED_REPLACEMENT','ATTEST_NEW_OCI_PEER','ADMIT_MIGRATION','START_REPLACEMENT','VERIFY_APPLICATION','RELEASE_PRODUCERS')
SOURCE_PINS={'tools.semantic_policy_token_owner.mount_observation':'f02137f9b2af62ddcfec9aad554ea572a0440870dfc065a23a21de2e58eff5b8',
    'tools.semantic_policy_token_owner.iam_admission':'4519d1d8685e29329d47378302fa1bf9ddbb6a36325b0181020a9c8eb0e29f16',
    'file_only_frame_observation':'ec2fc0a490bf8e52f7187be23e03eb7d3ead40c650e29c38c245b9291b6c3f2f'}
READS={};ERRORS=[]
class ReadDenied(Exception):pass

def require(ok,code):
    if not ok:raise ReadDenied(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def unique(pairs):
    result={}
    for key,value in pairs:require(key not in result,'DUPLICATE_JSON_KEY');result[key]=value
    return result

def read(path,maximum=262144,expected=None):
    path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_READ_PATH_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_CONTROLLED_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
            and s.st_nlink==1 and 0<s.st_size<=maximum,'PRIVATE_BOUNDED_RECORD_REQUIRED')
        data=bytearray()
        while len(data)<=maximum:
            part=os.read(fd,min(65536,maximum+1-len(data)))
            if not part:break
            data.extend(part)
        h=hashlib.sha256(data).hexdigest()
        require(len(data)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(path.lstat()),'PRIVATE_RECORD_READ_DRIFT')
        require(expected is None or h==expected,'PRIVATE_RECORD_HASH_DRIFT')
        if str(path)in READS:require(READS[str(path)][0]==h,'PRIVATE_RECORD_CHANGED_DURING_DIAGNOSIS')
        READS[str(path)]=(h,maximum)
        return json.loads(data,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(ReadDenied('NONFINITE_JSON')))
    finally:os.close(fd)

def emit(check,**values):
    fixed={'schema':'ouf.chatbot-mount-owner-failure-readback.v1','check':check,'readOnly':True,'automaticRetry':False,'budgetReset':False}
    require(not set(fixed)&set(values),'RESERVED_DIAGNOSTIC_FIELD')
    print(json.dumps({**fixed,**values},sort_keys=True),flush=True)
def attempt(check,call):
    try:return call()
    except Exception as error:
        ERRORS.append(check)
        # Only this reader's static codes may leave the process.
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)is not None,'CLOSED_PUBLIC_ERROR_REQUIRED')
        emit(check,status='UNAVAILABLE',reason=reason,exceptionMessagePrinted=False)

def projection(row):
    result={k:row[k]for k in('state','version','attempts','publicationCount','controlledPredecessorGrantAttempts','controlledCumulativeGrantAttempts','nextPhase','nextStep')if k in row}
    require(all(type(v)is int or(type(v)is str and re.fullmatch('[A-Z][A-Z0-9_]{0,79}',v))for v in result.values()),'CLOSED_RECORD_PROJECTION_REQUIRED')
    return result

def systemd(binding):
    path=Path(binding['path']);s=path.stat()
    require(str(path)=='/usr/bin/systemctl'and stat.S_ISREG(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
        and hashlib.sha256(path.read_bytes()).hexdigest()==binding['sha256'],'PINNED_SYSTEMD_READ_REQUIRED')
    p=subprocess.run([str(path),'show',UNIT,'--property=LoadState,ActiveState,SubState,MainPID,Job'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(p.returncode==0 and len(p.stdout)<=8192,'BOUNDED_SYSTEMD_GET_REQUIRED')
    rows=dict(line.split('=',1)for line in p.stdout.decode('ascii').splitlines()if'='in line)
    require(rows.get('ActiveState')in('inactive','failed')and rows.get('MainPID')=='0'and rows.get('Job')=='','OLD_ACTION_MUST_BE_STOPPED_NO_REPLAY')
    require(identity(s)==identity(path.stat()),'PINNED_SYSTEMD_CHANGED')
    return {'stopped':True,'loadState':rows.get('LoadState'),'activeState':rows['ActiveState']}

def inspect(engine):
    path=engine['socketPath'];pin=tuple(engine['socketBinding'])
    def guard():
        s=os.stat(path,follow_symlinks=False);require(stat.S_ISSOCK(s.st_mode)and(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==pin,'PINNED_ENGINE_SOCKET_DRIFT')
    guard()
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(10);self.sock.connect(path)
    c=Local('localhost',timeout=10)
    try:
        c.request('GET','/v1.44/containers/'+CID+'/json');r=c.getresponse();raw=r.read(2097153)
        require(r.status==200 and len(raw)<=2097152,'BOUNDED_CONTAINER_GET_REQUIRED');guard()
        return json.loads(raw,object_pairs_hook=unique)
    finally:c.close()

def journal(label,path):
    row=read(path);emit(label,recordHash=READS[str(Path(path))][0],**projection(row));return row

def source_check(bundle):
    for name,pin in SOURCE_PINS.items():
        require(bundle['declaration']['sourceHashes'].get(name)==pin,'FAILED_SOURCE_DECLARATION_PIN_DRIFT')
        raw=base64.b64decode(bundle['sources'][name],validate=True)
        require(0<len(raw)<=262144 and hashlib.sha256(raw).hexdigest()==pin,'FAILED_SOURCE_BYTES_PIN_DRIFT')
    emit('FAILED_SOURCE',exactFrozenMountOwnerAndFrameSources=True,sourceBodiesExecuted=False)

def transition_check(paths):
    row=read(Path(paths['transition'])/'recovery.json');effects=row.get('effects',[])
    require(type(effects)is list and all(x.get('phase')in PHASES and x.get('state')in('APPLIED','IN_FLIGHT','NO_EFFECT','UNKNOWN')for x in effects),'CLOSED_TRANSITION_PROJECTION_REQUIRED')
    marker=row.get('governedUnsignedReprocessing',{})
    emit('REGISTRY_TRANSITION',recordHash=digest(row),**projection(row),phases=[{'phase':x['phase'],'state':x['state']}for x in effects],
        oldFailedIntentRetained=marker.get('predecessorJournalHash')==OLD_TRANSITION,
        firstSixApplied=len(effects)>=6 and all(x['phase']==PHASES[i]and x['state']=='APPLIED'for i,x in enumerate(effects[:6])),
        failedSeventhUnsignedBoundary=row.get('nextPhase')==6 and len(effects)==7 and effects[6]['phase']=='ATTEST_NEW_OCI_PEER'and effects[6]['state']=='IN_FLIGHT')
    return row

def node_check(paths):
    root=Path(paths['node']);s=root.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'PRIVATE_NODE_DIRECTORY_REQUIRED')
    names=set(os.listdir(root));claims={'attestation-issuance-claim.json','paused-acceptance.json'}
    receipt=Path(paths['evidence'])/'ATTEST_NEW_OCI_PEER.json'
    emit('UNSIGNED_NODE_BOUNDARY',nodeContainsOnlyFramePolicy=names=={'frame-policy.json'},issuanceClaimAbsent=not bool(claims&names),
        acceptedPhaseReceiptAbsent=not os.path.lexists(receipt),unknownNodeMemberPresent=bool(names-claims-{'frame-policy.json'}),signatureIssuedByReader=False)
    policy=read(root/'frame-policy.json',131072)
    return policy

def lifetime_check(prepared,policy,worker):
    profile=prepared['owner']['iamProfile'];binding=prepared['owner']['binding'];minimum=policy['renewableToken']['minimumRemainingSeconds']
    required=profile['minimum_remaining'];require(type(minimum)is int and 1<=minimum<=3600 and type(required)is int and required==binding['minimum_remaining'],'EXACT_MINIMUM_METADATA_REQUIRED')
    emit('MOUNT_OWNER_LIFETIME_CONTRACT',mountMinimumRemainingSeconds=minimum,maximumReadDeadlineSeconds=30,ownerMinimumRemainingSeconds=required,
        oldCallerMaximumValiditySeconds=30+minimum,oldCallerAlwaysBelowOwnerMinimum=30+minimum<required,
        lifecycleDeadlineIsNotTokenExpiry=True,issuerTokenLifetimeObserved=False)
    wall,mono=time.time(),time.monotonic();window={}
    for key,now in(('tokenExpiresWall',wall),('tokenExpiresMonotonic',mono)):
        value=worker.get(key)
        if type(value)in(int,float)and math.isfinite(value):window[key+'RemainingSeconds']=max(0,int(value-now))
        else:window[key+'RemainingSeconds']=None
    emit('RETAINED_PUBLICATION_WINDOW',**window,currentTokenOrCredentialRead=False,windowIsHistoricalWorkerMetadataOnly=True)

def main():
    require(os.geteuid()==0,'ROOT_READ_ACCESS_REQUIRED');signal.alarm(90)
    emit('BEGIN',serviceMutations=0,databaseMutations=0,grantRequests=0,iamCalls=0,credentialOrTokenFilesRead=False)
    review=read(CONTEXT/'review.json',262144,REVIEW)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE,'EXACT_FAILED_SOURCE_REQUIRED')
    authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(all(authority.get(k)==v for k,v in review['scopes'].items()),'FAILED_SIGNED_SCOPE_DRIFT')
    process=review['scopes']['finiteActionProcess'];require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'EXACT_FAILED_PROCESS_REQUIRED')
    emit('PROCESS',**systemd(review['sourceClosure']['executables']['systemctl']))
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);prepared=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']and digest(prepared)==review['privateInputHashes']['preparedInputs'],'RETAINED_PRIVATE_INPUT_DRIFT')
    source_check(bundle)
    status=read(CONTEXT/'delivery-status.json',16384);require(status.get('authorityHash')==AUTHORITY and status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION'and status.get('reason')=='Permanent','EXACT_FAILED_MOUNT_OWNER_STATUS_REQUIRED')
    emit('STATUS',phase=status['phase'],reason=status['reason'],sourceCommit=SOURCE,authorityExpiredNow=authority['expiresAt']<=time.time())
    decision=read(CONTEXT/'decision.json');require(decision.get('approvedReviewHash')==REVIEW,'FAILED_DECISION_REVIEW_DRIFT')
    claim=journal('INCIDENT_CLAIM',CONTEXT.parent/CLAIM);require(claim.get('authorityHash')==AUTHORITY,'FAILED_INCIDENT_CLAIM_DRIFT')
    paths=prepared['registry']['directoryPlan'];attempt('REGISTRY_TRANSITION',lambda:transition_check(paths))
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    worker=journal('WORKER',owner/'recovery.json')
    session=journal('WORKER_SESSION',owner/'owner-session.json');admission=journal('ADMISSION',owner/'owner-admission.json')
    require(digest(session)==worker.get('workerSessionHash')and session==review['scopes']['policyTokenFiniteWorkerSession'],'SIGNED_WORKER_SESSION_DRIFT')
    emit('WORKER_HISTORY',priorControlledGrantAttempts=worker.get('controlledPredecessorGrantAttempts'),attempts=worker.get('attempts'),
        cumulativeAttempts=worker.get('controlledCumulativeGrantAttempts'),cumulativeEquationPass=worker.get('controlledCumulativeGrantAttempts')==worker.get('controlledPredecessorGrantAttempts',-1)+worker.get('attempts',-1),
        markerBlocked=admission.get('state')=='BLOCKED',firstGrantReceiptUnchanged=worker.get('firstGrantReceiptHash')=='4bb904ea93df0766647641fd397cac7d8504f1ca81252ce597d1db363a86105a')
    policy=attempt('UNSIGNED_NODE_BOUNDARY',lambda:node_check(paths))
    if policy is not None:attempt('MOUNT_OWNER_LIFETIME_CONTRACT',lambda:lifetime_check(prepared,policy,worker))
    for label in('authorization','containers','databases','gateway'):
        def later(label=label):
            row=journal('LATER_'+label,Path(process['directoryPlan'][label])/'recovery.json')
            emit('LATER_EFFECTS_'+label,effectCount=len(row.get('effects',[])),backupCount=len(row.get('backups',{})),mcpMigrationPresent=row.get('mcpMigration')is not None,mcpAuditRolePresent=row.get('mcpAuditRole')is not None)
        attempt('LATER_'+label,later)
    def native():
        row=inspect(prepared['engine']);require(row['Id']==CID,'EXACT_RETAINED_CONTAINER_REQUIRED');s=row['State']
        require(s.get('Status')in('created','running','paused','restarting','removing','exited','dead'),'CLOSED_NATIVE_STATE_REQUIRED')
        emit('REGISTRY_NATIVE',containerId=CID,running=s['Running'],paused=s['Paused'],status=s['Status'],pid=s['Pid'],restartCount=row['RestartCount'])
    attempt('REGISTRY_NATIVE',native)
    for path,(h,maximum)in list(READS.items()):read(path,maximum,h)
    emit('END',complete=not ERRORS,unavailableChecks=ERRORS,retainedRecordsStable=True,serviceMutations=0,databaseMutations=0,grantRequests=0,iamCalls=0,
        credentialOrTokenFilesRead=False,sourceBodiesExecuted=False,authorityRenewed=False,runtimeAuthorityIssued=False,chatbotEndToEndProven=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',exceptionMessagePrinted=False)
        raise SystemExit(1)
