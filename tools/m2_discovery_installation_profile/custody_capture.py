"""One fresh, bounded local custody capture; no IAM/Engine/network or authority.

Historical bytes select exact candidates only. Current process pins and file
identities are checked again. No credential/key bytes are printed or spooled.
"""
import hashlib,hmac,json,os,stat,time
from pathlib import Path

INPUT_ROOT=Path('/etc/ouf/deploy-snapshots/m2-discovery-installation-inputs-14e42ac9-20261029-v1')
INPUT_HASH='f759d397c000eba5b3113bcfee44bedf215577c81e9c40eccd98616a38714c6d'
MATERIAL_ROOT=Path('/etc/ouf/deploy-snapshots/semantic-discovery-runtime-inputs-682nr5ky')
MANIFEST_HASH='732a633e46cb06bb720352aa6a90946281ba6489e94aa35dc04820eae56b4a70'
SCOPE=Path('/etc/ouf/deploy-snapshots/m2-discovery-custody-f759d397-20261029-v1')
ROLES={'semantic','mcp','apisix','gateway-owner'}

class Stop(ValueError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def attrs(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def decode(raw):
    def pairs(rows):
        d=dict(rows);require(len(d)==len(rows),'DUPLICATE_PRIVATE_METADATA_KEY');return d
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:require(False,'NONFINITE_PRIVATE_METADATA'))
def process_pin(pid):
    require(type(pid) is int and pid>=1,'POSITIVE_CUSTODY_PID_REQUIRED')
    raw=Path('/proc/'+str(pid)+'/stat').read_bytes()
    require(0<len(raw)<16384 and b') ' in raw,'BOUNDED_CUSTODY_PROCESS_REQUIRED')
    namespaces={}
    for name in ('net','mnt'):
        info=Path('/proc/'+str(pid)+'/ns/'+name).stat();namespaces[name]=[info.st_dev,info.st_ino]
    return {'pid':pid,'startTicks':int(raw.rsplit(b') ',1)[1].split()[19]),'namespaces':namespaces}

class Capture:
    def __init__(self,scope):
        require(os.geteuid()==0,'ROOT_CUSTODY_CAPTURE_REQUIRED')
        scope=Path(scope);self.ancestors(scope)
        require(not os.path.lexists(scope),'CUSTODY_CAPTURE_SCOPE_CONSUMED_NO_REPLAY')
        os.mkdir(scope,0o700);self.scope=scope;self.until=time.monotonic()+45
        self.counts={'metadataReads':0,'credentialFileReads':0,'applicationMacKeyReads':0,'publicCertificateReads':0,'bytes':0}
        self.seals={};self.put('capture.claim.json',{'schema':'ouf.m2-discovery-custody-capture-claim.v1','automaticReplayAllowed':False})
    def check(self):require(time.monotonic()<self.until,'CUSTODY_CAPTURE_DEADLINE')
    @staticmethod
    def ancestors(path):
        require(path.is_absolute() and path.resolve()==path,'EXACT_CUSTODY_PATH_REQUIRED')
        for p in path.parents:
            s=p.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ROOT_PRIVATE_CUSTODY_ANCESTRY_REQUIRED')
    def put(self,name,value):
        raw=encoded(value);fd=os.open(self.scope/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(os.dup(fd),'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        finally:os.close(fd)
        fd=os.open(self.scope,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def read(self,path,uid,gid,mode,maximum,kind):
        self.check();path=Path(path);self.ancestors(path)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            s=os.fstat(fd)
            require(stat.S_ISREG(s.st_mode) and s.st_uid==uid and s.st_gid==gid and stat.S_IMODE(s.st_mode)==mode
                and s.st_nlink==1 and 0<s.st_size<=maximum,'CUSTODY_FILE_METADATA_UNPROVEN')
            raw=os.read(fd,maximum+1)
            require(len(raw)==s.st_size and attrs(s)==attrs(os.fstat(fd))==attrs(path.lstat()),'CUSTODY_FILE_CHANGED_DURING_READ')
        finally:os.close(fd)
        self.counts[kind]+=1;self.counts['bytes']+=len(raw)
        require(self.counts['bytes']<=4194304,'CUSTODY_CAPTURE_BYTE_LIMIT')
        self.seals[str(path)]=attrs(s);self.check();return raw

def collect(c,input_root=INPUT_ROOT,material_root=MATERIAL_ROOT,input_hash=INPUT_HASH,manifest_hash=MANIFEST_HASH,
            pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id')):
    inputs=decode(c.read(input_root/'inputs.json',0,0,0o600,2097152,'metadataReads'))
    require(inputs.get('schema')=='ouf.m2-discovery-private-installation-inputs.v1' and digest(inputs)==input_hash,
        'EXACT_CONSUMED_INSTALLATION_INPUT_PROVENANCE_REQUIRED')
    require(all(inputs.get(k) is False for k in ('historicalAuthorityReused','runtimeAuthorityIssued','automaticReplayAllowed','budgetReset')),
        'CAPTURE_CANNOT_GRANT_HISTORICAL_AUTHORITY')
    require(set(inputs['observations'])==set(inputs['processPins'])==ROLES,'EXACT_FOUR_CUSTODY_PROCESS_ROLES_REQUIRED')
    boot=boot_path.read_text().strip();require(boot==inputs['bootId'],'CUSTODY_CAPTURE_BOOT_CHANGED')
    for role,p in inputs['processPins'].items():
        require(inputs['observations'][role]['State']['Pid']==p['pid'] and pin(p['pid'])==p,'CUSTODY_CAPTURE_PROCESS_CHANGED')
    raw=c.read(material_root/'private-input-manifest.json',0,0,0o600,131072,'metadataReads');manifest=decode(raw)
    require(hashlib.sha256(raw).hexdigest()==manifest_hash
        and manifest.get('schema')=='ouf.discovery.private-runtime-input-manifest.v1'
        and manifest.get('mountsInstalled') is False and manifest.get('applicationCutoverAuthorized') is False
        and manifest.get('leaseAuthorityGranted') is False,'EXACT_UNAPPLIED_MATERIAL_PROVENANCE_REQUIRED')
    definitions=[('providerCredential','schema-gov-client-secret',10001,10001,'existingWorkloadCredentialHash',4096,'credentialFileReads'),
        ('registryDiscoveryKey','semantic-discovery-owner.key',10001,10001,'discoveryMacKeyHash',64,'applicationMacKeyReads'),
        ('gatewayDiscoveryKey','gateway-discovery-owner.key',636,636,'discoveryMacKeyHash',64,'applicationMacKeyReads'),
        ('publicProviderCa','provider-public-ca.crt',0,0,'publicCaHash',1048576,'publicCertificateReads')]
    candidates={}
    for role,name,uid,gid,key,limit,kind in definitions:
        p=material_root/name;raw=c.read(p,uid,gid,0o400 if uid else 0o600,limit,kind)
        require(hmac.compare_digest(hashlib.sha256(raw).hexdigest(),manifest[key]),'CUSTODY_MATERIAL_CONTENT_IDENTITY_DRIFT')
        if role.endswith('Key'):require(len(raw)==64 and all(chr(b) in '0123456789abcdef' for b in raw),'EXACT_DISCOVERY_MAC_KEY_REQUIRED')
        candidates[role]={'path':str(p),'sha256':manifest[key],'uid':uid,'gid':gid,'mode':0o400 if uid else 0o600,
            'metadata':c.seals[str(p)],'historicalAuthorityReused':False,'runtimeAdmissionProven':False}
    require(candidates['registryDiscoveryKey']['sha256']==candidates['gatewayDiscoveryKey']['sha256'],
        'DISCOVERY_CONSUMER_KEY_PAIR_DRIFT')
    require(boot_path.read_text().strip()==boot and all(pin(p['pid'])==p for p in inputs['processPins'].values()),
        'CUSTODY_CAPTURE_PROCESS_OR_BOOT_CHANGED')
    require(all(attrs(Path(p).lstat())==s for p,s in c.seals.items()),'CUSTODY_CAPTURE_INPUT_CHANGED')
    private={'schema':'ouf.m2-discovery-current-material-candidates.v1','installationInputsHash':input_hash,
        'materialManifestHash':manifest_hash,'processPins':inputs['processPins'],'candidates':candidates,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'historicalAuthorityReused':False}
    c.put('material-candidates.private.json',private)
    return {'schema':'ouf.m2-discovery-custody-capture-result.v1','status':'MATERIAL_CUSTODY_CANDIDATES_CAPTURED_NOT_ADMITTED',
        'complete':True,'scope':str(c.scope),'candidateBindingHash':digest(private),'counts':dict(c.counts),
        'currentProcessPinsObserved':4,'historicalAuthorityReused':False,'candidateFilesVerified':4,
        'matchedHistoricalHashesAreNotCurrentIamAdmission':True,'rawCredentialOrKeyValuesPrinted':False,
        'engineGets':0,'engineWrites':0,'sqlSessions':0,'iamRequests':0,'oauthRequests':0,'newKeysGenerated':0,
        'deploymentSigningKeyReads':0,'signaturesIssued':0,'containerLifecycleOperations':0,'imageImports':0,
        'budgetsGranted':0,'budgetReset':False,'automaticReplayAllowed':False,'scopeConsumed':True,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'stableCapabilitiesOperationalProven':False,
        'applicationE2EProven':False,'releaseAcceptance':False}

def main():
    c=None
    try:
        c=Capture(SCOPE);result=collect(c);c.put('result.json',result);code=0
    except Exception as e:
        result={'schema':'ouf.m2-discovery-custody-capture-result.v1','status':'STOP_RECONCILE',
            'reasonCode':str(e) if type(e) is Stop else 'CUSTODY_CAPTURE_UNPROVEN','complete':False,
            'scope':str(SCOPE),'scopeConsumed':os.path.lexists(SCOPE),'counts':dict(c.counts) if c else {},
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if c:
            try:c.put('result.json',result)
            except Exception:pass
        code=1
    print(json.dumps(result,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
