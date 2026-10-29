"""One-use root custody preparation only; no application/lease/network apply.
Existing OAuth credential is not rotated. New discovery MAC is separate from
consultation/provider/authority keys and copied for the two observed role UIDs.
"""
import hashlib,hmac,json,os,pwd,re,secrets,stat,subprocess,sys,tempfile,types
from pathlib import Path
ENVELOPE=Path('/home/oufadmin/ouf-semantic-workload-custody-ukcp1fpq/private-workload-custody.json')
ENVELOPE_HASH='39157d824a106eae23f7e11f2d3384d2606c3739eca2ed85c7e3ec8a14f7eab1'
READER_HASH='b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf'
PROFILE_HASH='05ac25e1dba32460d934865a0e2555ae22890eca7ce56392dfaa98aea7ed8a0b'
SEMANTIC='7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147'
SEMANTIC_IMAGE='sha256:f6525f2512c72a600ebcbc7060d55355d86e0627487b655e7c5c6288a0be7fc6'
SOUTHBOUND='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
DRIVER_HASH='66ff61a2a5f5a40279b615c7962796ebde6b0432dae167443a4ae4a3db8a5836'
SOUTHBOUND_PROFILE='dadb08b067e1a14dfdfe3fc8360f5544dc30885148a0d5c730913eb7c3d7073f'
CLAIM=Path('/etc/ouf/semantic-discovery-runtime-inputs-20261010.claim')
BASE=Path('/etc/ouf/deploy-snapshots')
DECISION='CHAT_OPERATOR_TECHNICAL_DELEGATION_20261010T091230_CEST'

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(ok,reason):
    if not ok:raise ValueError(reason)
def identity(v):return {'containerId':v['Id'],'imageId':v['Image'],'configurationHash':sha(encoded({k:v[k] for k in ('Config','HostConfig','Mounts')}|{'networks':v['NetworkSettings']['Networks']})),'generation':{k:v['State'][k] for k in ('Pid','StartedAt','Running')}}
def file_bytes(path,uid,modes,limit=2000000,expected=None):
    path=Path(path);require(path.is_absolute() and '..' not in path.parts,'EXACT_INPUT_PATH_REQUIRED')
    allowed={0,uid}
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid in allowed and not s.st_mode&0o022,'INPUT_ANCESTOR_CUSTODY_UNPROVEN')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==uid and before.st_nlink==1 and stat.S_IMODE(before.st_mode) in modes and before.st_size<=limit,'INPUT_FILE_CUSTODY_UNPROVEN')
        chunks=[];size=0
        while raw:=os.read(fd,min(65536,limit+1-size)):
            size+=len(raw);require(size<=limit,'BOUNDED_INPUT_REQUIRED');chunks.append(raw)
        raw=b''.join(chunks)
        def same(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(same(before)==same(os.fstat(fd))==same(path.lstat()) and len(raw)==before.st_size,'INPUT_CHANGED_DURING_READ')
    finally:os.close(fd)
    require(expected is None or sha(raw)==expected,'EXACT_INPUT_HASH_REQUIRED');return raw
def create(path,raw,uid=0,gid=0,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        os.fchown(fd,uid,gid);os.fchmod(fd,mode)
        with os.fdopen(os.dup(fd),'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    directory=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(directory)
    finally:os.close(directory)
def validate_envelope(v):
    require(type(v) is dict and set(v)=={'schema','clientId','credential','profileHash','profile','iam','gateway','gatewayWorkerIdentity'} and v['schema']=='ouf.discovery.private-semantic-workload-custody.v1' and v['clientId']=='ouf-semantic' and v['profileHash']==PROFILE_HASH and sha(encoded(v['profile']))==PROFILE_HASH,'EXACT_WORKLOAD_ENVELOPE_REQUIRED')
    require(type(v['credential']) is str and re.fullmatch('[!-~]{16,1024}',v['credential']),'EXACT_BOUNDED_WORKLOAD_CREDENTIAL_REQUIRED')
    require(v['gatewayWorkerIdentity']=={'uid':636,'gid':636,'observedNginxUids':[636],'observedNginxGids':[636],'hostUserNamespaceTranslationRequired':False},'EXACT_OBSERVED_GATEWAY_ROLE_REQUIRED')

def prepare_files(root,claim,credential,ca,bindings):
    """Actual POSIX custody boundary; the caller has authenticated all inputs."""
    require(os.geteuid()==0,'ROOT_CUSTODY_REQUIRED')
    s=Path(root).lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700,'EXCLUSIVE_PRIVATE_ROOT_REQUIRED')
    create(claim,encoded({'schema':'ouf.discovery.runtime-input-preparation-claim.v1','directory':str(root),'decisionRef':DECISION,'inputBindings':bindings,'applicationCutoverAuthorized':False,'leaseAuthorityGranted':False}))
    # One random key, separate copies owned by their actual consumers.
    key=secrets.token_hex(32).encode()
    create(root/'schema-gov-client-secret',credential.encode(),10001,10001,0o400)
    create(root/'semantic-discovery-owner.key',key,10001,10001,0o400)
    create(root/'gateway-discovery-owner.key',key,636,636,0o400)
    create(root/'provider-public-ca.crt',ca,0,0,0o600)
    manifest={'schema':'ouf.discovery.private-runtime-input-manifest.v1','inputBindings':bindings,'existingWorkloadCredentialHash':sha(credential.encode()),'discoveryMacKeyHash':sha(key),'publicCaHash':sha(ca),'consumerIdentities':{'semantic':{'uid':10001,'gid':10001},'gateway':{'uid':636,'gid':636}},'mountsInstalled':False,'applicationCutoverAuthorized':False,'leaseAuthorityGranted':False}
    create(root/'private-input-manifest.json',encoded(manifest));return sha(encoded(manifest))

def public_trust_source(bundle,policy,live,startup):
    """Bind public TLS custody through the admitted read-only APISIX config.
    That config contains a private key: validate its sealed metadata, never open it.
    """
    target='/usr/local/apisix/conf/config.yaml'
    source=str(BASE/'semantic-provider-v2-inputs-XE7IwlGm/config.yaml')
    config_hash='77342a509b0b0e9498728fa366f50ce031c19d78a636d4225de5e95e1ba97140'
    mounts=[m for m in bundle['mounts'] if m.get('destination')==target]
    require(len(mounts)==1 and mounts[0].get('type')=='bind' and mounts[0].get('source')==source and bool({'ro','rro'} & set(mounts[0].get('options') or [])) and 'rw' not in mounts[0]['options'],'EXACT_READ_ONLY_SOUTHBOUND_CONFIGURATION_REQUIRED')
    require(policy.get('schema')=='ouf.semantic-configured-creation-frame-policy.v1' and sha(encoded(policy['expectedOci']))==sha(encoded(bundle)),'EXACT_ADMITTED_CREATION_FRAME_REQUIRED')
    sources=[v for v in policy['sources'] if v.get('target')==target]
    require(len(sources)==1 and sources[0].get('source')==source and sources[0].get('readOnly') is True and sources[0].get('sha256')==config_hash and (sources[0].get('uid'),sources[0].get('gid'),sources[0].get('mode'))==(636,636,0o600),'SEALED_SOUTHBOUND_CONFIGURATION_SOURCE_REQUIRED')
    current=[m for m in live['Mounts'] if m.get('Destination')==target]
    require(live['Id']==SOUTHBOUND and live['Image']=='sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366' and live['State']['Running'] is True and len(current)==1 and current[0].get('Type')=='bind' and current[0].get('Source')==source and current[0].get('RW') is False,'CURRENT_READ_ONLY_SOUTHBOUND_CONFIGURATION_REQUIRED')
    trust=BASE/'semantic-provider-v2-trust-vf7B4SM5'
    require(startup.get('schema')=='ouf.semantic-provider-v2-startup-inputs.v1' and startup.get('status')=='PRIVATE_STARTUP_INPUTS_PREPARED' and startup.get('directory')==str(Path(source).parent) and startup.get('sourceHash')=='de06ef9b78cc0c33d7fe0efbedd9019edcac5ad2b680695adf4d2dc224e491b1' and startup.get('trustDirectory')==str(trust) and startup.get('trustReceiptHash')=='bb158aa0eda6c767f6bdf6f4ac6e0f8eefd93cfe6f0ee48196d0f9bf7f521458' and startup.get('outputHashes',{}).get('config.yaml')==config_hash,'EXACT_STARTUP_PUBLIC_TRUST_BINDING_REQUIRED')
    return trust

def collect(reader,report):
    require(not os.path.lexists(CLAIM),'INPUT_PREPARATION_ALREADY_CLAIMED_DO_NOT_REPLAY')
    user=pwd.getpwnam('oufadmin').pw_uid
    raw=file_bytes(ENVELOPE,user,{0o600},expected=ENVELOPE_HASH);v=reader.parse(raw);validate_envelope(v)
    human_raw=reader.private(reader.CONTEXT/'human-approval-binding.json');human=reader.parse(human_raw)
    require(human.get('approvalRef')==reader.APPROVAL,'EXACT_SOURCE_CONTEXT_REQUIRED')
    cfg_raw=reader.private(reader.CONTEXT/'execution-configuration.json',human['configurationHash']);cfg=reader.parse(cfg_raw)
    command=cfg['commandBindings']['docker'];reader.private(command['path'],command['sha256'],executable=True)
    cli=reader.OUTPUT/'activation-docker-cli';s=cli.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700 and not os.path.lexists(cli/'config.json'),'EXISTING_EMPTY_ROOT_CLI_REQUIRED')
    def native(args,stdin=None,as_json=True):
        if '--no-config' in args:
            report['administrativeLoginAttemptsIssued']+=1;report['iamReadRequests']+=1
        p=subprocess.run([command['path'],'--config',str(cli),*args],input=stdin,capture_output=True,timeout=20,env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock'})
        require(p.returncode==0 and len(p.stdout)<=2000000 and len(p.stderr)<=131072,'EXACT_RUNTIME_INPUT_NATIVE_READ_DENIED')
        reader.private(command['path'],command['sha256'],executable=True);return reader.parse(p.stdout) if as_json else p.stdout
    def gateway_worker():
        raw=native(['top',v['gateway']['containerId'],'-eo','pid,uid,gid,comm'],as_json=False)
        rows=raw.decode().splitlines()[1:];require(len(rows)<=256,'BOUNDED_GATEWAY_PROCESS_METADATA_REQUIRED')
        selected=[]
        for row in rows:
            parts=row.split();require(len(parts)==4,'EXACT_GATEWAY_PROCESS_METADATA_REQUIRED')
            if parts[3] in ('nginx','openresty'):
                require(all(p.isdecimal() for p in parts[:3]),'NUMERIC_GATEWAY_ROLE_IDENTITY_REQUIRED');selected.append(tuple(map(int,parts[1:3])))
        require(set(selected)=={(636,636)},'CURRENT_GATEWAY_WORKER_IDENTITY_DRIFT')
    current={name:native(['inspect','--type','container',v[name]['containerId']])[0] for name in ('iam','gateway')}
    require(all(identity(current[name])==v[name] for name in current),'SOURCE_CUSTODY_GENERATION_DRIFT')
    gateway_worker()
    semantic=native(['inspect','--type','container',SEMANTIC])[0]
    require(semantic['Image']==SEMANTIC_IMAGE and semantic['State']['Running'] is True and semantic['State']['Pid']==3789123,'RETAINED_PRIMARY_GENERATION_REQUIRED')
    profile=v['profile'][0];admin={row.split('=',1)[0]:row.split('=',1)[1] for row in current['iam']['Config']['Env']}
    pairs=[(admin[u],admin[p]) for u,p in (('KC_BOOTSTRAP_ADMIN_USERNAME','KC_BOOTSTRAP_ADMIN_PASSWORD'),('KEYCLOAK_ADMIN','KEYCLOAK_ADMIN_PASSWORD')) if admin.get(u) and admin.get(p)]
    require(len(pairs)==1 and re.fullmatch('[A-Za-z0-9_.@-]{1,128}',pairs[0][0]) and re.fullmatch('[^\r\n]{1,4096}',pairs[0][1]),'EXACT_CURRENT_LOCAL_ADMIN_CREDENTIAL_REQUIRED')
    wrapper='IFS= read -r KC_CLI_PASSWORD || exit 2; export KC_CLI_PASSWORD; exec /opt/keycloak/bin/kcadm.sh "$@"'
    args=['exec','-i',v['iam']['containerId'],'/bin/bash','-c',wrapper,'ouf-runtime-input-read','get','clients/'+profile['id']+'/client-secret','--no-config','--server','http://127.0.0.1:8080','--realm','master','--user',pairs[0][0],'-r','ouf','--fields','value']
    password=(pairs[0][1]+'\n').encode()
    profile_args=args.copy();profile_args[profile_args.index('clients/'+profile['id']+'/client-secret')]='clients';profile_args[profile_args.index('--fields')+1]='id,clientId,enabled,publicClient,serviceAccountsEnabled,clientAuthenticatorType,directAccessGrantsEnabled,standardFlowEnabled,fullScopeAllowed,protocol,defaultClientScopes,optionalClientScopes';profile_args.extend(['-q','clientId=ouf-semantic'])
    require(native(profile_args,password)==v['profile'],'CURRENT_WORKLOAD_PROFILE_DRIFT')
    secret=native(args,password)
    require(set(secret)=={'value'} and type(secret['value']) is str and hmac.compare_digest(secret['value'],v['credential']),'EXISTING_WORKLOAD_SECRET_ROTATED_OR_DRIFTED')
    require(native(profile_args,password)==v['profile'],'WORKLOAD_PROFILE_CHANGED_DURING_READ')
    driver_raw=reader.private(reader.OUTPUT/'registry'/SOUTHBOUND/'driver.json',DRIVER_HASH);driver=reader.parse(driver_raw)
    require(sha(encoded(driver['profile']))==SOUTHBOUND_PROFILE,'EXACT_CURRENT_SOUTHBOUND_PROFILE_REQUIRED')
    bundle_raw=reader.private(Path(driver['profile']['bundlePath'])/'config.json');bundle=reader.parse(bundle_raw)
    require(sha(encoded(bundle))==driver['profile']['bundleHash'],'EXACT_CURRENT_SOUTHBOUND_OCI_REQUIRED')
    southbound=native(['inspect','--type','container',SOUTHBOUND])[0]
    startup_path=BASE/'semantic-provider-v2-inputs-XE7IwlGm/runtime-input-receipt.json'
    startup_raw=reader.private(startup_path);startup=reader.parse(startup_raw)
    frame_path=BASE/'semantic-provider-v2-transaction-draft-g1yrsazc/southbound/framePolicy.json'
    frame_raw=reader.private(frame_path,'f49155fa412bb76d529713cb4ac2c253105884e9e72f7d2d74dfc5ccf9c5c822')
    trust=public_trust_source(bundle,reader.parse(frame_raw),southbound,startup)
    leaf=trust/'southbound/server.crt'
    trust_raw=reader.private(trust/'trust-receipt.json','bb158aa0eda6c767f6bdf6f4ac6e0f8eefd93cfe6f0ee48196d0f9bf7f521458');receipt=reader.parse(trust_raw)
    require(receipt.get('schema')=='ouf.semantic-provider-v2-private-trust.v1' and receipt.get('status')=='PRIVATE_TRUST_PREPARED' and receipt.get('authorityProfileHash')=='7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18','CONSUMED_PUBLIC_TRUST_RECEIPT_REQUIRED')
    ca=file_bytes(trust/'ca.crt',0,{0o600},65536,receipt['artifactHashes']['ca.crt'])
    cert=file_bytes(leaf,636,{0o600},65536,receipt['artifactHashes']['southbound/server.crt'])
    require(b'PRIVATE KEY' not in ca+cert and b'BEGIN CERTIFICATE' in ca and b'BEGIN CERTIFICATE' in cert,'PUBLIC_CERTIFICATES_ONLY_REQUIRED')
    openssl='/usr/bin/openssl';openssl_hash='acc10176d038aeb7b2a77d9ec972ac2985857a7191f7aecb7c54ef0e2c7e9549'
    reader.private(openssl,openssl_hash,executable=True)
    for args in (['verify','-CAfile',str(trust/'ca.crt'),'-purpose','sslserver','-verify_hostname','ouf-semantic-southbound-v2',str(leaf)],['x509','-in',str(leaf),'-checkend','3600','-noout'],['x509','-in',str(trust/'ca.crt'),'-checkend','3600','-noout']):
        p=subprocess.run([openssl,*args],stdin=subprocess.DEVNULL,capture_output=True,timeout=5);require(p.returncode==0,'EXISTING_PUBLIC_TLS_CHAIN_OR_WINDOW_UNPROVEN')
    reader.private(openssl,openssl_hash,executable=True)
    require(file_bytes(trust/'ca.crt',0,{0o600},65536,receipt['artifactHashes']['ca.crt'])==ca and file_bytes(leaf,636,{0o600},65536,receipt['artifactHashes']['southbound/server.crt'])==cert,'PUBLIC_CERTIFICATE_CHANGED_DURING_VERIFY')
    require(identity(native(['inspect','--type','container',SOUTHBOUND])[0])==identity(southbound) and reader.private(startup_path)==startup_raw and reader.private(frame_path)==frame_raw,'SOUTHBOUND_SOURCE_CHANGED_DURING_READ')
    gateway_worker()
    for name in current:require(identity(native(['inspect','--type','container',v[name]['containerId']])[0])==v[name],'SOURCE_CUSTODY_CHANGED_DURING_READ')
    require(identity(native(['inspect','--type','container',SEMANTIC])[0])==identity(semantic),'PRIMARY_CHANGED_DURING_READ')
    require(file_bytes(ENVELOPE,user,{0o600},expected=ENVELOPE_HASH)==raw and reader.private(trust/'trust-receipt.json')==trust_raw and reader.private(reader.OUTPUT/'registry'/SOUTHBOUND/'driver.json',DRIVER_HASH)==driver_raw and reader.private(Path(driver['profile']['bundlePath'])/'config.json')==bundle_raw and reader.private(reader.CONTEXT/'human-approval-binding.json')==human_raw and reader.private(reader.CONTEXT/'execution-configuration.json',human['configurationHash'])==cfg_raw,'INPUT_CUSTODY_CHANGED_DURING_READ')
    bindings={'privateEnvelopeHash':ENVELOPE_HASH,'workloadProfileHash':PROFILE_HASH,'semantic':identity(semantic),'gateway':v['gateway'],'iam':v['iam'],'southboundDriverHash':DRIVER_HASH,'southboundProfileHash':SOUTHBOUND_PROFILE,'southbound':identity(southbound),'creationFramePolicyHash':sha(frame_raw),'startupReceiptHash':sha(startup_raw),'southboundConfigurationHash':'77342a509b0b0e9498728fa366f50ce031c19d78a636d4225de5e95e1ba97140','publicTrustReceiptHash':sha(trust_raw),'publicCaHash':sha(ca),'southboundCertificateHash':sha(cert),'sourceContextHash':sha(cfg_raw)}
    return v,ca,bindings

def main():
    report={'schema':'ouf.discovery.runtime-input-preparation.v1','existingConfigurationWrites':0,'containerLifecycleOperations':0,'imageImports':0,'firewallWrites':0,'databaseWrites':0,'commonLockAcquired':False,'r9Touched':False,'privateKeyFilesOpened':0,'installationAuthorityKeysRead':0,'deploymentSignaturesIssued':0,'workloadTokenGrantRequests':0,'externalProviderCalls':0,'privateValuesPrinted':False,'administrativeLoginAttemptsIssued':0,'iamReadRequests':0,'iamConfigurationWrites':0,'mountsInstalled':False,'applicationCutoverAuthorized':False,'applicationHealthProven':False,'notReleaseAcceptance':True}
    root=None
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'EXACT_ISOLATED_ROOT_PREPARATION_REQUIRED')
        raw=globals().get('__reader_source_bytes__');require(type(raw) is bytes and len(raw)<=131072 and sha(raw)==READER_HASH,'SEALED_READ_ONLY_HELPER_REQUIRED')
        reader=types.ModuleType('sealed_custody_reader');reader.__file__='sealed-read-only-reader';exec(compile(raw,'sealed-read-only-reader','exec'),reader.__dict__)
        v,ca,bindings=collect(reader,report)
        root=Path(tempfile.mkdtemp(prefix='semantic-discovery-runtime-inputs-',dir=BASE));root.chmod(0o700)
        manifest_hash=prepare_files(root,CLAIM,v['credential'],ca,bindings)
        report.update(status='ROOT_RUNTIME_INPUTS_PREPARED_NOT_MOUNTED',evidenceDirectory=str(root),privateManifestHash=manifest_hash,existingCredentialCopiedWithoutRotation=True,runtimeDiscoveryMacKeysGenerated=1,runtimeDiscoveryMacRoleCopies=2,semanticUid=10001,gatewayUid=636,publicProviderCaCaptured=True,existingSouthboundLeafChainAndHostnameVerified=True,doNotRerunApply=True)
        create(root/'receipt.json',encoded(report));code=0
    except Exception as error:
        reason=str(error);report.update(status='INPUT_PREPARATION_BLOCKED',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'RUNTIME_INPUT_PREPARATION_UNPROVEN',errorType=type(error).__name__,evidenceDirectory=str(root) if root else None,doNotRerunApply=os.path.lexists(CLAIM));code=1
    print('OUF_APPLICATION_RUNTIME_INPUTS='+json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
