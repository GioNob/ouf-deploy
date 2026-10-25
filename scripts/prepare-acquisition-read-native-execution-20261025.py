#!/usr/bin/env python3
"""Refine the frozen plan with current Engine identity and authenticated image bytes.

Preparation only: GET allowlist, no image load/start/stop/admin/OAuth/SQL/signing.
"""
import copy,gzip,hashlib,http.client,importlib.util,json,os,re,shutil,signal,socket,stat,struct,sys,tempfile,time
from pathlib import Path
PLAN=Path('/etc/ouf/deploy-snapshots/acquisition-read-native-plan-mac-v1/execution-plan.json')
PLAN_HASH='47b206e2eb602c115ef9c7c67937f2b2aeeff645fb8b56347c81f546a4ba60ca'
RECEIPT_HASH='8e7117f962da2fe9cc0b1e8d5af0a4b5d189947005239e26f6dad6736b740a08'
ROOT=Path('/etc/ouf/deploy-snapshots/acquisition-native-execution-inputs-47b206e2eb602c11')
HELPERS={'plan_helper.py':'09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd','image_custody.py':'e8157a8b5909c893ce95e431f1094c983fd692c695f99bb6067aff6dc59ca8c2'}
PROFILE={'path':'/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json','sha256':'7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18'}
POLICY={'path':'/etc/ouf/deploy-snapshots/semantic-trust-policy-preparation-20261004-172336/trust-policy.json','sha256':'21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42'}
CONTEXT={'installationRef':'ouf-lab-netcup-01','entityRef':'ouf-lab','intentIssuerRef':'ouf-lab-infrastructure-installer','approvalIssuerRef':'ouf-lab-infrastructure-installer','attestorRef':'ouf-lab-node-attestor'}
COUNTS={'engineGetAttempts':0,'imageArchivesRead':0,'nativeArchivesPrepared':0,'publicAuthorityMetadataReads':0}
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def identity_profile(info):
    require(type(info)is dict and type(info.get('DriverStatus'))is list,'TYPED_CURRENT_ENGINE_DRIVER_STATUS_REQUIRED')
    rows=info['DriverStatus'];require(all(type(v)is list and len(v)==2 and all(type(x)is str for x in v)for v in rows)and len({v[0]for v in rows})==len(rows),'UNIQUE_CURRENT_DRIVER_STATUS_REQUIRED')
    values=dict(rows)
    if values.get('driver-type')=='io.containerd.snapshotter.v1':return 'CONFIG_AND_NATIVE_MANIFEST'
    require('driver-type'not in values and info.get('Driver')in('overlay2','aufs','btrfs','zfs','vfs','devicemapper'),'UNQUALIFIED_ENGINE_IMAGE_IDENTITY_PROFILE')
    return 'CONFIGURATION_ID'
def public_authority(p,profile_binding=PROFILE,policy_binding=POLICY,context=CONTEXT):
    profile=p.decode(p.protected(Path(profile_binding['path']),profile_binding['sha256']));COUNTS['publicAuthorityMetadataReads']+=1
    policy=p.decode(p.protected(Path(policy_binding['path']),policy_binding['sha256']));COUNTS['publicAuthorityMetadataReads']+=1;now=int(time.time())
    require(profile.get('schema')=='ouf.semantic-existing-installation-authority-bindings.v1'and profile.get('authorities')==context and profile.get('policyBinding')==policy_binding and set(profile.get('keyRefs',{}))==set(profile.get('keyBindings',{}))=={'installer','attestor'},'EXACT_CURRENT_INSTALLATION_PROFILE_REQUIRED')
    require(set(policy)=={'schema','installationRef','entityRef','keys'}and policy['schema']=='ouf.semantic-deployment-trust-policy.v1'and policy['installationRef']==context['installationRef']and policy['entityRef']==context['entityRef']and type(policy['keys'])is list and len(policy['keys'])==2,'EXACT_EXISTING_PUBLIC_POLICY_REQUIRED')
    for role,issuer,roles in(('installer',context['intentIssuerRef'],{'DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'}),('attestor',context['attestorRef'],{'CREATION_ATTESTATION'})):
        keys=[k for k in policy['keys']if k.get('keyRef')==profile['keyRefs'][role]and k.get('issuerRef')==issuer];require(len(keys)==1,'UNIQUE_CURRENT_INSTALLATION_ROLE_REQUIRED');k=keys[0];binding=profile['keyBindings'][role]
        require(set(k)=={'keyRef','issuerRef','roles','publicKey','notBefore','expiresAt','state'}and type(k['roles'])is list and len(k['roles'])==len(roles)and set(k['roles'])==roles and type(k['publicKey'])is str and re.fullmatch('[a-f0-9]{64}',k['publicKey'])and k['state']=='ACTIVE'and type(k['notBefore'])is int and type(k['expiresAt'])is int and 0<=k['notBefore']<=now and k['expiresAt']>=now+930,'FULL_FUTURE_REVIEW_WINDOW_PUBLIC_KEY_AUTHORITY_REQUIRED')
        require(type(binding)is dict and set(binding)=={'path','sha256'}and type(binding['path'])is str and Path(binding['path']).is_absolute()and'..'not in Path(binding['path']).parts and re.fullmatch('[a-f0-9]{64}',binding['sha256']),'EXACT_EXISTING_SIGNING_KEY_BINDING_REQUIRED')
    return {'profileBinding':profile_binding,'trustPolicy':policy_binding,'context':context,'profile':profile,'policy':policy,'privateKeysOpened':False,'livePolicyRevalidationAtIssuanceRequired':True}
class Engine:
    def __init__(self,p,binding,allowed,root):self.p,self.binding,self.allowed,self.root=p,binding,set(allowed),root
    def socket(self):
        path=Path(self.binding['socketPath']);self.p.ancestry(path.parent);require(path.is_absolute()and str(path.resolve())==str(path),'CANONICAL_PINNED_ENGINE_SOCKET_REQUIRED');v=path.lstat()
        require(stat.S_ISSOCK(v.st_mode)and v.st_uid==0 and [v.st_dev,v.st_ino,v.st_uid,v.st_gid,stat.S_IMODE(v.st_mode)]==self.binding['socketBinding'],'EXACT_RETAINED_ENGINE_SOCKET_REQUIRED');return str(path)
    def get(self,path):
        require(path in self.allowed and COUNTS['engineGetAttempts']<14,'FOURTEEN_EXACT_ENGINE_GETS_ONLY');selected=self.socket();outer=self
        COUNTS['engineGetAttempts']+=1;n=COUNTS['engineGetAttempts'];self.p.put(self.root/('engine-get-%02d.claim.json'%n),{'method':'GET','path':path,'attemptNotCompletion':True})
        class Local(http.client.HTTPConnection):
            def connect(c):
                c.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.sock.settimeout(4);c.sock.connect(selected);peer=list(struct.unpack('3i',c.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
                require(peer==outer.binding['peerCredentials']and peer[1]==0,'SAME_CAPTURED_ROOT_ENGINE_PEER_REQUIRED')
        c=Local('retained-local-engine',timeout=4)
        try:
            c.request('GET',path,headers={'Connection':'close'});r=c.getresponse();raw=r.read(2097153);require(0<len(raw)<=2097152,'BOUNDED_CURRENT_ENGINE_RESPONSE_REQUIRED');self.p.put(self.root/('engine-get-%02d.response.json'%n),{'status':r.status,'raw':raw.decode('utf-8')});require(r.status==200,'EXACT_CURRENT_ENGINE_GET_REQUIRED');self.socket();return self.p.decode(raw)
        finally:c.close()
def archive(p,images,descriptor,role,root,native):
    expected=Path('/etc/ouf/deploy-snapshots/acquisition-read-packages-2f9a2336572e1bbc')/role/'image.tar.gz';require(descriptor['path']==str(expected),'EXACT_STAGED_ROLE_ARCHIVE_REQUIRED');return archive_at(p,images,descriptor,root,native)
def archive_at(p,images,d,root,native):
    path=Path(d['path']);p.ancestry(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o400 and 0<before.st_size<=536870912,'ROOT_PROTECTED_CANDIDATE_ARCHIVE_REQUIRED');COUNTS['imageArchivesRead']+=1
        with os.fdopen(os.dup(fd),'rb')as source:
            checksum=hashlib.sha256()
            for block in iter(lambda:source.read(1048576),b''):checksum.update(block)
            require(checksum.hexdigest()==d['sha256'],'EXACT_CI_COMPRESSED_ARCHIVE_HASH_REQUIRED');source.seek(-4,2);size=struct.unpack('<I',source.read(4))[0];require(0<size<=images.LIMIT,'BOUNDED_GZIP_DECLARED_SIZE_REQUIRED');require(shutil.disk_usage(root).free>=3*size+268435456,'NATIVE_ARCHIVE_PREPARATION_DISK_HEADROOM_REQUIRED');source.seek(0)
            with tempfile.TemporaryFile(dir=root)as expanded,gzip.GzipFile(fileobj=source)as zipped:
                total=0
                while True:
                    block=zipped.read(min(1048576,images.LIMIT-total+1))
                    if not block:break
                    total+=len(block);require(total<=images.LIMIT,'BOUNDED_IMAGE_EXPANSION_REQUIRED');expanded.write(block)
                require(total==size,'EXACT_GZIP_DECLARED_SIZE_REQUIRED');expanded.flush();expanded.seek(0);checksum,_=images.hashed(expanded,images.LIMIT);expanded.seek(0);audit=images.archive(expanded,checksum,d['imageId'],d['sourceCommit']);name='native-'+d['imageId'][7:]+'.tar';target=root/name
                # Separate role directories prevent accidental archive aliases across equal candidate IDs.
                out=os.open(target,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
                try:
                    with os.fdopen(os.dup(out),'r+b')as output:derived=images.tagless_archive(expanded,output,audit,containerd=native);output.flush();os.fsync(output.fileno())
                    pin=list(p.frame(os.fstat(out)))
                finally:os.close(out)
            if native:audit['nativeIdentity']=images.native_identity(audit)
            require(p.frame(before)==p.frame(os.fstat(fd))==p.frame(path.lstat()),'ORIGINAL_CI_IMAGE_ARCHIVE_CHANGED');COUNTS['nativeArchivesPrepared']+=1
            return {'sourceArchive':d,'nativeArchive':{'path':str(target),'sha256':derived['derivedArchiveSha256'],'bytes':derived['archiveBytes'],'metadata':pin},'audit':audit,'nativeImageId':images.runtime_image_id(audit),'configurationAndLayerBytesUnchanged':True,'imageRebuilt':False,'imageRelabelled':False}
    finally:os.close(fd)
def labels(request,audit):
    explicit=request.get('Labels')or{};defaults=audit['imageConfig'].get('Labels')or{};additions={k:v for k,v in defaults.items()if k not in explicit}
    require(all(k.startswith('org.opencontainers.image.')for k in additions),'NO_UNREVIEWED_MANAGER_IMAGE_LABEL_ADDITION')
    names=lambda rows:{r.split('=',1)[0]for r in rows}
    require(names(audit['imageConfig'].get('Env')or[])<=names(request.get('Env')or[]),'NO_UNREVIEWED_CANDIDATE_ENVIRONMENT_DEFAULTS')
    return {'profile':'DOCKER_EXACT_IMAGE_LABEL_DEFAULTS_V1','expectedLabels':{**defaults,**explicit},'imageDefaultAdditions':additions,'allExplicitLabelsPreserved':True}
def prepare(p,images,plan_path=PLAN,plan_hash=PLAN_HASH,receipt_hash=RECEIPT_HASH,root=ROOT,engine_factory=Engine,authority_reader=public_authority,archive_reader=archive):
    require(os.geteuid()==os.getegid()==0,'ROOT_NATIVE_PREPARATION_REQUIRED');p.ancestry(root.parent);require(not os.path.lexists(root),'NATIVE_PREPARATION_SCOPE_CONSUMED_NO_REPLAY');root.mkdir(mode=0o700);p.put(root/'claim.json',{'schema':'ouf.acquisition-native-execution-preparation-claim.v1','frozenPlanHash':plan_hash,'maximumEngineGets':14,'maximumSeconds':240,'containerWrites':0,'imageImports':0,'gatewayRequests':0,'automaticReplayAllowed':False,'budgetReset':False})
    plan=p.decode(p.protected(plan_path,plan_hash));receipt=p.decode(p.protected(plan_path.parent/'complete.json',receipt_hash));require(plan['schema']=='ouf.acquisition-read-native-plan.v1'and plan['executionEntryQualified']is False and plan['runtimeAuthorityIssued']is False and plan['targetApplyAuthorized']is False and receipt['complete']is True and receipt['privatePlanHash']==plan_hash,'EXACT_COMPLETED_FROZEN_PLAN_REQUIRED')
    inputs=p.decode(p.protected(p.INPUTS,plan['capturedInputsHash']));p.check_processes(inputs)
    authority=authority_reader(p);ids={v['containerId']for v in plan['existingApplications'].values()};networks={v['network']['id']:v['network']['name']for v in [*plan['readComponents'].values(),plan['mcpReplacement']]};require(len(ids)==5 and 1<=len(networks)<=3,'FIVE_RETAINED_ROLES_AND_BOUND_NETWORKS_REQUIRED')
    allowed={'/v1.44/info',*('/v1.44/containers/'+cid+'/json'for cid in ids),*('/v1.44/networks/'+nid for nid in networks)};engine=engine_factory(p,plan['engineBinding'],allowed,root)
    def current():
        for role,binding in plan['existingApplications'].items():
            value=engine.get('/v1.44/containers/'+binding['containerId']+'/json');s=value['State'];require(s['Running']is True and not any(s.get(k)for k in('Paused','Restarting','Dead','OOMKilled'))and not s.get('Error')and p.stable_binding(value)==binding,'CURRENT_RETAINED_COHORT_CHANGED');require(p.process_pin(s['Pid'])==inputs['currentProcessPins'][role],'CURRENT_RETAINED_PROCESS_CHANGED')
    current();info=engine.get('/v1.44/info');profile=identity_profile(info)
    for nid,name in networks.items():
        row=engine.get('/v1.44/networks/'+nid);require(row.get('Id')==nid and row.get('Name')==name and row.get('Driver')=='bridge'and row.get('Scope')=='local'and not row.get('Ingress')and not row.get('ConfigOnly'),'CURRENT_LOCAL_ROLE_NETWORK_REQUIRED')
    mem=Path('/proc/meminfo').read_text();match=re.findall(r'^MemAvailable:\s+([0-9]+) kB$',mem,re.MULTILINE);require(len(match)==1 and int(match[0])*1024>=1342177280,'CURRENT_READ_COMPONENT_MEMORY_HEADROOM_REQUIRED')
    native=copy.deepcopy(plan);candidate_facts={}
    for role in('ingestion','udp','mcp'):
        target=root/role;target.mkdir(mode=0o700);fact=archive_reader(p,images,plan['candidateArchives'][role],role,target,profile=='CONFIG_AND_NATIVE_MANIFEST');candidate_facts[role]=fact;proposal=native['mcpReplacement']if role=='mcp'else native['readComponents'][role];original=copy.deepcopy(proposal['request']);proposal['request']['Image']=fact['nativeImageId'];proposal['runtimeLabelProjection']=labels(original,fact['audit']);changed=copy.deepcopy(proposal['request']);changed['Image']=original['Image'];require(changed==original,'ONLY_PROVEN_NATIVE_IMAGE_ID_REFINEMENT_ALLOWED');p.put(target/'audit.json',fact)
    current();p.check_processes(inputs);p.protected(plan_path,plan_hash);p.protected(plan_path.parent/'complete.json',receipt_hash)
    context={'schema':'ouf.acquisition-native-execution-inputs.v1','frozenPlanHash':plan_hash,'frozenPlanPath':str(plan_path),'frozenReceiptHash':receipt_hash,'nativeProposal':native,'nativeProposalHash':p.digest(native),'imageIdentityProfile':profile,'candidateFacts':candidate_facts,'publicAuthority':authority,'bootId':inputs['bootId'],'sourceClosure':getattr(p,'__sealed_source_closure__',None),'preparationCounts':{**COUNTS,'privateMetadataReads':p.COUNTS['privateMetadataReads']},'originalRegistryWorkerNotSelected':True,'freshAdmissionAndConfigurationRevalidationBeforeApplyRequired':True,'executionEntryQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'applicationE2EProven':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    p.put(root/'native-inputs.json',context)
    result={'schema':'ouf.acquisition-native-execution-inputs-result.v1','status':'ACQUISITION_NATIVE_EXECUTION_INPUTS_PREPARED_NOT_AUTHORIZED','complete':True,'privateInputsPath':str(root/'native-inputs.json'),'privateInputsHash':p.digest(context),'frozenPlanHash':plan_hash,'nativeProposalHash':p.digest(native),'imageIdentityProfile':profile,'nativeImageIds':{r:f['nativeImageId']for r,f in candidate_facts.items()},'currentRetainedCohortMatchesFrozen':True,'publicAuthorityMetadataCurrent':True,**COUNTS,'privateMetadataReads':p.COUNTS['privateMetadataReads'],'maximumEngineGets':14,'countsAreThisPreparationOnly':True,'originalPlannerGatewayGetCountRetained':1,'originalPlannerAdminCredentialReadCountRetained':1,'gatewayAdminRequests':0,'networkNamespaceJoins':0,'sqlSessions':0,'oauthRequests':0,'serviceCredentialFilesOpened':0,'privateSigningKeysRead':0,'imageImports':0,'containerWrites':0,'databaseMigrations':0,'sourceActivations':0,'humanBudgetsGranted':0,'originalScopeWrites':0,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,'executionEntryQualified':False,'targetApplyAuthorized':False,'applicationReadinessProven':False,'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False,'credentialValuesPrinted':False,'addressesPrinted':False};p.put(root/'complete.json',result);return result
def bootstrap():
    # Source files were copied0400 under the pinned root launcher. No ambient imports.
    root=Path(__file__).resolve().parent;modules={}
    for name,expected in HELPERS.items():
        path=root/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and 0<s.st_size<=65536,'ROOT_PROTECTED_HELPER_REQUIRED');raw=os.read(fd,s.st_size+1);require(len(raw)==s.st_size and sha(raw)==expected,'EXACT_NATIVE_HELPER_HASH_REQUIRED')
        finally:os.close(fd)
        spec=importlib.util.spec_from_loader('sealed_'+name[:-3],loader=None);m=importlib.util.module_from_spec(spec);exec(compile(raw,str(path),'exec'),m.__dict__);modules[name]=m
    p=modules['plan_helper.py'];p.ancestry(root);entry=Path(__file__).resolve();entry_raw=p.protected(entry);p.__sealed_source_closure__={str(root/name):expected for name,expected in HELPERS.items()};p.__sealed_source_closure__[str(entry)]=sha(entry_raw);return p,modules['image_custody.py']
def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ONE_ISOLATED_ROOT_NATIVE_PREPARATION_REQUIRED');signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(Stop('FINITE_NATIVE_PREPARATION_TIMEOUT')));signal.alarm(240)
        p,images=bootstrap();result=prepare(p,images);print(encoded(result).decode());return 0
    except Exception as e:
        code=str(e)if type(e).__name__ in ('Stop','ImageCustodyDenied')and re.fullmatch('[A-Z0-9_]{1,120}',str(e))else'ACQUISITION_NATIVE_PREPARATION_UNPROVEN'
        print(encoded({'schema':'ouf.acquisition-native-execution-inputs-result.v1','status':'STOP_RECONCILE','reasonCode':code,'complete':False,**COUNTS,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'imageImports':0,'containerWrites':0,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}).decode());return 2
    finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
