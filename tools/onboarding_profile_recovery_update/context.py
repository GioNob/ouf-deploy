"""Private state and receipts for a new, exact ONBOARDING-only runtime intent.

This module is not a production entrypoint. The sealed entrypoint supplies its
fixed target bindings; explicit alternate bindings are only used by CI fixtures.
"""
import copy,hashlib,ipaddress,os,re,shutil,stat,subprocess,sys,time
from pathlib import Path
from urllib.parse import quote
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
TARGET={'executionInputsHash':'564038c5d487f0a4f4504cca4c6e9e418e1f715dbf95fe9ce97cb2b27c297b76',
 'conditionalPlanHash':'432c2930c119223449870e935a1ac0f485607812e73019928b4148d9238ab22a',
 'inputsHash':'1ce0ce1cd27195565393798d4d06246047c5b46c12cef39bc31aee4ed7aff82c',
 'nativeImageId':'sha256:e4690481db28e3e70335704de89e563dcf32ecf70e4a0caea1bdc30c48aa4359',
 'sourceCommit':'6ea5242f711761a384fa1b23667971601bc2c38b','testedCommit':'e42c398af3ab6989a956925445c478f8eb9f2446',
 'nativeArchiveHash':'1553453fcdfd6166a38234194a81f8f6d04bb41a9552453fc51fb5c831e216a2',
 'executionInputsPath':'/etc/ouf/deploy-snapshots/onboarding-profile-recovery-image-plan-1ce0ce1cd2719556-v1/execution-inputs.json',
 'conditionalPlanPath':'/etc/ouf/deploy-snapshots/onboarding-profile-recovery-image-plan-1ce0ce1cd2719556-v1/execution-plan.json',
 'ownerOverlayPath':'/opt/ouf/secrets/onboarding-ths.yaml',
 'executionRoot':'/etc/ouf/deploy-snapshots/onboarding-profile-recovery-v36-apply-564038c5d487f0a4-v1',
 'transportHashes':{'retainedEngineBindingHash':'8e3adb93d5874ee423092e7171e501a2fcef3386c44fbe48ee40c7c92ef8bb01','capturedEngineBindingHash':'c17569848d56b8efb49ded7ab94b9e4e307ecb0b80eead2fed42aa34d1ed5718','peerCredentialsHash':'7ff52993d5d3cb149089942de7fc7a6511db2671cf2125976c081ad6fff89772'}}
PROFILE={'path':'/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json','sha256':'7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18'}
POLICY={'path':'/etc/ouf/deploy-snapshots/semantic-trust-policy-preparation-20261004-172336/trust-policy.json','sha256':'21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42'}
CONTEXT={'installationRef':'ouf-lab-netcup-01','entityRef':'ouf-lab','intentIssuerRef':'ouf-lab-infrastructure-installer','approvalIssuerRef':'ouf-lab-infrastructure-installer','attestorRef':'ouf-lab-node-attestor'}
def public_authority(p,profile_binding=PROFILE,policy_binding=POLICY,context=CONTEXT):
    profile=p.decode(p.protected(Path(profile_binding['path']),profile_binding['sha256']));None
    policy=p.decode(p.protected(Path(policy_binding['path']),policy_binding['sha256']));None;now=int(time.time())
    require(profile.get('schema')=='ouf.semantic-existing-installation-authority-bindings.v1'and profile.get('authorities')==context and profile.get('policyBinding')==policy_binding and set(profile.get('keyRefs',{}))==set(profile.get('keyBindings',{}))=={'installer','attestor'},'EXACT_CURRENT_INSTALLATION_PROFILE_REQUIRED')
    require(set(policy)=={'schema','installationRef','entityRef','keys'}and policy['schema']=='ouf.semantic-deployment-trust-policy.v1'and policy['installationRef']==context['installationRef']and policy['entityRef']==context['entityRef']and type(policy['keys'])is list and len(policy['keys'])==2,'EXACT_EXISTING_PUBLIC_POLICY_REQUIRED')
    for role,issuer,roles in(('installer',context['intentIssuerRef'],{'DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'}),('attestor',context['attestorRef'],{'CREATION_ATTESTATION'})):
        keys=[k for k in policy['keys']if k.get('keyRef')==profile['keyRefs'][role]and k.get('issuerRef')==issuer];require(len(keys)==1,'UNIQUE_CURRENT_INSTALLATION_ROLE_REQUIRED');k=keys[0];binding=profile['keyBindings'][role]
        require(set(k)=={'keyRef','issuerRef','roles','publicKey','notBefore','expiresAt','state'}and type(k['roles'])is list and len(k['roles'])==len(roles)and set(k['roles'])==roles and type(k['publicKey'])is str and re.fullmatch('[a-f0-9]{64}',k['publicKey'])and k['state']=='ACTIVE'and type(k['notBefore'])is int and type(k['expiresAt'])is int and 0<=k['notBefore']<=now and k['expiresAt']>=now+930,'FULL_FUTURE_REVIEW_WINDOW_PUBLIC_KEY_AUTHORITY_REQUIRED')
        require(type(binding)is dict and set(binding)=={'path','sha256'}and type(binding['path'])is str and Path(binding['path']).is_absolute()and'..'not in Path(binding['path']).parts and re.fullmatch('[a-f0-9]{64}',binding['sha256']),'EXACT_EXISTING_SIGNING_KEY_BINDING_REQUIRED')
    return {'profileBinding':profile_binding,'trustPolicy':policy_binding,'context':context,'profile':profile,'policy':policy,'privateKeysOpened':False,'livePolicyRevalidationAtIssuanceRequired':True}
def retained_host_policy(host):
    # Memory=0 is the Engine's retained no-hard-limit value, not a controller
    # budget. Preserve it exactly; missing/bool/negative remain invalid.
    require(host.get('AutoRemove')is False and type(host.get('Memory'))is int and host['Memory']>=0,'EXACT_RETAINED_ONBOARDING_HOST_POLICY_REQUIRED')
    require(host.get('OomKillDisable')is None or type(host.get('OomKillDisable'))is bool,'TYPED_RETAINED_ONBOARDING_OOM_POLICY_REQUIRED')
    return {'memoryBytes':host['Memory'],'memoryPolicy':'RETAIN_EXACT_ZERO_NO_HARD_LIMIT'if host['Memory']==0 else'RETAIN_EXACT_POSITIVE_LIMIT','autoRemove':False,'oomKillDisable':host.get('OomKillDisable'),'resourcePolicyChanged':False}
class Context:
    def __init__(self,parts,auth,sign,journal,closure,*,case=TARGET,public_authority=None,runtime=None):
        self.core,self.p,self.images,self.mac,self.http,self.ports_module,self.watch,self.engine_helpers,self.terminal=[parts[k]for k in('authority','plan_helper','image_custody','retained_mac','transport','ports','quarantine','engine_creation','terminal')]
        self.fence,self.database,self.backup=parts['state_fence'],parts['database'],parts['backup']
        self.auth,self.sign,self.journal_module=auth,sign,journal;self.closure=copy.deepcopy(closure);self.case=copy.deepcopy(case);self.root=Path(case['executionRoot']);self.serial=0
        self.execution=None;self.counts={k:0 for k in self.core.LIMITS};self.responses=0;self.receiptBytes=0;self.runtime=runtime;self.prior_seals={};self.prior_inventories=[]
        self.p.ancestry(self.root.parent);require(not os.path.lexists(self.root),'PROFILE_V36_SCOPE_CONSUMED_NO_REPLAY');self.root.mkdir(mode=0o700);self.root.chmod(0o700);self.sync(self.root.parent)
        self.write(self.root,'preparation-claim.json',{'schema':'ouf.onboarding-profile-recovery-preflight-claim.v1','executionInputsHash':case['executionInputsHash'],'maximums':self.core.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
        def metadata(path,expected=None):
            self.reserve('ownerConfigurationReads');return self.read(path,expected)
        self.native=metadata(case['executionInputsPath'],case['executionInputsHash']);frozen=metadata(case['conditionalPlanPath'],case['conditionalPlanHash']);result=metadata(str(Path(case['executionInputsPath']).parent/'result.json'))
        n=self.native
        require(n['schema']=='ouf.onboarding-profile-recovery-private-execution-inputs.v1'and n['capturedInputsHash']==case['inputsHash']
            and n['conditionalNativePlanHash']==case['conditionalPlanHash']and n['conditionalLifecyclePlanCompiled']is True
            and n['nativeImageId']==case['nativeImageId']and n['imageAudit']['sourceCommit']==n['testedCommit']==case['testedCommit']and n['reviewedSourceCommit']==case['sourceCommit']
            and n['nativeArchive']['sha256']==case['nativeArchiveHash']and self.images.runtime_image_id(n['imageAudit'])==n['nativeImageId']
            and all(n[k]is False for k in('executionEntryQualified','runtimeAuthorityIssued','lifecyclePlanCompiled','currentRuntimeRevalidated','targetUpdateAuthorized','automaticReplayAllowed','budgetReset')),'EXACT_NEW_PRIVATE_V36_IMAGE_AND_INPUTS_REQUIRED')
        require(result['schema']=='ouf.onboarding-profile-recovery-image-plan-prepared.v1'and result['status']=='ONBOARDING_PROFILE_RECOVERY_IMAGE_AND_CONDITIONAL_PLAN_PREPARED_NOT_AUTHORIZED'
            and result['complete']is True and result['executionInputsHash']==case['executionInputsHash']and result['conditionalNativePlanHash']==case['conditionalPlanHash']
            and result['counts']=={'privateMetadataReads':3,'ciZipReads':1,'nativeArchivesPrepared':1,'engineGets':0,'containerWrites':0,'imageImports':0}
            and result['runtimeAuthorityIssued']is False and result['databaseAdmissionProven']is False,'EXACT_COMPLETED_CONDITIONAL_PREPARATION_REQUIRED')
        require(frozen['schema']=='ouf.onboarding-profile-recovery-conditional-native-plan.v1'and frozen['kind']=='FROZEN_CONDITIONAL_PROPOSAL_NOT_EXECUTABLE'
            and frozen['capturedInputsHash']==case['inputsHash']and frozen['bootId']==n['bootId']and frozen['engineBinding']==n['engineBinding']
            and frozen['onboardingProcessPin']==n['currentProcessPin']and frozen['onboardingReplacement']['oldBinding']==self.p.stable_binding(n['currentOnboarding'])
            and frozen['onboardingReplacement']['request']['Image']==n['nativeImageId']and frozen['databaseMigration']['from']==35 and frozen['databaseMigration']['to']==36
            and frozen['databaseMigration']['flywayChecksum']==-317278534
            and all(frozen[k]is False for k in('runtimeAuthorityIssued','targetApplyAuthorized','databaseAdmissionProven','currentRuntimeRevalidated','newJobOrHumanBudgetAuthorized','sourceActivationAuthorized','databaseRestoreAuthorized','automaticReplayAllowed','budgetReset')),'EXACT_FROZEN_V36_CONDITIONAL_PROPOSAL_REQUIRED')
        self.database_profile=copy.deepcopy(frozen['boundDatabaseProfile']);self.transport_compatibility=self.database.retained_transport(self.core,self.database_profile,n['engineBinding'],case['transportHashes'])
        self.readiness=copy.deepcopy(frozen['onboardingReplacement']['readiness']);self.migrations=self.p.decode((Path(__file__).parent/'migration-fence.json').read_bytes())
        require(self.migrations==frozen['candidateApplicationFacts']['migrations']and len(self.migrations)==36,'EXACT_AUTHENTICATED_36_RESOURCE_FENCE_REQUIRED')
        self.application_facts=copy.deepcopy(frozen['candidateApplicationFacts']);self.configuration_raw=parts['configuration_raw']
        self.inputs={'bootId':n['bootId'],'currentObservations':{'onboarding':copy.deepcopy(n['currentOnboarding'])},'currentProcessPins':{'onboarding':copy.deepcopy(n['currentProcessPin'])}}
        self.proposal=copy.deepcopy(frozen);self.proposal.update(existingApplications={'onboarding':self.p.stable_binding(n['currentOnboarding'])},
            nativeIdentityProfile='CONFIG_AND_NATIVE_MANIFEST'if n['imageAudit'].get('nativeIdentity')else'CONFIG_DIGEST',readiness=self.readiness,
            operationalSqlHash=self.core.sha(self.fence.query(False).encode()),operationalSqlAfterHash=self.core.sha(self.fence.query(True).encode()),
            retainedImagePreparationCounts=copy.deepcopy(result['counts']))
        self.retained_preflight={'newScope':True,'oldScopesConsumed':True,'oldAuthorityReused':False,'retainedDiagnosticCounts':copy.deepcopy(frozen['retainedDiagnosticApplyCounts'])}
        overlays=frozen['nativeFlywayConfiguration']['ownerOverlays'];require(len(overlays)==1 and overlays[0]['binding']['path']==case['ownerOverlayPath'],'EXACT_NAMED_OWNER_CONFIGURATION_BINDING_REQUIRED')
        self.reserve('ownerConfigurationContentReads');self.owner_overlay_raw,self.owner_overlay_binding=self.p.private_config(case['ownerOverlayPath'],overlays[0]['binding'])
        self.native['candidateFacts']={'onboarding':{'audit':n['imageAudit']}}
        self.engine=self.http.Engine(self.p,n['engineBinding']);self.engine.before=self.before_dispatch;self.engine.retained=self.retained
        self.public_authority=public_authority or globals()['public_authority'];self.authority_metadata=self.refresh_authority();self.profile=self.authority_metadata['profile'];self.openssl=self.executable()
        self.input_seals={path:list(self.p.frame(Path(path).lstat()))for path in(case['executionInputsPath'],case['conditionalPlanPath'],str(Path(case['executionInputsPath']).parent/'result.json'))}
        self.source_seals={path:list(self.p.frame(Path(path).lstat()))for path in closure}
        self.archive=n['nativeArchive'];require(Path(self.archive['path']).parent==Path(case['executionInputsPath']).parent,'EXACT_NEW_PREPARED_ARCHIVE_LOCATION_REQUIRED');self.verify_archive()
        self.application_jar=self.extract_application()
        if self.runtime is not None:self.runtime_binding=self.runtime_snapshot()
        self.check_sources()
    def extract_application(self):
        import tarfile
        target=self.root/'application.jar';found=0
        with tarfile.open(self.archive['path'],'r:')as outer:
            for name in self.native['imageAudit']['layerMembers']:
                with outer.extractfile(name)as stream,tarfile.open(fileobj=stream,mode='r|*')as layer:
                    for member in layer:
                        require(member.name not in('app/.wh.application.jar','app/.wh..wh..opq'),'NO_APPLICATION_LAYER_WHITEOUT')
                        if member.name not in('app/application.jar','./app/application.jar'):continue
                        found+=1;require(found==1 and member.isfile()and member.size==self.application_facts['jarBytes'],'ONE_EXACT_APPLICATION_JAR_REQUIRED')
                        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
                        with layer.extractfile(member)as source,os.fdopen(fd,'wb')as out:
                            os.fchmod(out.fileno(),0o400);shutil.copyfileobj(source,out,1048576);out.flush();os.fsync(out.fileno())
        require(found==1 and sha(target.read_bytes())==self.application_facts['jarSha256'],'EXACT_QUALIFIED_APPLICATION_JAR_BYTES_REQUIRED');self.sync(self.root)
        return {'path':str(target),'sha256':self.application_facts['jarSha256'],'metadata':list(self.p.frame(target.lstat()))}
    def classify_configuration(self,postgres):
        import ast,types,zipfile
        from urllib.parse import urlsplit
        names=('application_json_metadata','owner_json_overlay','overlay_text','additional_location','verify')
        def private_file(path,checksum,maximum):
            require(path==self.application_jar['path']and checksum==self.application_jar['sha256']and maximum==268435456,'ONLY_EXACT_NEW_APPLICATION_JAR');require(sha(Path(path).read_bytes())==checksum,'APPLICATION_JAR_CHANGED')
        def owner(path):
            require(path==self.case['ownerOverlayPath'],'ONLY_ONE_NAMED_OWNER_CONFIGURATION');return self.owner_overlay_raw,self.owner_overlay_binding
        namespace={'hashlib':hashlib,'json':__import__('json'),'os':os,'Path':Path,'re':re,'urlsplit':urlsplit,'zipfile':zipfile,'require':require,
            'env':lambda rows:self.p.env({'Env':rows}),'private_file':private_file,'private_config':owner}
        nodes=[n for n in ast.parse(self.configuration_raw).body if isinstance(n,ast.FunctionDef)and n.name in names]
        require(len(nodes)==len(names),'EXACT_REUSED_CONFIGURATION_DEFINITIONS_REQUIRED');exec(compile(ast.Module(body=nodes,type_ignores=[]),'<sealed-configuration>','exec'),namespace)
        identity=self.database_profile['identity'];result=namespace['verify'](self.native['currentOnboarding'],{'jar':self.application_jar},postgres,
            {'user':identity['runtimeRole'],'database':identity['database'],'schema':identity['schema']},identity['postgresPort'],self.application_facts['applicationYamlSha256'])
        retained=copy.deepcopy(self.proposal['nativeFlywayConfiguration']);retained['configurationSha256']=self.application_facts['applicationYamlSha256']
        require(result==retained,'EXACT_RETAINED_CONFIGURATION_CHANNELS_AND_NEW_PACKAGED_CONFIG_REQUIRED')
        self.proposal['nativeFlywayConfiguration']=result;self.configuration_classified=True;del self.owner_overlay_raw
    def sync(self,path):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    def write(self,root,name,value):
        require(re.fullmatch('[A-Za-z0-9_.-]+',name)is not None,'CLOSED_PRIVATE_ONBOARDING_FILENAME')
        raw=value if isinstance(value,bytes)else self.p.encoded(value);require(len(raw)<=8*1024*1024,'BOUNDED_PRIVATE_ONBOARDING_EVIDENCE')
        path=Path(root)/name;fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        with os.fdopen(fd,'wb')as stream:
            os.fchmod(stream.fileno(),0o400);stream.write(raw);stream.flush();os.fsync(stream.fileno())
        self.sync(path.parent)
    def read(self,path,expected):return self.p.decode(self.p.protected(Path(path),expected))
    def evidence(self,name,value):
        # Controller and its single forked watchdog never overwrite or collide.
        self.serial+=1;self.write(self.root,name+'-'+str(os.getpid())+'-%05d.json'%self.serial,value)
    def retained(self,method,path,status,raw):
        self.receiptBytes+=len(raw);require(self.receiptBytes<=64*1024*1024,'FINITE_PRIVATE_RECEIPT_BYTE_BUDGET')
        self.evidence('raw-engine-response',{'method':method,'path':path,'status':status,'rawBodyHex':raw.hex()});self.responses+=1
    def reserve(self,kind):
        if self.execution:self.execution.reserve(kind)
        else:
            require(self.counts[kind]<self.core.LIMITS[kind],'FINITE_ONBOARDING_PREFLIGHT_BUDGET');self.counts[kind]+=1;self.evidence('preflight-attempt',{'kind':kind,'attempt':self.counts[kind],'attemptNotCompletion':True})
    def refresh_authority(self):
        self.reserve('ownerConfigurationReads');self.reserve('ownerConfigurationReads');value=self.public_authority(self.p)
        if hasattr(self,'authority_metadata'):require(value==self.authority_metadata,'INSTALLATION_PUBLIC_AUTHORITY_CHANGED')
        return value
    def executable(self):
        path=Path('/usr/bin/openssl').resolve(strict=True);self.p.ancestry(path.parent);s=path.lstat();require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_mode&0o111 and not s.st_mode&0o022 and s.st_size<=64000000,'TRUSTED_OPENSSL_REQUIRED')
        r=subprocess.run([str(path),'version'],capture_output=True,timeout=2,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'});v=re.match(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b',r.stdout)
        require(r.returncode==0 and v is not None and len(r.stdout)<=256,'EXACT_OPENSSL_VERSION_REQUIRED');return {'path':str(path),'sha256':sha(path.read_bytes()),'version':v[1].decode()}
    def verify_archive(self):
        d=self.native['nativeArchive'];path=Path(d['path']);self.p.ancestry(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb')as stream:
            s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and list(self.p.frame(s))==d['metadata']and s.st_size==d['bytes'],'ROOT_PREPARED_ARCHIVE_CUSTODY_REQUIRED')
            h=hashlib.sha256()
            for block in iter(lambda:stream.read(65536),b''):h.update(block)
            require(h.hexdigest()==d['sha256']==self.case['nativeArchiveHash']and list(self.p.frame(os.fstat(fd)))==d['metadata']==list(self.p.frame(path.lstat())),'PREPARED_ARCHIVE_BYTES_OR_SEAL_CHANGED')
    def check_sources(self):
        if hasattr(self,'runtime_binding'):self.runtime_check()
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.inputs['bootId']==self.proposal['bootId'],'SAME_ONBOARDING_UPDATE_HOST_BOOT_REQUIRED')
        for path,metadata in self.input_seals.items():require(list(self.p.frame(Path(path).lstat()))==metadata,'PREPARED_INPUT_SEAL_CHANGED')
        for path,metadata in self.prior_seals.items():require(list(self.p.frame(Path(path).lstat()))==metadata,'RECONCILED_PREFLIGHT_SEAL_CHANGED')
        for prior in self.prior_inventories:
            require(list(self.p.frame(Path(prior['path']).lstat()))==prior['metadata']and sorted(os.listdir(prior['path']))==prior['names'],'ORIGINAL_UNISSUED_PREFLIGHT_DIRECTORY_CHANGED')
        for path,metadata in self.source_seals.items():require(list(self.p.frame(Path(path).lstat()))==metadata,'SEALED_ONBOARDING_EXECUTOR_SOURCE_CHANGED')
        if hasattr(self,'backup_proof'):require(list(self.p.frame(Path(self.backup_proof['path']).lstat()))==self.backup_proof['metadata'],'VERIFIED_BACKUP_SEAL_CHANGED')
        if hasattr(self,'application_jar'):require(list(self.p.frame(Path(self.application_jar['path']).lstat()))==self.application_jar['metadata'],'APPLICATION_JAR_SEAL_CHANGED')
        require(list(self.p.frame(Path(self.archive['path']).lstat()))==self.archive['metadata'],'PREPARED_ARCHIVE_SEAL_CHANGED')
        require(list(self.p.frame(Path(self.owner_overlay_binding['path']).lstat()))==self.owner_overlay_binding['metadata'],'EXACT_CLASSIFIED_OWNER_CONFIGURATION_CHANGED')
    def closed_path(self,method,path,body):
        old=self.proposal['onboardingReplacement'];ids={v['containerId']for v in self.proposal['existingApplications'].values()}|getattr(self,'admitted_peer_ids',set())|{self.database_profile['postgresRuntimeBinding']['containerId']}
        if self.execution:ids|={v['id']for v in self.execution.read_journal()['candidates'].values()}
        names={old['retiredName']};gets={'/v1.44/info','/v1.44/networks/'+old['network']['id'],'/v1.44/images/'+quote(self.native['nativeImageId'],safe='')+'/json'}|{'/v1.44/containers/'+cid+'/json'for cid in ids|names}
        require(method in('GET','POST')and(method!='GET'or path in gets and body is None),'CLOSED_ONBOARDING_READ_ALLOWLIST_REQUIRED')
    def before_dispatch(self,method,path,body):
        self.closed_path(method,path,body)
        if method=='POST':
            require(self.execution is not None,'NO_RUNTIME_WRITE_WITHOUT_EXECUTION')
            row=self.execution.read_journal()
            if row['quarantine']is None:
                self.execution.gate.check();self.ports.assert_write(path,body)
            else:
                candidate=row['candidates'].get('onboarding');require(candidate and candidate.get('configurationVerified')is True,'ONLY_VERIFIED_OWN_ONBOARDING_NEGATIVE')
                cid=candidate['id'];require(cid not in{v['containerId']for v in self.proposal['existingApplications'].values()},'NEGATIVE_MUST_NOT_SELECT_RETAINED_CONTAINER')
                require((path,body)in[('/v1.44/containers/'+cid+'/update',{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}}),('/v1.44/containers/'+cid+'/stop?t=2',None)],'ONLY_OWN_ONBOARDING_DISABLE_STOP_NEGATIVE')
            self.evidence('engine-dispatch-claim',{'method':method,'path':path,'bodyHash':self.core.digest(body),'attemptNotCompletion':True})
    def preflight_get(self,path):
        self.reserve('engineGets');return self.engine.request('GET',path)
    def current(self):
        print('Verifico owner corrente, PostgreSQL e peer della rete; sole letture Engine, nessuna SQL prima di APPROVO.',flush=True)
        self.check_sources();old=self.proposal['onboardingReplacement']
        s,v=self.preflight_get('/v1.44/containers/'+old['oldBinding']['containerId']+'/json')
        require(s==200 and self.p.stable_binding(v)==old['oldBinding']and v['State']['Running']is True
                and v['State']['Paused']is False and v['State']['Restarting']is False
                and self.p.process_pin(v['State']['Pid'])==self.native['currentProcessPin'],'EXACT_CAPTURED_ONBOARDING_GENERATION_REQUIRED')
        s,_=self.preflight_get('/v1.44/containers/'+old['retiredName']+'/json');require(s==404,'RETAINED_ONBOARDING_NAME_ALREADY_EXISTS')
        s,info=self.preflight_get('/v1.44/info');require(s==200 and info['ServerVersion']=='29.8.1','QUALIFIED_ENGINE_VERSION_CHANGED')
        native=['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[])
        require(native==(self.proposal['nativeIdentityProfile']=='CONFIG_AND_NATIVE_MANIFEST'),'CURRENT_ENGINE_NATIVE_IDENTITY_PROFILE_CHANGED')
        s,net=self.preflight_get('/v1.44/networks/'+old['network']['id'])
        require(s==200 and net['Id']==old['network']['id']and net['Name']==old['network']['name']and net['Driver']=='bridge'and net['Scope']=='local','EXACT_CURRENT_NETWORK_REQUIRED')
        endpoints=net.get('Containers')or{};require(type(endpoints)is dict and 1<=len(endpoints)<=16,'BOUNDED_CURRENT_PEER_COHORT_REQUIRED')
        wanted=old['request']['NetworkingConfig']['EndpointsConfig'][old['network']['name']]['MacAddress'].lower()
        require([cid for cid,row in endpoints.items()if str(row.get('MacAddress','')).lower()==wanted]==[old['oldBinding']['containerId']],'SOLE_CURRENT_OWNER_MAC_REQUIRED')
        if hasattr(self,'network_baseline'):require(endpoints==self.network_baseline,'NETWORK_CHANGED_DURING_HUMAN_REVIEW')
        self.network_baseline=copy.deepcopy(endpoints)
        pg=self.database_profile['postgresRuntimeBinding']['containerId']
        peer_ids=(set(endpoints)|{pg})-{old['oldBinding']['containerId']}
        require(all(re.fullmatch('[a-f0-9]{64}',cid)for cid in peer_ids),'EXACT_NETWORK_PEER_IDENTITIES_REQUIRED')
        self.admitted_peer_ids=peer_ids
        for cid in sorted(peer_ids):
            role='peer-'+cid[:16];s,v=self.preflight_get('/v1.44/containers/'+cid+'/json')
            require(s==200 and v['State']['Running']is True and v['State']['Paused']is False and v['State']['Restarting']is False,'RUNNING_UNCHANGED_PEER_REQUIRED')
            binding=self.p.stable_binding(v);pin=self.p.process_pin(v['State']['Pid'])
            if cid==pg:
                self.database.check_postgres(self,v)
                if not getattr(self,'configuration_classified',False):self.classify_configuration(v)
            if role in self.proposal['existingApplications']:
                require(binding==self.proposal['existingApplications'][role]and pin==self.inputs['currentProcessPins'][role],'PEER_CHANGED_DURING_HUMAN_REVIEW')
            else:
                require(not hasattr(self,'cohort_frozen'),'NO_PEER_ADOPTION_AFTER_REVIEW');self.proposal['existingApplications'][role]=binding;self.inputs['currentProcessPins'][role]=pin
        if hasattr(self,'cohort_frozen'):require(set(self.proposal['existingApplications'])=={'onboarding',*('peer-'+cid[:16]for cid in peer_ids)},'SAME_COMPLETE_PEER_COHORT_REQUIRED')
        self.cohort_frozen=True;self.admission()
    def admission(self):
        mem=Path('/proc/meminfo').read_text();rows=re.findall(r'^MemAvailable:\s+([0-9]+) kB$',mem,re.MULTILINE);required=max(self.proposal['onboardingReplacement']['request']['HostConfig']['Memory'],268435456)+134217728
        require(len(rows)==1 and int(rows[0])*1024>=required and shutil.disk_usage(self.root).free>=536870912+self.archive['bytes'],'FRESH_FINITE_ONBOARDING_CAPACITY_REQUIRED')
    def restore_policy(self,role):require(role=='onboarding','ONBOARDING_ONLY_RESTART_POLICY');return self.proposal['onboardingReplacement']['restoreRestartPolicy']
    def import_claim(self):
        row=self.execution.record();i=row['nextStage'];require(self.core.STAGES[i]=='IMPORT_ONBOARDING'and len(row['effects'])==i+1 and row['effects'][-1]['state']=='CLAIMED','CLAIMED_EXACT_NATIVE_IMPORT_REQUIRED')
        self.execution.gate.check();self.verify_archive();self.evidence('native-import-dispatch-claim',{'method':'POST','path':'/v1.44/images/load?quiet=1','archiveHash':self.archive['sha256'],'attemptNotCompletion':True})
    def finalize(self,result):
        # Called by NativePorts.final_result INSIDE Execution.run's invocation
        # fence. No lock is held over I/O except the single-invocation fence.
        c=self.core;gate=self.gate;context=self.review['verification']['context']
        signer=self.sign.ExistingEd25519Signer(self.profile['keyBindings']['attestor'],self.profile['keyRefs']['attestor'],gate.verifier,{'role':'CREATION_ATTESTATION','issuerRef':context['attestorRef'],'installationRef':context['installationRef'],'entityRef':context['entityRef']})
        gate.check();raw=c.encoded(result);self.write(self.root,'candidate-result.json',raw)
        c.authentication_file(self.root/'authority',c.sha(raw)+'.CREATION_ATTESTATION.json',signer.sign(raw))
        require(gate.verifier(raw,'CREATION_ATTESTATION',context['attestorRef'],context['installationRef'],context['entityRef'])is True,'SIGNED_ONBOARDING_NATIVE_RESULT_REQUIRED')
        gate.check();self.execution.save(self.execution.record(),state='COMPLETE');self.write(self.root,'result.json',result);return result
    def candidate_configuration(self,role,v,started,restored,quarantine=False):
        proposal=self.proposal['onboardingReplacement']if role=='onboarding'else self.proposal['readComponents'][role];request=proposal['request'];require(v['Name']=='/'+proposal['name']and v['Image']==request['Image']and re.fullmatch('[a-f0-9]{64}',v['Id']),'EXACT_CREATED_CANDIDATE_IDENTITY_REQUIRED')
        for key,value in request.items():
            if key in('HostConfig','NetworkingConfig'):continue
            expected=proposal['runtimeLabelProjection']['expectedLabels']if key=='Labels'else value;require(v['Config'].get(key)==expected,'EXACT_CANDIDATE_CONFIG_FIELD_'+key.upper())
        defaults=self.native['candidateFacts'][role]['audit']['imageConfig']
        for key,value in v['Config'].items():
            if key in request or key=='MacAddress':continue
            require(value in(None,False,0,'',[],{})or key in('Shell','OnBuild')and value==defaults.get(key),'UNREVIEWED_NONDEFAULT_CREATED_CONFIG_FIELD')
        host=copy.deepcopy(request['HostConfig'])
        if restored:host['RestartPolicy']=self.restore_policy(role)
        # Stopped candidates may have Docker's already-materialized OOM default.
        ever_started=started or v['State'].get('StartedAt')not in(None,'','0001-01-01T00:00:00Z')
        projection=proposal.get('runtimeHostProjection');materialized=projection=={'profile':'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1','requestedOomKillDisable':None,'materializedOomKillDisable':False,'retainedMemoryBytes':host.get('Memory')}and host.get('OomKillDisable')is None
        require(self.engine_helpers.requested_host_config_matches(host,v['HostConfig'],started=ever_started or materialized),'EXACT_CANDIDATE_HOST_CONFIGURATION_REQUIRED')
        if role=='onboarding':require(self.core.digest(sorted(v['Mounts'],key=lambda m:m['Destination']))==proposal['oldBinding']['mountsHash'],'EXACT_ONBOARDING_RETAINED_MOUNTS_REQUIRED')
        else:
            observed={m['Destination']:m for m in v['Mounts']};expected={m['Target']:m for m in request['HostConfig']['Mounts']};extra=set(observed)-set(expected);require(not extra or extra=={'/tmp'}and observed['/tmp']['Type']=='tmpfs'and not observed['/tmp'].get('Source'),'ONLY_REVIEWED_READ_MOUNTS_REQUIRED')
            for destination,m in expected.items():
                actual=observed.get(destination,{});require(actual.get('Type')==m['Type']and actual.get('RW')is False and(actual.get('Source')if m['Type']=='bind'else actual.get('Name'))==m['Source'],'EXACT_EXISTING_READ_ONLY_MOUNT_REQUIRED')
        networks=v['NetworkSettings']['Networks'];name=proposal['network']['name'];require(set(networks)=={name}and networks[name]['NetworkID']==proposal['network']['id'],'EXACT_CANDIDATE_NETWORK_REQUIRED');endpoint=networks[name]
        if started:
            require(v['State']['Running']is True and v['State']['Paused']is False and v['State']['Restarting']is False and v['RestartCount']==0 and self.p.valid_mac(endpoint['MacAddress']),'EXACT_RUNNING_CANDIDATE_GENERATION_REQUIRED')
            requested=request['NetworkingConfig']['EndpointsConfig'][name];require(all(a in(endpoint.get('Aliases')or[])for a in requested.get('Aliases',[])),'EXACT_CANDIDATE_ALIASES_REQUIRED')
            if role=='onboarding':
                require(endpoint['MacAddress'].lower()==requested['MacAddress'].lower(),'EXACT_RETAINED_ONBOARDING_ENDPOINT_MAC_REQUIRED')
                ipam=requested.get('IPAMConfig')or{}
                for field,current in(('IPv4Address','IPAddress'),('IPv6Address','GlobalIPv6Address')):
                    if ipam.get(field):require(endpoint.get(current)==ipam[field],'EXACT_RETAINED_ONBOARDING_ENDPOINT_IP_REQUIRED')
            else:
                original=self.read(self.inputs['currentObservations'][role]['path'],self.inputs['currentObservations'][role]['sha256']);require(endpoint['MacAddress'].lower()!=next(iter(original['NetworkSettings']['Networks'].values()))['MacAddress'].lower(),'READ_REPLICA_MAC_MUST_DIFFER_FROM_LIVE_OWNER')
            require(v['Config'].get('MacAddress')in(None,'')or v['Config']['MacAddress'].lower()==endpoint['MacAddress'].lower(),'CONFIG_ENDPOINT_MAC_DRIFT')
        else:require(v['State']['Running']is False and v['State']['Pid']==0,'CANDIDATE_MUST_REMAIN_STOPPED')

    def runtime_snapshot(self):
        stdlib=self.runtime.stdlib_binding();python=Path(sys.executable).resolve(strict=True);self.p.ancestry(python.parent);row=python.lstat();require(stat.S_ISREG(row.st_mode)and row.st_uid==row.st_gid==0 and row.st_mode&0o111 and not row.st_mode&0o022,'ROOT_PYTHON_RUNTIME_REQUIRED');metadata={}
        for relative,binding in stdlib['fileHashes'].items():
            original=Path(stdlib['root'])/relative;target=Path(binding['resolvedPath']);metadata[relative]={'original':list(self.p.frame(original.lstat())),'resolved':list(self.p.frame(target.lstat()))}
        return {'python':{'path':str(python),'sha256':sha(python.read_bytes()),'metadata':list(self.p.frame(row))},'stdlib':stdlib,'metadata':metadata,'noSiteRequired':True,'isolatedRequired':True,'dontWriteBytecodeRequired':True}
    def runtime_check(self):
        runtime=self.runtime_binding;require(list(self.p.frame(Path(runtime['python']['path']).lstat()))==runtime['python']['metadata'],'PYTHON_EXECUTABLE_CHANGED')
        for relative,meta in runtime['metadata'].items():
            original=Path(runtime['stdlib']['root'])/relative;resolved=Path(runtime['stdlib']['fileHashes'][relative]['resolvedPath']);require(original.resolve()==resolved and list(self.p.frame(original.lstat()))==meta['original']and list(self.p.frame(resolved.lstat()))==meta['resolved'],'SEALED_STDLIB_CHANGED')
