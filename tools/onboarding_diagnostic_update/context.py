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
TARGET={'executionInputsHash':'c22586172070809d414d3654f3e002b7e1d84d749daae9b31dac8d1d14cbd0c0',
        'inputsHash':'5909d1003e88231c1d41a799a12539127d27386f79a04ed345ad9d29eaaddb6d',
        'nativeImageId':'sha256:074bd16ec8ebd98cbf1ee085af9767a5f7e322072a541e85bd37925002fa5df2',
        'sourceCommit':'a5ed8b05c264a8221783a6e323ba00117aed891d','testedCommit':'692277b1bf5def4a2b5b1ba4fb6770c16b136fb5',
        'nativeArchiveHash':'87585bd8d50f8d955ef1abc26c43df52a481ac89df2ed2722ace3765aad1b071',
        'executionInputsPath':'/etc/ouf/deploy-snapshots/onboarding-diagnostic-image-inputs-5909d1003e88231c-v1/execution-inputs.json',
        'inputsPath':'/etc/ouf/deploy-snapshots/onboarding-diagnostic-current-inputs-20261026-v1/inputs.json',
        'databaseIdentityPath':'/etc/ouf/deploy-snapshots/onboarding-budget-v35-54d86bbcd2ea47fd/native-plan-v1/execution-plan.json',
        'databaseIdentityHash':'b17c2c99cc791cced8ee00ed190e30b75c518ae84e2dd4a9ae7eef521390c8bd',
        'ownerOverlayPath':'/opt/ouf/secrets/onboarding-ths.yaml',
        'executionRoot':'/etc/ouf/deploy-snapshots/onboarding-diagnostic-update-c22586172070809d-v1'}
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
        self.fence,self.database=parts['state_fence'],parts['database']
        self.auth,self.sign,self.journal_module=auth,sign,journal;self.closure=copy.deepcopy(closure);self.case=copy.deepcopy(case);self.root=Path(case['executionRoot']);self.serial=0
        self.execution=None;self.counts={k:0 for k in self.core.LIMITS};self.responses=0;self.receiptBytes=0;self.runtime=runtime;self.prior_seals={}
        self.p.ancestry(self.root.parent);require(not os.path.lexists(self.root),'ONBOARDING_UPDATE_SCOPE_CONSUMED_NO_REPLAY');self.root.mkdir(mode=0o700);self.root.chmod(0o700)
        self.sync(self.root.parent);self.write(self.root,'preparation-claim.json',{'schema':'ouf.onboarding-diagnostic-update-preflight-claim.v1','executionInputsHash':case['executionInputsHash'],'maximums':self.core.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
        self.reserve('ownerConfigurationReads');self.native=self.read(case['executionInputsPath'],case['executionInputsHash'])
        self.reserve('ownerConfigurationReads');self.inputs=self.read(case['inputsPath'],case['inputsHash'])
        n=self.native
        require(n['schema']=='ouf.onboarding-diagnostic-private-execution-inputs.v1'and n['capturedInputsHash']==case['inputsHash']
                and n['nativeImageId']==case['nativeImageId']and n['imageAudit']['sourceCommit']==n['testedCommit']==case['testedCommit']
                and n['reviewedSourceCommit']==case['sourceCommit']and n['nativeArchive']['sha256']==case['nativeArchiveHash']
                and all(n[k]is False for k in('executionEntryQualified','runtimeAuthorityIssued','lifecyclePlanCompiled','currentRuntimeRevalidated','targetUpdateAuthorized','automaticReplayAllowed','budgetReset')),
                'EXACT_CONSUMED_ONBOARDING_IMAGE_INPUTS_REQUIRED')
        require(self.inputs['schema']=='ouf.onboarding-diagnostic-current-inputs.v1'and n['bootId']==self.inputs['bootId']
                and n['currentOnboarding']==self.inputs['onboardingObservation']and n['currentProcessPin']==self.inputs['onboardingProcessPin']
                and n['engineBinding']==self.inputs['engineBinding']and n['engineInfoHash']==self.core.digest(self.inputs['engineInfo']),
                'EXACT_CAPTURE_AND_PREPARATION_LINEAGE_REQUIRED')
        self.reserve('ownerConfigurationReads');frozen=self.read(case['databaseIdentityPath'],case['databaseIdentityHash'])
        require(frozen['schema']=='ouf.onboarding-v35-frozen-native-plan.v1','RETAINED_DATABASE_IDENTITY_METADATA_ONLY')
        self.database_profile=copy.deepcopy(frozen['boundDatabaseProfile']);profile=self.database_profile
        require(profile['schema']=='ouf.current-onboarding-database-snapshot-profile.v1'and profile['engineBinding']==n['engineBinding']
                and profile['runtimeBindingProfile']=='ouf.runtime-binding.native-mount-order.v1','EXACT_RETAINED_NATIVE_DATABASE_TRANSPORT_REQUIRED')
        self.readiness=copy.deepcopy(frozen['replacements']['onboarding']['readiness'])
        require(type(self.readiness['readinessPort'])is int and 1<=self.readiness['readinessPort']<=65535
                and self.readiness['readinessPath']in('/q/health/ready','/health/ready'),'RETAINED_OWNER_READINESS_ENDPOINT_REQUIRED')
        self.reserve('ownerConfigurationReads');migration_path=Path(__file__).resolve().parent/'migration-fence.json'
        migration_doc=self.read(migration_path,closure[str(migration_path)])
        self.migrations=migration_doc
        old=n['currentOnboarding'];request=self.p.config_copy(old);image=n['imageAudit']['imageConfig']
        retained_request=frozen['replacements']['onboarding']['request']
        for key in('Env','Entrypoint','Cmd','User','WorkingDir','Healthcheck'):
            require(request.get(key)==retained_request.get(key),'SAME_CLASSIFIED_OWNER_LAUNCH_CONFIGURATION_REQUIRED')
        overlays=frozen['nativeFlywayConfiguration']['ownerOverlays']
        require(len(overlays)==1 and overlays[0]['binding']['path']==case['ownerOverlayPath'],'ONLY_NAMED_RETAINED_OWNER_CONFIGURATION_REQUIRED')
        self.reserve('ownerConfigurationContentReads')
        raw,self.owner_overlay_binding=self.p.private_config(case['ownerOverlayPath'],overlays[0]['binding'])
        del raw
        require(request['User']in(image['User'],image['User'].split(':')[0])and request['Entrypoint']==image['Entrypoint']
                and request.get('Cmd')==image.get('Cmd'),'EXACT_RETAINED_OWNER_LAUNCH_REQUIRED')
        name=old['Name'].removeprefix('/');require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,160}',name),'BOUND_OWNER_NAME_REQUIRED')
        host=copy.deepcopy(old['HostConfig']);restore=copy.deepcopy(host['RestartPolicy']);host['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
        endpoint=next(iter(old['NetworkSettings']['Networks'].values()));network=self.p.network(old,[name,*(endpoint.get('Aliases')or[])],preserve_mac=True)
        request.update(Image=case['nativeImageId'],HostConfig=host,NetworkingConfig=network['request'])
        replacement={'name':name,'retiredName':name+'-retained-diagnostic-'+case['executionInputsHash'][:12],
                     'request':request,'network':{'name':network['name'],'id':network['id']},'oldBinding':self.p.stable_binding(old),
                     'restoreRestartPolicy':restore,'oldNativeHostConfig':copy.deepcopy(old['HostConfig'])}
        retained_ipam=copy.deepcopy(endpoint.get('IPAMConfig')or{})
        require(type(retained_ipam)is dict and set(retained_ipam)<={'IPv4Address','IPv6Address','LinkLocalIPs'},'CLOSED_RETAINED_OWNER_ENDPOINT_ALLOCATION')
        for source,target,version in(('IPAddress','IPv4Address',4),('GlobalIPv6Address','IPv6Address',6)):
            address=endpoint.get(source)
            if address:
                parsed=ipaddress.ip_address(address);require(parsed.version==version and not parsed.is_unspecified and not parsed.is_multicast,'EXACT_RETAINED_ENDPOINT_ADDRESS_REQUIRED')
                require(retained_ipam.get(target)in(None,'',address),'STATIC_OBSERVED_IP_MISMATCH');retained_ipam[target]=address
        request['NetworkingConfig']['EndpointsConfig'][network['name']]['IPAMConfig']=retained_ipam
        for port,bindings in(request['HostConfig'].get('PortBindings')or{}).items():
            if any(row.get('HostPort')in(None,'','0')for row in bindings):
                actual=(old['NetworkSettings'].get('Ports')or{}).get(port)
                require(type(actual)is list and len(actual)==len(bindings)and all(type(r)is dict and str(r.get('HostPort','')).isdigit()and 1<=int(r['HostPort'])<=65535 for r in actual),'ALREADY_ALLOCATED_PUBLISHED_PORT_REQUIRED')
                request['HostConfig']['PortBindings'][port]=copy.deepcopy(actual)
        old_labels=request.get('Labels')or{};defaults=image.get('Labels')or{}
        require(all(k.startswith('org.opencontainers.image.')for k in set(defaults)-set(old_labels)),'ONLY_QUALIFIED_IMAGE_LABEL_DEFAULTS')
        replacement['runtimeLabelProjection']={'expectedLabels':{**defaults,**old_labels}}
        replacement['retainedResourcePolicy']=retained_host_policy(host)
        if host.get('OomKillDisable')is None:replacement['runtimeHostProjection']={'profile':'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1','requestedOomKillDisable':None,'materializedOomKillDisable':False,'retainedMemoryBytes':host['Memory']}
        self.proposal={'schema':'ouf.onboarding-diagnostic-conditional-lifecycle-plan.v1','capturedInputsHash':case['inputsHash'],
                       'executionInputsHash':case['executionInputsHash'],'bootId':n['bootId'],'engineBinding':n['engineBinding'],
                       'nativeIdentityProfile':'CONFIG_AND_NATIVE_MANIFEST'if n['imageAudit'].get('nativeIdentity')else'CONFIG_DIGEST',
                       'existingApplications':{'onboarding':self.p.stable_binding(old)},'onboardingReplacement':replacement,
                       'legacyConfigMacDetachPolicy':self.mac.policy(old),'operationalSqlHash':self.core.sha(self.fence.query().encode()),
                       'databaseTransportIdentityHash':self.core.digest(profile),'readiness':self.readiness,
                       'retainedCaptureCounts':copy.deepcopy(self.inputs['counts']),
                       'retainedImagePreparationCounts':{'ciZipReads':1,'containerWrites':0,'engineGets':0,'imageImports':0,'nativeArchivesPrepared':1,'privateMetadataReads':2}}
        self.inputs['currentObservations']={'onboarding':old};self.inputs['currentProcessPins']={'onboarding':n['currentProcessPin']}
        self.native['candidateFacts']={'onboarding':{'audit':self.native['imageAudit']}}
        self.engine=self.http.Engine(self.p,n['engineBinding']);self.engine.before=self.before_dispatch;self.engine.retained=self.retained
        self.public_authority=public_authority or globals()['public_authority'];self.authority_metadata=self.refresh_authority();self.profile=self.authority_metadata['profile'];self.openssl=self.executable()
        self.input_seals={path:list(self.p.frame(Path(path).lstat()))for path in(case['executionInputsPath'],case['inputsPath'],case['databaseIdentityPath'])}
        self.source_seals={path:list(self.p.frame(Path(path).lstat()))for path in closure}
        self.archive=self.native['nativeArchive'];require(Path(self.archive['path']).parent==Path(case['executionInputsPath']).parent,'EXACT_PREPARED_ARCHIVE_LOCATION_REQUIRED')
        self.verify_archive()
        if self.runtime is not None:self.runtime_binding=self.runtime_snapshot()
        self.check_sources()
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
        for path,metadata in self.source_seals.items():require(list(self.p.frame(Path(path).lstat()))==metadata,'SEALED_ONBOARDING_EXECUTOR_SOURCE_CHANGED')
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
            if cid==pg:self.database.check_postgres(self,v)
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
