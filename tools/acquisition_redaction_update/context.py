"""Private state and receipts for a new, exact two-READ runtime intent.

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
    require(host.get('AutoRemove')is False and type(host.get('Memory'))is int and host['Memory']>=0,'EXACT_RETAINED_READ_HOST_POLICY_REQUIRED')
    require(host.get('OomKillDisable')is None or type(host.get('OomKillDisable'))is bool,'TYPED_RETAINED_READ_OOM_POLICY_REQUIRED')
    return {'memoryBytes':host['Memory'],'memoryPolicy':'RETAIN_EXACT_ZERO_NO_HARD_LIMIT'if host['Memory']==0 else'RETAIN_EXACT_POSITIVE_LIMIT','autoRemove':False,'oomKillDisable':host.get('OomKillDisable'),'resourcePolicyChanged':False}
TARGET={'nativePlanHash':'f11dbe659ba4367a1d873a8938f43546a6851bbdcbb907eb588cb1323122f5fd',
        'frozenPlanHash':'d5ce0235cd9014656ceaacd0dcc984a5ff0db93e2be3cac9e67c18fc42f156e2',
        'inputsHash':'9bbe7298c2eff0be51bf943919c9db0044413256b08efe620a503f79aef4d7d2',
        'nativePlanPath':'/etc/ouf/deploy-snapshots/acquisition-redaction-image-plan-9bbe7298c2eff0be-v1/native-plan.json',
        'resultPath':'/etc/ouf/deploy-snapshots/acquisition-redaction-image-plan-9bbe7298c2eff0be-v1/result.json',
        'inputsPath':'/etc/ouf/deploy-snapshots/acquisition-redaction-update-inputs-v1/inputs.json',
        'executionRoot':'/etc/ouf/deploy-snapshots/acquisition-redaction-update-f11dbe659ba4367a-v1',
        'sources':{'ingestion':'7d85bfe0d1423bcb13e115f06c92d8a0baa1ebf7','udp':'125510cf9d970aff7db66a0a8f27eb98b50bb6de'},
        'archives':{'ingestion':'c0a94d767f3a666c93a465bbe4201fc6647a77be55f92b82b20ce19ae4b43280','udp':'a26d65e46da9f27eef9bd8fa076742ef1e28dde2a97fa90af2a13b0d80fc72c3'}}
class Context:
    def __init__(self,parts,auth,sign,journal,closure,*,case=TARGET,public_authority=None,runtime=None):
        self.core,self.p,self.images,self.mac,self.http,self.ports_module,self.watch,self.engine_helpers,self.terminal=[parts[k]for k in('authority','plan_helper','image_custody','retained_mac','transport','ports','quarantine','engine_creation','terminal')]
        self.auth,self.sign,self.journal_module=auth,sign,journal;self.closure=copy.deepcopy(closure);self.case=copy.deepcopy(case)
        self.root=Path(case['executionRoot']);self.serial=0;self.execution=None;self.runtime=runtime
        self.counts={k:0 for k in self.core.LIMITS};self.responses=0;self.receiptBytes=0
        self.p.ancestry(self.root.parent);require(not os.path.lexists(self.root),'REDACTION_UPDATE_SCOPE_CONSUMED_NO_REPLAY')
        self.root.mkdir(mode=0o700);self.root.chmod(0o700);self.sync(self.root.parent)
        self.write(self.root,'preparation-claim.json',{'schema':'ouf.acquisition-redaction-preflight-claim.v1','nativePlanHash':case['nativePlanHash'],'maximums':self.core.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
        for name,path,digest in(('native','nativePlanPath','nativePlanHash'),('inputs','inputsPath','inputsHash')):
            self.reserve('ownerConfigurationReads');setattr(self,name,self.read(case[path],case[digest]))
        self.reserve('ownerConfigurationReads');result=self.read(case['resultPath'],None)
        require(result['schema']=='ouf.acquisition-redaction-image-plan-prepared.v1'and result['status']=='ACQUISITION_REDACTION_IMAGES_AND_PLAN_PREPARED_NOT_AUTHORIZED'
                and result['complete']is True and result['nativePlanHash']==case['nativePlanHash']and result['frozenPlanHash']==case['frozenPlanHash']
                and result['inputsHash']==case['inputsHash']and result['runtimeAuthorityIssued']is False and result['executionEntryQualified']is False
                and result['counts']=={'privateMetadataReads':2,'ciZipReads':2,'nativeArchivesPrepared':2,'engineGets':0,'containerWrites':0,'imageImports':0},'EXACT_POSITIVE_OFFLINE_PLAN_RECEIPT_REQUIRED')
        require(self.native['schema']=='ouf.acquisition-redaction-native-image-plan.v1'and self.native['frozenPlanHash']==case['frozenPlanHash']==self.p.digest(self.native['proposal'])
                and self.native['proposal']['capturedInputsHash']==case['inputsHash']and self.native['executionEntryQualified']is False and self.native['runtimeAuthorityIssued']is False
                and self.inputs['schema']=='ouf.acquisition-redaction-update-inputs.v1'and self.inputs['candidateSourceCommits']==case['sources'],'EXACT_PREPARED_TWO_READ_NATIVE_PLAN_REQUIRED')
        self.proposal=copy.deepcopy(self.native['proposal']);self.archives={};self.facts=self.native['nativeImages']
        require(set(self.proposal['readReplacements'])==set(self.facts)==set(case['sources'])==set(case['archives'])=={'ingestion','udp'},'EXACT_TWO_READ_REPLACEMENTS_REQUIRED')
        require(self.proposal['mcpUnchanged']is True and self.proposal['gatewayUnchanged']is True and self.proposal['originalWorkersUnchanged']is True
                and self.proposal['registryWorkerTouched']is False and self.proposal['grantChangesAuthorized']is False and self.proposal['acquisitionCallsAuthorized']is False,'NO_OTHER_RUNTIME_INTENT_REQUIRED')
        for role in self.core.ROLES:
            row=self.proposal['readReplacements'][role];fact=self.facts[role];archive=fact['archive'];identity=fact['identity'];audit=fact['audit'];request=row['request']
            require(audit['sourceCommit']==case['sources'][role]and archive['sha256']==case['archives'][role]==identity['derivedArchiveSha256']
                    and identity['configurationImageId']==request['Image']and self.images.runtime_image_id(audit)==identity['nativeImageId']
                    and result['nativeImages'][role]==identity and Path(archive['path']).parent==Path(case['nativePlanPath']).parent/role,'EXACT_BOUND_READ_ARCHIVE_IDENTITY_REQUIRED')
            self.archives[role]=archive;request['Image']=identity['nativeImageId']
            row['runtimeImageProjection']={'configurationImageId':identity['configurationImageId'],'nativeImageId':identity['nativeImageId'],'rebuildOrRelabel':False}
            defaults=audit['imageConfig'].get('Labels')or{};labels=request.get('Labels')or{}
            require(all(k.startswith('org.opencontainers.image.')for k in set(defaults)-set(labels)),'ONLY_QUALIFIED_IMAGE_LABEL_DEFAULTS')
            row['runtimeLabelProjection']={'expectedLabels':{**defaults,**labels}}
            host=request['HostConfig'];row['retainedResourcePolicy']=retained_host_policy(host)
            if host.get('OomKillDisable')is None:row['runtimeHostProjection']={'profile':'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1','requestedOomKillDisable':None,'materializedOomKillDisable':False,'retainedMemoryBytes':host['Memory']}
        self.engine=self.http.Engine(self.p,self.proposal['engineBinding']);self.engine.before=self.before_dispatch;self.engine.retained=self.retained
        self.public_authority=public_authority or globals()['public_authority'];self.authority_metadata=self.refresh_authority();self.profile=self.authority_metadata['profile'];self.openssl=self.executable()
        self.input_seals={case[k]:list(self.p.frame(Path(case[k]).lstat()))for k in('nativePlanPath','inputsPath','resultPath')}
        self.source_seals={path:list(self.p.frame(Path(path).lstat()))for path in closure};self.verify_archive()
        if runtime is not None:self.runtime_binding=self.runtime_snapshot()
        self.check_sources()
    def sync(self,path):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)

    def write(self,root,name,value):
        require(re.fullmatch('[A-Za-z0-9_.-]+',name)is not None,'CLOSED_PRIVATE_READ_FILENAME')
        raw=value if isinstance(value,bytes)else self.p.encoded(value);require(len(raw)<=8*1024*1024,'BOUNDED_PRIVATE_READ_EVIDENCE')
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
            require(self.counts[kind]<self.core.LIMITS[kind],'FINITE_READ_PREFLIGHT_BUDGET');self.counts[kind]+=1;self.evidence('preflight-attempt',{'kind':kind,'attempt':self.counts[kind],'attemptNotCompletion':True})

    def refresh_authority(self):
        self.reserve('ownerConfigurationReads');self.reserve('ownerConfigurationReads');value=self.public_authority(self.p)
        if hasattr(self,'authority_metadata'):require(value==self.authority_metadata,'INSTALLATION_PUBLIC_AUTHORITY_CHANGED')
        return value

    def executable(self):
        path=Path('/usr/bin/openssl').resolve(strict=True);self.p.ancestry(path.parent);s=path.lstat();require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_mode&0o111 and not s.st_mode&0o022 and s.st_size<=64000000,'TRUSTED_OPENSSL_REQUIRED')
        r=subprocess.run([str(path),'version'],capture_output=True,timeout=2,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'});v=re.match(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b',r.stdout)
        require(r.returncode==0 and v is not None and len(r.stdout)<=256,'EXACT_OPENSSL_VERSION_REQUIRED');return {'path':str(path),'sha256':sha(path.read_bytes()),'version':v[1].decode()}

    def finalize(self,result):
        # Called by NativePorts.final_result INSIDE Execution.run's invocation
        # fence. No lock is held over I/O except the single-invocation fence.
        c=self.core;gate=self.gate;context=self.review['verification']['context']
        signer=self.sign.ExistingEd25519Signer(self.profile['keyBindings']['attestor'],self.profile['keyRefs']['attestor'],gate.verifier,{'role':'CREATION_ATTESTATION','issuerRef':context['attestorRef'],'installationRef':context['installationRef'],'entityRef':context['entityRef']})
        gate.check();raw=c.encoded(result);self.write(self.root,'candidate-result.json',raw)
        c.authentication_file(self.root/'authority',c.sha(raw)+'.CREATION_ATTESTATION.json',signer.sign(raw))
        require(gate.verifier(raw,'CREATION_ATTESTATION',context['attestorRef'],context['installationRef'],context['entityRef'])is True,'SIGNED_READ_NATIVE_RESULT_REQUIRED')
        gate.check();self.execution.save(self.execution.record(),state='COMPLETE');self.write(self.root,'result.json',result);return result

    def runtime_snapshot(self):
        stdlib=self.runtime.stdlib_binding();python=Path(sys.executable).resolve(strict=True);self.p.ancestry(python.parent);row=python.lstat();require(stat.S_ISREG(row.st_mode)and row.st_uid==row.st_gid==0 and row.st_mode&0o111 and not row.st_mode&0o022,'ROOT_PYTHON_RUNTIME_REQUIRED');metadata={}
        for relative,binding in stdlib['fileHashes'].items():
            original=Path(stdlib['root'])/relative;target=Path(binding['resolvedPath']);metadata[relative]={'original':list(self.p.frame(original.lstat())),'resolved':list(self.p.frame(target.lstat()))}
        return {'python':{'path':str(python),'sha256':sha(python.read_bytes()),'metadata':list(self.p.frame(row))},'stdlib':stdlib,'metadata':metadata,'noSiteRequired':True,'isolatedRequired':True,'dontWriteBytecodeRequired':True}

    def runtime_check(self):
        runtime=self.runtime_binding;require(list(self.p.frame(Path(runtime['python']['path']).lstat()))==runtime['python']['metadata'],'PYTHON_EXECUTABLE_CHANGED')
        for relative,meta in runtime['metadata'].items():
            original=Path(runtime['stdlib']['root'])/relative;resolved=Path(runtime['stdlib']['fileHashes'][relative]['resolvedPath']);require(original.resolve()==resolved and list(self.p.frame(original.lstat()))==meta['original']and list(self.p.frame(resolved.lstat()))==meta['resolved'],'SEALED_STDLIB_CHANGED')

    def verify_archive(self):
        for role,d in self.archives.items():
            path=Path(d['path']);self.p.ancestry(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb')as stream:
                s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and list(self.p.frame(s))==d['metadata']and s.st_size==d['bytes'],'ROOT_PREPARED_ARCHIVE_CUSTODY_REQUIRED')
                h=hashlib.sha256()
                for block in iter(lambda:stream.read(65536),b''):h.update(block)
                require(h.hexdigest()==d['sha256']==self.case['archives'][role]and list(self.p.frame(os.fstat(fd)))==d['metadata']==list(self.p.frame(path.lstat())),'PREPARED_ARCHIVE_BYTES_OR_SEAL_CHANGED')
    def check_sources(self):
        if hasattr(self,'runtime_binding'):self.runtime_check()
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.inputs['bootId']==self.proposal['bootId'],'SAME_REDACTION_UPDATE_HOST_BOOT_REQUIRED')
        for path,metadata in {**self.input_seals,**self.source_seals}.items():require(list(self.p.frame(Path(path).lstat()))==metadata,'PREPARED_INPUT_OR_SOURCE_SEAL_CHANGED')
        for d in self.archives.values():require(list(self.p.frame(Path(d['path']).lstat()))==d['metadata'],'PREPARED_ARCHIVE_SEAL_CHANGED')
    def closed_path(self,method,path,body):
        ids={v['containerId']for v in self.proposal['existingApplications'].values()}
        if self.execution:ids|={v['id']for v in self.execution.read_journal()['candidates'].values()}
        rows=self.proposal['readReplacements'];names={v['retiredName']for v in rows.values()}
        gets={'/v1.44/info'}|{'/v1.44/networks/'+v['network']['id']for v in rows.values()}|{'/v1.44/images/'+quote(v['identity']['nativeImageId'],safe='')+'/json'for v in self.facts.values()}|{'/v1.44/containers/'+cid+'/json'for cid in ids|names}
        require(method in('GET','POST')and(method!='GET'or path in gets and body is None),'CLOSED_TWO_READ_ENGINE_ALLOWLIST_REQUIRED')
    def before_dispatch(self,method,path,body):
        self.closed_path(method,path,body)
        if method=='POST':
            require(self.execution is not None,'NO_RUNTIME_WRITE_WITHOUT_EXECUTION');row=self.execution.read_journal()
            if row['quarantine']is None:self.execution.gate.check();self.ports.assert_write(path,body)
            else:
                candidates=[c for r,c in row['candidates'].items()if r in self.core.ROLES and c.get('configurationVerified')is True]
                commands=[x for c in candidates for x in(('/v1.44/containers/'+c['id']+'/update',{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}}),('/v1.44/containers/'+c['id']+'/stop?t=2',None))]
                require((path,body)in commands and all(c['id']not in{v['containerId']for v in self.proposal['existingApplications'].values()}for c in candidates),'ONLY_OWN_VERIFIED_READ_NEGATIVE_COMMANDS')
            self.evidence('engine-dispatch-claim',{'method':method,'path':path,'bodyHash':self.core.digest(body),'attemptNotCompletion':True})
    def preflight_get(self,path):
        self.reserve('engineGets');return self.engine.request('GET',path)
    def current(self):
        print('Verifico sette generazioni, due nomi retained e reti; sole letture Engine.',flush=True);self.check_sources()
        for role,b in self.proposal['existingApplications'].items():
            s,v=self.preflight_get('/v1.44/containers/'+b['containerId']+'/json')
            require(s==200 and v['State']['Running']is True and v['State']['Paused']is False and v['State']['Restarting']is False and self.p.stable_binding(v)==b and self.p.process_pin(v['State']['Pid'])==self.inputs['currentProcessPins'][role],'EXACT_SEVEN_CURRENT_GENERATIONS_REQUIRED')
        for row in self.proposal['readReplacements'].values():
            s,_=self.preflight_get('/v1.44/containers/'+row['retiredName']+'/json');require(s==404,'RETAINED_READ_NAME_ALREADY_EXISTS')
        s,info=self.preflight_get('/v1.44/info');require(s==200 and info['ServerVersion']=='29.8.1','QUALIFIED_ENGINE_VERSION_CHANGED')
        native=['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[]);require(native==(self.proposal['nativeIdentityProfile']=='CONFIG_AND_NATIVE_MANIFEST'),'CURRENT_ENGINE_NATIVE_IDENTITY_PROFILE_CHANGED')
        baselines={}
        for row in self.proposal['readReplacements'].values():
            net=row['network'];s,v=self.preflight_get('/v1.44/networks/'+net['id']);require(s==200 and v['Id']==net['id']and v['Name']==net['name']and v['Driver']=='bridge'and v['Scope']=='local','EXACT_CURRENT_READ_NETWORK_REQUIRED')
            wanted=row['request']['NetworkingConfig']['EndpointsConfig'][net['name']]['MacAddress'].lower();members=v.get('Containers')or{}
            require([cid for cid,ep in members.items()if str(ep.get('MacAddress','')).lower()==wanted]==[row['oldBinding']['containerId']],'SOLE_CURRENT_READ_ENDPOINT_MAC_OWNER_REQUIRED')
            baselines[net['id']]=copy.deepcopy(members)
        if hasattr(self,'network_baseline'):require(baselines==self.network_baseline,'NETWORK_CHANGED_DURING_HUMAN_REVIEW')
        self.network_baseline=baselines;self.admission()
    def admission(self):
        rows=re.findall(r'^MemAvailable:\s+([0-9]+) kB$',Path('/proc/meminfo').read_text(),re.MULTILINE)
        required=sum(max(v['request']['HostConfig']['Memory'],268435456)for v in self.proposal['readReplacements'].values())+134217728
        require(len(rows)==1 and int(rows[0])*1024>=required and shutil.disk_usage(self.root).free>=536870912+sum(v['bytes']for v in self.archives.values()),'FRESH_FINITE_TWO_READ_CAPACITY_REQUIRED')
    def restore_policy(self,role):
        require(role in self.core.ROLES,'ONLY_TWO_READ_RESTART_POLICIES');return self.proposal['readReplacements'][role]['restoreRestartPolicy']
    def import_claim(self,role):
        row=self.execution.record();i=row['nextStage'];require(self.core.STAGES[i]=='IMPORT_'+role.upper()+'_READ'and len(row['effects'])==i+1 and row['effects'][-1]['state']=='CLAIMED','CLAIMED_EXACT_NATIVE_IMPORT_REQUIRED')
        self.execution.gate.check();self.verify_archive();self.evidence('native-import-dispatch-claim',{'role':role,'method':'POST','path':'/v1.44/images/load?quiet=1','archiveHash':self.archives[role]['sha256'],'attemptNotCompletion':True})
    def candidate_configuration(self,role,v,started,restored,quarantine=False):
        require(role in self.core.ROLES,'ONLY_TWO_OWN_READ_CANDIDATES');proposal=self.proposal['readReplacements'][role];request=proposal['request']
        require(v['Name']=='/'+proposal['name']and v['Image']==request['Image']and re.fullmatch('[a-f0-9]{64}',v['Id']),'EXACT_CREATED_READ_IDENTITY_REQUIRED')
        for key,value in request.items():
            if key in('HostConfig','NetworkingConfig'):continue
            expected=proposal['runtimeLabelProjection']['expectedLabels']if key=='Labels'else value
            require(v['Config'].get(key)==expected,'EXACT_CANDIDATE_CONFIG_FIELD_'+key.upper())
        for key,value in v['Config'].items():
            if key in request or key=='MacAddress':continue
            require(value in(None,False,0,'',[],{})or key in('Shell','OnBuild')and value==self.facts[role]['audit']['imageConfig'].get(key),'UNREVIEWED_NONDEFAULT_CREATED_CONFIG_FIELD')
        host=copy.deepcopy(request['HostConfig'])
        if restored:host['RestartPolicy']=self.restore_policy(role)
        ever_started=started or v['State'].get('StartedAt')not in(None,'','0001-01-01T00:00:00Z')
        projection=proposal.get('runtimeHostProjection');materialized=projection=={'profile':'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1','requestedOomKillDisable':None,'materializedOomKillDisable':False,'retainedMemoryBytes':host.get('Memory')}and host.get('OomKillDisable')is None
        require(self.engine_helpers.requested_host_config_matches(host,v['HostConfig'],started=ever_started or materialized),'EXACT_CANDIDATE_HOST_CONFIGURATION_REQUIRED')
        require(self.core.digest(sorted(v['Mounts'],key=lambda m:m['Destination']))==proposal['oldBinding']['mountsHash'],'EXACT_READ_RETAINED_MOUNTS_REQUIRED')
        name=proposal['network']['name'];networks=v['NetworkSettings']['Networks'];require(set(networks)=={name}and networks[name]['NetworkID']==proposal['network']['id'],'EXACT_CANDIDATE_NETWORK_REQUIRED')
        endpoint=networks[name];requested=request['NetworkingConfig']['EndpointsConfig'][name];declared=v['Config'].get('MacAddress')
        require(declared in(None,'')or self.p.valid_mac(declared)and declared.lower()==requested['MacAddress'].lower(),'CONFIG_ENDPOINT_MAC_DRIFT')
        if started:
            require(v['State']['Running']is True and v['State']['Paused']is False and v['State']['Restarting']is False and v['RestartCount']==0,'EXACT_RUNNING_CANDIDATE_GENERATION_REQUIRED')
            require(self.p.valid_mac(endpoint.get('MacAddress'))and endpoint['MacAddress'].lower()==requested['MacAddress'].lower(),'EXACT_RETAINED_READ_ENDPOINT_MAC_REQUIRED')
            require(all(a in(endpoint.get('Aliases')or[])for a in requested.get('Aliases',[])),'EXACT_CANDIDATE_ALIASES_REQUIRED')
            for field,current in(('IPv4Address','IPAddress'),('IPv6Address','GlobalIPv6Address')):
                if requested.get('IPAMConfig',{}).get(field):require(endpoint.get(current)==requested['IPAMConfig'][field],'EXACT_RETAINED_READ_ENDPOINT_IP_REQUIRED')
        else:require(v['State']['Running']is False and v['State']['Pid']==0,'CANDIDATE_MUST_REMAIN_STOPPED')

