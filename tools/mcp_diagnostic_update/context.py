"""Private state and receipts for a new, exact MCP-only runtime intent.

This module is not a production entrypoint. The sealed entrypoint supplies its
fixed target bindings; explicit alternate bindings are only used by CI fixtures.
"""
import copy,hashlib,os,re,shutil,stat,subprocess,sys,time
from pathlib import Path
from urllib.parse import quote
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
TARGET={'nativePlanHash':'ff06ec1afc5da65dc6b6c64edb9ab9ec87926f4a9de7aec355b69b96c4cd8653',
        'frozenPlanHash':'d1baf924e456bd5d2ce5a9bd3b8cb6f12ea80016feb76cde3c1556eec497a142',
        'inputsHash':'fb4b7c9ae832e779192f1ff6e032e49c696752e182a57b8e9464f5a76000b3e4',
        'nativeImageId':'sha256:9a1af5be94ff3dda4084b829e824482c5cf863525375c6f104a3fe89517e781e',
        'sourceCommit':'9a374dd07745f059de3ad39757c68f02db6d29c3',
        'nativeArchiveHash':'dafe0b0be9bf78717061923b1d1fe9feab2f01b81fd1e432a8b7a35a7677bcc3',
        'nativePlanPath':'/etc/ouf/deploy-snapshots/mcp-denial-image-plan-fb4b7c9ae832e779-v1/native-plan.json',
        'inputsPath':'/etc/ouf/deploy-snapshots/mcp-denial-update-inputs-9a374dd07745f059-v1/inputs.json',
        'executionRoot':'/etc/ouf/deploy-snapshots/mcp-diagnostic-update-ff06ec1afc5da65d-v1'}
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
class Context:
    def __init__(self,parts,auth,sign,journal,closure,*,case=TARGET,public_authority=None,runtime=None):
        self.core,self.p,self.images,self.mac,self.http,self.ports_module,self.watch,self.engine_helpers,self.terminal=[parts[k]for k in('authority','plan_helper','image_custody','retained_mac','transport','ports','quarantine','engine_creation','terminal')]
        self.auth,self.sign,self.journal_module=auth,sign,journal;self.closure=copy.deepcopy(closure);self.case=copy.deepcopy(case);self.root=Path(case['executionRoot']);self.serial=0
        self.execution=None;self.counts={k:0 for k in self.core.LIMITS};self.responses=0;self.receiptBytes=0;self.runtime=runtime
        self.native=self.read(case['nativePlanPath'],case['nativePlanHash']);self.inputs=self.read(case['inputsPath'],case['inputsHash'])
        require(self.native['schema']=='ouf.mcp-denial-native-image-plan.v1'and self.native['frozenPlanHash']==case['frozenPlanHash']==self.p.digest(self.native['proposal'])
                and self.native['nativeImageId']==case['nativeImageId']and self.native['imageAudit']['sourceCommit']==case['sourceCommit']
                and self.native['nativeArchive']['sha256']==case['nativeArchiveHash']and self.native['executionEntryQualified']is False
                and self.native['runtimeAuthorityIssued']is False and self.native['proposal']['capturedInputsHash']==case['inputsHash'],'EXACT_PREPARED_MCP_NATIVE_PLAN_REQUIRED')
        self.native['candidateFacts']={'mcp':{'audit':self.native['imageAudit']}} # local adapter, never rewrites retained native-plan bytes
        self.proposal=copy.deepcopy(self.native['proposal']);request=self.proposal['mcpReplacement']['request'];request['Image']=case['nativeImageId']
        candidate=self.native['imageAudit']['imageConfig'];old_labels=request.get('Labels')or{};defaults=candidate.get('Labels')or{}
        require(all(k.startswith('org.opencontainers.image.')for k in set(defaults)-set(old_labels)),'ONLY_QUALIFIED_IMAGE_LABEL_DEFAULTS')
        self.proposal['mcpReplacement']['runtimeLabelProjection']={'expectedLabels':{**defaults,**old_labels}}
        host=request['HostConfig'];require(host.get('AutoRemove')is False and type(host.get('Memory'))is int and host['Memory']>0,'FINITE_RETAINED_MCP_HOST_POLICY_REQUIRED')
        if host.get('OomKillDisable')is None:self.proposal['mcpReplacement']['runtimeHostProjection']={'profile':'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1','requestedOomKillDisable':None,'materializedOomKillDisable':False,'positiveMemoryBytes':host['Memory']}
        self.p.ancestry(self.root.parent);require(not os.path.lexists(self.root),'MCP_UPDATE_SCOPE_CONSUMED_NO_REPLAY');self.root.mkdir(mode=0o700);self.root.chmod(0o700)
        self.sync(self.root.parent);self.write(self.root,'preparation-claim.json',{'schema':'ouf.mcp-diagnostic-update-preflight-claim.v1','nativePlanHash':case['nativePlanHash'],'maximums':self.core.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
        self.engine=self.http.Engine(self.p,self.proposal['engineBinding']);self.engine.before=self.before_dispatch;self.engine.retained=self.retained
        self.public_authority=public_authority or globals()['public_authority'];self.authority_metadata=self.refresh_authority();self.profile=self.authority_metadata['profile'];self.openssl=self.executable()
        self.input_seals={path:list(self.p.frame(Path(path).lstat()))for path in(case['nativePlanPath'],case['inputsPath'])}
        self.source_seals={path:list(self.p.frame(Path(path).lstat()))for path in closure}
        self.archive=self.native['nativeArchive'];require(Path(self.archive['path']).parent==Path(case['nativePlanPath']).parent,'EXACT_PREPARED_ARCHIVE_LOCATION_REQUIRED')
        self.verify_archive();
        if self.runtime is not None:self.runtime_binding=self.runtime_snapshot()
        self.check_sources()
    def sync(self,path):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    def write(self,root,name,value):
        require(re.fullmatch('[A-Za-z0-9_.-]+',name)is not None,'CLOSED_PRIVATE_MCP_FILENAME')
        raw=value if isinstance(value,bytes)else self.p.encoded(value);require(len(raw)<=8*1024*1024,'BOUNDED_PRIVATE_MCP_EVIDENCE')
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
            require(self.counts[kind]<self.core.LIMITS[kind],'FINITE_MCP_PREFLIGHT_BUDGET');self.counts[kind]+=1;self.evidence('preflight-attempt',{'kind':kind,'attempt':self.counts[kind],'attemptNotCompletion':True})
    def refresh_authority(self):
        self.reserve('ownerConfigurationReads');self.reserve('ownerConfigurationReads');value=self.public_authority(self.p)
        if hasattr(self,'authority_metadata'):require(value==self.authority_metadata,'INSTALLATION_PUBLIC_AUTHORITY_CHANGED')
        return value
    def executable(self):
        path=Path('/usr/bin/openssl').resolve(strict=True);self.p.ancestry(path.parent);s=path.lstat();require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_mode&0o111 and not s.st_mode&0o022,'TRUSTED_OPENSSL_REQUIRED')
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
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.inputs['bootId']==self.proposal['bootId'],'SAME_MCP_UPDATE_HOST_BOOT_REQUIRED')
        for path,metadata in self.input_seals.items():require(list(self.p.frame(Path(path).lstat()))==metadata,'PREPARED_INPUT_SEAL_CHANGED')
        for path,metadata in self.source_seals.items():require(list(self.p.frame(Path(path).lstat()))==metadata,'SEALED_MCP_EXECUTOR_SOURCE_CHANGED')
        require(list(self.p.frame(Path(self.archive['path']).lstat()))==self.archive['metadata'],'PREPARED_ARCHIVE_SEAL_CHANGED')
    def closed_path(self,method,path,body):
        old=self.proposal['mcpReplacement'];ids={v['containerId']for v in self.proposal['existingApplications'].values()}
        if self.execution:ids|={v['id']for v in self.execution.read_journal()['candidates'].values()}
        names={old['retiredName']};gets={'/v1.44/info','/v1.44/networks/'+old['network']['id'],'/v1.44/images/'+quote(self.native['nativeImageId'],safe='')+'/json'}|{'/v1.44/containers/'+cid+'/json'for cid in ids|names}
        require(method in('GET','POST')and(method!='GET'or path in gets and body is None),'CLOSED_MCP_READ_ALLOWLIST_REQUIRED')
    def before_dispatch(self,method,path,body):
        self.closed_path(method,path,body)
        if method=='POST':
            require(self.execution is not None,'NO_RUNTIME_WRITE_WITHOUT_EXECUTION')
            row=self.execution.read_journal()
            if row['quarantine']is None:
                self.execution.gate.check();self.ports.assert_write(path,body)
            else:
                candidate=row['candidates'].get('mcp');require(candidate and candidate.get('configurationVerified')is True,'ONLY_VERIFIED_OWN_MCP_NEGATIVE')
                cid=candidate['id'];require(cid not in{v['containerId']for v in self.proposal['existingApplications'].values()},'NEGATIVE_MUST_NOT_SELECT_RETAINED_CONTAINER')
                require((path,body)in[('/v1.44/containers/'+cid+'/update',{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}}),('/v1.44/containers/'+cid+'/stop?t=2',None)],'ONLY_OWN_MCP_DISABLE_STOP_NEGATIVE')
            self.evidence('engine-dispatch-claim',{'method':method,'path':path,'bodyHash':self.core.digest(body),'attemptNotCompletion':True})
    def preflight_get(self,path):
        self.reserve('engineGets');return self.engine.request('GET',path)
    def current(self):
        print('Verifico sette generazioni correnti, nome retained e rete; sole letture Engine.',flush=True)
        self.check_sources()
        for role,b in self.proposal['existingApplications'].items():
            s,v=self.preflight_get('/v1.44/containers/'+b['containerId']+'/json');require(s==200 and v['State']['Running']is True and self.p.stable_binding(v)==b and self.p.process_pin(v['State']['Pid'])==self.inputs['currentProcessPins'][role],'EXACT_SEVEN_CURRENT_GENERATIONS_REQUIRED')
        old=self.proposal['mcpReplacement'];s,_=self.preflight_get('/v1.44/containers/'+old['retiredName']+'/json');require(s==404,'RETAINED_MCP_NAME_ALREADY_EXISTS')
        s,info=self.preflight_get('/v1.44/info');require(s==200 and info['ServerVersion']=='29.8.1','QUALIFIED_ENGINE_VERSION_CHANGED')
        native=['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[]);require(native==(self.proposal['nativeIdentityProfile']=='CONFIG_AND_NATIVE_MANIFEST'),'CURRENT_ENGINE_NATIVE_IDENTITY_PROFILE_CHANGED')
        s,net=self.preflight_get('/v1.44/networks/'+old['network']['id']);require(s==200 and net['Name']==old['network']['name']and net['Driver']=='bridge'and net['Scope']=='local','EXACT_CURRENT_NETWORK_REQUIRED')
        require(old['oldBinding']['containerId']in(net.get('Containers')or{}),'OLD_MCP_ENDPOINT_REQUIRED')
        baseline=copy.deepcopy(net.get('Containers')or{})
        if hasattr(self,'network_baseline'):require(baseline==self.network_baseline,'NETWORK_CHANGED_DURING_HUMAN_REVIEW')
        self.network_baseline=baseline;self.admission()
    def admission(self):
        mem=Path('/proc/meminfo').read_text();rows=re.findall(r'^MemAvailable:\s+([0-9]+) kB$',mem,re.MULTILINE);required=max(self.proposal['mcpReplacement']['request']['HostConfig']['Memory'],268435456)+134217728
        require(len(rows)==1 and int(rows[0])*1024>=required and shutil.disk_usage(self.root).free>=536870912+self.archive['bytes'],'FRESH_FINITE_MCP_CAPACITY_REQUIRED')
    def restore_policy(self,role):require(role=='mcp','MCP_ONLY_RESTART_POLICY');return self.proposal['mcpReplacement']['restoreRestartPolicy']
    def import_claim(self):
        row=self.execution.record();i=row['nextStage'];require(self.core.STAGES[i]=='IMPORT_MCP'and len(row['effects'])==i+1 and row['effects'][-1]['state']=='CLAIMED','CLAIMED_EXACT_NATIVE_IMPORT_REQUIRED')
        self.execution.gate.check();self.verify_archive();self.evidence('native-import-dispatch-claim',{'method':'POST','path':'/v1.44/images/load?quiet=1','archiveHash':self.archive['sha256'],'attemptNotCompletion':True})
    def finalize(self,result):
        # Called by NativePorts.final_result INSIDE Execution.run's invocation
        # fence. No lock is held over I/O except the single-invocation fence.
        c=self.core;gate=self.gate;context=self.review['verification']['context']
        signer=self.sign.ExistingEd25519Signer(self.profile['keyBindings']['attestor'],self.profile['keyRefs']['attestor'],gate.verifier,{'role':'CREATION_ATTESTATION','issuerRef':context['attestorRef'],'installationRef':context['installationRef'],'entityRef':context['entityRef']})
        gate.check();raw=c.encoded(result);self.write(self.root,'candidate-result.json',raw)
        c.authentication_file(self.root/'authority',c.sha(raw)+'.CREATION_ATTESTATION.json',signer.sign(raw))
        require(gate.verifier(raw,'CREATION_ATTESTATION',context['attestorRef'],context['installationRef'],context['entityRef'])is True,'SIGNED_MCP_NATIVE_RESULT_REQUIRED')
        gate.check();self.execution.save(self.execution.record(),state='COMPLETE');self.write(self.root,'result.json',result);return result
    def candidate_configuration(self,role,v,started,restored,quarantine=False):
        proposal=self.proposal['mcpReplacement']if role=='mcp'else self.proposal['readComponents'][role];request=proposal['request'];require(v['Name']=='/'+proposal['name']and v['Image']==request['Image']and re.fullmatch('[a-f0-9]{64}',v['Id']),'EXACT_CREATED_CANDIDATE_IDENTITY_REQUIRED')
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
        projection=proposal.get('runtimeHostProjection');materialized=projection=={'profile':'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1','requestedOomKillDisable':None,'materializedOomKillDisable':False,'positiveMemoryBytes':host.get('Memory')}and host.get('OomKillDisable')is None
        require(self.engine_helpers.requested_host_config_matches(host,v['HostConfig'],started=ever_started or materialized),'EXACT_CANDIDATE_HOST_CONFIGURATION_REQUIRED')
        if role=='mcp':require(self.core.digest(sorted(v['Mounts'],key=lambda m:m['Destination']))==proposal['oldBinding']['mountsHash'],'EXACT_MCP_RETAINED_MOUNTS_REQUIRED')
        else:
            observed={m['Destination']:m for m in v['Mounts']};expected={m['Target']:m for m in request['HostConfig']['Mounts']};extra=set(observed)-set(expected);require(not extra or extra=={'/tmp'}and observed['/tmp']['Type']=='tmpfs'and not observed['/tmp'].get('Source'),'ONLY_REVIEWED_READ_MOUNTS_REQUIRED')
            for destination,m in expected.items():
                actual=observed.get(destination,{});require(actual.get('Type')==m['Type']and actual.get('RW')is False and(actual.get('Source')if m['Type']=='bind'else actual.get('Name'))==m['Source'],'EXACT_EXISTING_READ_ONLY_MOUNT_REQUIRED')
        networks=v['NetworkSettings']['Networks'];name=proposal['network']['name'];require(set(networks)=={name}and networks[name]['NetworkID']==proposal['network']['id'],'EXACT_CANDIDATE_NETWORK_REQUIRED');endpoint=networks[name]
        if started:
            require(v['State']['Running']is True and v['State']['Paused']is False and v['State']['Restarting']is False and v['RestartCount']==0 and self.p.valid_mac(endpoint['MacAddress']),'EXACT_RUNNING_CANDIDATE_GENERATION_REQUIRED')
            requested=request['NetworkingConfig']['EndpointsConfig'][name];require(all(a in(endpoint.get('Aliases')or[])for a in requested.get('Aliases',[])),'EXACT_CANDIDATE_ALIASES_REQUIRED')
            if role=='mcp':require(endpoint['MacAddress'].lower()==requested['MacAddress'].lower(),'EXACT_RETAINED_MCP_ENDPOINT_MAC_REQUIRED')
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
