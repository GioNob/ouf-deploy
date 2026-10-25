#!/usr/bin/env python3
"""One exact signed2READ/1MCP/2route installation. No source activation or E2E acceptance."""
import ast,copy,hashlib,importlib.util,json,os,re,shutil,signal,stat,subprocess,sys,sysconfig,time,types
from pathlib import Path
NATIVE=Path('/etc/ouf/deploy-snapshots/acquisition-native-execution-inputs-47b206e2eb602c11/native-inputs.json')
NATIVE_HASH='5fa62e4f6869a6f40fb512878dcf65dcb6ffaf941be487e4189826f418046591'
ROOT=Path('/etc/ouf/deploy-snapshots/acquisition-read-apply-'+NATIVE_HASH)
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def sha(v):return hashlib.sha256(v).hexdigest()
def source(path):
    path=Path(path);require(path.is_absolute()and path.resolve()==path,'CANONICAL_APPLY_SOURCE_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_APPLY_SOURCE_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);frame=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'));require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and 0<s.st_size<=131072,'ROOT_PRIVATE_APPLY_SOURCE_REQUIRED');raw=os.read(fd,s.st_size+1);require(len(raw)==s.st_size and frame(s)==frame(os.fstat(fd))==frame(path.lstat()),'APPLY_SOURCE_DRIFT');return raw
    finally:os.close(fd)
def load(name,path,closure):
    raw=source(path);closure[str(path)]=sha(raw);m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m
def selected(name,path,names,environment,closure):
    raw=source(path);closure[str(path)]=sha(raw);nodes=[n for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names];require({n.name for n in nodes}==set(names),'EXACT_AUTHENTICATION_DEFINITION_SELECTION_REQUIRED');m=types.ModuleType(name);m.__dict__.update(environment);sys.modules[name]=m;exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),m.__dict__);return m
def package(name):m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m

def components():
    code=Path(__file__).resolve().parent;manifest=source(code/'sources.json');mapping=json.loads(manifest);required={'apply.py','protocol.py','transport.py','ports.py','quarantine.py','recovery_journal.py','engine_creation.py','plan_helper.py','image_custody.py','native_prepare.py','authentication.py','signing.py','auth_protocol.py','auth_preexec.py','auth_producer.py','runtime_binding.py'};allowed=(required,required|{'continuation.py'},required|{'continuation.py','retained_mac.py'});require(type(mapping)is dict and set(mapping)in allowed,'COMPLETE_CLOSED_APPLY_SOURCE_MANIFEST_REQUIRED');closure={str(code/'sources.json'):sha(manifest)}
    for name,expected in mapping.items():require(re.fullmatch('[a-f0-9]{64}',expected)is not None and sha(source(code/name))==expected,'PINNED_APPLY_SOURCE_CLOSURE_REQUIRED')
    require('tools'not in sys.modules,'ISOLATED_AUTHENTICATION_NAMESPACE_REQUIRED');package('tools');package('tools.semantic_lease_recovery')
    selected('tools.semantic_provider_preexec',code/'auth_preexec.py',('PreexecDenied',),{},closure)
    selected('tools.semantic_provider_deployment_protocol',code/'auth_protocol.py',('identity','hashed'),{'re':re},closure)
    selected('tools.semantic_provider_deployment_producer',code/'auth_producer.py',('encoded',),{'json':json},closure)
    auth=load('tools.semantic_provider_deployment_authentication',code/'authentication.py',closure);sign=load('tools.semantic_provider_deployment_signing',code/'signing.py',closure)
    journal=load('tools.semantic_lease_recovery.recovery_journal',code/'recovery_journal.py',closure)
    parts={name:load('sealed_acquisition_'+name,code/(name+'.py'),closure)for name in('protocol','transport','ports','quarantine','engine_creation','plan_helper','image_custody','native_prepare')}
    parts['runtime']=selected('sealed_acquisition_runtime',code/'runtime_binding.py',('stdlib_binding',),{'Path':Path,'sysconfig':sysconfig,'sys':sys,'os':os,'stat':stat,'hashlib':hashlib,'re':re,'binding':types.SimpleNamespace(require=require,identity=parts['plan_helper'].frame,CandidateDenied=Stop)},closure)
    if'retained_mac.py'in mapping:parts['retained_mac']=load('sealed_acquisition_retained_mac',code/'retained_mac.py',closure)
    closure[str(Path(__file__).resolve())]=mapping['apply.py']
    if'continuation.py'in mapping:closure[str(code/'continuation.py')]=mapping['continuation.py']
    return parts,auth,sign,journal,closure
def bootstrap():return Context(*components())
class Context:
    NATIVE_HASH=NATIVE_HASH
    def __init__(self,parts,auth,sign,journal,closure,*,native_path=NATIVE,native_hash=NATIVE_HASH,root=ROOT):
        self.core,self.http,self.ports_module,self.watch,self.engine_helpers,self.p,self.images,self.preparer=[parts[k]for k in('protocol','transport','ports','quarantine','engine_creation','plan_helper','image_custody','native_prepare')];self.auth,self.sign,self.journal_module=auth,sign,journal;self.closure=closure;self.runtime=parts['runtime'];self.mac=parts.get('retained_mac');self.root=Path(root);self.NATIVE_HASH=native_hash;self.native_path=Path(native_path);self.serial=0;self.counts={k:0 for k in self.core.LIMITS}
        self.native=self.p.decode(self.p.protected(self.native_path,self.NATIVE_HASH));require(self.native['schema']=='ouf.acquisition-native-execution-inputs.v1'and self.native['executionEntryQualified']is False and self.native['targetApplyAuthorized']is False and self.native['frozenPlanHash']==self.preparer.PLAN_HASH and self.p.digest(self.native['nativeProposal'])==self.native['nativeProposalHash'],'EXACT_NATIVE_PROPOSAL_INPUT_REQUIRED');self.proposal=copy.deepcopy(self.native['nativeProposal']);require(self.proposal['mcpReplacement']['oldNativeHostConfig'].get('AutoRemove')is False,'OLD_MCP_MUST_NOT_AUTOREMOVE');self.inputs=self.p.decode(self.p.protected(self.p.INPUTS,self.proposal['capturedInputsHash']));self.p.ancestry(self.root.parent);require(not os.path.lexists(self.root),'ACQUISITION_APPLY_SCOPE_CONSUMED_NO_REPLAY');self.root.mkdir(mode=0o700);parent_fd=os.open(self.root.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent_fd)
        finally:os.close(parent_fd)
        self.write(self.root,'preparation-claim.json',{'schema':'ouf.acquisition-signed-execution-preparation-claim.v1','nativeInputsHash':self.NATIVE_HASH,'maximums':self.core.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False});self.engine=self.http.Engine(self.p,self.proposal['engineBinding'])
        for proposal in [*self.proposal['readComponents'].values(),self.proposal['mcpReplacement']]:
            host=proposal['request']['HostConfig']
            if host.get('OomKillDisable')is None:proposal['runtimeHostProjection']={'profile':'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1','requestedOomKillDisable':None,'materializedOomKillDisable':False,'positiveMemoryBytes':host['Memory']}
        self.refresh_authority();self.openssl=self.executable();self.runtime_binding=self.runtime_snapshot();self.key=None;self.load_admin_key();self.check_sources()
    def write(self,root,name,value):self.p.put(Path(root)/name,value)
    def read(self,path,expected):return self.p.decode(self.p.protected(Path(path),expected))
    def evidence(self,name,value):self.serial+=1;self.write(self.root,name+'-%04d.json'%self.serial,value)
    def reserve(self,kind):
        require(self.counts[kind]<self.core.LIMITS[kind],'PREFLIGHT_OPERATION_BUDGET_EXHAUSTED');self.counts[kind]+=1;self.evidence('preflight-claim',{'kind':kind,'attempt':self.counts[kind],'attemptNotCompletion':True})
    def refresh_authority(self):
        self.reserve('ownerConfigurationReads');self.reserve('ownerConfigurationReads');current=self.preparer.public_authority(self.p);require(current==self.native['publicAuthority'],'CURRENT_INSTALLATION_PUBLIC_AUTHORITY_CHANGED');self.profile=current['profile'];return current
    def executable(self):
        path=Path('/usr/bin/openssl').resolve(strict=True);self.p.ancestry(path.parent);s=path.lstat();require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_mode&0o111 and not s.st_mode&0o022 and s.st_size<=64000000,'ROOT_OPENSSL_REQUIRED');raw=path.read_bytes();r=subprocess.run([str(path),'version'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'});version=re.match(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b',r.stdout);require(r.returncode==0 and len(r.stdout)<=256 and version is not None,'REAL_OPENSSL_VERSION_REQUIRED');return {'path':str(path),'sha256':sha(raw),'version':version[1].decode()}
    def runtime_snapshot(self):
        stdlib=self.runtime.stdlib_binding();python=Path(sys.executable).resolve(strict=True);self.p.ancestry(python.parent);row=python.lstat();require(stat.S_ISREG(row.st_mode)and row.st_uid==row.st_gid==0 and row.st_mode&0o111 and not row.st_mode&0o022,'ROOT_PYTHON_RUNTIME_REQUIRED');metadata={}
        for relative,binding in stdlib['fileHashes'].items():
            original=Path(stdlib['root'])/relative;target=Path(binding['resolvedPath']);metadata[relative]={'original':list(self.p.frame(original.lstat())),'resolved':list(self.p.frame(target.lstat()))}
        return {'python':{'path':str(python),'sha256':sha(python.read_bytes()),'metadata':list(self.p.frame(row))},'stdlib':stdlib,'metadata':metadata,'noSiteRequired':True,'isolatedRequired':True,'dontWriteBytecodeRequired':True}
    def runtime_check(self):
        runtime=self.runtime_binding;require(list(self.p.frame(Path(runtime['python']['path']).lstat()))==runtime['python']['metadata'],'PYTHON_EXECUTABLE_CHANGED')
        for relative,meta in runtime['metadata'].items():
            original=Path(runtime['stdlib']['root'])/relative;resolved=Path(runtime['stdlib']['fileHashes'][relative]['resolvedPath']);require(original.resolve()==resolved and list(self.p.frame(original.lstat()))==meta['original']and list(self.p.frame(resolved.lstat()))==meta['resolved'],'SEALED_STDLIB_CHANGED')
    def check_sources(self):
        self.runtime_check()
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.native['bootId'],'SAME_ACQUISITION_BOOT_REQUIRED')
        for path,h in self.closure.items():require(sha(source(path))==h,'APPLY_SOURCE_CLOSURE_CHANGED')
        self.p.protected(self.native_path,self.NATIVE_HASH)
        for path,h in self.native['sourceClosure'].items():self.p.protected(Path(path),h)
        for role,fact in self.native['candidateFacts'].items():
            path=Path(fact['nativeArchive']['path']);self.p.ancestry(path.parent);require(list(self.p.frame(path.lstat()))==fact['nativeArchive']['metadata'],'SEALED_NATIVE_ARCHIVE_METADATA_CHANGED')
    def metadata(self,binding):
        path=Path(binding['path']);exception=self.p._EXISTING_CONFIG_CUSTODY.get(str(path));require(list(self.p.frame(path.lstat()))==binding['metadata'],'ADMIN_KEY_METADATA_CHANGED')
        for parent in reversed(path.parents):require(self.p.selected_directory_custody(parent.lstat(),str(parent),exception),'SELECTED_KEY_ANCESTRY_CHANGED')
    def check_owner_configuration(self,reserve):
        gateway=self.proposal['gateway'];reserve('ownerConfigurationReads');self.p.private_config(gateway['transportBinding']['configBinding']['path'],gateway['transportBinding']['configBinding']);reserve('ownerConfigurationReads');self.p.private_config(gateway['projectionBinding']['path'],gateway['projectionBinding'])
        if gateway['transportBinding']['adminKeyBinding']:self.metadata(gateway['transportBinding']['adminKeyBinding'])
    def load_admin_key(self):
        gateway=self.proposal['gateway'];self.reserve('ownerConfigurationReads');raw,_=self.p.private_config(gateway['transportBinding']['configBinding']['path'],gateway['transportBinding']['configBinding']);binding=gateway['transportBinding']['adminKeyBinding']
        if binding:
            self.reserve('serviceCredentialFileReads');key,_=self.p.private_config(binding['path'],binding);self.key=self.p.selected_admin_key(raw,key.decode('ascii').strip())
        else:self.key=self.p.selected_admin_key(raw)
    def preflight_get(self,path):self.reserve('engineGets');s,v=self.engine.request('GET',path);self.evidence('preflight-engine-response',{'status':s,'body':v});return s,v
    def current(self):
        for role,b in self.proposal['existingApplications'].items():
            s,v=self.preflight_get('/v1.44/containers/'+b['containerId']+'/json');require(s==200 and v['State']['Running']is True and self.p.stable_binding(v)==b and self.p.process_pin(v['State']['Pid'])==self.inputs['currentProcessPins'][role],'CURRENT_FROZEN_COHORT_REQUIRED')
        for name in [self.proposal['readComponents'][r]['name']for r in('ingestion','udp')]+[self.proposal['mcpReplacement']['retiredName']]:s,_=self.preflight_get('/v1.44/containers/'+name+'/json');require(s==404,'NEW_CANDIDATE_OR_RETAINED_NAME_ALREADY_EXISTS')
        s,info=self.preflight_get('/v1.44/info');require(s==200 and self.preparer.identity_profile(info)==self.native['imageIdentityProfile'],'SAME_CURRENT_ENGINE_IMAGE_PROFILE_REQUIRED');self.admission();self.check_sources();self.check_owner_configuration(self.reserve)
    def admission(self):
        mem=Path('/proc/meminfo').read_text();v=re.findall(r'^MemAvailable:\s+([0-9]+) kB$',mem,re.MULTILINE);require(len(v)==1 and int(v[0])*1024>=1342177280,'CURRENT_READ_REPLICA_MEMORY_ADMISSION_REQUIRED');require(shutil.disk_usage(self.root).free>=268435456+sum(f['nativeArchive']['bytes']for f in self.native['candidateFacts'].values()),'CURRENT_EXACT_IMAGE_IMPORT_DISK_ADMISSION_REQUIRED')
    def admin(self,method,path,body=None):return self.http.namespace(self.p,self.inputs['currentProcessPins']['gateway'],'admin',method,path,body,self.key)
    def route_rows(self,doc):
        require(type(doc)is dict and type(doc.get('list'))is list and len(doc['list'])<=256,'BOUNDED_CURRENT_ADMIN_ROUTE_LIST_REQUIRED');rows=[]
        for entry in doc['list']:
            row=entry.get('value',entry)
            if type(row)is dict and type(row.get('value'))is dict:row=row['value']
            require(type(row)is dict and type(row.get('id'))is str,'TYPED_CURRENT_ROUTE_REQUIRED');rows.append({k:v for k,v in row.items()if k not in('create_time','update_time')})
        self.route_map(rows);return rows
    def route_map(self,rows):
        require(type(rows)is list and all(type(v)is dict and type(v.get('id'))is str for v in rows)and len({v['id']for v in rows})==len(rows),'EXACT_UNIQUE_GATEWAY_ROUTE_MAP_REQUIRED');return {v['id']:v for v in rows}
    def legacy_mac_policy(self):
        ref=self.inputs['currentObservations']['mcp'];original=self.read(ref['path'],ref['sha256'])
        if original['Config'].get('MacAddress')in(None,''):return None
        require(self.mac is not None,'QUALIFIED_LEGACY_MAC_PROFILE_REQUIRED')
        return self.mac.policy(original)
    def restore_policy(self,role):
        row=self.proposal['mcpReplacement']if role=='mcp'else self.proposal['readComponents'][role];return row['restoreRestartPolicy']if role=='mcp'else row['restartPolicyAfterVerifiedReadiness']
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
def operator(ctx):
    c=ctx.core;ctx.current();ctx.reserve('adminGets');routes=ctx.admin('GET','/apisix/admin/routes');ctx.evidence('preflight-admin',routes);require(routes['status']==200 and ctx.route_map(ctx.route_rows(ctx.p.decode(routes['body'].encode())))==ctx.route_map(ctx.proposal['gateway']['previousRoutes']),'FRESH_EXACT_GATEWAY_BASELINE_REQUIRED')
    for f in ctx.native['candidateFacts'].values():
        path=Path(f['nativeArchive']['path']);h=hashlib.sha256()
        with path.open('rb')as stream:
            for block in iter(lambda:stream.read(1048576),b''):h.update(block)
        require(h.hexdigest()==f['nativeArchive']['sha256'],'EXACT_PRE_REVIEW_NATIVE_ARCHIVE_BYTES_REQUIRED')
    closure=copy.deepcopy(ctx.closure);review={'schema':'ouf.acquisition-read-native-review.v1','executionRoot':str(ctx.root),'frozenPlanHash':ctx.native['frozenPlanHash'],'nativePlan':{'frozenPlanHash':ctx.native['frozenPlanHash'],'nativeInputsHash':ctx.NATIVE_HASH,'runtimeBinding':ctx.runtime_binding,'runtimeBindingHash':c.digest(ctx.runtime_binding),'proposal':ctx.proposal,'legacyConfigMacDetachPolicy':ctx.legacy_mac_policy()},'sourceClosure':closure,'sourceClosureHash':c.digest(closure),'logicalOperationRef':ctx.NATIVE_HASH,'bootId':ctx.native['bootId'],'maximumSeconds':900,'maximums':copy.deepcopy(c.LIMITS),'stages':list(c.STAGES),'negativeCleanup':{'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':3,'disableCandidateRestartFirst':True},'preflightCounts':copy.deepcopy(ctx.counts),'verification':{'trustPolicy':ctx.native['publicAuthority']['trustPolicy'],'openssl':ctx.openssl,'context':ctx.native['publicAuthority']['context']},'retainedPreparationCounts':{'nativeEngineGets':12,'nativeMetadataReads':8,'nativePublicAuthorityMetadataReads':2,'macPlannerAdminGets':1,'macPlannerCredentialReads':1,'macPlannerMetadataReads':15,'originalPlannerMetadataReads':11,'originalPlannerConfigurationReads':1,'diagnosticMetadataReads':6},'databaseRestoreAuthorized':False,'humanBudgetOrSourceActivationAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False};review['nativePlanHash']=c.digest(review['nativePlan']);c.validate_review(review);ctx.write(ctx.root,'review.json',review)
    decision=c.terminal_decision(review,ctx.root/'review.json');ctx.read(ctx.root/'review.json',c.digest(review));ctx.current();ctx.refresh_authority();gate=c.issue(review,ctx.root,ctx.profile,decision,ctx.write,ctx.read);print(c.encoded({'schema':'ouf.acquisition-read-native-issued.v1','reviewHash':c.digest(review),'authorityHash':c.sha(gate.raw),'runtimeAuthorityIssued':True,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False}).decode(),flush=True)
    ports=ctx.ports_module.NativePorts(ctx,review,gate);execution=c.Execution(gate,ctx.journal_module.Journal(ctx.root),ports);execution.initialize()
    try:
        ctx.watch.launch(ctx,review,gate,execution.journal);result=execution.run()
    except BaseException:
        try:ctx.watch.negative(ctx,review,gate.raw,execution.journal,'CONTROLLER_STOPPED')
        except BaseException:ctx.write(ctx.root,'quarantine-unproven.json',{'status':'STOP_RECONCILE','negativeEffectMayBePartial':True,'automaticReplayAllowed':False})
        raise
    return finalize(ctx,review,gate,result)
def finalize(ctx,review,gate,result):
    c=ctx.core;context=review['verification']['context'];signer=ctx.sign.ExistingEd25519Signer(ctx.profile['keyBindings']['attestor'],ctx.profile['keyRefs']['attestor'],gate.verifier,{'role':'CREATION_ATTESTATION','issuerRef':context['attestorRef'],'installationRef':context['installationRef'],'entityRef':context['entityRef']});gate.check();ctx.write(ctx.root,'result.json',result);c.authentication_file(ctx.root/'authority',c.sha(c.encoded(result))+'.CREATION_ATTESTATION.json',signer.sign(c.encoded(result)));require(gate.verifier(c.encoded(result),'CREATION_ATTESTATION',context['attestorRef'],context['installationRef'],context['entityRef'])is True,'SIGNED_FINAL_ACQUISITION_RESULT_REQUIRED');return result
def main():
    ctx=None
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ONE_ISOLATED_ROOT_ACQUISITION_APPLY_REQUIRED')
        def cancelled(*_):raise Stop('ACQUISITION_CONTROLLER_INTERRUPTED_RECONCILE_ONLY')
        for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,cancelled)
        ctx=bootstrap();result=operator(ctx)
    except Exception as e:
        reason=str(e)if type(e).__name__ in('Stop','PreexecDenied','CreationDenied','ImageCustodyDenied')and re.fullmatch('[A-Z0-9_]{1,120}',str(e))else'ACQUISITION_NATIVE_EXECUTION_UNPROVEN';result={'schema':'ouf.acquisition-read-native-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,'contextPath':str(ctx.root)if ctx else None,'runtimeEffectsMayBePartial':True,'applicationE2EProven':False,'humanBudgetsGranted':0,'sourceActivations':0,'automaticReplayAllowed':False,'automaticRollbackPerformed':False,'budgetReset':False,'releaseAcceptance':False,'credentialValuesPrinted':False,'addressesPrinted':False}
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True);return 0 if result.get('complete')else 2
if __name__=='__main__':raise SystemExit(main())
