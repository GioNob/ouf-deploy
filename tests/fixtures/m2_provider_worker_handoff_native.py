"""Finite joint native proof, never an installer or an operational entrypoint.

The provider's v4 admission is real. A separate process runs the production
worker factory against that exact provider, Registry, kernel and common inode.
Docker boundary, images/review and Registry predecessor remain modeled by the
provider fixture. This does not qualify WorkerMaterialization, the sealed unit,
full Docker composition, capability publication or target application E2E.
"""
import copy,dataclasses,fcntl,importlib.util,json,os,signal,socket,struct,sys,threading,time
from pathlib import Path


def qualify(phase,root,commands,state_root,run,*,docker_engine=None):
    assert os.environ.get('GITHUB_ACTIONS')=='true' and os.geteuid()==0
    assert len(threading.enumerate())==1,'CI_FORK_REQUIRES_SINGLE_THREADED_PARENT'
    from tools.m2_discovery_installation_profile import lease_worker as worker
    from tools.m2_discovery_installation_profile.native_generation_probe import ticks
    from tools.m2_discovery_installation_profile import provider_runtime_installation as runtime
    from deadline_backend import DeadlineNftBackend
    import dns
    owner=phase.runtime;parent=owner.parent;window=owner.creation.window
    prep=owner.issuer.scope['preparerTemplate'];common=Path(prep['lockFile'])
    original_lock=runtime.custody(common,0o600)[1]
    preserved={Path(prep['coordinationJournal']):Path(prep['coordinationJournal']).read_bytes()}
    preserved.update({p:p.read_bytes() for p in phase.journal.root.glob('*.json')})
    provider=owner.creation.owned_id();registry=window.engine.inspect(window.transition)['Id']
    def native(cid):
        if docker_engine is None:return json.loads(run(commands['runc'],'--root',str(state_root),'state',cid).stdout)
        status,value=docker_engine.request('GET','/v1.44/containers/'+cid+'/json')
        assert status==200 and value['Id']==cid
        state=value['State']
        return {'pid':state['Pid'],'status':'paused' if state['Paused'] else 'running' if state['Running'] else 'stopped'}
    def pause_provider(paused,*,check=True):
        if docker_engine is None:
            return run(commands['runc'],'--root',str(state_root),'pause' if paused else 'resume',provider,check=check)
        status,_=docker_engine.request('POST','/v1.44/containers/'+provider+('/pause' if paused else '/unpause'))
        if check:assert status==204
    identities={cid:native(cid) for cid in (registry,provider)}
    pins={cid:(s['pid'],ticks(s['pid']),Path('/proc',str(s['pid']),'ns/net').stat().st_ino)
        for cid,s in identities.items()}
    assert identities[registry]['status']=='paused' and identities[provider]['status']=='running'
    assert owner.observe_started()[0]=='APPLIED' and window.observe_closed()['state']=='CLOSED'
    # Full installation admission is a predecessor, not a health-check task.
    # Validate its actual output once, then keep its exact current records,
    # finite mandate and authority/generation checks. This CI-only seal is NOT
    # the installed worker's operational trust/lifetime contract.
    admission_started=time.monotonic();material=owner.publication.material();app=material['materialized']
    snapshot={'desiredProfileHash':owner.admission.template['configurationTemplate']['desiredProfileHash'],
        'profiles':{'provider':{**owner.admission.template['expectedNodeProfiles']['provider'],
            'applicationHash':app['applicationHash']}},'peers':{'provider':{
                'containerId':provider,'imageId':owner.admission.template['expectedImages']['provider'],
                'pid':pins[provider][0],'startTicks':pins[provider][1],
                'namespace':{'identity':[Path('/proc',str(pins[provider][0]),'ns/net').stat().st_dev,pins[provider][2]]}}}}
    proof=owner.admission.current(snapshot);provider_root=Path(material['root'])
    names={'intent':'intent.json','attestation':'attestation.json','approval':'approval.json',
        'acceptanceMandate':'node-acceptance.json','consumption':'deployment.json'}
    records={name:runtime.custody(provider_root/file,0o600)[0] for name,file in names.items()}
    assert proof['recordsHash']==worker.fingerprint({k:__import__('hashlib').sha256(v).hexdigest() for k,v in records.items()})
    assert proof['adapterHash']==__import__('hashlib').sha256(runtime.custody(provider_root/'adapter.json',0o600)[0]).hexdigest()
    seals={p:runtime.custody(p,0o600) for directory_ in (provider_root,owner.root,phase.root,window.root)
        for p in directory_.glob('*.json')}
    expires=min(json.loads(records[name])['expiresAt'] for name in ('intent','approval','acceptanceMandate'))
    admission_seconds=time.monotonic()-admission_started
    directory=root/'joint-worker';directory.mkdir(mode=0o700)
    ledger=directory/'ledger';ledger.mkdir(mode=0o700)
    journal=worker.Journal(ledger);coord_path=directory/'coordination.json'
    cfg=copy.deepcopy(prep['kernel']);profile=copy.deepcopy(prep['dns']);binding=copy.deepcopy(prep['coordinationBinding'])
    coord_path.write_bytes(runtime.encoded({'schema':'ouf.semantic-lease-coordination.v1',**binding,
        'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,
        'leaseAddresses':[[] for _ in cfg['providerFlows']]}));coord_path.chmod(0o600)
    assert coord_path!=Path(prep['coordinationJournal']) and not any(owner.coordinator.sets())
    policy=worker.Policy(delays=(5,10),max_attempts=4,max_elapsed=60,attempt_timeout=15,jitter=0)
    generation=worker.fingerprint({'parent':parent.sha,'child':window.child_hash,'pins':pins})
    scope={'sourceClosureHash':parent.scope['sourceClosureHash'],
        'installationInputsHash':parent.scope['installationInputsHash'],'contextRef':worker.fingerprint({'joint':generation}),
        'generationRef':generation,'policyHash':worker.fingerprint(dataclasses.asdict(policy)),
        'coordinatorBindingHash':worker.fingerprint(binding),'configurationHash':worker.fingerprint(cfg),
        'dnsProfileHash':worker.fingerprint(profile),'leaseStructureHash':binding['leaseStructureHash'],
        'pollSeconds':1,'heartbeatSeconds':1}
    recovery=worker.DiscoveryRecovery(journal,None,policy,scope['contextRef'],generation,
        lambda:(time.time(),time.monotonic()),lambda:.5)
    journal.initialize({**recovery.initial(),'discoveryLeaseScopeHash':worker.fingerprint(scope)})
    initial=journal.read()
    run(commands['ip'],'link','set','lo','up')
    assert profile['resolvers']==['192.0.2.53'] and profile['resolverPort']==53
    run(commands['ip'],'addr','add','192.0.2.53/32','dev','lo')
    server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('192.0.2.53',53));server.settimeout(.1)
    control={'ttl':30,'queries':0};done=threading.Event();left,right=socket.socketpair()
    def free_locks():
        for path in (common,ledger/'recovery.lock'):
            fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW)
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(fd)
    def child(channel):
        channel.settimeout(45)
        backend=DeadlineNftBackend([commands['nft']],cfg,binding['leaseStructureHash'],5)
        coordination=runtime.PrivateJournal(coord_path)
        coordinator=runtime.Coordinator(runtime.LeaseOwner(cfg,profile,backend),binding,
            lambda:runtime.hold_common_lock(common),coordination.read,coordination.write)
        module_path=Path(worker.__file__).parents[1]/'semantic_lease_recovery/readback_margin_compiler.py'
        spec=importlib.util.spec_from_file_location('joint_native_readback_compiler',module_path)
        compiler=importlib.util.module_from_spec(spec);spec.loader.exec_module(compiler)
        def admission(_):
            parent.registry_child(window.child,window.raw)
            parent.guard('providerInstallation',owner.creation.component)
            return time.time()<expires and all(runtime.custody(path,0o600)==seal for path,seal in seals.items())
        def current(_):
            for cid,expected in pins.items():
                actual=native(cid);pid=actual['pid']
                if (pid,ticks(pid),Path('/proc',str(pid),'ns/net').stat().st_ino)!=expected:return False
                if actual['status']!=('paused' if cid==registry else 'running'):return False
            return True
        original=dns.exchange
        def exchange(*args,**kwargs):free_locks();return original(*args,**kwargs)
        dns.exchange=exchange
        supervisor=worker.build_worker(coordinator,journal,policy,scope,runtime_guard=admission,
            generation_guard=current,custody_guard=lambda *_:backend.verify_ownership(cfg) or True,
            dns=dns,compiler=compiler,random_value=lambda:.5)
        # Neither installer signing nor a new provider lifecycle is allowed.
        from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
        def forbidden(*_args,**_kwargs):raise AssertionError('CI_WORKER_MUST_NOT_SIGN')
        ExistingEd25519Signer.sign=forbidden
        with journal.invocation():
            stream=channel.makefile('rwb',buffering=0)
            while True:
                command=stream.readline(129).strip()
                if command==b'stop':supervisor.r.adapter.pause();return
                if command==b'tick':value=supervisor.tick()
                elif command==b'renew':value=supervisor.renew(supervisor.tick())
                else:raise AssertionError('CI_EXACT_WORKER_COMMAND_REQUIRED')
                public={k:value.get(k) for k in ('state','reason','attempts','publicationCount','startedWall',
                    'startedMonotonic','nextWall','nextMonotonic','contextRef','generationRef')}
                stream.write(runtime.encoded(public)+b'\n')
    pid=os.fork()
    if pid==0:
        left.close();server.close()
        try:child(right)
        except BaseException as error:
            import traceback
            traceback.print_exc();os._exit(1)
        os._exit(0)
    right.close();left.settimeout(45);stream=left.makefile('rwb',buffering=0)
    def respond():
        while not done.is_set():
            try:query,peer=server.recvfrom(4096)
            except socket.timeout:continue
            except OSError:return
            control['queries']+=1;end=12
            while query[end]:end+=query[end]+1
            end+=1;qtype=struct.unpack('!H',query[end:end+2])[0]
            raw=socket.inet_pton(socket.AF_INET if qtype==1 else socket.AF_INET6,
                '1.1.1.1' if qtype==1 else '2606:4700:4700::1111')
            reply=query[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+query[12:end+4]
            reply+=b'\xc0\x0c'+struct.pack('!HHIH',qtype,1,control['ttl'],len(raw))+raw
            server.sendto(reply,peer)
    thread=threading.Thread(target=respond,daemon=True);thread.start()
    def request(command):
        stream.write(command.encode()+b'\n');raw=stream.readline(4097)
        assert 0<len(raw)<=4096,'CI_JOINT_WORKER_REPLY_REQUIRED'
        return json.loads(raw)
    try:
        first=request('tick');assert first['state']=='ACTIVE',first
        second=request('renew');assert second['state']=='ACTIVE' and second['publicationCount']>first['publicationCount'],second
        assert second['attempts']==first['attempts']==1
        # Lifetime invocation fencing is real and cannot reset/reinitialize.
        try:
            with journal.invocation():raise AssertionError('SECOND_WORKER_FENCE_ACCEPTED')
        except BlockingIOError:pass
        control['ttl']=0
        paused=request('renew');assert paused['state']=='RETRY_WAIT',paused
        assert not any(owner.coordinator.sets());free_locks()
        queries=control['queries'];before=journal.read();assert before['nextMonotonic']>time.monotonic()
        held=request('tick');assert held['state']=='RETRY_WAIT' and held['attempts']==paused['attempts'],held
        assert control['queries']==queries and held['nextMonotonic']==before['nextMonotonic']
        control['ttl']=30
        remaining=before['nextMonotonic']-time.monotonic()
        if remaining>0:time.sleep(min(remaining+.03,10))
        recovered=request('tick');assert recovered['state']=='ACTIVE' and recovered['attempts']>first['attempts'],recovered
        assert recovered['publicationCount']>second['publicationCount']
        assert recovered['startedWall']==first['startedWall']==initial['startedWall']
        assert recovered['startedMonotonic']==first['startedMonotonic']==initial['startedMonotonic']
        pause_provider(True)
        blocked=request('tick');assert blocked['state']=='BLOCKED' and blocked['reason']=='GENERATION_CHANGED',blocked
        assert not any(owner.coordinator.sets());free_locks()
        pause_provider(False)
        queries=control['queries'];again=request('tick')
        assert again['state']=='BLOCKED' and again['attempts']==blocked['attempts'] and control['queries']==queries
        assert all(p.read_bytes()==raw for p,raw in preserved.items())
        assert runtime.custody(common,0o600)[1]==original_lock
        assert window.observe_closed()['state']=='CLOSED' and native(registry)['status']=='paused'
        assert native(provider)['status']=='running' and owner.observe_started()[0]=='APPLIED'
        request_stop=b'stop\n';stream.write(request_stop)
        reaped,status=os.waitpid(pid,0);assert reaped==pid and os.waitstatus_to_exitcode(status)==0;pid=None
        return {'schema':'ouf.m2-provider-worker-native-handoff-ci.v1','realV4ProviderAdmissionFeedsWorkerGuard':True,
            'distinctWorkerProcess':True,'sameRegistryProviderParentChildAndCommonLock':True,
            'sameKernelDnsBindingAndPreservedProviderJournal':True,'realDnsNftTwoFamilyPublicationAndRenewal':True,
            'dnsFailureRevokesBothFamiliesAndPersistsBackoff':True,'noDnsOrAttemptDuringPersistedWait':True,
            'recoveryPreservesOriginalClocksIncidentAndCumulativeCounters':True,'concurrentInvocationDenied':True,
            'nativeProviderPauseBlocksWorkerAndResumeDoesNotRearm':True,'registryRemainsPausedAtClosedGate':True,
            'finiteInstallerAdmissionOnly':True,'sealedWorkerInstallationProven':False,
            'fullInitialAdmissionSeconds':round(admission_seconds,3),
            'currentFiniteAdmissionRecordSealsCheckedWithoutRecompilingInstaller':True,
            'modeledDockerBoundaryAndSyntheticImagesReviewRegistryPredecessor':docker_engine is None,
            'actualDockerBoundary':docker_engine is not None,'syntheticImagesReviewRegistryPredecessor':True,
            'combinedNativeDockerCompositionProven':docker_engine is not None,'fullCohortProven':False,'applicationE2EProven':False,
            'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,'releaseAcceptance':False}
    finally:
        if pid is not None:
            os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
        stream.close();left.close();done.set();thread.join(timeout=1);server.close()
        pause_provider(False,check=False)
        # Revoke only through the new worker journal, preserving the provider's
        # admission history even on failure. This is disposable-CI cleanup.
        cleanup_backend=runtime.NftBackend([commands['nft']],cfg,binding['leaseStructureHash'],5)
        cleanup_journal=runtime.PrivateJournal(coord_path)
        cleanup=runtime.Coordinator(runtime.LeaseOwner(cfg,profile,cleanup_backend),binding,
            lambda:runtime.hold_common_lock(common),cleanup_journal.read,cleanup_journal.write)
        cleanup.quiesce()
