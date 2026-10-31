"""CI composition of a real admitted provider and the production sealed worker.

Registry admission predecessors remain explicitly modeled. The provider reader,
late native capture, signer, publisher, registration and systemd start are real.
No installed/previous worker or ledger is adopted by this disposable fixture.
"""
import copy,dataclasses,hashlib,json,os,socket,struct,threading,time,types
from pathlib import Path
from tools.m2_discovery_installation_profile import lease_capsule as capsule
from tools.m2_discovery_installation_profile import lease_installation_template as templates
from tools.m2_discovery_installation_profile import lease_start_owner as starts
from tools.m2_discovery_installation_profile import lease_file_installation as files
from tools.m2_discovery_installation_profile import lease_registration as registration
from tools.m2_discovery_installation_profile import lease_attestation as attestation
from tools.m2_discovery_installation_profile import lease_installation_phase as sequence
from tools.m2_discovery_installation_profile import lease_observation as observation
from tools.m2_discovery_installation_profile.lease_materialization import WorkerMaterialization
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from bounded_recovery import Policy,fingerprint

encoded=files.encoded;digest=files.digest


def review(auth,root,provider_template,profile_scope,registry_request):
    """All static worker expectations are compiled before the provider exists."""
    install=root/'sealed-worker';ledger=root/'worker-ledger';sandbox=root/'worker-sandbox'
    fences=root/'worker-fences';fences.mkdir(mode=0o700)
    dirs={name:auth.root/('sealed-worker-'+name) for name in
        ('start','publication','registration','issuance','signatures','observations','sequence','evidence')}
    for directory in dirs.values():directory.mkdir(mode=0o700)
    source_root=Path(__file__).resolve().parents[2]
    raw,manifest=capsule.build(source_root)
    def program(path):
        p=Path(path).resolve();return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'maximumBytes':67108864}
    prep=profile_scope['preparerTemplate'];python=program('/usr/bin/python3');nft=program(prep['commands']['nft'])
    openssl=program(auth.openssl);policy=Policy(delays=(1,2),max_attempts=8,max_elapsed=600,attempt_timeout=30,jitter=0)
    kernel=copy.deepcopy(prep['kernel']);dns=copy.deepcopy(prep['dns']);binding=copy.deepcopy(prep['coordinationBinding'])
    scope={'sourceClosureHash':manifest['dependencyClosureHash'],'installationInputsHash':auth.review['installationInputsHash'],
        'contextRef':digest({'ciSealedWorker':str(root)}),'generationRef':None,'policyHash':fingerprint(dataclasses.asdict(policy)),
        'coordinatorBindingHash':fingerprint(binding),'configurationHash':fingerprint(kernel),'dnsProfileHash':fingerprint(dns),
        'leaseStructureHash':binding['leaseStructureHash'],'pollSeconds':1,'heartbeatSeconds':1}
    recipe={'schema':'ouf.discovery-operational-lease-recipe.v1','kernel':kernel,'dns':dns,'binding':binding,
        'policy':json.loads(encoded(dataclasses.asdict(policy))),'scope':scope,'nft':nft,
        'coordinationJournal':str(ledger/'coordination.json'),'leaseCommonLock':prep['lockFile'],
        'leaseCommonLockIdentity':files.inode(prep['lockFile'])}
    trust=auth.policy.read_bytes();trust_path=install/'public-trust/policy.json'
    config={'schema':'ouf.discovery-operational-lease-configuration.v1','installationInputsHash':scope['installationInputsHash'],
        'desiredProfileHash':auth.review['desiredProfileHash'],'sourceManifest':manifest,
        'sources':[python,nft,openssl,{'path':str(install/'capsule.py'),'sha256':hashlib.sha256(raw).hexdigest(),'maximumBytes':len(raw)},
            {'path':str(install/'worker-recipe.json'),'sha256':'0'*64,'maximumBytes':1048576}],
        'verification':{'trustPolicy':{'path':str(trust_path),'sha256':hashlib.sha256(trust).hexdigest()},
            'openssl':{k:v for k,v in openssl.items() if k!='maximumBytes'}|{'version':auth.native('version').decode().split()[1]},
            'context':{k:auth.context[k] for k in ('installationRef','entityRef','attestorRef')}},
        'serviceUnitPath':str(install/'owner.service'),'serviceUnitHash':'0'*64,'commonInvocationLock':str(fences/'owner.lock'),
        'commonLockIdentity':None,'generationReceiptPath':str(install/'current-generation.json'),
        'hostBootIdPath':str(install/'host-boot-id'),'ledgerRoot':str(ledger),'scopePolicyHash':scope['policyHash']}
    registry_recipe=profile_scope['registryRecipe']
    template=templates.template(config,recipe,python,source_closure_hash=provider_template['sourceClosureHash'],
        expected_images={'provider':provider_template['expectedImageId'],'registry':registry_request['Image']},
        expected_node_profiles={'provider':__import__('tools.m2_discovery_installation_profile.provider_installation_template',fromlist=['expected_node_profile']).expected_node_profile(provider_template),
            'registry':{'nodeRecipeHash':digest(registry_recipe),'imageConfigurationHash':registry_recipe['imageConfigurationHash'],
                'rootfsSealHash':digest(registry_recipe['expectedRootfsSeal'])}},
        installation_root=str(install),signing_key_paths=[str(auth.key)],engine_unit='ouf-docker-contract-daemon.service',sandbox_root=str(sandbox))
    manager=program('/usr/bin/systemctl')
    unit='ouf-admitted-worker-'+root.name[-8:]+'.service'
    start_scope=starts.start_scope(template,unit_name=unit,manager=manager,directory=str(dirs['start']))
    verifier=DetachedAuthenticator(auth.binding(auth.policy),str(dirs['signatures']),auth.verifier.openssl_binding)
    signer=ExistingEd25519Signer(auth.binding(auth.key),'synthetic-attestor-key',verifier,
        {'role':'CREATION_ATTESTATION','issuerRef':auth.context['attestorRef'],
            'installationRef':auth.context['installationRef'],'entityRef':auth.context['entityRef']})
    setup={'template':template,'capsule':raw,'trust':trust,'sources':{str(trust_path):trust},'signer':signer,
        'start':start_scope,'dirs':dirs,'unit':unit,'install':install,'ledger':ledger}
    return template,setup


def bind_review(auth,setup,provider_scope):
    t=setup['template'];d=setup['dirs'];start=setup['start'];signer=setup['signer']
    bare=files.publication_scope(t,start,str(d['publication']))
    managed=registration.registration_scope(t,start,unit_directory='/etc/systemd/system',journal_directory=str(d['registration']))
    component=registration.registered_component(t,bare,managed)
    issuance=attestation.issuance_scope(t,provider_scope,directory=str(d['issuance']),signature_directory=str(d['signatures']),
        observation_root=str(d['observations']),key_binding=signer.key,key_ref=signer.key_ref)
    component=attestation.attested_component(t,component,issuance)
    seq=sequence.sequence_scope(t,component,directory=str(d['sequence']))
    auth.review['components']['operationalLeaseInstallation']=sequence.sequenced_component(t,component,seq)
    return digest(start)


def qualify(provider_phase,auth,setup,boundary,run):
    owner=provider_phase.runtime;window=owner.creation.window;engine=owner.creation.engine
    parent=owner.parent;template=setup['template'];recipe=owner.issuer.scope['registryRecipe']
    unit=setup['unit'];ledger=setup['ledger'];install=setup['install']
    assert engine.inspect(window.transition)['State']['Paused'] is True
    preserved={Path(owner.issuer.scope['preparerTemplate']['coordinationJournal']):
        Path(owner.issuer.scope['preparerTemplate']['coordinationJournal']).read_bytes()}
    preserved.update({p:p.read_bytes() for p in provider_phase.root.glob('*.json')})
    # The Registry full-admission predecessor is explicitly modeled here. Same
    # signed recipe, real Docker peer, parent/child and native provider are used.
    node=object.__new__(starts.DiscoveryNodeOwner);node.engine=engine;node.recipe=copy.deepcopy(recipe)
    node.authority=window.child;node.raw=window.raw;node.signer=setup['signer'];node.transition=window.transition
    node.store=starts.NativeEvidenceStore(setup['dirs']['evidence']);node.request=copy.deepcopy(window.request)
    identity=__import__('tools.m2_discovery_installation_profile.provider_profiles',fromlist=['registry_identity']).registry_identity(owner.creation,owner.issuer.scope)
    node.adapter=types.SimpleNamespace(request={'applicationHash':identity['applicationHash']})
    node.verify_retained=lambda:{'syntheticRegistryFullAdmissionPredecessor':True}
    intent={'creationRequestHash':digest(node.request),'nodeRecipeHash':digest(node.recipe),
        'leaseInstallationScopeHash':digest(setup['start']),'priorEvidencePhase':'INSTALL_AUTHENTICATED_TRANSPORT'}
    phases=json.loads(window.raw)['phaseIntentHashes'];index=starts.PHASES.index(starts.PHASE)
    boundary.update(state='IN_FLIGHT',nextPhase=index,effects=[{
        'phase':phase,'state':'APPLIED' if i<index else 'IN_FLIGHT','intentHash':phases[phase],
        'authorityEvidenceHash':window.child_hash,'nativeEvidenceHash':'9'*64}
        for i,phase in enumerate(starts.PHASES[:index+1])])
    server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('192.0.2.53',53));server.settimeout(.1)
    done=threading.Event();queries=[0]
    def respond():
        while not done.is_set():
            try:query,peer=server.recvfrom(4096)
            except socket.timeout:continue
            except OSError:return
            queries[0]+=1;end=12
            while query[end]:end+=query[end]+1
            end+=1;qtype=struct.unpack('!H',query[end:end+2])[0]
            address=socket.inet_pton(socket.AF_INET if qtype==1 else socket.AF_INET6,
                '1.1.1.1' if qtype==1 else '2606:4700:4700::1111')
            reply=query[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+query[12:end+4]
            reply+=b'\xc0\x0c'+struct.pack('!HHIH',qtype,1,30,len(address))+address
            server.sendto(reply,peer)
    thread=threading.Thread(target=respond,daemon=True);thread.start()
    def command(*args,check=True):return run(*args,check=check).stdout
    def row():return json.loads((ledger/'recovery.json').read_bytes())
    def wait(predicate):
        end=time.monotonic()+45
        while time.monotonic()<end:
            try:
                value=row()
                if predicate(value):return value
            except FileNotFoundError:pass
            time.sleep(.1)
        print(command('journalctl','-u',unit,'--no-pager','-n','35',check=False).decode(),flush=True)
        raise AssertionError('CI_ADMITTED_SEALED_WORKER_TIMEOUT')
    try:
        materializer=WorkerMaterialization(node_owner=node,provider=owner.admission,signer=setup['signer'],
            capsule=setup['capsule'],installation_sources=setup['sources'])
        phase=materializer.prepare_once(intent)
        assert materializer.prepared(intent).files.material==phase.files.material
        dispatches=[];manager=phase.start.manager
        def lost(args):
            value=manager(args)
            if args[0]=='start':dispatches.append(args);raise TimeoutError('CI_LOST_ACTUAL_SEALED_START_REPLY')
            return value
        phase.start.manager=lost
        try:phase.apply(intent);raise AssertionError('CI_LOST_MANAGER_REPLY_NOT_INJECTED')
        except TimeoutError as error:assert str(error)=='CI_LOST_ACTUAL_SEALED_START_REPLY'
        first=wait(lambda v:v['state']=='ACTIVE' and v['publicationCount']>=2)
        result,proof=phase.observe(intent)
        assert result=='APPLIED' and proof['installedWorkerObservation']['bothOwnedLeaseFamiliesPositive']
        assert len(dispatches)==1
        observed=observation.observe(install/'configuration.json',phase.start.proposal['serviceUnit']['configurationAnchor'],
            unit_name=unit,systemctl=setup['start']['manager'])
        pid=observed['managerProcessId'];assert pid>1
        view=Path('/proc')/str(pid)/'root'
        assert not (view/str(auth.key).lstrip('/')).exists()
        fields={k:v.strip() for k,v in (line.split(':',1) for line in Path('/proc',str(pid),'status').read_text().splitlines() if ':' in line)}
        assert int(fields['CapEff'],16)==1<<12 and fields['NoNewPrivs']=='1'
        command('systemctl','kill','--signal=KILL','--kill-who=main',unit)
        recovered=wait(lambda v:v['state']=='ACTIVE' and v['attempts']>first['attempts'] and v['reentryCount']>first['reentryCount'])
        assert recovered['startedWall']==first['startedWall'] and recovered['publicationCount']>=first['publicationCount']
        provider=owner.creation.owned_id();assert engine.request('POST','/v1.44/containers/'+provider+'/kill?signal=SIGKILL')[0]==204
        blocked=wait(lambda v:v['state']=='BLOCKED');assert not any(owner.coordinator.sets())
        before=queries[0];time.sleep(1.5)
        assert row()['state']=='BLOCKED' and row()['attempts']==blocked['attempts'] and queries[0]==before
        assert all(p.read_bytes()==raw for p,raw in preserved.items())
        assert engine.inspect(window.transition)['State']['Paused'] is True
        return {'schema':'ouf.m2-admitted-provider-sealed-worker-ci.v1','realDockerProviderV4Admission':True,
            'lateMaterializationAttestationPublicationRegistrationStart':True,'lostManagerReplyReconciledWithoutSecondStart':True,
            'sealedUnitOnlyCapNetAdminAndKeyHidden':True,'sigkillReentryRetainsStartedTimeAndCounters':True,
            'providerTerminationRevokesAndBlocksWithoutAutomaticRestartOrRearm':True,'providerHistoryAndRegistryPausePreserved':True,
            'syntheticRegistryAdmissionImagesAndReview':True,'fullCohortProven':False,'applicationE2EProven':False,
            'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,'releaseAcceptance':False}
    finally:
        command('systemctl','stop',unit,check=False)
        (Path('/etc/systemd/system')/unit).unlink(missing_ok=True)
        command('systemctl','daemon-reload',check=False);command('systemctl','reset-failed',unit,check=False)
        done.set();thread.join(timeout=1);server.close()
