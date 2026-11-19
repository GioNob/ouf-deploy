"""Real Docker v4 provider admission and finite distinct-worker handoff.

Disposable CI only. Images, parent review and Registry admission predecessors
are synthetic; the actual candidate OCI never supplies its own expectations.
"""
import copy,hashlib,json,os,shutil,stat,subprocess,sys,tempfile,time,types,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_transaction_profiles')]
import test_m2_provider_profiles as fixtures
import test_m2_discovery_lease_installation_template as workers
from test_m2_provider_installation_template import inputs
from tools.m2_discovery_installation_profile import provider_runtime_installation as runtime
from tools.m2_discovery_installation_profile import provider_installation_phase as sequence
from tools.m2_discovery_installation_profile.native_profile import DiscoveryProfile,FILE_ROLES
from tools.m2_discovery_installation_profile.frame_inputs import compile_inputs,ENGINE
from tools.semantic_provider_node_observation import rootfs_seal
from tools.semantic_provider_deployment_authentication import VerificationBudget,attributes
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_lease_nft import structure_hash
from gated_process_observation import GatedProcessObservation
from engine_creation import Engine
from qualify_m2_provider_installation_native import run,pin,private,diagnose_broker

WRAPPER=Path('/usr/local/sbin/ouf-m2-provider-ci')
STATE_ROOT=Path('/run/docker/runtime-runc/moby')
STORAGE='/var/lib/ouf-docker-29'
BUNDLE='/run/containerd/io.containerd.runtime.v2.task/moby'
LIMITS={'maxEntries':10000,'maxBytes':67108864,'maxDepth':32}


def cli(*args):
    return run('docker',*args).stdout.decode().strip()


def main(*,sealed_worker=False,registry_node=False,legacy_reader_control=False):
    assert not registry_node or sealed_worker
    assert os.geteuid()==os.getegid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    assert cli('version','--format','{{.Server.Version}}')=='29.8.1'
    assert json.loads(cli('info','--format','{{json .}}'))['DockerRootDir']==STORAGE
    case=fixtures.Profiles();ids=[];auth=None;table=None;wrapper_owned=False;network='ouf-joint-'+uuid.uuid4().hex[:10]
    token=None;registry_setup=None
    commands={k:str(Path(shutil.which(k)).resolve()) for k in ('runc','nft','ip','nsenter','unshare','mount','umount','sysctl')}
    with tempfile.TemporaryDirectory(prefix='ouf-joint-docker-',dir='/var/lib') as tmp:
        root=Path(tmp);root.chmod(0o700)
        native=root/'commands';native.mkdir(mode=0o700)
        for name,path in list(commands.items()):
            if name!='runc':continue
            destination=native/name;shutil.copyfile(path,destination);destination.chmod(0o755)
            assert pin(destination)['sha256']==pin(path)['sha256'];commands[name]=str(destination)
        try:
            if registry_node:
                from fixtures.m2_registry_node_worker_native import TokenFixture
                token=TokenFixture(run)
            cli('pull','alpine:3.22');image=cli('image','inspect','alpine:3.22','--format','{{.Id}}')
            nid=cli('network','create','--internal','--subnet','10.77.0.0/24',
                '--opt','com.docker.network.bridge.name=brfixture',network)
            request,selection,*_=copy.deepcopy(fixtures.registry_fixture());request['Image']=image
            request['HostConfig']['NetworkMode']=network
            request['NetworkingConfig']={'EndpointsConfig':{network:{'NetworkID':nid,'MacAddress':'02:00:00:00:01:02',
                'IPAMConfig':{'IPv4Address':'10.77.0.3'}}}}
            for i,role in enumerate(FILE_ROLES):
                item=selection['files'][role];p=root/('registry-'+role)
                private(p,('CI_SYNTHETIC_'+role).encode(),item['mode']);os.chown(p,item['uid'],item['gid'])
                item['source']=str(p);item['sha256']=pin(p)['sha256']
                if registry_node:item['metadataHash']=runtime.digest(attributes(p.lstat()))
                request['HostConfig']['Mounts'][i]['Source']=str(p)
            for index,key in ((5,'configtree'),(6,'renewable_token')):
                if registry_node and key=='renewable_token':
                    p=token.output;s=p.stat();selection[key].update(source=str(p),
                        fileName=token.owner.binding.output_member,directoryDevice=s.st_dev,directoryInode=s.st_ino,
                        ownerBindingHash=token.owner.binding.digest())
                    request['HostConfig']['Mounts'][index]['Source']=str(p)
                    request['Env']=[('OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE='+selection[key]['target']+'/'+selection[key]['fileName'])
                        if v.startswith('OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE=') else v for v in request['Env']]
                    continue
                p=root/('registry-'+key);p.mkdir(mode=0o750);os.chown(p,0,10001)
                selection[key]['source']=str(p);request['HostConfig']['Mounts'][index]['Source']=str(p)
                if registry_node:
                    p.chmod(0o500);os.chown(p,10001,10001)
                    password=p/selection[key]['fileName'];private(password,b'CI_SYNTHETIC_DB_PASSWORD',0o400)
                    os.chown(password,10001,10001);selection[key]['sha256']=pin(password)['sha256']
            profile=DiscoveryProfile(request,**selection)
            template,launch=compile_inputs((ROOT/'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes(),
                request,execution_profile=profile,engine_profile=ENGINE)
            context={'schema':'ouf.semantic-docker-frame-context.v1','containerId':'c'*64,'bundleParent':BUNDLE,
                'metadataParent':STORAGE+'/containers','networkNamespaceParent':'/run/docker/netns',
                'networkNamespaceName':None,'cgroupDriver':'systemd','storageParent':STORAGE,
                'rootfsPath':STORAGE+'/rootfs/overlayfs/'+'c'*64}
            definition=(request,selection,template,launch,context)
            opts=inputs();opts['request']['Image']=image;opts['runtime_binding']=pin(commands['runc'])
            opts['request']['HostConfig']['NetworkMode']=network
            opts['request']['NetworkingConfig']={'EndpointsConfig':{network:{'NetworkID':nid,'MacAddress':'02:00:00:00:01:01',
                'IPAMConfig':{'IPv4Address':'10.77.0.2'}}}}
            opts['docker_context_template'].update(bundleParent=BUNDLE,metadataParent=STORAGE+'/containers',
                storageParent=STORAGE,networkNamespaceParent='/run/docker/netns',rootfsLayout='docker-containerd-overlayfs-v1')
            source=root/'provider-source';private(source,b'CI_INDEPENDENT_PROVIDER_SOURCE');os.chown(source,636,636)
            old_source=opts['launch']['sources'][0]['source']
            opts['launch']['sources'][0].update(source=str(source),sha256=pin(source)['sha256'])
            opts['launch']['manifest']['mounts'][0]['source']=str(source)
            opts['request']['HostConfig']['Mounts'][0]['Source']=str(source)
            for mount in opts['frame_template']['expectedOci']['mounts']:
                if mount.get('source')==old_source:mount['source']=str(source)
            # A separately created control peer qualifies image/rootfs layout
            # BEFORE review or the admitted candidate exists. Its OCI is never
            # read into either expected frame template.
            sockpath=Path('/var/run/docker.sock').resolve();s=sockpath.stat()
            engine=Engine(str(sockpath),(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
            control=copy.deepcopy(opts['request']);control['HostConfig']['Runtime']='runc'
            control['NetworkingConfig']['EndpointsConfig'][network].update(MacAddress='02:00:00:00:01:04',IPAMConfig={'IPv4Address':'10.77.0.4'})
            status,created=engine.request('POST','/v1.44/containers/create',control);assert status==201,created
            control_id=created['Id'];ids.append(control_id)
            assert engine.request('POST','/v1.44/containers/'+control_id+'/start')[0]==204
            assert engine.request('POST','/v1.44/containers/'+control_id+'/pause')[0]==204
            opts['expected_rootfs_seal']=rootfs_seal(Path(STORAGE+'/rootfs/overlayfs/'+control_id),LIMITS,VerificationBudget(15))
            registry_rootfs=None
            if registry_node:
                control=copy.deepcopy(request)
                control['NetworkingConfig']['EndpointsConfig'][network].update(MacAddress='02:00:00:00:01:05',IPAMConfig={'IPv4Address':'10.77.0.5'})
                status,created=engine.request('POST','/v1.44/containers/create',control);assert status==201,created
                control_id=created['Id'];ids.append(control_id)
                assert engine.request('POST','/v1.44/containers/'+control_id+'/start')[0]==204
                assert engine.request('POST','/v1.44/containers/'+control_id+'/pause')[0]==204
                registry_rootfs=rootfs_seal(Path(STORAGE+'/rootfs/overlayfs/'+control_id),LIMITS,VerificationBudget(15))
            # The independent southbound baseline deliberately supplies all
            # Engine defaults, including seccomp, AppArmor and mount ordering.
            issuer0,w,auth,_,_,options,_=case.fixture(definition=definition,provider_inputs=opts,rootfs_limits=LIMITS,
                gate_seconds=300 if registry_node else 120)
            if registry_node:
                options.update(maximum_seconds=300,handoff_window=copy.deepcopy(fixtures.m.FULL_HANDOFF_WINDOW))
            prep=options['preparer_template'];prep.update(commands={k:commands[k] for k in prep['commands']},
                commandHashes={k:pin(commands[k])['sha256'] for k in prep['commands']},hostNetworkNamespace=runtime.host_namespace())
            if registry_node:
                prep['kernel']['staticFlows'].append({'purpose':'DNS','source':'10.77.0.3',
                    'destination':'192.0.2.53','protocol':'udp','port':53})
            options['registry_recipe']['runtimeRoot']=str(STATE_ROOT)
            cfg=options['runtime_configuration'];cfg['runtimeStateRoot']=str(STATE_ROOT.parent)
            auth.write(Path(options['runtime_configuration_binding']['path']),runtime.encoded(cfg))
            options['runtime_configuration_binding']=auth.binding(Path(options['runtime_configuration_binding']['path']))
            options['runtime_root_parents']=[str(STATE_ROOT.parent)]
            table=prep['kernel']['tableName']='ci_provider_lease'
            run(commands['nft'],'-f','-',raw=materialize(prep['kernel'],empty_provider_sets=True)['nftRules'].encode())
            tables={family:json.loads(run(commands['nft'],'-j','list','table',family,table).stdout) for family in ('inet','bridge')}
            prep['coordinationBinding']['leaseStructureHash']=structure_hash(tables)
            prep['coordinationBinding']['configurationHash']=runtime.digest(prep['kernel'])
            kernel_root=root/'provider-kernel';kernel_root.mkdir(mode=0o700)
            prep['lockFile']=str(kernel_root/'kernel.lock')
            auth.write(Path(prep['lockFile']),b'');auth.write(Path(prep['coordinationJournal']),runtime.encoded({
                'schema':'ouf.semantic-lease-coordination.v1',**prep['coordinationBinding'],'state':'QUIESCED',
                'leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[]]}))
            if registry_node:
                from fixtures.m2_registry_node_worker_native import configure_recipe
                registry_setup=configure_recipe(auth,root,options,commands,registry_rootfs)
            recipe=options['registry_recipe'];node_intent={'creationRequestHash':w.request_hash,
                **{k:recipe[k] for k in ('sourceClosureHash','qualifiedPackageHash','imageConfigurationHash')},'nodeRecipeHash':runtime.digest(recipe)}
            phases=runtime.decode(w.raw)['phaseIntentHashes'];phases['ATTEST_NEW_OCI_PEER']=runtime.digest(node_intent)
            if registry_node:phases['INSTALL_AUTHENTICATED_TRANSPORT']=runtime.digest(registry_setup['transportIntent'])
            child,raw=auth.child(creation_request_hash=w.request_hash,phase_intent_hashes=phases)
            w.child,w.raw,w.child_hash=child,raw,hashlib.sha256(raw).hexdigest()
            boundary=w.transition.read();boundary['transitionAuthorityEvidenceHash']=w.child_hash
            for effect in boundary['effects']:effect.update(authorityEvidenceHash=w.child_hash,intentHash=phases[effect['phase']])
            w.transition.read=lambda:copy.deepcopy(boundary)
            ps=fixtures.m.profile_scope(issuer0.template,issuer0.creation.scope,**options)
            worker_setup=None
            if sealed_worker:
                from fixtures.m2_admitted_provider_sealed_worker_native import review,bind_review
                lease,worker_setup=review(auth,root,issuer0.template,ps,request)
            else:
                co,worker_recipe,_,py,wo=workers.Template().fixture()
                wo.update(source_closure_hash=issuer0.template['sourceClosureHash'],signing_key_paths=[str(auth.key)])
                wo['expected_images']['provider']=issuer0.template['expectedImageId']
                wo['expected_node_profiles']['provider']=fixtures.m.templates.expected_node_profile(issuer0.template)
                co['verification']['context']={k:auth.context[k] for k in ('installationRef','entityRef','attestorRef')}
                lease=workers.m.template(co,worker_recipe,py,**wo)
            from tools.m2_discovery_installation_profile.provider_materialized_admission import admission_scope
            adm=admission_scope(lease,issuer0.template,issuer0.creation.scope,ps)
            if WRAPPER.exists():
                expected=b'#!/bin/sh\ncase "$1" in features|version|--version) exec /opt/ouf-docker-29/runc "$@";; *) exit 1;; esac\n'
                assert runtime.custody(WRAPPER,0o755)[0]==expected,'EXACT_CI_FEATURE_ONLY_BOOTSTRAP_REQUIRED'
                # This is pre-review disposable CI setup, not the production
                # wrapper switch or adoption of any existing installation.
                WRAPPER.unlink()
            with WRAPPER.open('xb') as stream:
                wrapper_owned=True
                stream.write(runtime.wrapper_bytes(ps['pythonBinding']['path'],ps['sourceRoot'],ps['priorRuntimeConfigurationBinding']['path']))
            WRAPPER.chmod(0o755)
            rs=runtime.runtime_scope(ps,wrapper_binding=auth.binding(WRAPPER),common_lock_identity=list(runtime.custody(prep['lockFile'],0o600)[1]))
            seqroot=auth.root/'sequence';seqroot.mkdir(mode=0o700)
            component={'schema':'ouf.discovery-composed-provider-installation-scope.v2','creation':issuer0.creation.scope,'installation':rs,'admission':adm,
                'sequence':sequence.provider_sequence_scope(issuer0.creation.scope,rs,adm,journal_directory=seqroot)}
            auth.review['components']['providerInstallation']=component
            if sealed_worker:
                start_hash=bind_review(auth,worker_setup,adm)
                worker_intent={'creationRequestHash':w.request_hash,'nodeRecipeHash':runtime.digest(recipe),
                    'leaseInstallationScopeHash':start_hash,'priorEvidencePhase':'INSTALL_AUTHENTICATED_TRANSPORT'}
                phases['START_DISTINCT_LEASE_WORKER']=runtime.digest(worker_intent)
                # Initial CI authority only, before either reviewed candidate
                # is created. Match the already finite parent120s window; no
                # renewal, replay or extension after any installation effect.
                auth.now=int(time.time())
                child,raw=auth.child(expires=300 if registry_node else 120,
                    creation_request_hash=w.request_hash,phase_intent_hashes=phases)
                w.child,w.raw,w.child_hash=child,raw,hashlib.sha256(raw).hexdigest()
                boundary['transitionAuthorityEvidenceHash']=w.child_hash
                for effect in boundary['effects']:effect.update(authorityEvidenceHash=w.child_hash,intentHash=phases[effect['phase']])
            parent=auth.fixture(seconds=300 if registry_node else 120);w.parent=parent;w.parent_hash=parent.sha
            parent.clock=w.child.clock=auth.verifier.clock=time.time
            # Replace the fixture transport in full: all HTTP results and
            # configuration/process/generation observations come from Docker.
            w.engine=engine
            store_root=root/'native-predecessor-evidence';store_root.mkdir(mode=0o700);w.store=type(w.store)(store_root)
            status,created=engine.request('POST','/v1.44/containers/create?name='+engine.name(w.transition),request)
            assert status==201,created
            registry=created['Id'];ids.append(registry)
            assert engine.request('POST','/v1.44/containers/'+registry+'/start')[0]==204
            gate=GatedProcessObservation(request);w.process=gate;end=time.monotonic()+10
            while True:
                actual=engine.matching_configuration(w.transition,request,engine.inspect(w.transition))
                if gate.observe(actual['State']['Pid'])['processKind']=='GATE_WAITING':break
                assert time.monotonic()<end;time.sleep(.05)
            assert engine.request('POST','/v1.44/containers/'+registry+'/pause')[0]==204
            actual=engine.inspect(w.transition);w.store.publish('STAGE_PAUSED_REPLACEMENT',actual)
            boundary['effects'][-1]['nativeEvidenceHash']=runtime.digest(actual)
            creation=runtime.ProviderCreation(parent=parent,window=w,template=issuer0.template,
                journal_directory=issuer0.creation.root,installation_component=component)
            issuer=runtime.ProviderInitialIssuer(creation=creation,scope=ps,signers=issuer0.signers)
            publication=runtime.ProviderProfilePublication(issuer)
            reader=runtime.MaterializedProviderAdmission(publication=publication,lease_template=lease)
            backend=runtime.NftBackend([commands['nft']],prep['kernel'],prep['coordinationBinding']['leaseStructureHash'],5)
            journal=runtime.PrivateJournal(Path(prep['coordinationJournal']))
            coord=runtime.Coordinator(runtime.LeaseOwner(prep['kernel'],prep['dns'],backend),prep['coordinationBinding'],
                lambda:runtime.hold_common_lock(Path(prep['lockFile'])),journal.read,journal.write)
            owner=runtime.ProviderRuntimeInstallation(publication=publication,admission=reader,scope=rs,coordinator=coord)
            mutations=[];native_request=engine.request
            def dispatch(method,path,body=None):
                result=native_request(method,path,body)
                if method=='POST':
                    mutations.append((path,result[0]))
                    if '/containers/create?' in path and result[0]==201:ids.append(result[1]['Id'])
                    if path.endswith('/start'):
                        assert result[0]==204,'CI_REAL_PROVIDER_START_FAILED:'+str(result)
                        raise TimeoutError('CI_LOST_SUCCESSFUL_DOCKER_PROVIDER_START_REPLY')
                return result
            engine.request=dispatch
            phase=sequence.ProviderInstallationPhase(owner)
            try:phase.apply();outcome,proof=phase.observe();assert outcome=='APPLIED',proof
            except Exception:
                try:
                    material=publication.material();diagnose_broker(material,STATE_ROOT)
                    actual_path=Path(material['root'])/'bundle/config.json'
                    if actual_path.exists():
                        actual_oci=json.loads(actual_path.read_bytes());expected_oci=material['materialized']['framePolicy']['expectedOci']
                        changes=[]
                        def compare(expected,actual,path=''):
                            if type(expected) is dict and type(actual) is dict:
                                for key in sorted(set(expected)|set(actual)):
                                    if key not in expected or key not in actual:changes.append(path+'/'+key)
                                    else:compare(expected[key],actual[key],path+'/'+key)
                            elif expected!=actual:changes.append(path)
                        compare(expected_oci,actual_oci)
                        print('CI_INDEPENDENT_PROVIDER_OCI_DIFFERENCE_PATHS='+json.dumps(changes[:40]),flush=True)
                        print('CI_PROVIDER_MOUNT_OPTIONS='+json.dumps({label:[{'target':v['destination'],'options':v.get('options',[])}
                            for v in value['mounts']] for label,value in (('expected',expected_oci),('actual',actual_oci))},sort_keys=True),flush=True)
                    for denial in Path(material['root']).glob('broker-denial-*.json'):
                        value=runtime.private_json(denial)
                        print('CI_RETAINED_BROKER_DENIAL='+json.dumps(value,sort_keys=True),flush=True)
                    for selected in (STATE_ROOT,Path('/run/containerd/runc/moby')):
                        result=run(commands['runc'],'--root',str(selected),'state',registry,check=False)
                        print('CI_REGISTRY_RUNTIME_ROOT='+json.dumps({'root':str(selected),'returncode':result.returncode,
                            'state':json.loads(result.stdout) if result.returncode==0 else None},sort_keys=True),flush=True)
                except Exception:pass
                raise
            provider=creation.owned_id()
            assert len([p for p,s in mutations if '/containers/create?' in p])==1
            assert len([p for p,s in mutations if p.endswith('/start')])==1
            assert engine.inspect(w.transition)['State']['Paused'] and w.observe_closed()['state']=='CLOSED'
            if sealed_worker:
                run(commands['ip'],'addr','add','192.0.2.53/32','dev','lo')
                from fixtures.m2_admitted_provider_sealed_worker_native import qualify
                node=None
                if registry_node:
                    from fixtures.m2_registry_node_worker_native import attest_and_install
                    node=attest_and_install(phase,auth,registry_setup,boundary,token)
                print(json.dumps(qualify(phase,auth,worker_setup,boundary,run,registry_node=node,
                    legacy_reader_control=legacy_reader_control),sort_keys=True),flush=True)
                if registry_node and not legacy_reader_control:
                    from fixtures.m2_registry_node_worker_native import final_read
                    print(json.dumps(final_read(node,token),sort_keys=True),flush=True)
            else:
                from fixtures.m2_provider_worker_handoff_native import qualify
                print(json.dumps(qualify(phase,root,commands,STATE_ROOT,run,docker_engine=engine),sort_keys=True),flush=True)
            assert len([p for p,s in mutations if p.endswith('/start')])==1
            print(json.dumps({'schema':'ouf.m2-provider-docker-worker-ci.v1','actualDocker29Boundary':True,
                'actualProviderV4AdmissionAndRegistryGate':True,'lostActualStartReplyReconciledWithoutReplay':True,
                'independentControlPeerRootfsSealBeforeCandidateReview':True,'expectedOciFromIndependentCommittedBaseline':True,
                'actualProviderCreateAttempts':1,'actualProviderStartAttempts':1,
                'syntheticImagesReviewAndRegistryAdmissionPredecessor':not registry_node,
                'syntheticImagesAndReview':True,'actualRegistryNodeAndTransport':registry_node,
                'sealedWorkerInstallationProven':sealed_worker and not legacy_reader_control,
                'legacyRecoveryReaderNegativeControl':legacy_reader_control,
                'fullCohortProven':False,'applicationE2EProven':False,'targetApplyAuthorized':False,
                'runtimeAuthorityIssued':False,'releaseAcceptance':False},sort_keys=True),flush=True)
        finally:
            for cid in reversed(ids):run('docker','rm','-f',cid,check=False)
            run('docker','network','rm',network,check=False)
            if table:
                for family in ('inet','bridge'):run(commands['nft'],'delete','table',family,table,check=False)
            if registry_setup:
                for family in ('inet','bridge'):run(commands['nft'],'delete','table',family,'ci_registry_shared',check=False)
            if wrapper_owned:WRAPPER.unlink(missing_ok=True)
            if sealed_worker:run(commands['ip'],'addr','del','192.0.2.53/32','dev','lo',check=False)
            case.doCleanups()
            if token:token.close()

if __name__=='__main__':
    assert sys.argv[1:] in ([],['--sealed-worker'],['--registry-worker'],['--registry-worker','--legacy-recovery-reader-control'])
    main(sealed_worker=bool(sys.argv[1:]),registry_node='--registry-worker' in sys.argv[1:],
        legacy_reader_control='--legacy-recovery-reader-control' in sys.argv[1:])
