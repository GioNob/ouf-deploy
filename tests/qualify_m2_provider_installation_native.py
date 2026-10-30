"""Real runc v4 admission/gate/nft/wrapper/signers; modeled Docker boundary.

Disposable synthetic independent frames/rootfs and ephemeral review keys only.
Docker29 creation is separately qualified. This fixture makes no target or
full application/cohort claim and never calls the synthetic admission writer.
"""
import copy,hashlib,json,os,shutil,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_transaction_profiles')]
import test_m2_provider_profiles as fixtures
import test_m2_discovery_lease_installation_template as workers
from test_m2_provider_installation_template import inputs
from tools.m2_discovery_installation_profile import provider_runtime_installation as runtime
from tools.m2_discovery_installation_profile import provider_installation_phase as sequence
from tools.m2_discovery_installation_profile.native_generation_probe import ticks
from tools.semantic_provider_node_observation import rootfs_seal
from tools.semantic_provider_deployment_authentication import VerificationBudget
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_lease_nft import structure_hash
from gated_process_observation import GatedProcessObservation

def run(*args,raw=None,check=True):
    # A created init inherits its stdio before exec. Files keep the runc
    # control operation bounded even while that init remains alive.
    with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
        process=subprocess.run(list(args),input=raw,stdout=out,stderr=err,timeout=45)
        out.seek(0);err.seek(0)
        p=subprocess.CompletedProcess(args,process.returncode,out.read(2097153),err.read(2097153))
    assert len(p.stdout)<=2097152 and len(p.stderr)<=2097152
    if check and p.returncode:raise RuntimeError('CI_NATIVE_COMMAND_FAILED:'+Path(args[0]).name+':'+p.stderr.decode()[-1600:])
    return p
def pin(path):
    p=Path(path).resolve();return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
def private(path,raw,mode=0o600):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode)
def rootfs(path):
    for name in ('bin','usr/bin','etc','proc','app','run','dev','dev/pts','dev/shm','dev/mqueue','sys','sys/fs/cgroup'):
        (path/name).mkdir(parents=True,exist_ok=True)
    shutil.copyfile(shutil.which('busybox'),path/'bin/busybox');(path/'bin/busybox').chmod(0o755)
    for name in ('sh','sleep'):(path/'bin'/name).symlink_to('busybox')
    for name in ('etc/hosts','etc/hostname','etc/resolv.conf','approved-source'):(path/name).touch()
    path.chmod(0o755)
def attach(commands,root,cid,host,child,mac,ipv4):
    state=json.loads(run(commands['runc'],'--root',str(root),'state',cid).stdout);pid=state['pid']
    run(commands['nsenter'],'--net=/proc/'+str(pid)+'/ns/net',commands['sysctl'],'-q','-w',
        'net.ipv6.conf.all.disable_ipv6=1','net.ipv6.conf.default.disable_ipv6=1')
    run(commands['ip'],'link','add',host,'type','veth','peer','name',child)
    run(commands['ip'],'link','set',host,'master','brfixture');run(commands['ip'],'link','set',host,'up')
    run(commands['ip'],'link','set',child,'netns',str(pid))
    def childrun(*args):return run(commands['nsenter'],'--net=/proc/'+str(pid)+'/ns/net',commands['ip'],*args)
    childrun('link','set',child,'name','eth0');childrun('link','set','eth0','address',mac)
    childrun('addr','add',ipv4+'/24','dev','eth0');childrun('link','set','eth0','up');childrun('link','set','lo','up')
    return state

def main():
    assert os.geteuid()==os.getegid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    assert Path('/proc/self/ns/net').stat().st_ino!=Path('/proc/1/ns/net').stat().st_ino
    commands={k:str(Path(shutil.which(k)).resolve()) for k in ('runc','nft','ip','nsenter','unshare','mount','umount','sysctl')}
    case=fixtures.Profiles();auth=None;wrapper=None;state_root=None;created=[];table=None
    with tempfile.TemporaryDirectory(prefix='ouf-provider-native-',dir='/var/lib') as tmp:
        root=Path(tmp);root.chmod(0o700);provider_id='9'*64;registry_id='f'*64
        state_parent=root/'runc';state_parent.mkdir(mode=0o700);state_root=state_parent/'state';state_root.mkdir(mode=0o700)
        run(commands['ip'],'link','add','brfixture','type','bridge');run(commands['ip'],'link','set','brfixture','up')
        try:
            # Independently author the Registry gate's full runc frame before
            # create, preserving its exact DiscoveryProfile seven roles/argv.
            request,selection,t,l,c=copy.deepcopy(fixtures.registry_fixture())
            baseline=inputs()['frame_template']['expectedOci']
            t['expectedOci'].update(ociVersion='1.3.0')
            t['expectedOci']['linux']['namespaces']=copy.deepcopy(baseline['linux']['namespaces'])
            defaults=[copy.deepcopy(v) for v in baseline['mounts'] if v['type']!='bind']
            t['expectedOci']['mounts']=defaults+t['expectedOci']['mounts']
            for role,item in selection['files'].items():
                old=item['source'];p=root/('registry-'+role);private(p,('CI_SYNTHETIC_'+role).encode(),item['mode']);os.chown(p,item['uid'],item['gid'])
                item['source']=str(p)
                for mount in t['expectedOci']['mounts']:
                    if mount.get('source')==old:mount['source']=str(p)
                for collection in (l['sources'],l['manifest']['mounts']):
                    for v in collection:
                        if v['source']==old:v['source']=str(p)
                for mount in request['HostConfig']['Mounts']:
                    if mount['Source']==old:mount['Source']=str(p)
            for key in ('configtree','renewable_token'):
                old=selection[key]['source'];p=root/('registry-'+key);p.mkdir(mode=0o750)
                selection[key]['source']=str(p)
                for mount in t['expectedOci']['mounts']:
                    if mount.get('source')==old:mount['source']=str(p)
                for v in l['manifest']['mounts']:
                    if v['source']==old:v['source']=str(p)
                for mount in request['HostConfig']['Mounts']:
                    if mount['Source']==old:mount['Source']=str(p)
            c.update(bundleParent=str(root/'registry-bundles'),metadataParent=str(root/'registry-storage/containers'),
                storageParent=str(root/'registry-storage'),networkNamespaceParent=str(root/'registry-netns'))
            definition=(request,selection,t,l,c)
            # Provider rootfs and all source bytes are fixed before the modeled
            # Docker create. Expected OCI is independently compiled, never read
            # from a task to construct its own policy.
            opts=inputs();opts['runtime_binding']=pin(commands['runc'])
            opts['docker_context_template'].update(bundleParent=str(root/'provider-bundles'),
                metadataParent=str(root/'provider-storage/containers'),storageParent=str(root/'provider-storage'),
                networkNamespaceParent=str(root/'provider-netns'))
            pfs=root/'provider-bundles'/provider_id/'rootfs';rootfs(pfs)
            source=root/'provider-source';private(source,b'CI_INDEPENDENT_PROVIDER_SOURCE');os.chown(source,636,636)
            old=opts['launch']['sources'][0]['source'];opts['launch']['sources'][0].update(source=str(source),sha256=pin(source)['sha256'])
            opts['launch']['manifest']['mounts'][0]['source']=str(source);opts['request']['HostConfig']['Mounts'][0]['Source']=str(source)
            for mount in opts['frame_template']['expectedOci']['mounts']:
                if mount.get('source')==old:mount['source']=str(source)
            opts['frame_template']['expectedOci']['process'].pop('apparmorProfile',None)
            opts['expected_rootfs_seal']=rootfs_seal(pfs,{'maxEntries':10000,'maxBytes':16777216,'maxDepth':32},VerificationBudget(10))
            old,w,auth,provider,calls,options,sources=case.fixture(definition=definition,provider_inputs=opts,
                rootfs_limits={'maxEntries':10000,'maxBytes':16777216,'maxDepth':32})
            prep=options['preparer_template'];prep.update(commands={k:commands[k] for k in prep['commands']},
                commandHashes={k:pin(commands[k])['sha256'] for k in prep['commands']},hostNetworkNamespace=runtime.host_namespace())
            options['registry_recipe']['runtimeRoot']=str(state_root)
            cfg=options['runtime_configuration'];cfg['runtimeStateRoot']=str(state_parent)
            auth.write(Path(options['runtime_configuration_binding']['path']),runtime.encoded(cfg))
            options['runtime_configuration_binding']=auth.binding(Path(options['runtime_configuration_binding']['path']))
            options['runtime_root_parents']=[str(state_parent)];options['rootfs_limits']['maxBytes']=16777216
            kernel=prep['kernel'];table=kernel['tableName']='ci_provider_lease'
            run(commands['nft'],'-f','-',raw=materialize(kernel,empty_provider_sets=True)['nftRules'].encode())
            tables={family:json.loads(run(commands['nft'],'-j','list','table',family,table).stdout) for family in ('inet','bridge')}
            prep['coordinationBinding']['leaseStructureHash']=structure_hash(tables)
            auth.write(Path(prep['lockFile']),b'');auth.write(Path(prep['coordinationJournal']),runtime.encoded({
                'schema':'ouf.semantic-lease-coordination.v1',**prep['coordinationBinding'],'state':'QUIESCED',
                'leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[]]}))
            ps=fixtures.m.profile_scope(old.template,old.creation.scope,**options)
            co,recipe,snapshot,py,wo=workers.Template().fixture();wo.update(source_closure_hash=old.template['sourceClosureHash'],signing_key_paths=[str(auth.key)])
            wo['expected_images']['provider']=old.template['expectedImageId'];wo['expected_node_profiles']['provider']=fixtures.m.templates.expected_node_profile(old.template)
            co['verification']['context']={k:auth.context[k] for k in ('installationRef','entityRef','attestorRef')}
            lease=workers.m.template(co,recipe,py,**wo)
            from tools.m2_discovery_installation_profile.provider_materialized_admission import admission_scope
            adm=admission_scope(lease,old.template,old.creation.scope,ps)
            wrapper=Path('/usr/local/sbin/ouf-provider-native-'+root.name)
            private(wrapper,runtime.wrapper_bytes(ps['pythonBinding']['path'],ps['sourceRoot'],ps['priorRuntimeConfigurationBinding']['path']),0o755)
            rs=runtime.runtime_scope(ps,wrapper_binding=auth.binding(wrapper),common_lock_identity=list(runtime.custody(prep['lockFile'],0o600)[1]))
            seqroot=auth.root/'sequence';seqroot.mkdir(mode=0o700)
            component={'schema':'ouf.discovery-composed-provider-installation-scope.v2','creation':old.creation.scope,'installation':rs,'admission':adm,
                'sequence':sequence.provider_sequence_scope(old.creation.scope,rs,adm,journal_directory=seqroot)}
            auth.review['components']['providerInstallation']=component;parent=auth.fixture();w.parent=parent;w.parent_hash=parent.sha
            creation=runtime.ProviderCreation(parent=parent,window=w,template=old.template,journal_directory=old.creation.root,installation_component=component)
            issuer=runtime.ProviderInitialIssuer(creation=creation,scope=ps,signers=old.signers)
            pub=runtime.ProviderProfilePublication(issuer);reader=runtime.MaterializedProviderAdmission(publication=pub,lease_template=lease)
            backend=runtime.NftBackend([commands['nft']],kernel,prep['coordinationBinding']['leaseStructureHash'],5)
            journal=runtime.PrivateJournal(Path(prep['coordinationJournal']))
            coord=runtime.Coordinator(runtime.LeaseOwner(kernel,prep['dns'],backend),prep['coordinationBinding'],
                lambda:runtime.hold_common_lock(Path(prep['lockFile'])),journal.read,journal.write)
            owner=runtime.ProviderRuntimeInstallation(publication=pub,admission=reader,scope=rs,coordinator=coord)
            # Actual Registry runc gate and reciprocal bridge NIC.
            rcontext=copy.deepcopy(ps['registryRecipe']['dockerContext']);rcontext.pop('rootfsLayout')
            rcontext.update(containerId=registry_id,networkNamespaceName=None,
                rootfsPath=rcontext['storageParent']+'/rootfs/overlayfs/'+registry_id)
            rpolicy=fixtures.m.registry_policy(t,l,rcontext,execution_profile=w.profile);rfs=Path(rcontext['rootfsPath']);rootfs(rfs)
            for mnt in rpolicy['expectedOci']['mounts']:
                target=rfs/mnt['destination'].lstrip('/')
                if mnt['type']=='bind':
                    src=Path(mnt['source'])
                    if not src.exists():private(src,b'CI_ENGINE_METADATA',0o644)
                    if src.is_dir():target.mkdir(parents=True,exist_ok=True)
                    else:target.parent.mkdir(parents=True,exist_ok=True);target.touch(exist_ok=True)
            rbundle=Path(rcontext['bundleParent'])/registry_id;private(rbundle/'config.json',runtime.encoded(rpolicy['expectedOci']))
            created.append(registry_id);run(commands['runc'],'--systemd-cgroup','--root',str(state_root),'create','--bundle',str(rbundle),registry_id)
            peer=old.template['transportTemplate'][0]['peerIngress']['declaration']['networkBindings'][0]
            attach(commands,state_root,registry_id,'ci_rhost','ci_rchild',peer['mac'],peer['ipv4'])
            run(commands['runc'],'--root',str(state_root),'start',registry_id)
            gate=GatedProcessObservation(w.request);pid=json.loads(run(commands['runc'],'--root',str(state_root),'state',registry_id).stdout)['pid']
            deadline=time.monotonic()+5
            while gate.observe(pid)['processKind']!='GATE_WAITING':assert time.monotonic()<deadline;time.sleep(.05)
            run(commands['runc'],'--root',str(state_root),'pause',registry_id)
            native_calls=[];fake=creation.engine.request
            def registry_native():
                state=json.loads(run(commands['runc'],'--root',str(state_root),'state',registry_id).stdout)
                return {'Id':registry_id,'Name':'/'+__import__('engine_creation').Engine.name(w.transition),
                    'Image':w.request['Image'],'Config':{k:v for k,v in w.request.items() if k not in ('HostConfig','NetworkingConfig')},
                    'HostConfig':w.request['HostConfig'],'Mounts':[], 'NetworkSettings':{},'RestartCount':0,
                    'State':{'Pid':state['pid'],'Running':state['status'] in ('paused','running'),'Paused':state['status']=='paused',
                        'Restarting':False,'StartedAt':'2026-10-30T00:00:00Z'}}
            creation.engine.inspect=lambda _:registry_native()
            creation.engine.runtime_binding=__import__('engine_creation').Engine.runtime_binding
            import types
            creation.engine.matching_configuration=types.MethodType(__import__('engine_creation').Engine.matching_configuration,creation.engine)
            w.process=gate
            actual=registry_native();hash_=w.store.publish('STAGE_PAUSED_REPLACEMENT',actual)
            row=w.transition.read();row['effects'][-1]['nativeEvidenceHash']=runtime.digest(actual);w.transition.read=lambda:copy.deepcopy(row)
            def dispatch(method,path,body=None):
                if path=='/v1.44/info':return 200,{'ServerVersion':'29.8.1','Driver':'overlayfs','CgroupDriver':'systemd',
                    'Runtimes':{old.template['creationRequest']['HostConfig']['Runtime']:{'path':str(wrapper),'runtimeArgs':[]}}}
                if method=='POST' and path.endswith(('/pause','/unpause')):
                    native_calls.append(path);run(commands['runc'],'--root',str(state_root),'pause' if path.endswith('/pause') else 'resume',registry_id);return 204,None
                if method=='POST' and path.endswith('/start'):
                    native_calls.append(path);material=pub.material();bundle=root/'provider-bundles'/provider_id
                    for mnt in material['materialized']['framePolicy']['expectedOci']['mounts']:
                        if mnt['type']=='bind' and not Path(mnt['source']).exists():private(Path(mnt['source']),b'CI_METADATA',0o644)
                    private(bundle/'config.json',runtime.encoded(material['materialized']['framePolicy']['expectedOci']))
                    created.append(provider_id);run(str(wrapper),'--systemd-cgroup','--root',str(state_root),'create','--bundle',str(bundle),provider_id)
                    own=old.template['networkBindings'][0];attach(commands,state_root,provider_id,'ci_phost','ci_pchild',own['mac'],own['ipv4'])
                    run(str(wrapper),'--systemd-cgroup','--root',str(state_root),'start',provider_id)
                    state=json.loads(run(commands['runc'],'--root',str(state_root),'state',provider_id).stdout)
                    provider['native']['State'].update(Status='running',Running=True,Pid=state['pid'])
                    raise TimeoutError('CI_LOST_SUCCESSFUL_NATIVE_PROVIDER_START_REPLY')
                return fake(method,path,body)
            creation.engine.request=dispatch
            phase=sequence.ProviderInstallationPhase(owner);phase.apply();outcome,proof=phase.observe();assert outcome=='APPLIED'
            assert w.observe_closed()['state']=='CLOSED' and gate.observe(pid)['processKind']=='GATE_WAITING'
            assert json.loads(run(commands['runc'],'--root',str(state_root),'state',provider_id).stdout)['status']=='running'
            assert sum(p.endswith('/start') for p in native_calls)==1
            assert runtime.private_json(Path(pub.material()['root'])/'attestation.json')['schema']=='ouf.semantic-created-candidate-attestation.v2'
            print(json.dumps({'schema':'ouf.m2-provider-installation-native-ci.v1','realV4NodeBrokerInstallerAdmission':True,
                'realIndependentFullOciRootfsAndNativeNicObserved':True,'realRegistryGateClosedBeforeReturn':True,
                'realNftAndCommonLock':True,'realWrapperCasAndEd25519':True,'lostNativeStartReplyReconciledWithoutReplay':True,
                'modeledDockerProviderCreateStartBoundary':True,'syntheticImagesReviewAndPredecessors':True,
                'fullCohortProven':False,'applicationE2EProven':False,'targetApplyAuthorized':False,'runtimeAuthorityIssued':False},sort_keys=True))
        finally:
            if state_root:
                for cid in reversed(created):
                    run(commands['runc'],'--root',str(state_root),'resume',cid,check=False)
                    run(commands['runc'],'--root',str(state_root),'kill',cid,'KILL',check=False)
                    run(commands['runc'],'--root',str(state_root),'delete','--force',cid,check=False)
            if wrapper:wrapper.unlink(missing_ok=True)
            if table:
                run(commands['nft'],'delete','table','inet',table,check=False);run(commands['nft'],'delete','table','bridge',table,check=False)
            case.doCleanups()

if __name__=='__main__':main()
