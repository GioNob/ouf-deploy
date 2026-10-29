"""Disposable Docker29 native frame/files/configtree test; no owner admission.

The runtime image and private inputs are synthetic. Java never executes. The
independent committed Engine baseline supplies expected OCI, not the live OCI.
"""
import hashlib,http.client,json,os,shutil,socket,struct,subprocess,sys,tempfile,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from test_m2_discovery_native_profile import fixture
from tools.m2_discovery_installation_profile.native_profile import DiscoveryProfile,FILE_ROLES,digest,ENTRY,JAVA
from tools.m2_discovery_installation_profile.frame_inputs import compile_inputs,ENGINE
from tools.m2_discovery_installation_profile.frame import compile_policy
from projected_frame_observation import ProjectedFrameObservation
from configtree_mount_observation import ConfigtreeMountObservation
from tools.m2_discovery_installation_profile.node_owner import ObservationBudget
from tools.semantic_provider_deployment_authentication import attributes

def run(*args):
    return subprocess.check_output(args,stderr=subprocess.PIPE,timeout=120).decode().strip()

def main(package_directory=None, output=None):
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    info=json.loads(run('docker','info','--format','{{json .}}'))
    assert info['ServerVersion']=='29.8.1' and info['Driver']=='overlayfs' and info['CgroupDriver']=='systemd'
    task=Path(tempfile.mkdtemp(prefix='discovery-native-',dir='/var/lib'));task.chmod(0o700)
    cid=None; network='ouf-disc-'+uuid.uuid4().hex[:12];tag='ouf-discovery-frame-fixture:'+uuid.uuid4().hex
    try:
        if package_directory is None:
            run('docker','pull','alpine:3.22');base=json.loads(run('docker','image','inspect','alpine:3.22'))[0]['RepoDigests']
            assert len(base)==1 and '@sha256:' in base[0]
            (task/'Dockerfile').write_text('FROM '+base[0]+'\nRUN addgroup -S -g 10001 ouf && adduser -S -D -H -u 10001 -G ouf ouf\nUSER 10001:10001\nWORKDIR /app\n')
            run('docker','build','-t',tag,str(task));image=json.loads(run('docker','image','inspect',tag))[0]['Id']
        else:
            package_directory=Path(package_directory)
            assert package_directory.is_absolute() and output is not None
            record_raw=(package_directory/'package-record.json').read_bytes();record=json.loads(record_raw)
            assert hashlib.sha256(record_raw).hexdigest()=='fb49890ba3f99bd40aeb51b8aa87ff941177f1cb8d7a433e15cfe8b3ba0dedbb'
            image='sha256:a0bc481df9735abb60b5a6d085a6b7d84ae76c53ae31db84ad5859ff6a46518e'
            assert record['imageId']==image and record['sourceCommit']=='4f8fb581916075a539bda4428be7bd8af073a569'
            assert record['runtimeUser']=='10001:10001' and record['targetApplyAuthorized'] is False
            archive=package_directory/'image.docker.tar'
            assert hashlib.sha256(archive.read_bytes()).hexdigest()=='4457a59574c06ec47ce686a40fb017e4cb3fe31bd12a62d8a5644d9d3d4f7d8c'
            run('docker','load','--input',str(archive))
            native_image=json.loads(run('docker','image','inspect',image))[0]
            assert native_image['Id']==image and native_image['Config']['User']=='10001:10001'
            assert native_image['Config']['Entrypoint']==JAVA and native_image['Config'].get('Cmd') in (None,[])
        network_id=run('docker','network','create',network)
        request,selection,*_=fixture();request['Image']=image
        if package_directory is not None:
            from tools.m2_discovery_installation_profile.native_profile import FILE_ENV
            targets=dict(zip(FILE_ROLES,('/run/ouf/delegation.key','/run/ouf/proposal.key',
                '/run/secrets/schema-gov-client-secret','/run/secrets/semantic-discovery-owner.key','/run/ouf/provider-trust.p12')))
            values=dict(row.split('=',1) for row in request['Env'])
            preserved=dict(row.split('=',1) for row in selection['preserved_environment'])
            for row in native_image['Config'].get('Env',[]):
                key,value=row.split('=',1);values[key]=value;preserved[key]=value
            for role,target in targets.items():
                selection['files'][role]['target']=target
                if role in FILE_ENV:values[FILE_ENV[role]]=target
            values['JAVA_TOOL_OPTIONS']='-Djavax.net.ssl.trustStore='+targets['tlsTrustStore']+' -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit'
            selection['configtree']['target']='/run/ouf/database'
            selection['renewable_token']['target']='/run/ouf/policy'
            values['SPRING_CONFIG_IMPORT']='configtree:/run/ouf/database/'
            values['OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE']='/run/ouf/policy/token'
            request['Env']=[k+'='+v for k,v in values.items()]
            selection['preserved_environment']=[k+'='+v for k,v in preserved.items()]
        request['HostConfig']['NetworkMode']=network
        request['NetworkingConfig']={'EndpointsConfig':{network:{'NetworkID':network_id}}}
        for role,f in selection['files'].items():
            p=task/role;p.write_bytes(('synthetic-'+role).encode());os.chown(p,f['uid'],f['gid']);p.chmod(f['mode'])
            f.update(source=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),metadataHash=digest(attributes(p.lstat())))
        tree=selection['configtree'];db=task/'database';db.mkdir(mode=0o500);os.chown(db,10001,10001)
        password=db/tree['fileName'];password.write_bytes(b'CI_SYNTHETIC_NOT_A_TARGET_PASSWORD');os.chown(password,10001,10001);password.chmod(0o400)
        tree.update(source=str(db),sha256=hashlib.sha256(password.read_bytes()).hexdigest())
        token=selection['renewable_token'];td=task/'policy';td.mkdir(mode=0o750);os.chown(td,0,10001)
        (td/token['fileName']).write_text('CI_NO_RUNTIME_AUTHORITY');os.chown(td/token['fileName'],0,10001);(td/token['fileName']).chmod(0o440)
        token.update(source=str(td),directoryDevice=td.stat().st_dev,directoryInode=td.stat().st_ino)
        binds=[{k:selection['files'][role][k] for k in ('source','target','readOnly')} for role in FILE_ROLES]
        binds += [{k:tree[k] for k in ('source','target','readOnly')},{'source':token['source'],'target':token['target'],'readOnly':True}]
        request['HostConfig']['Mounts']=[{'Type':'bind','Source':b['source'],'Target':b['target'],'ReadOnly':True} for b in binds]
        profile=DiscoveryProfile(request,**selection)
        # Exercise the actual JSON Engine contract. CLI flag processing can
        # reorder environment entries and is not the production create API.
        class UnixConnection(http.client.HTTPConnection):
            def connect(self):
                self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(15)
                self.sock.connect('/var/run/docker.sock')
                peer=struct.unpack('3i',self.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                assert peer[1]==0
        connection=UnixConnection('localhost',timeout=15)
        try:
            connection.request('POST','/v1.44/containers/create',body=json.dumps(request).encode(),headers={'Content-Type':'application/json'})
            response=connection.getresponse();body=response.read(2097153);assert response.status==201 and len(body)<=2097152
            cid=json.loads(body)['Id']
        finally:connection.close()
        run('docker','start',cid);run('docker','pause',cid)
        actual=json.loads(run('docker','inspect',cid))[0];pid=actual['State']['Pid']
        assert actual['Config']['Env']==request['Env']
        assert actual['State']['Paused'] and actual['RestartCount']==0 and actual['Image']==image
        cmdline=(Path('/proc')/str(pid)/'cmdline').read_bytes();assert cmdline==b'\0'.join(x.encode() for x in ENTRY+JAVA)+b'\0'
        state=json.loads(run('runc','--root','/run/docker/runtime-runc/moby','state',cid))
        parents=('/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby','/run/containerd/io.containerd.runtime.v2.task/moby')
        matches=[p for p in parents if state['bundle']==p+'/'+cid];assert len(matches)==1
        storage=info['DockerRootDir'];assert storage=='/var/lib/ouf-docker-29'
        context={'schema':'ouf.semantic-docker-frame-context.v1','containerId':cid,'bundleParent':matches[0],
            'metadataParent':storage+'/containers','networkNamespaceParent':'/run/docker/netns',
            'networkNamespaceName':None,'cgroupDriver':'systemd','storageParent':storage,'rootfsPath':storage+'/rootfs/overlayfs/'+cid}
        baseline=(ROOT/'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes()
        template,launch=compile_inputs(baseline,request,execution_profile=profile,engine_profile=ENGINE)
        policy=compile_policy(template,launch,context,execution_profile=profile)
        owner=task/'owner.py';owner.write_bytes((ROOT/'tools/semantic_frame_compiler/frame-observer.py').read_bytes());owner.chmod(0o600)
        policy_path=task/'policy.json';policy_path.write_text(json.dumps(policy));policy_path.chmod(0o600)
        cfg={name:{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for name,p in [('source',owner),('configuration',policy_path)]}
        cfg['bundleParents']=list(parents);budget=ObservationBudget(120);observer=ProjectedFrameObservation(cfg,budget)
        modules,schema=observer.owner(owner.read_bytes());bundle=json.loads(observer.bundle(Path(state['bundle'])/'config.json'))
        (task/'expected-oci.json').write_text(json.dumps(policy['expectedOci'],indent=2));(task/'actual-oci.json').write_text(json.dumps(bundle,indent=2))
        modules['review_semantic_oci_policy'].configured_profile(bundle,policy['expectedOci'],policy['manifest'],policy['startup'],policy['approvedHooks'],schema)
        current=modules['observe_semantic_mount_view'].generation(pid,budget)
        modules['observe_semantic_creation_frame'].source_mount_frame(pid,current,bundle,policy['sources'],budget)
        generation={'pid':pid,'startTicks':current['startTicks'],'namespaceInode':current['networkNamespaceInode']}
        ConfigtreeMountObservation(tree,budget).observe(generation)
        assert json.loads(run('docker','inspect',cid))[0]['State']==actual['State']
        assert (Path('/proc')/str(pid)/'cmdline').read_bytes()==cmdline
        result={'schema':'ouf.m2-discovery-native-frame-ci.v1','engine':ENGINE,'fullIndependentOciMatched':True,
            'fiveNativeReadonlyFilesObserved':True,'databaseConfigtreeNativeObserved':True,'javaStarted':False,
            'syntheticImageAndPrivateInputs':True,'tokenOwnerAdmissionProven':False,'providerTlsOrIamProven':False,
            'signaturesIssued':0,'targetAcceptance':False,'applicationE2EProven':False}
        if package_directory is not None:
            from tools.semantic_provider_node_observation import rootfs_seal
            limits={'maxEntries':100000,'maxBytes':8589934592,'maxDepth':64}
            seal=rootfs_seal(Path(context['rootfsPath']),limits,ObservationBudget(180))
            assert json.loads(run('docker','inspect',cid))[0]['State']==actual['State']
            assert (Path('/proc')/str(pid)/'cmdline').read_bytes()==cmdline
            result.update(schema='ouf.m2-discovery-registry-image-rootfs-ci.v1',
                imageId=image,sourceCommit=record['sourceCommit'],packageRecordHash=hashlib.sha256(record_raw).hexdigest(),
                rootfsSeal=seal,limits=limits,mountTargets=[b['target'] for b in binds],
                exactCandidateImageUsed=True,syntheticImageAndPrivateInputs=False,syntheticPrivateInputs=True,
                derivation='DOCKER29_CONTAINERD_OVERLAYFS_PAUSED_FULL_DISCOVERY_GATE',
                runtimeAuthorityIssued=False,nativePublisherTrustAccepted=False,targetApplyAuthorized=False,
                rootfsSealHasExclusions=False,targetMountSelectionApproved=False)
            with Path(output).open('x') as stream:stream.write(json.dumps(result,indent=2)+'\n')
        (task/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
    finally:
        if cid:subprocess.run(['docker','rm','--force',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
        subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
        print('CI_EVIDENCE_DIRECTORY='+str(task))

if __name__=='__main__':main()
