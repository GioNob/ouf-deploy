"""Exact original signed V11 image: pre-Java gate and same-PID Java release.
No real DB, provider, transport authority, target or CSV acceptance.
"""
import copy,hashlib,importlib.util,json,os,shutil,stat,subprocess,sys,tempfile,time,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
sys.path.insert(0,str(ROOT/'tools/semantic_cohort_admission/cohort-draft'))
import tools
tools.__path__.append(str(ROOT/'tools'))
from tools.semantic_policy_token_owner.producer import DomainOwner
from six_mount_frame_observation import SixMountFrameObservation
class TokenFixtureOwner(DomainOwner):
    # Synthetic current IAM/source authority; never installed on the VPS.
    def guard(self,binding_hash):pass
    def prepare(self,binding_hash,deadline):pass
    def pause(self):pass
    def admit(self,token,*args):return token=='synthetic-token-only'
TOKEN_OWNER=TokenFixtureOwner()
TOKEN_POLICY=None
from engine_creation import Engine
from creation_adapter import CreationAdapter
from gated_stage_adapter import GatedStageAdapter
from gated_release_adapter import GatedReleaseAdapter
from gated_process_observation import GatedProcessObservation
from gated_creation_plan import compile_gate,PROFILE
from native_evidence_store import NativeEvidenceStore
from executor_composition_fixture import compose
from cutover_executor import CutoverDenied
from transition_journal import digest
from paused_workload_binding import PausedWorkloadBinding
from tools.semantic_provider_node_observation import rootfs_seal
from tools.semantic_provider_deployment_authentication import VerificationBudget,decode
from tools.semantic_provider_preexec_native import NativeBackend
from tools.semantic_provider_deployment_admission import application_hash
from configtree_mount_observation import ConfigtreeMountObservation
from projected_frame_observation import ProjectedFrameObservation
from paused_attestation_adapter import PausedAttestationAdapter
from paused_node_acceptance import PausedNodeAcceptance
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
import test_cutover_authority_native as signed_fixture
from paused_node_observation import PausedNodeObservation
from tools.semantic_provider_deployment_admission import transport_hash
import image_custody as custody
import image_manifest_identity as identity

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
verify=load('gated_v11_package','scripts/verify-durable-v11-package.py')
private_plan=load('gated_private_plan','scripts/prepare-gated-v11-private-plan.py')

def command(args,timeout=120):
    p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if p.returncode or len(p.stdout)>2097152:raise ValueError('GATED_V11_NATIVE_OPERATION_UNPROVEN')
    return p.stdout

def file_hash(path,limit=536870912):
    h=hashlib.sha256();size=0
    with Path(path).open('rb') as stream:
        while block:=stream.read(1048576):
            size+=len(block)
            if size>limit:raise ValueError('GATED_V11_FILE_UNBOUNDED')
            h.update(block)
    return h.hexdigest()

def paused_filesystem(e,engine,store,socket,request,configtree,sources,fixture_root,peer,attestation_holder):
    """Native read-only seal; never construct an approval from observed OCI.

    No independent target policy is supplied by this fixture. This qualifies
    streaming/stability on original image bytes, not owner acceptance.
    """
    row=e.t.read()
    with e.t.invocation():
        e.t.begin('ATTEST_NEW_OCI_PEER',e.intent_hashes['ATTEST_NEW_OCI_PEER'],e.authority_hash,row['version'])
    binding=PausedWorkloadBinding(engine,e.t,request,store);before=binding.observe()
    cid=before['runtimeBinding']['containerId'];pid=before['runtimeBinding']['pid']
    binary=str(Path(shutil.which('runc')).resolve());state=None
    roots=(socket.parent/'exec/runtime-runc/moby',Path('/run/docker/runtime-runc/moby'),Path('/run/containerd/runc/moby'))
    for runtime_root in roots:
        result=subprocess.run([binary,'--root',str(runtime_root),'state',cid],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
        if result.returncode==0:
            state=decode(result.stdout,16384);break
    if state is None:raise ValueError('ORIGINAL_V11_PAUSED_RUNC_STATE_UNPROVEN')
    binding.verify_runc_state(state,before)
    bundle=Path(state['bundle'])
    # The isolated Engine may use the host containerd task parent. Never widen
    # to /run: only this exact random fixture CID under closed task parents.
    task_parents=(socket.parent/'exec/docker/containerd/daemon/io.containerd.runtime.v2.task/moby',
                  Path('/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby'),
                  Path('/run/containerd/io.containerd.runtime.v2.task/moby'))
    assert bundle.is_absolute() and bundle.name==cid and (bundle.is_relative_to(socket.parent) or bundle.parent in task_parents), 'EXACT_FIXTURE_CONTAINERD_BUNDLE_PARENT_REQUIRED'
    config=bundle/'config.json';raw=config.read_bytes();oci=decode(raw,131072)
    root=Path(oci['root']['path']);root=root if root.is_absolute() else bundle/root
    assert '..' not in root.parts and (root==bundle/'rootfs' or root.is_relative_to(socket.parent)), 'EXACT_FIXTURE_ROOTFS_PARENT_REQUIRED'
    generation=NativeBackend.generation(None,pid)
    limits={'maxEntries':100000,'maxBytes':8589934592,'maxDepth':64}
    first=rootfs_seal(root,limits,VerificationBudget(18))
    second=rootfs_seal(root,limits,VerificationBudget(18))
    assert first==second and first['entries']>100 and first['bytes']>1000000
    assert config.read_bytes()==raw and NativeBackend.generation(None,pid)==generation
    assert binding.observe()==before
    directory=ConfigtreeMountObservation(configtree,VerificationBudget(18)).observe(generation)
    # This fixture's expected OCI is synthetic, never target policy approval.
    # The production observer has no observed-OCI-to-policy generation API.
    projected=fixture_root/'projected';projected.mkdir(mode=0o700)
    owner=projected/'owner.py';owner.write_bytes((ROOT/'tools/semantic_frame_compiler/frame-observer.py').read_bytes());owner.chmod(0o600)
    mounts=[{k:s[k] for k in ('source','target','readOnly')} for s in sources]+[{k:configtree[k] for k in ('source','target','readOnly')}]+[{k:TOKEN_POLICY[k] for k in ('source','target')}|{'readOnly':True}]
    process=oci['process'];policy={'schema':'ouf.semantic-configured-six-mount-frame-policy.v1','expectedOci':copy.deepcopy(oci),
            'manifest':{'user':'10001:10001','readOnlyRoot':False,'memoryBytes':2147483648,'pidsLimit':512,'mounts':mounts},
            'startup':{'uid':10001,'gid':10001,'umask':process['user'].get('umask'),'cwd':process['cwd'],'args':process['args'],'env':process['env']},
            'approvedHooks':oci.get('hooks') or {},'sources':sources,'configtree':configtree,'renewableToken':TOKEN_POLICY,'delegationKeyTarget':sources[3]['target']}
    policy_path=projected/'policy.json';policy_path.write_text(json.dumps(policy,sort_keys=True,separators=(',',':')));policy_path.chmod(0o600)
    bindings={'source':{'path':str(owner),'sha256':file_hash(owner)},'configuration':{'path':str(policy_path),'sha256':file_hash(policy_path)},'bundleParents':[str(bundle.parent)]}
    frame_hash,_=SixMountFrameObservation(bindings,VerificationBudget(18),TOKEN_OWNER,binding).observe(generation,config,application_hash(oci),file_hash(policy_path))
    result=subprocess.run([binary,'--root',str(runtime_root),'state',peer['containerId']],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
    assert result.returncode==0;peer_state=decode(result.stdout,16384);assert peer_state['status']=='running'
    peer_oci=decode((Path(peer_state['bundle'])/'config.json').read_bytes(),131072)
    commands={name:{'path':str(Path(shutil.which(name)).resolve()),'sha256':file_hash(Path(shutil.which(name)).resolve())} for name in ('ip','nsenter')}
    app_binding={'interface':'eth0','bridge':peer['bridge'],'mac':peer['appMac'],'ipv4':peer['appIp'],'workloadRef':'fixtureSemantic','bindingRef':'fixtureSemanticFace'}
    peer_binding={'interface':'eth0','bridge':peer['bridge'],'mac':peer['mac'],'ipv4':peer['ip'],'workloadRef':'fixturePeer','bindingRef':'fixturePeerFace'}
    transport=[{'purpose':'WORKLOAD_GATEWAY','authorityRef':'SYNTHETIC_FIXTURE_ONLY','source':peer['appIp'],'destination':peer['ip'],'protocol':'tcp','port':8443,
                'peerIngress':{'kind':'CREATED_CANDIDATE','declaration':{'containerId':peer['containerId'],'applicationHash':application_hash(peer_oci),'networkBindings':[peer_binding]},'bindingRef':'fixturePeerFace'}}]
    cfg={'runtimeBinding':{'path':binary,'sha256':file_hash(binary)},'runtimeRootParents':[str(Path(runtime_root).parent)],'bundleParents':[str(bundle.parent)],'commands':commands,
         'candidate':{'networkBindings':[app_binding],'transport':transport,'tableName':'fixtureV11'},'rootfsLimits':limits}
    observed_request={'containerId':cid,'generation':generation,'applicationHash':application_hash(oci),'artifactHash':file_hash(policy_path),'transportHash':transport_hash(cfg['candidate']),'transactionId':e.t.context}
    context={'schema':'ouf.semantic-paused-node-context.v1',**{k:before[k] for k in ('transitionContextHash','creationRequestHash','stageEvidenceHash')},'runtimeRoot':str(runtime_root),'bundleHash':application_hash(oci)}
    budget=VerificationBudget(18);observer=PausedNodeObservation(cfg,budget,binding,SixMountFrameObservation(bindings,budget,TOKEN_OWNER,binding))
    complete=observer.observe(observed_request,context,observer.frame.bundle)
    assert complete['rootfsSeal']==first and len(complete['peerObservations'])==1 and complete['completeCreationAccepted'] is False
    wrong_cfg=copy.deepcopy(cfg);wrong_cfg['candidate']['transport'][0]['peerIngress']['declaration']['applicationHash']='f'*64
    wrong_request={**observed_request,'transportHash':transport_hash(wrong_cfg['candidate'])}
    budget=VerificationBudget(18);wrong=PausedNodeObservation(wrong_cfg,budget,binding,SixMountFrameObservation(bindings,budget,TOKEN_OWNER,binding))
    try:wrong.observe(wrong_request,context,wrong.frame.bundle)
    except ValueError:pass
    else:raise AssertionError('RECIPROCAL_PEER_OCI_DRIFT_ACCEPTED')
    assert binding.observe()==before and e.t.read()['nextPhase']==6
    old=Path(sources[0]['source']).read_bytes();Path(sources[0]['source']).write_bytes(b'changed-source')
    try:
        try:SixMountFrameObservation(bindings,VerificationBudget(18),TOKEN_OWNER,binding).observe(generation,config,application_hash(oci),file_hash(policy_path))
        except ValueError:pass
        else:raise AssertionError('PROJECTED_FILE_HASH_DRIFT_ACCEPTED')
    finally:Path(sources[0]['source']).write_bytes(old)
    secret=Path(configtree['source'])/configtree['fileName'];original=secret.read_bytes()
    secret.write_bytes(b'changed-fixture')
    try:
        try:ConfigtreeMountObservation(configtree,VerificationBudget(18)).observe(generation)
        except ValueError:pass
        else:raise AssertionError('CONFIGTREE_HASH_DRIFT_ACCEPTED')
    finally:secret.write_bytes(original)
    extra=Path(configtree['source'])/'UNAPPROVED';extra.write_bytes(b'extra')
    try:
        try:ConfigtreeMountObservation(configtree,VerificationBudget(18)).observe(generation)
        except ValueError:pass
        else:raise AssertionError('CONFIGTREE_EXTRA_FILE_ACCEPTED')
    finally:extra.unlink()
    os.chmod(configtree['source'],0o700)
    try:
        try:ConfigtreeMountObservation(configtree,VerificationBudget(18)).observe(generation)
        except ValueError:pass
        else:raise AssertionError('CONFIGTREE_PERMISSION_DRIFT_ACCEPTED')
    finally:os.chmod(configtree['source'],0o500)
    assert ConfigtreeMountObservation(configtree,VerificationBudget(18)).observe(generation)['sameSourceFileInMountedView']
    # Actual scoped Ed25519 over actual native observation, with a disposable
    # synthetic owner/authority. Never target approval or target key issuance.
    signed=signed_fixture.SignedCutover();signed.setUp();attestation_holder['cleanup']=signed.doCleanups
    trust=json.loads(signed.policy.read_bytes());key=trust['keys'][1];key['publicKey']=signed.grant['publicKey']
    signed.write(signed.policy,signed_fixture.encoded(trust));signed.verifier.policy_binding=signed.binding(signed.policy)
    authority_context={k:signed.context[k] for k in ('installationRef','entityRef','attestorRef')}
    expected={**{k:e.intents['ATTEST_NEW_OCI_PEER'][k] for k in ('creationRequestHash','sourceClosureHash','qualifiedPackageHash','imageConfigurationHash')},
              'transitionContextHash':e.t.context,'phaseIntentHash':e.intent_hashes['ATTEST_NEW_OCI_PEER'],
              **{k:observed_request[k] for k in ('artifactHash','applicationHash','transportHash')}}
    payload={'schema':'ouf.semantic-paused-node-acceptance-authorization.v1','issuerRef':authority_context['attestorRef'],
             'installationRef':authority_context['installationRef'],'entityRef':authority_context['entityRef'],**expected,
             'containerId':cid,'generationBinding':'OBSERVED_PAUSED_GATED','rootfsSeal':complete['rootfsSeal'],'issuedAt':signed.now,
             'expiresAt':signed.now+180,'state':'ACTIVE','attestationAuthorized':True,'completeCreationAccepted':True}
    authorization=signed_fixture.encoded(payload);signer=ExistingEd25519Signer(signed.binding(signed.key),key['keyRef'],signed.verifier,
                           {'role':'CREATION_ATTESTATION','issuerRef':authority_context['attestorRef'],'installationRef':authority_context['installationRef'],'entityRef':authority_context['entityRef']})
    signature=signer.sign(authorization);authorization_path=signed.root/'paused-acceptance.json';signed.write(authorization_path,authorization)
    signed.write(signed.signatures/(hashlib.sha256(authorization).hexdigest()+'.CREATION_ATTESTATION.json'),signature)
    budget=VerificationBudget(18);native_observer=PausedNodeObservation(cfg,budget,binding,SixMountFrameObservation(bindings,budget,TOKEN_OWNER,binding))
    acceptance=PausedNodeAcceptance(signed.verifier,authority_context,expected)
    attestation_holder['adapter']=PausedAttestationAdapter(e.t,e.intents['ATTEST_NEW_OCI_PEER'],store,native_observer,acceptance,observed_request,context,signed.binding(authorization_path))
    e.run(7);e.run(7)
    assert e.t.read()['nextPhase']==7 and len([v for v in e.t.read()['effects'] if v['phase']=='ATTEST_NEW_OCI_PEER' and v['state']=='APPLIED'])==1
    result={'rootfsSeal':first,'observedCompleteOciHash':application_hash(oci),'stableDoubleRootfsSeal':True,
            'actualPausedRuncContract':True,'independentOciPolicyAccepted':False,'reciprocalPeersVerified':True,
            'singletonConfigtreeObservation':directory,'configtreeHashExtraFileAndPermissionDriftRejected':True,
            'actualSixProjectedInputFrameObserved':True,'requestBindCount':4,'requestStructuredMountCount':2,'tokenOwnerAdmissionSynthetic':True,'projectedFrameHash':frame_hash,'projectedFileHashDriftRejected':True,
            'fixtureExpectedOciDerivedFromObservedOci':True,'completePausedNodeObservationHash':digest(complete),
            'reciprocalPeerOciDriftRejected':True,'unsignedObservationDidNotAdvanceAttestationPhase':True,
            'actualScopedPausedAcceptanceFixtureVerified':True,'signedAttestationPhaseCompletedOnce':True,
            'fixturePausedAcceptanceSignaturesIssued':1,'targetSignaturesIssued':0}
    return result

class Fixture:
    def __init__(self):self.cleanups=[]
    def addCleanup(self,fn):self.cleanups.append(fn)
    def close(self):
        for fn in reversed(self.cleanups):fn()

def main():
    global TOKEN_POLICY
    assert os.geteuid()==0
    spec=verify.SPECS['semantic'];verified=verify.verify(ROOT/'semantic.zip','semantic');fixture=Fixture()
    exact_configuration=private_plan.image_configuration(ROOT/'semantic.zip')
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        root=Path(directory);root.chmod(0o700)
        with zipfile.ZipFile(ROOT/'semantic.zip') as archive:
            for name in ('image.docker.tar','source.tar','source-inventory.json','application.jar','package-record.json','migration-continuity.json','trivy-image.json','Dockerfile.resolved','provenance.json'):
                rows=[i for i in archive.infolist() if Path(i.filename).name==name];assert len(rows)==1
                with archive.open(rows[0]) as src,(root/name).open('xb') as dst:shutil.copyfileobj(src,dst,1048576)
        for name in ('image.docker.tar','source.tar','source-inventory.json','application.jar','package-record.json','migration-continuity.json','trivy-image.json','Dockerfile.resolved'):
            command(['gh','attestation','verify',str(root/name),'--repo','GioNob/ouf-semantic-registry','--signer-workflow','GioNob/ouf-semantic-registry/.github/workflows/discovery-durable-candidate.yml','--source-digest','3ec99277b8383e496913b9fd3bb05c877825abf5','--source-ref','refs/heads/codex/discovery-durable-resilience-20261011','--deny-self-hosted-runners','--bundle',str(root/'provenance.json'),'--format','json'])
        expected=verified['memberSha256']['image.docker.tar']
        with (root/'image.docker.tar').open('rb') as stream:audit=custody.archive(stream,expected,spec['image'],spec['source'])
        with tempfile.TemporaryFile() as envelope:
            with (root/'image.docker.tar').open('rb') as src:record=custody.tagless_archive(src,envelope,audit)
            envelope.seek(0);audit=custody.archive(envelope,record['derivedArchiveSha256'],spec['image'],spec['source']);descriptor=identity.descriptor(envelope,audit)
            assert descriptor['digest']=='sha256:bd48ab35db0441b1f4f48422e7190adaff176a61cddde5f981d93e496ad4b24a'
            envelope.seek(0);socket=Path(os.environ['OUF_CUSTODY_SOCKET']);s=socket.stat();engine=Engine(str(socket),(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
            status,version=engine.request('GET','/version');assert status==200 and version['Version']=='29.8.1','EXACT_TARGET_VERSION_FIXTURE_ENGINE_REQUIRED'
            p=subprocess.run(['docker','--host','unix://'+str(socket),'image','load'],stdin=envelope,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120);assert p.returncode==0
        status,image=engine.request('GET','/v1.48/images/'+descriptor['digest']+'/json?manifests=true');assert status==200
        image_proof=identity.loaded(audit,descriptor,image)
        assert exact_configuration['config']==audit['imageConfig']
        network_name='ouf-v11-fixture';bridge='ov11cif'
        status,network=engine.request('POST','/v1.48/networks/create',{'Name':network_name,'Driver':'bridge','Internal':True,'EnableIPv6':False,
                            'Options':{'com.docker.network.bridge.name':bridge},'IPAM':{'Driver':'default','Config':[{'Subnet':'172.29.42.0/24'}]}});assert status==201
        network_id=network['Id'];peer_ip='172.29.42.2';peer_mac='02:42:ac:1d:2a:02';app_ip='172.29.42.6';app_mac='02:42:ac:1d:2a:06'
        peer_request={'Image':descriptor['digest'],'User':'10001:10001','Entrypoint':['/bin/sh','-c','exec sleep 600'],
                      'HostConfig':{'NetworkMode':network_name,'Runtime':'runc','RestartPolicy':{'Name':'no','MaximumRetryCount':0},'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],'Memory':268435456,'MemorySwap':268435456,'PidsLimit':128},
                      'NetworkingConfig':{'EndpointsConfig':{network_name:{'NetworkID':network_id,'IPAMConfig':{'IPv4Address':peer_ip},'MacAddress':peer_mac}}}}
        status,native_peer=engine.request('POST','/v1.48/containers/create',peer_request);assert status==201
        peer_id=native_peer['Id'];fixture.addCleanup(lambda:engine.request('DELETE','/v1.48/networks/'+network_id));fixture.addCleanup(lambda:engine.request('DELETE','/v1.48/containers/'+peer_id+'?force=true'))
        status,_=engine.request('POST','/v1.48/containers/'+peer_id+'/start');assert status==204
        peer={'containerId':peer_id,'ip':peer_ip,'mac':peer_mac,'bridge':bridge,'appIp':app_ip,'appMac':app_mac}
        private_directory=root/'private-configtree';private_directory.mkdir(mode=0o500);os.chown(private_directory,10001,10001)
        secret=private_directory/'OUF_SEM_DB_PASSWORD';secret.write_bytes(b'synthetic-fixture-only');os.chown(secret,10001,10001);secret.chmod(0o400)
        configtree={'source':str(private_directory),'target':'/run/ouf-configtree','readOnly':True,'uid':10001,'gid':10001,
                    'directoryMode':0o500,'fileName':secret.name,'fileMode':0o400,'maxBytes':4096,'sha256':file_hash(secret)}
        sources=[]
        for name in ('tls-certificate','tls-key','mac-policy'):
            source=root/name;source.write_bytes(b'synthetic-fixture-only');os.chown(source,10001,10001);source.chmod(0o400)
            sources.append({'source':str(source),'target':'/run/ouf-'+name,'readOnly':True,'uid':10001,'gid':10001,'mode':0o400,'maxBytes':4096,'sha256':file_hash(source)})
        key=root/'static-delegation-key';key.write_bytes(b'synthetic-static-key-only');os.chown(key,10001,10001);key.chmod(0o400)
        sources.append({'source':str(key),'target':'/run/static-delegation-key','readOnly':True,'uid':10001,'gid':10001,'mode':0o400,'maxBytes':4096,'sha256':file_hash(key)})
        token_directory=root/'renewable-token';token_directory.mkdir(mode=0o750);os.chown(token_directory,0,10001)
        token=token_directory/'token.jwt';token.write_bytes(b'synthetic-token-only');os.chown(token,0,10001);token.chmod(0o440)
        info=token_directory.stat()
        TOKEN_POLICY={'source':str(token_directory),'target':'/run/renewable-token','fileName':token.name,'gid':10001,
            'directoryDevice':info.st_dev,'directoryInode':info.st_ino,'ownerBindingHash':'a'*64,'maxBytes':16384,'minimumRemainingSeconds':30}
        parent={'Image':descriptor['digest'],'User':'10001:10001','Env':list(audit['imageConfig'].get('Env') or [])+['OUF_SEM_DB_URL=jdbc:postgresql://127.0.0.1:1/fixture_only','OUF_SEM_DB_USER=fixture','OUF_SEM_DB_PASSWORD=fixture','OUF_DISCOVERY_WORKER_ENABLED=false','OUF_SCHEMA_GOV_ENABLED=false'],
                'HostConfig':{'Runtime':'runc','Privileged':False,'NetworkMode':network_name,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Memory':2147483648,'MemorySwap':2147483648,'NanoCpus':2000000000,'PidsLimit':512,
                              'Binds':[s['source']+':'+s['target']+':ro' for s in sources[:3]]+[str(private_directory)+':/run/ouf-configtree:ro'],
                              'Mounts':[{'Type':'bind','Source':str(token_directory),'Target':'/run/renewable-token','ReadOnly':True},{'Type':'bind','Source':str(key),'Target':'/run/static-delegation-key','ReadOnly':True}]},
                'NetworkingConfig':{'EndpointsConfig':{network_name:{'NetworkID':network_id,'IPAMConfig':{'IPv4Address':app_ip},'MacAddress':app_mac}}}}
        request,proposal=compile_gate(parent,digest(parent),{'config':audit['imageConfig']});process=GatedProcessObservation(request)
        before=root/'before';before.mkdir(mode=0o700);before_store=NativeEvidenceStore(before)
        intent={'creationRequestHash':digest(request),'priorEvidencePhase':'STAGE_PAUSED_REPLACEMENT','preApplicationGateProfile':PROFILE}
        attestation_holder={};attest_intent={'creationRequestHash':digest(request),'sourceClosureHash':'e'*64,
                          'qualifiedPackageHash':spec['zipSha256'],'imageConfigurationHash':digest(audit['imageConfig']),'nodeRecipeHash':'f'*64}
        e,store=compose(fixture,'START_REPLACEMENT',intent,lambda t,s:GatedReleaseAdapter(engine,t,request,s,before_store,process,lambda point:None),additional={
            'CREATE_REPLACEMENT':(request,lambda t,s:CreationAdapter(engine,t,request,s)),
            'STAGE_PAUSED_REPLACEMENT':({'creationRequestHash':digest(request),'priorEvidencePhase':'CREATE_REPLACEMENT'},lambda t,s:GatedStageAdapter(engine,t,request,s,process,lambda point:None)),
            'ATTEST_NEW_OCI_PEER':(attest_intent,lambda t,s:type('SyntheticLateOwnerFixture',(),{'apply':lambda self,i:attestation_holder['adapter'].apply(i),'observe':lambda self,i:attestation_holder['adapter'].observe(i)})())},creation_request=request)
        cid=None
        try:
            e.run(6);native=engine.inspect(e.t);cid=native['Id'];pid=native['State']['Pid'];gate=process.observe(pid)
            assert gate['processKind']=='GATE_WAITING' and native['Image']==descriptor['digest']
            jar_before=file_hash('/proc/'+str(pid)+'/root/app/application.jar');assert jar_before==verified['memberSha256']['application.jar']
            java_before=file_hash('/proc/'+str(pid)+'/root/opt/java/openjdk/bin/java');assert process.observe(pid)==gate
            filesystem=paused_filesystem(e,engine,store,socket,request,configtree,sources,root,peer,attestation_holder)
            deadline=time.monotonic()+5
            while True:
                try:e.run(11);break
                except CutoverDenied:
                    assert e.t.read()['state']=='IN_FLIGHT' and time.monotonic()<deadline
                    time.sleep(.05)
            java=process.observe(pid);assert java['processKind']=='APPLICATION_RUNNING' and java['generation']==gate['generation']
            assert file_hash('/proc/'+str(pid)+'/exe')==java_before
            receipt={'schema':'ouf.native-six-mount-original-v11-execution.v1','status':'ORIGINAL_V11_WAIT_GATE_AND_SAME_PID_JAVA_EXEC_OBSERVED','sourceCommit':spec['source'],'originalZipSha256':spec['zipSha256'],'nativeManifestImageId':descriptor['digest'],'signedSubjectsVerified':8,'layersVerified':len(audit['layers']),'actualApplicationJarMatchesPublishedBytes':True,'actualJavaLauncherUnchanged':True,'javaNotExecutedBeforeRelease':True,'actualSameGenerationJavaExec':True,'capabilitiesEmpty':True,'noNewPrivileges':True,'imageRebuilt':False,'fixtureImageImports':1,'targetImageImports':0,'authorityAndOtherPhasesSynthetic':True,'databaseMigrationTested':False,'completeOciRootfsPeerAcceptanceProven':False,'providerCalls':0,'applicationReadyProven':False,'targetApplied':False,'notReleaseAcceptance':True}
            receipt.update(filesystem)
            receipt['qualifiedEngineVersion']=version['Version']
            print('OUF_SIX_MOUNT_ORIGINAL_V11='+json.dumps(receipt,sort_keys=True));(ROOT/'native-six-mount-v11-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        finally:
            if 'cleanup' in attestation_holder:attestation_holder['cleanup']()
            if cid is not None:engine.request('DELETE','/v1.44/containers/'+cid+'?force=true')
            fixture.close()

if __name__=='__main__':main()

