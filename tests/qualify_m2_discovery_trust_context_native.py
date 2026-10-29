"""Real Docker29.8.1/root filesystem/kernel context; synthetic CA/provenance only."""
import copy,hashlib,json,os,socket,stat,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from test_m2_discovery_trust_preparation import PublicTrustPreparation
from tools.m2_discovery_installation_profile import trust_preparation as trust
from tools.m2_discovery_installation_profile import native_context as native


def main():
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    def cli(*args):return subprocess.check_output(['docker',*args],text=True,stderr=subprocess.PIPE,timeout=45,
        env={**os.environ,'DOCKER_API_VERSION':'1.44'}).strip()
    assert cli('version','--format','{{.Server.Version}}')=='29.8.1'
    PublicTrustPreparation.setUpClass();ids=[]
    try:
        f=PublicTrustPreparation();base,material,owner,args,_=f.fixture('real-context')
        cli('pull','alpine:3.22')
        core=material['currentObservations'];issuer=owner['ownerInputs']['iamProfile']['issuer']
        endpoint=owner['ownerInputs']['iamProfile']['token_endpoint']
        for alias in sorted(core):
            cid=cli('run','-d','--network','bridge','--user','10001:10001',
                '-e','OUF_IAM_ISSUER='+issuer,'-e','OUF_SCHEMA_GOV_TOKEN_ENDPOINT='+endpoint,
                'alpine:3.22','sleep','240')
            ids.append(cid);core[alias]=json.loads(cli('inspect',cid))[0]
        provider_id=cli('run','-d','--network','bridge','--user','10001:10001','alpine:3.22','sleep','240')
        ids.append(provider_id);provider=json.loads(cli('inspect',provider_id))[0]
        socket_path=Path('/var/run/docker.sock').resolve();s=socket_path.lstat()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.connect(str(socket_path));peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
        assert peer[1]==0
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();args['boot_path'].write_text(boot)
        material.update(selectedInstallationObservations={r:core[a] for r,a in material['installationRoleMap'].items()},
            bootId=boot,processPins={a:trust.process_pin(r['State']['Pid']) for a,r in core.items()},
            rootProcessPins={'pid1':trust.process_pin(1),'engine':trust.process_pin(peer[0])},
            engineBinding={'socketPath':str(socket_path),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],
                          'peerCredentials':peer})
        source=base/'provider-material';source.mkdir(mode=0o700)
        manifest={'schema':'ouf.discovery.private-runtime-input-manifest.v1',
            'inputBindings':{'southbound':native.provider_identity(provider)},
            'publicCaHash':material['preparedCopies']['publicProviderCa']['sha256'],
            'mountsInstalled':False,'applicationCutoverAuthorized':False,'leaseAuthorityGranted':False}
        raw=native.encoded(manifest);manifest_path=source/'private-input-manifest.json'
        manifest_path.write_bytes(raw);manifest_path.chmod(0o600);manifest_hash=hashlib.sha256(raw).hexdigest()
        material['projectionPlan']['materialManifestHash']=manifest_hash
        material_path=args['material_root']/'prepared-inputs.private.json'
        material_path.write_bytes(native.encoded(material));args['material_hash']=native.digest(material)
        args.update(pin=trust.process_pin,engine_factory=trust.ReadOnlyEngine)
        before={p:p.read_bytes() for p in base.rglob('*') if p.is_file()}
        c=trust.TrustPreparation(base/'native-positive');prepared=trust.prepare(c,**args)
        reread=native.decode(c.read(material_path,0,0,0o600,2097152,'metadataReads'))
        assert native.digest(reread)==args['material_hash']
        result=native.collect(c,material=reread,trust_result=prepared,material_root=source,
            manifest_hash=manifest_hash,pin=trust.process_pin,boot_path=args['boot_path'])
        assert result['currentPeerCount']==14 and result['nativeNodesObserved']==2
        assert c.counts['engineGets']==27 and c.counts['contextEngineGets']==5
        assert c.counts['nativeConfigurationReads']==2 and c.counts['metadataReads']==5
        assert c.counts['credentialFileReads']==c.counts['applicationMacKeyReads']==0
        record=native.decode((c.scope/'native-context.private.json').read_bytes())
        assert set(record['nativeNodes'])=={'semantic','provider'}
        for row in record['nativeNodes'].values():
            spec=native.decode(Path(row['configurationPath']).read_bytes())
            assert spec==row['oci'] and Path(row['rootfsPath']).is_dir()
            assert row['networkNamespaceIdentity']==trust.process_pin(row['runtimeBinding']['pid'])['namespaces']['net']
        assert all(p.read_bytes()==raw for p,raw in before.items())
        positive={p:p.read_bytes() for p in c.scope.iterdir()}
        try:trust.TrustPreparation(c.scope);raise AssertionError('replayed')
        except ValueError:pass
        assert all(p.read_bytes()==raw for p,raw in positive.items())
        cli('stop','--time','1',provider_id)
        denied=trust.TrustPreparation(base/'native-provider-stopped');prepared2=trust.prepare(denied,**args)
        try:
            native.collect(denied,material=material,trust_result=prepared2,material_root=source,
                manifest_hash=manifest_hash,pin=trust.process_pin,boot_path=args['boot_path'])
            raise AssertionError('stopped provider accepted')
        except ValueError:pass
        assert not (denied.scope/'native-context.private.json').exists()
        assert (denied.scope/'provider-trust.p12').exists()
        assert all(p.read_bytes()==raw for p,raw in positive.items())
        print(json.dumps({'schema':'ouf.m2-discovery-trust-and-native-context-ci.v1',
            'actualDisposableCorePeers':13,'additionalProviderPeer':1,'rootUnixEngineAndKernelPinsObserved':True,
            'engineGets':27,'contextEngineGets':5,'nativeOciConfigurationsObserved':2,'metadataReads':5,
            'publicStoreRootGroupModeVerified':True,'applicationCredentialsAndKeysRead':0,
            'sourceFilesAndPositiveEvidencePreserved':True,'consumedScopeReplayDenied':True,
            'stoppedProviderRefusedWithPartialPublicStorePreserved':True,
            'syntheticCaAndHistoricalProvenance':True,'targetExecuted':False,'targetTlsAdmissionProven':False,
            'iamRequests':0,'oauthRequests':0,'sqlSessions':0,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'applicationE2EProven':False},sort_keys=True))
    finally:
        for cid in ids:subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=20)
        PublicTrustPreparation.tearDownClass()

if __name__=='__main__':main()
