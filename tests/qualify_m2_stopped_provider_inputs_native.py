"""Actual Docker core/Registry OCI plus stopped provider, synthetic review metadata."""
import copy,hashlib,json,os,shutil,socket,stat,struct,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from test_m2_stopped_provider_inputs import history
from tools.m2_discovery_installation_profile import stopped_provider_preparation as m


def main():
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    def cli(*args):
        return subprocess.check_output(['docker',*args],text=True,stderr=subprocess.PIPE,timeout=45,
            env={**os.environ,'DOCKER_API_VERSION':'1.44'}).strip()
    assert cli('version','--format','{{.Server.Version}}')=='29.8.1'
    root=Path(tempfile.mkdtemp(prefix='ouf-stopped-provider-ci-',dir='/var/lib'));root.chmod(0o700);ids=[]
    def write(p,raw,mode=0o600,gid=0):
        p.write_bytes(raw);os.chown(p,0,gid);p.chmod(mode)
    def obj(p,v):write(p,m.encoded(v) if hasattr(m,'encoded') else json.dumps(v,sort_keys=True,separators=(',',':')).encode())
    def raw(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    def raw_hash(v):return hashlib.sha256(raw(v)).hexdigest()
    try:
        cli('pull','alpine:3.22');core={}
        roles=['semantic','mcp','apisix','gateway-owner']+['peer-'+str(i) for i in range(9)]
        for role in roles:
            cid=cli('run','-d','--network','bridge' if role=='semantic' else 'none',
                '--user','10001:10001','alpine:3.22','sleep','300')
            ids.append(cid);core['original::'+role]=json.loads(cli('inspect',cid))[0]
        provider_id=cli('run','-d','--network','bridge','--user','636:636','alpine:3.22','sleep','300')
        ids.append(provider_id);running=json.loads(cli('inspect',provider_id))[0]
        cli('stop','--time','1',provider_id);provider=json.loads(cli('inspect',provider_id))[0]
        # Counterexample: stopping changes the combined identity through the
        # runtime network, with the static Docker configuration unchanged.
        static_keys=('Config','HostConfig','Mounts')
        static_unchanged=all(running[k]==provider[k] for k in static_keys)
        runtime_network_changed=running['NetworkSettings']['Networks']!=provider['NetworkSettings']['Networks']
        assert static_unchanged and runtime_network_changed
        selected_socket=Path('/var/run/docker.sock').resolve();st=selected_socket.lstat()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.connect(str(selected_socket));peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
        binding={'socketPath':str(selected_socket),'socketBinding':[st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)],'peerCredentials':peer}
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        # Public certificate-only fixture; the preparation verifies/reuses bytes,
        # while prior public-store Java/TLS qualification remains separate.
        key=root/'synthetic-ca.key';ca=root/'ca.crt';p12=root/'fixture.p12'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(ca),
            '-days','2','-subj','/CN=synthetic-stopped-inputs','-addext','basicConstraints=critical,CA:TRUE'],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
        subprocess.run(['openssl','pkcs12','-export','-nokeys','-in',str(ca),'-out',str(p12),'-password','pass:changeit'],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        public=p12.read_bytes()
        def fixture(name):
            base=root/name;base.mkdir(mode=0o700)
            dirs={k:base/k for k in ('reconciliation','material','trust','history','owner')}
            for p in dirs.values():p.mkdir(mode=0o700)
            role_map={r:'original::'+r for r in roles[:4]}
            material={'schema':'ouf.m2-discovery-private-material-role-preparation.v1','currentObservations':core,
                'processPins':{a:m.process_pin(v['State']['Pid']) for a,v in core.items()},
                'rootProcessPins':{'pid1':m.process_pin(1),'engine':m.process_pin(peer[0])},'engineBinding':binding,
                'bootId':boot,'installationRoleMap':role_map,
                'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'historicalAuthorityReused':False,
                'automaticReplayAllowed':False,'budgetReset':False}
            material_hash=m.digest(material);mp=dirs['material']/'prepared-inputs.private.json';obj(mp,material)
            policy={'schema':'ouf.semantic-deployment-trust-policy.v1','keys':[]}
            policy_path=dirs['owner']/'public-policy.json';obj(policy_path,policy)
            owner={'schema':'ouf.registry-operational-token-configuration.v1',
                'verification':{'trustPolicy':{'path':str(policy_path),'sha256':raw_hash(policy)}}}
            owner_path=dirs['owner']/'configuration.json';obj(owner_path,owner);owner_hash=m.digest(owner)
            p=dirs['trust']/'provider-trust.p12';write(p,public,0o440,10001)
            store={'path':str(p),'sha256':hashlib.sha256(public).hexdigest(),'uid':0,'gid':10001,'mode':0o440,'metadata':m.attrs(p.lstat())}
            trust={'schema':'ouf.m2-discovery-prepared-public-trust.v1','publicStore':store,
                'proposal':{'materialBinding':{'path':str(mp),'sha256':material_hash},
                    'iamOwnerConfigurationBinding':{'path':str(owner_path),'sha256':owner_hash},'sha256':store['sha256']}}
            trust_hash=m.digest(trust);tp=dirs['trust']/'public-trust-inputs.json';obj(tp,trust)
            analysis={'classification':'CURRENT_PROVIDER_STATE_BLOCKS_NATIVE_CONTEXT','providerAdmissionProven':False}
            recon={'schema':'ouf.m2-provider-read-only-reconciliation.v1','analysis':analysis,
                'materialBinding':trust['proposal']['materialBinding'],
                'preservedTrustInputsBinding':{'path':str(tp),'sha256':trust_hash},'preservedPublicStore':store,
                'currentViews':{'1.44':provider},'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
                'automaticReplayAllowed':False,'budgetReset':False}
            recon_hash=m.digest(recon);obj(dirs['reconciliation']/'reconciliation.private.json',recon)
            result={'schema':'ouf.m2-provider-reconciliation-result.v1','status':'READ_ONLY_PROVIDER_RECONCILIATION_COMPLETE',
                'scope':str(dirs['reconciliation']),'complete':True,'scopeConsumed':True,'analysis':analysis,
                'reconciliationHash':recon_hash,'preservedTrustInputsHash':trust_hash,'preservedPublicStoreSha256':store['sha256'],
                'retainedCorePinStates':{'MATCHED':13,'PROCESS_ABSENT':0,'GENERATION_CHANGED':0},
                'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,
                'applicationE2EProven':False,'releaseAcceptance':False}
            obj(dirs['reconciliation']/'result.json',result)
            values,_=history();profile=values['driver']['profile'];profile['containerId']=provider_id
            # Poison old executable references: historical metadata must never
            # invoke its driver or turn its old start flag into current authority.
            values['driver']['runtimeBinding']={'path':'/must-not-execute','sha256':'f'*64}
            catalog={}
            for name,v in values.items():
                p=dirs['history']/(name+'.json');obj(p,v);catalog[name]={'path':str(p),'sha256':raw_hash(v)}
            args=dict(recon_root=dirs['reconciliation'],result_hash=m.digest(result),recon_hash=recon_hash,
                material_root=dirs['material'],material_hash=material_hash,trust_root=dirs['trust'],trust_hash=trust_hash,
                store_hash=store['sha256'],owner_hash=owner_hash,catalog=catalog,
                provider_id=provider_id,provider_image=provider['Image'],profile_hash=m.digest(profile))
            return base,dirs,args
        base,dirs,args=fixture('positive')
        before={p:p.read_bytes() for p in base.rglob('*') if p.is_file()}
        c=m.StoppedProviderPreparation(base/'new');result=m.prepare(c,**args)
        assert result['counts']['metadataReads']==11 and result['counts']['engineGets']==27
        assert result['counts']['contextEngineGets']==5 and result['counts']['nativeConfigurationReads']==1
        assert result['counts']['recoveredPublicStoreReads']==1 and result['providerNativeContextsObserved']==0
        assert not result['stoppedProviderUsedAsLivePeer'] and not result['oldDriverMayExecute']
        assert result['newPublicStoresPrepared']==0 and not result['targetApplyAuthorized']
        assert all(p.read_bytes()==v for p,v in before.items())
        private=m.decode((c.scope/'installation-inputs.private.json').read_bytes())
        assert private['currentStoppedProvider']['State']['Running'] is False
        assert private['historicalRecords']['driver']['profile']['applicationStartAuthorized'] is True
        assert private['oldDriverMayExecute'] is False and private['historicalAuthorityReused'] is False
        assert private['currentRegistryNativeContext']['networkNamespaceIdentity']==m.process_pin(core['original::semantic']['State']['Pid'])['namespaces']['net']
        sealed={p:p.read_bytes() for p in c.scope.iterdir()}
        try:m.StoppedProviderPreparation(c.scope);raise AssertionError('replayed scope')
        except ValueError:pass
        assert all(p.read_bytes()==v for p,v in sealed.items())
        bad,bd,ba=fixture('changed-source')
        p=Path(ba['catalog']['launch']['path']);p.write_bytes(p.read_bytes()+b'\n')
        denied=m.StoppedProviderPreparation(bad/'new')
        try:m.prepare(denied,**ba);raise AssertionError('unbound historical source accepted')
        except ValueError:pass
        assert denied.counts['engineGets']==0 and denied.counts['nativeConfigurationReads']==0
        bad2,bd2,ba2=fixture('changed-store')
        p=bd2['trust']/'provider-trust.p12';p.write_bytes(p.read_bytes()+b'changed')
        denied2=m.StoppedProviderPreparation(bad2/'new')
        try:m.prepare(denied2,**ba2);raise AssertionError('changed store accepted')
        except ValueError:pass
        assert denied2.counts['engineGets']==0
        cli('start',provider_id)
        live=m.StoppedProviderPreparation(base/'unexpectedly-running')
        try:m.prepare(live,**args);raise AssertionError('running provider adopted through stopped contract')
        except ValueError:pass
        assert live.counts['nativeConfigurationReads']==0 and not (live.scope/'installation-inputs.private.json').exists()
        assert all(p.read_bytes()==v for p,v in before.items())
        print(json.dumps({'schema':'ouf.m2-stopped-provider-inputs-native-ci.v1','actualDockerVersion':'29.8.1',
            'actualCorePeers':13,'additionalProvider':1,'providerStoppedIsInputNotLivePeer':True,
            'staticDockerFieldsUnchangedOnStop':static_unchanged,'runtimeNetworkChangedOnStop':runtime_network_changed,
            'registryNativeOciAndNamespaceObserved':True,'providerOciOrNamespaceFabricated':False,
            'oldHistoricalStartFlagAndExecutableNotReused':True,'metadataReads':11,'engineGets':27,'contextEngineGets':5,
            'newPublicStoresPrepared':0,'oldFilesAndPublicStorePreserved':True,'replayDenied':True,
            'changedHistoricalSourceDeniedBeforeEngine':True,'changedStoreDeniedBeforeEngine':True,
            'unexpectedRunningProviderDeniedBeforeRegistryOci':True,
            'historicalContractsAndCaAreSynthetic':True,'productionStaticDriftCauseProven':False,
            'targetExecuted':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'applicationE2EProven':False},sort_keys=True))
    finally:
        for cid in ids:subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=20)
        shutil.rmtree(root)

if __name__=='__main__':main()
