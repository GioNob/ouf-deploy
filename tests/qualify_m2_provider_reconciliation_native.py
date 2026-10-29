"""Real Docker negotiated CLI vs1.44, POSIX custody/pins; no target authority."""
import copy,hashlib,json,os,shutil,socket,stat,struct,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from test_m2_provider_reconciliation import stop
from tools.m2_discovery_installation_profile import provider_reconciliation as m


def main():
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    env={**os.environ};env.pop('DOCKER_API_VERSION',None)
    def cli(*args,api=None):
        e={**env}
        if api:e['DOCKER_API_VERSION']=api
        return subprocess.check_output(['docker',*args],env=e,stderr=subprocess.PIPE,text=True,timeout=45).strip()
    assert cli('version','--format','{{.Server.Version}}')=='29.8.1'
    root=Path(tempfile.mkdtemp(prefix='ouf-provider-reconcile-ci-',dir='/var/lib'));root.chmod(0o700);ids=[]
    def write(p,raw,mode=0o600,gid=0):
        p.write_bytes(raw);os.chown(p,0,gid);p.chmod(mode)
    def obj(p,v):write(p,m.encoded(v))
    try:
        cli('pull','alpine:3.22');core={}
        for i in range(13):
            cid=cli('run','-d','--network','none','--user','10001:10001','alpine:3.22','sleep','300')
            ids.append(cid);core['peer-'+str(i)]=json.loads(cli('inspect',cid,api='1.44'))[0]
        cid=cli('run','-d','--network','bridge','--user','10001:10001','alpine:3.22','sleep','300')
        ids.append(cid);modern=json.loads(cli('inspect',cid))[0];legacy=json.loads(cli('inspect',cid,api='1.44'))[0]
        socket_path=Path('/var/run/docker.sock').resolve();s=socket_path.lstat()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.connect(str(socket_path));peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
        assert peer[1]==0
        binding={'socketPath':str(socket_path),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],
                 'peerCredentials':peer}
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        ca=root/'ca.crt';key=root/'synthetic-ca.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),
            '-out',str(ca),'-days','2','-subj','/CN=synthetic-reconciliation-only','-addext','basicConstraints=critical,CA:TRUE'],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
        public_p12=root/'public-fixture.p12'
        subprocess.run(['openssl','pkcs12','-export','-nokeys','-in',str(ca),'-out',str(public_p12),
            '-password','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        public_bytes=public_p12.read_bytes();ca_hash=hashlib.sha256(ca.read_bytes()).hexdigest()
        def fixture(name):
            base=root/name;base.mkdir(mode=0o700)
            old=base/'consumed';old.mkdir(mode=0o700);material_root=base/'materials';material_root.mkdir(mode=0o700)
            manifest_root=base/'manifest';manifest_root.mkdir(mode=0o700)
            manifest={'schema':'ouf.discovery.private-runtime-input-manifest.v1','inputBindings':{'southbound':m.identity(modern)},
                'publicCaHash':ca_hash,'mountsInstalled':False,'applicationCutoverAuthorized':False,'leaseAuthorityGranted':False}
            raw=m.encoded(manifest);write(manifest_root/'private-input-manifest.json',raw);manifest_hash=hashlib.sha256(raw).hexdigest()
            material={'schema':'ouf.m2-discovery-private-material-role-preparation.v1','bootId':boot,
                'currentObservations':core,'processPins':{a:m.process_pin(v['State']['Pid']) for a,v in core.items()},
                'rootProcessPins':{'pid1':m.process_pin(1),'engine':m.process_pin(peer[0])},'engineBinding':binding,
                'projectionPlan':{'materialManifestHash':manifest_hash},
                'preparedCopies':{'publicProviderCa':{'sha256':ca_hash}},
                'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'historicalAuthorityReused':False,
                'automaticReplayAllowed':False,'budgetReset':False}
            material_hash=m.digest(material);material_path=material_root/'prepared-inputs.private.json';obj(material_path,material)
            p=old/'provider-trust.p12';write(p,public_bytes,0o440,10001);store={'path':str(p),'uid':0,'gid':10001,'mode':0o440,
                'sha256':hashlib.sha256(public_bytes).hexdigest(),'metadata':m.attrs(p.lstat())}
            trust={'schema':'ouf.m2-discovery-prepared-public-trust.v1','publicStore':store,
                'proposal':{'materialBinding':{'path':str(material_path),'sha256':material_hash},
                    'iamOwnerConfigurationBinding':{'path':'/fixture/owner/configuration.json','sha256':m.OWNER_HASH},
                    'sha256':store['sha256']},
                'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'targetTlsAdmissionProven':False,'currentOwnerAdmissionProven':False}
            obj(old/'public-trust-inputs.json',trust);obj(old/'result.json',stop())
            obj(old/'context-engine-get-3-claim.json',{'method':'GET','path':'/v1.44/containers/'+cid+'/json','attemptNotCompletion':True})
            obj(old/'context-engine-get-3-response.json',legacy)
            return base,old,dict(stop_scope=old,material_root=material_root,material_hash=material_hash,
                manifest_root=manifest_root,manifest_hash=manifest_hash)
        base,old,args=fixture('representation');before={p:p.read_bytes() for p in base.rglob('*') if p.is_file()}
        c=m.ReconciliationCapture(base/'new');result=m.reconcile(c,**args)
        a=result['analysis']
        assert a['negotiatedApi']!='1.44',a
        # Native facts decide whether both representations actually have the
        # same identity. A schema difference alone is not a configuration change.
        captured_matches=m.identity(legacy)==m.identity(modern)
        assert a['identityChecks']['captured']['completeIdentityMatches']==captured_matches
        assert a['negotiatedApi'] in a['matchingCurrentApis'],a
        assert ('1.44' in a['matchingCurrentApis']) is captured_matches
        assert a['classification']==('HISTORICAL_IDENTITY_MATCHES_CURRENT_VIEW_NO_ADMISSION'
            if captured_matches else 'HISTORICAL_IDENTITY_MATCHES_A_CURRENT_API_REPRESENTATION'),a
        assert c.counts['metadataReads']==6 and c.counts['providerEngineGets']==5
        assert c.counts['recoveredPublicStoreReads']==1
        assert c.counts['credentialFileReads']==c.counts['applicationMacKeyReads']==0
        assert not result['targetApplyAuthorized'] and not a['resumeAllowed']
        assert all(p.read_bytes()==raw for p,raw in before.items())
        sealed={p:p.read_bytes() for p in c.scope.iterdir()}
        try:m.ReconciliationCapture(c.scope);raise AssertionError('consumed replay')
        except ValueError:pass
        assert all(p.read_bytes()==raw for p,raw in sealed.items())
        cli('update','--restart','on-failure:1',cid)
        drift=m.ReconciliationCapture(base/'current-config-drift');changed=m.reconcile(drift,**args)
        assert changed['analysis']['matchingCurrentApis']==[]
        assert changed['analysis']['classification']=='HISTORICAL_PROVIDER_IDENTITY_HAS_NO_CURRENT_VIEW_MATCH'
        assert not changed['analysis']['resumeAllowed'] and all(p.read_bytes()==raw for p,raw in before.items())
        cli('stop','--time','1',cid)
        stopped=m.ReconciliationCapture(base/'current-stopped');stopped_result=m.reconcile(stopped,**args)
        assert stopped_result['analysis']['classification']=='CURRENT_PROVIDER_STATE_BLOCKS_NATIVE_CONTEXT'
        assert not stopped_result['analysis']['resumeAllowed']
        assert all(p.read_bytes()==raw for p,raw in before.items())
        bad,old2,args2=fixture('store-drift');p=old2/'provider-trust.p12';p.write_bytes(p.read_bytes()+b'altered')
        denied=m.ReconciliationCapture(bad/'new')
        try:m.reconcile(denied,**args2);raise AssertionError('altered store accepted')
        except ValueError:pass
        assert denied.counts['providerEngineGets']==0 and not (denied.scope/'reconciliation.private.json').exists()
        bad3,old3,args3=fixture('wrong-stop');v=stop();v['counts']['nativeConfigurationReads']=1;obj(old3/'result.json',v)
        denied3=m.ReconciliationCapture(bad3/'new')
        try:m.reconcile(denied3,**args3);raise AssertionError('different predecessor accepted')
        except ValueError:pass
        assert denied3.counts['providerEngineGets']==0 and denied3.counts['recoveredPublicStoreReads']==0
        print(json.dumps({'schema':'ouf.m2-provider-reconciliation-native-ci.v1',
            'actualDockerVersion':'29.8.1','actualCorePeers':13,'additionalProvider':1,
            'actualNegotiatedApi':a['negotiatedApi'],'cliNegotiatedIdentityMatchesExactHttpView':True,
            'sameProviderCliVs144IdentityMismatchObserved':not captured_matches,'productionCauseProven':False,
            'apiSchemaDifferenceDoesNotImplyIdentityChange':True,'stoppedProviderReportedWithoutRestart':True,
            'fieldDroppingUsed':False,'metadataReads':6,'providerEngineGets':5,'recoveredPublicStoreReads':1,
            'realRestartPolicyDriftDoesNotMatchAnyView':True,'alteredStoreDeniedBeforeEngine':True,
            'otherStopDeniedBeforeEngineOrStoreRead':True,'priorFilesAndPublicStorePreserved':True,
            'sameScopeReplayDenied':True,'fixtureCaAndHistoricalProvenanceAreSynthetic':True,
            'targetExecuted':False,'resumeAllowed':False,'providerAdmissionProven':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'applicationE2EProven':False},sort_keys=True))
    finally:
        for cid in ids:subprocess.run(['docker','rm','-f',cid],env=env,capture_output=True,timeout=20)
        shutil.rmtree(root)

if __name__=='__main__':main()
