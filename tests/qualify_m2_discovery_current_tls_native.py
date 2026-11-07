"""Real namespace switch, TLS/CA/SNI and protected Python; no target or full cohort.

The Registry/selected-owner wrapper is modeled. Primitive sessions enter the
real current namespace and contact only these disposable local TLS servers.
"""
import copy,gc,hashlib,http.server,ipaddress,os,shutil,socketserver,ssl,subprocess,sys,tempfile,threading,unittest,warnings
from pathlib import Path
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_tls as fixtures
from tools.m2_discovery_installation_profile import current_tls as m
from tools.m2_discovery_installation_profile import native_generation_probe as generation


class NativeTls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid()!=0:raise AssertionError('ROOT_NATIVE_TLS_FIXTURE_REQUIRED')
        cls.temp=tempfile.TemporaryDirectory(dir=ROOT,prefix='current-tls-native-');cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name);cls.root.chmod(0o700);cls.openssl,cls.cas,cls.store,_=fixtures.public_fixture(cls.root)
        addresses=subprocess.check_output(['hostname','-I'],timeout=5).decode().split()
        cls.address=next(str(ipaddress.ip_address(v)) for v in addresses if ipaddress.ip_address(v).version==4
            and ipaddress.ip_address(v).is_private and not ipaddress.ip_address(v).is_loopback)
        cls.servers={}
        for role in ('iam','provider'):
            key=cls.root/(role+'-server.key');csr=cls.root/(role+'-server.csr');cert=cls.root/(role+'-server.pem')
            ext=cls.root/(role+'-server.ext');ext.write_text('subjectAltName=DNS:'+role+'.fixture.invalid\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n')
            subprocess.run([cls.openssl,'req','-new','-newkey','ed25519','-nodes','-keyout',str(key),'-out',str(csr),
                '-subj','/CN='+role+'.fixture.invalid'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            subprocess.run([cls.openssl,'x509','-req','-in',str(csr),'-CA',str(cls.root/(role+'.pem')),
                '-CAkey',str(cls.root/(role+'.key')),'-CAcreateserial','-out',str(cert),'-days','2','-extfile',str(ext)],
                check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            key.chmod(0o600);cert.chmod(0o600)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            class Handler(socketserver.BaseRequestHandler):
                def handle(self):
                    self.request.settimeout(2)
                    try:self.request.recv(1)
                    except (OSError,ssl.SSLError):pass
            class Server(socketserver.ThreadingMixIn,socketserver.TCPServer):
                daemon_threads=True
                allow_reuse_address=True
            server=Server(('0.0.0.0',0),Handler);server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=lambda s=server:s.serve_forever(poll_interval=.02),daemon=True);thread.start()
            cls.addClassCleanup(lambda s=server,t=thread:(s.shutdown(),s.server_close(),t.join(timeout=3)))
            cls.servers[role]=(server.server_address[1],hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest())
    def setUp(self):
        self.fd=os.open('/proc/self/ns/net',os.O_RDONLY|os.O_CLOEXEC);self.addCleanup(os.close,self.fd)
        python=Path(sys.executable).resolve()
        self.reader=object.__new__(m.CurrentTlsIdentities)
        self.reader.operational=SimpleNamespace(worker=SimpleNamespace(template={'python':{
            'path':str(python),'sha256':hashlib.sha256(python.read_bytes()).hexdigest(),'maximumBytes':67108864}}))
    def session(self,role='iam',name=None,ca=None):
        return self.reader.session(self.fd,self.address,self.servers[role][0],name or role+'.fixture.invalid',
            self.cas[ca or role],m.ObservationBudget(10))
    def test_real_namespace_tls_session_verifies_current_chain_and_hostname(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always',ResourceWarning);proof=self.session();gc.collect()
        self.assertFalse([w for w in caught if issubclass(w.category,ResourceWarning)])
        self.assertTrue(proof['hostnameAndChainVerified']);self.assertEqual(proof['peerCertificateHash'],self.servers['iam'][1])
        self.assertIn(proof['tlsVersion'],('TLSv1.2','TLSv1.3'))
    def test_real_wrong_hostname_and_wrong_root_have_no_positive_session(self):
        with self.assertRaisesRegex(ValueError,'TLS_IDENTITY_UNPROVEN'):self.session(name='unreviewed.fixture.invalid')
        with self.assertRaisesRegex(ValueError,'TLS_IDENTITY_UNPROVEN'):self.session(ca='provider')
    def test_changed_python_binding_denies_before_namespace_child(self):
        self.reader.operational.worker.template['python']['sha256']='f'*64
        with self.assertRaises(ValueError):self.session()

    def composed(self,mutate=None,worker_failure=False):
        """Actual TLS wrapper/Unix GETs; owner/profile/Java lineage are modeled.

        The namespace and process pins are the actual test process. This does
        not make that process a Registry Java workload or admit a real cohort.
        """
        seen=[];actual={};network='ouf-backend';network_id='d'*64;pid=os.getpid()
        for index,role in enumerate(('iam','provider'),1):
            actual[role]={'Id':format(index+30,'064x'),'Image':'sha256:'+'a'*64,'Config':{},'HostConfig':{},'Mounts':[],
                'NetworkSettings':{'Networks':{network:{'NetworkID':network_id,'IPAddress':self.address}},
                    'Ports':{str(self.servers[role][0])+'/tcp':[{'HostPort':'443'}]}},
                'State':{'Pid':pid,'StartedAt':'fixture-only','Running':True,'Paused':False,'Restarting':False},'RestartCount':0}
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(handler):
                seen.append((handler.command,handler.path))
                if mutate:mutate(len(seen),actual)
                cid=handler.path.split('/')[-2];row=next(v for v in actual.values() if v['Id']==cid)
                raw=m.encoded(row);handler.send_response(200);handler.send_header('Content-Length',str(len(raw)))
                handler.end_headers();handler.wfile.write(raw)
            def log_message(*a):pass
        socket_path=self.root/'engine.sock';server=socketserver.UnixStreamServer(str(socket_path),Handler);socket_path.chmod(0o600)
        thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=.02),daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(timeout=2),socket_path.unlink()))
        info=socket_path.stat();binding=[info.st_dev,info.st_ino,info.st_uid,info.st_gid,0o600]
        engine=m.Engine(str(socket_path),tuple(binding));process=fixtures.cohort.m.process_pin(pid)
        inputs=fixtures.cohort.fixture();inputs['engineBinding']={'socketPath':str(socket_path),'socketBinding':binding,
            'peerCredentials':[pid,0,0],'startTicks':process['startTicks']};inputs['rootProcessPins']['engine']=process
        inputs['peers']['caddy']['runtimeBinding']=m.Engine.runtime_binding(actual['iam'])
        inputs['peers']['caddy']['processPin']=process
        store=self.root/'composed.p12';store.write_bytes(self.store);store.chmod(0o440)
        self.addCleanup(store.unlink)
        f={'source':str(store),'uid':0,'gid':0,'mode':0o440,'maxBytes':1048576,
            'sha256':hashlib.sha256(self.store).hexdigest(),'metadataHash':m.digest(m.attributes(store.lstat()))}
        tls_inputs={k:inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')}
        tls_inputs.update(schema=m.SCHEMA,executionProfileHash='e'*64,trustStoreBindingHash=m.digest(f),
            caFiles={role:{'path':str(self.root/(role+'.pem')),'sha256':hashlib.sha256(raw).hexdigest(),'maximumBytes':1048576}
                for role,raw in self.cas.items()},
            endpoints={role:{'peerRole':'caddy' if role=='iam' else 'provider','network':network,
                'port':self.servers[role][0],'serverName':role+'.fixture.invalid'} for role in ('iam','provider')})
        profile=object.__new__(m.DiscoveryProfile);profile.verify=lambda request:'e'*64
        profile.selection={'files':{'tlsTrustStore':f},'references':{
            'OUF_IAM_ISSUER':'https://iam.fixture.invalid','OUF_SCHEMA_GOV_GATEWAY_BASE_URL':'https://provider.fixture.invalid'}}
        app=SimpleNamespace(profile=profile,request={'HostConfig':{'NetworkMode':network},
            'NetworkingConfig':{'EndpointsConfig':{network:{'NetworkID':network_id}}}})
        selected=SimpleNamespace(installation=SimpleNamespace(application=app))
        held={'state':'READY','nextPhase':12,'version':42}
        def current_held(expected=None):
            self.assertTrue(expected is None or expected==held);return copy.deepcopy(held)
        selected.held=current_held
        runtime=object.__new__(m.CurrentCohortRuntime);runtime.selected=selected
        runtime.inputs=m.bind_tls_inputs(inputs,tls_inputs);runtime.guard=lambda:None
        worker=self.reader.operational.worker
        worker.node=SimpleNamespace(engine=engine,request={});worker.transition=worker.store=None
        worker.verify_generation=Mock()
        provider=actual['provider'];peer={'containerId':provider['Id'],'pid':pid,'startedAt':provider['State']['StartedAt'],
            'startTicks':generation.ticks(pid),'dockerBindingHash':m.digest({k:provider[k] for k in generation.DOCKER_FIELDS})}
        proposal={'configuration':{'verification':{'openssl':{'path':self.openssl,
            'sha256':hashlib.sha256(Path(self.openssl).read_bytes()).hexdigest()}}}}
        operational=object.__new__(m.CurrentOperationalWorker);operational.selected=selected;operational.worker=worker
        operational.guard=lambda:None
        operational.base=SimpleNamespace(material=lambda budget:({},proposal,{'peers':{'provider':peer}},None))
        operational.operational=Mock();operational.observe=Mock(return_value={'currentWorkerAndPositiveOwnedLeasesObserved':True})
        if worker_failure:operational.observe.side_effect=ValueError('CURRENT_OPERATIONAL_WORKER_QUIESCED')
        running={'runtimeBinding':{'pid':pid},'process':{'generation':{'namespaceInode':os.fstat(self.fd).st_ino}}}
        reader=m.CurrentTlsIdentities(runtime,operational,tls_inputs)
        native=patch.object(m,'RunningWorkloadBinding');native.start().return_value.observe.return_value=running;self.addCleanup(native.stop)
        return reader,seen,operational

    @contextmanager
    def namespace_fds_closed(self):
        opened=[];native_open=os.open
        def observed_open(path,*args,**kwargs):
            fd=native_open(path,*args,**kwargs)
            if '/ns/net' in str(path):opened.append(fd)
            return fd
        with patch.object(m.os,'open',side_effect=observed_open):
            try:yield
            finally:
                self.assertEqual(len(opened),1)
                with self.assertRaises(OSError):os.fstat(opened[0])

    def test_composed_wrapper_uses_four_native_gets_and_four_actual_tls_sessions(self):
        reader,seen,operational=self.composed()
        with patch.object(reader,'session',wraps=reader.session) as sessions:
            proof=reader.observe()
        self.assertTrue(proof['currentTlsIdentitiesObserved']);self.assertTrue(proof['reviewedJavaTrustAnchorsObserved'])
        self.assertEqual((len(seen),sessions.call_count,proof['engineGets'],proof['tlsHandshakes']),(4,4,4,4))
        self.assertEqual({v[0] for v in seen},{'GET'});operational.observe.assert_called_once()
        self.assertFalse(proof['workloadCredentialAdmissionProvenHere']);self.assertFalse(proof['fullCohortProven'])

    def test_peer_generation_drift_after_tls_has_no_composed_admission(self):
        def drift(count,actual):
            if count==4:actual['iam']['State']['Paused']=True
        reader,seen,_=self.composed(mutate=drift)
        with patch.object(reader,'session',wraps=reader.session) as sessions,self.namespace_fds_closed():
            with self.assertRaisesRegex(ValueError,'TLS_PEER_RUNNING_GENERATION_REQUIRED'):reader.observe()
        self.assertEqual((len(seen),sessions.call_count),(4,4))

    def test_quiesced_worker_denies_composition_even_after_successful_tls(self):
        reader,seen,_=self.composed(worker_failure=True)
        with patch.object(reader,'session',wraps=reader.session) as sessions,self.namespace_fds_closed():
            with self.assertRaisesRegex(ValueError,'WORKER_QUIESCED'):reader.observe()
        self.assertEqual((len(seen),sessions.call_count),(2,4))

    def test_engine_constructor_denial_occurs_before_namespace_fd_is_opened(self):
        reader,seen,_=self.composed()
        with patch.object(m,'CurrentTlsEngine',side_effect=ValueError('ENGINE_BINDING_DENIED')), \
             patch.object(m.os,'open',wraps=os.open) as opened:
            with self.assertRaisesRegex(ValueError,'ENGINE_BINDING_DENIED'):reader.observe()
        self.assertFalse([c for c in opened.call_args_list if '/ns/net' in str(c)])
        self.assertEqual(seen,[])

if __name__=='__main__':unittest.main()
