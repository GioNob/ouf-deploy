"""Real namespace switch, TLS/CA/SNI and protected Python; no target or full cohort.

The Registry/selected-owner wrapper is modeled. Primitive sessions enter the
real current namespace and contact only these disposable local TLS servers.
"""
import gc,hashlib,ipaddress,os,shutil,socketserver,ssl,subprocess,sys,tempfile,threading,unittest,warnings
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_tls as fixtures
from tools.m2_discovery_installation_profile import current_tls as m


class NativeTls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid()!=0:raise AssertionError('ROOT_NATIVE_TLS_FIXTURE_REQUIRED')
        cls.temp=tempfile.TemporaryDirectory(dir=ROOT,prefix='current-tls-native-');cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name);cls.root.chmod(0o700);cls.openssl,cls.cas,_,_=fixtures.public_fixture(cls.root)
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

if __name__=='__main__':unittest.main()
