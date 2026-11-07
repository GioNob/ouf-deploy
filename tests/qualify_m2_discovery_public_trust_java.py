"""Actual Java21 PKCS12 and isolated IAM/provider TLS; synthetic certificates."""
import hashlib,json,os,socket,ssl,subprocess,sys,tempfile,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.m2_discovery_installation_profile import public_truststore as m

def main():
    assert os.environ.get('GITHUB_ACTIONS')=='true'
    java=os.environ['JAVA_HOME']+'/bin/java'
    def run(args):return subprocess.run(args,check=True,capture_output=True,timeout=20)
    assert 'version "21.' in run([java,'-version']).stderr.decode()
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder);public={}
        for name in ('iam','provider','outsider'):
            run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout',str(root/(name+'.key')),
                '-out',str(root/(name+'.pem')),'-subj','/CN=fixture-'+name,'-addext','basicConstraints=critical,CA:TRUE'])
            public[name]=(root/(name+'.pem')).read_bytes()
            run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(root/(name+'-leaf.key')),
                '-out',str(root/(name+'.csr')),'-subj','/CN=localhost'])
            (root/'extensions').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n')
            run(['openssl','x509','-req','-in',str(root/(name+'.csr')),'-CA',str(root/(name+'.pem')),
                '-CAkey',str(root/(name+'.key')),'-CAcreateserial','-days','1','-out',str(root/(name+'-leaf.pem')),
                '-extfile',str(root/'extensions')])
        fp=lambda raw:hashlib.sha256(ssl.PEM_cert_to_DER_cert(raw.decode())).hexdigest()
        raw,receipt=m.build(public['iam'],[fp(public['iam'])],public['provider'],hashlib.sha256(public['provider']).hexdigest(),time.time())
        path=root/'public.p12';path.write_bytes(raw)
        expected=','.join(receipt['allCaFingerprints'])
        args=[java,str(ROOT/'tests/fixtures/discovery-public-trust/CheckPublicTrust.java'),str(path),expected]
        run(args)
        for name in ('iam','provider','outsider'):
            listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(8)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(root/(name+'-leaf.pem')),str(root/(name+'-leaf.key')))
            received=[]
            def serve():
                try:
                    conn,_=listener.accept();conn.settimeout(6)
                    with conn:
                        with context.wrap_socket(conn,server_side=True) as tls:received.append(tls.recv(1))
                except (ssl.SSLError,TimeoutError,OSError):pass
            thread=threading.Thread(target=serve);thread.start()
            try:
                value=subprocess.run([*args,str(listener.getsockname()[1])],capture_output=True,timeout=15)
                thread.join(timeout=8);assert not thread.is_alive()
                if name=='outsider':assert value.returncode!=0 and received==[]
                else:assert value.returncode==0 and received==[b'\x01'],value.stderr[-1000:]
            finally:listener.close()
        tampered=root/'tampered.p12';changed=bytearray(raw);changed[-8]^=1;tampered.write_bytes(changed)
        value=subprocess.run([java,str(ROOT/'tests/fixtures/discovery-public-trust/CheckPublicTrust.java'),str(tampered),expected],capture_output=True,timeout=15)
        assert value.returncode!=0
        print(json.dumps({'schema':'ouf.m2-discovery-public-java-trust-ci.v1','java21ExactPublicCertificateSetVerified':True,
            'privateKeyEntries':0,'iamAndProviderIsolatedTlsAccepted':True,'undeclaredIssuerRejectedBeforeApplicationByte':True,
            'tamperedIntegrityRejected':True,'syntheticCertificatesAndLocalhostPeers':True,'targetTlsAdmissionProven':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'applicationE2EProven':False},sort_keys=True))

if __name__=='__main__':main()
