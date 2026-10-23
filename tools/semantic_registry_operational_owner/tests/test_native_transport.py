"""Actual TLS, Ed25519 custody, IAM and atomic publication on disposable CI.

Only the issuer's data and installation signature are synthetic fixtures. The
production guard, ledger, transport, admission and publisher are not replaced.
No target repair/installation/Java authorization success is asserted here.
"""
from dataclasses import asdict
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.semantic_registry_operational_owner import core, store, guard, adapter, contract
from tools.semantic_policy_token_owner.iam_admission import IamProfile, PinnedIamOpener
from tools.semantic_policy_token_owner.producer import Binding
from tools.semantic_provider_deployment_authentication import signing_bytes


@unittest.skipUnless(os.environ.get('OUF_NATIVE_OPERATIONAL_OWNER')=='1',
                     'Requires explicit disposable root/TLS/CHOWN native scope')
class NativeOwner(unittest.TestCase):
    def write(self,path,raw,mode=0o600):
        path.write_bytes(raw);path.chmod(mode);return path

    def native(self,*args):
        return subprocess.run([str(self.openssl),*args],check=True,stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10).stdout

    def binding(self,path):
        return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

    def setUp(self):
        self.assertEqual(os.geteuid(),0)
        native_parent=Path('/etc/ouf-operational-owner-native-tests')
        native_parent.mkdir(mode=0o700,exist_ok=True)
        self.assertEqual((native_parent.stat().st_uid,native_parent.stat().st_mode&0o777),(0,0o700))
        self.temp=tempfile.TemporaryDirectory(dir=native_parent,prefix='fixture-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.openssl=Path(shutil.which('openssl')).resolve(strict=True)
        self.ca=self.root/'ca.pem';tls_key=self.root/'tls.key'
        self.native('req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=iam.fixture.test','-addext','subjectAltName=DNS:iam.fixture.test',
            '-addext','basicConstraints=critical,CA:TRUE','-keyout',str(tls_key),'-out',str(self.ca))
        self.ca.chmod(0o600);tls_key.chmod(0o600)
        self.calls=[];self.tokens={};self.reject=False;self.sequence=0;fixture=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):self.reply(None)
            def do_POST(self):self.reply(urllib.parse.parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode()))
            def reply(self,fields):
                fixture.calls.append((self.path,fields))
                p=fixture.profile
                if self.path.endswith('/.well-known/openid-configuration'):
                    value={'issuer':p.issuer,'token_endpoint':p.token_endpoint,'introspection_endpoint':p.introspection_endpoint}
                elif self.path.endswith('/introspect'):
                    token=fields.get('token',[''])[0];issued=fixture.tokens.get(token)
                    value={'active':False} if fixture.reject or issued is None else dict(
                        active=True,iss=p.issuer,client_id=p.client_id,sub=p.subject_id,
                        tenant_id=p.tenant_id,ouf_actor_type='SERVICE',aud=p.audience,
                        scope='authorization.bundle.read',iat=issued,exp=issued+300)
                else:
                    fixture.sequence+=1;token='DISPOSABLE_TOKEN_'+str(fixture.sequence)
                    fixture.tokens[token]=int(time.time())
                    value={'access_token':token,'token_type':'Bearer','expires_in':300}
                raw=json.dumps(value).encode()
                self.send_response(200);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(self.ca,tls_key)
        self.server.socket=ctx.wrap_socket(self.server.socket,server_side=True)
        issuer='https://iam.fixture.test:'+str(self.server.server_port)+'/realms/fixture'
        self.profile=IamProfile(issuer,issuer+'/protocol/openid-connect/token',
            issuer+'/protocol/openid-connect/token/introspect','fixture-client','fixture-subject',
            'fixture-tenant','fixture-audience',('authorization.bundle.read',),
            ('authorization.bundle.read',),('127.0.0.1',),90,3600)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.close_server)
        self.install=self.root/'installed';self.install.mkdir(mode=0o700)
        self.ledger=self.root/'ledger';self.ledger.mkdir(mode=0o700)
        self.output=self.root/'output';self.output.mkdir(mode=0o750);os.chown(self.output,0,10001)
        self.credential_directory=self.root/'credential-input';self.credential_directory.mkdir(mode=0o700)
        self.secret=self.write(self.credential_directory/'credential',b'DISPOSABLE_FIXTURE_SECRET',0o400)
        self.common=self.write(self.root/'common.lock',b'')
        self.unit=self.write(self.root/'fixture.service',b'SYNTHETIC_UNIT_NOT_MANAGER_QUALIFICATION\n',0o644)
        self.fence=self.write(self.root/'fence.json',core.encoded({'fixtureOwner':'operational'}))
        self.policy=core.RenewalPolicy(60,240,15,30,3,10,(5,15,60))
        context=ssl.create_default_context(cadata=self.ca.read_text('ascii'))
        transport=PinnedIamOpener(self.profile,lambda:(time.time(),time.monotonic()),context=context)
        binding=Binding(self.profile.token_endpoint,self.profile.client_id,'authorization.bundle.read',str(self.output),'token.jwt',10001)
        s=self.secret.stat();o=self.output.stat()
        owner={'binding':asdict(binding),'iamProfile':asdict(self.profile),'credentialPath':str(self.secret),
               'credentialMetadata':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns],
               'outputDirectoryIdentity':{'device':o.st_dev,'inode':o.st_ino},'tlsTrustHash':transport.trust_digest()}
        self.signing_key=self.root/'fixture-signing.pem'
        self.native('genpkey','-algorithm','ED25519','-out',str(self.signing_key));self.signing_key.chmod(0o600)
        self.public=self.native('pkey','-in',str(self.signing_key),'-pubout','-outform','DER')[12:].hex()
        self.ctx={'installationRef':'fixture-installation','entityRef':'fixture-entity','attestorRef':'fixture-attestor',
                  'intentIssuerRef':'fixture-installer','approvalIssuerRef':'fixture-installer'}
        self.public_directory=self.root/'public-trust';self.public_directory.mkdir(mode=0o700)
        self.trust=self.write(self.public_directory/'trust.json',core.encoded(dict(
            schema='ouf.semantic-deployment-trust-policy.v1',installationRef=self.ctx['installationRef'],
            entityRef=self.ctx['entityRef'],keys=[dict(keyRef='fixture-attestor-key',
                issuerRef=self.ctx['attestorRef'],roles=['CREATION_ATTESTATION'],publicKey=self.public,
                notBefore=int(time.time())-60,expiresAt=int(time.time())+3600,state='ACTIVE'),
                dict(keyRef='fixture-installer-key',issuerRef=self.ctx['intentIssuerRef'],
                    roles=['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'],publicKey=self.public,
                    notBefore=int(time.time())-60,expiresAt=int(time.time())+3600,state='ACTIVE')])))
        manifest={'schema':'ouf.registry-operational-owner-sources.v1','sourceCommit':'a'*40,
                  'sourceHashes':{},'dependencyClosureHash':'b'*64,'bootstrapHash':'c'*64}
        for name in contract.SOURCE_NAMES:
            module=importlib.import_module(name)
            manifest['sourceHashes'][name]=hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
        self.config={'schema':'ouf.registry-operational-token-configuration.v1','proposalHash':'d'*64,
            'sourceManifest':manifest,'sources':[dict(self.binding(Path(sys.executable).resolve()),maximumBytes=67108864)],
            'ownerInputs':owner,'policy':json.loads(core.encoded(asdict(self.policy))),
            'destinations':{'ledgerRoot':str(self.ledger),'installationRoot':str(self.install),'commonInvocationLock':str(self.common)},
            'priorControlledAttempts':321,'predecessorInputsHash':'e'*64,
            'fenceBinding':{'path':str(self.fence),'value':{'fixtureOwner':'operational'}},
            'commonLockIdentity':list(store.file_identity(self.common.stat())),
            'verification':{'trustPolicy':self.binding(self.trust),'openssl':dict(self.binding(self.openssl),
                version=self.native('version').decode().split()[1]),'context':self.ctx},'tlsCa':self.binding(self.ca),
            'serviceUnitPath':str(self.unit)}
        self.config_path=self.write(self.install/'configuration.json',core.encoded(self.config))
        self.config_hash=hashlib.sha256(self.config_path.read_bytes()).hexdigest()
        self.receipt={'schema':'ouf.registry-operational-token-installation-receipt.v1','complete':True,
            'configurationHash':self.config_hash,'proposalHash':self.config['proposalHash'],
            'sourceManifestHash':core.digest(manifest),'operationalRenewalInstalled':True,'priorControlledAttempts':321,
            'serviceUnitPath':str(self.unit),'serviceUnitHash':self.binding(self.unit)['sha256']}
        self.write(self.install/'installed.json',core.encoded(self.receipt))
        self.signatures=self.install/'receipt-signatures';self.signatures.mkdir(mode=0o700)
        self.sign_receipt()
        self.clock=lambda:('fixture-current-boot',time.time(),time.monotonic())
        row=core.initial(self.config_hash,'e'*64,321,self.policy,'fixture-current-boot',self.clock()[1:])
        for name,raw in [('state.json',core.encoded(row)),('invocation.lock',b''),('cas.lock',b'')]:
            self.write(self.ledger/name,raw)

    def close_server(self):
        self.server.shutdown();self.thread.join(2);self.server.server_close()

    def sign_receipt(self):
        raw=core.encoded(self.receipt)
        header=dict(schema='ouf.semantic-deployment-detached-signature.v1',algorithm='Ed25519',
            keyRef='fixture-attestor-key',role='CREATION_ATTESTATION',issuerRef=self.ctx['attestorRef'],
            installationRef=self.ctx['installationRef'],entityRef=self.ctx['entityRef'],payloadHash=hashlib.sha256(raw).hexdigest())
        frame=self.write(self.root/'frame',signing_bytes(raw,header))
        signature=self.native('pkeyutl','-sign','-rawin','-inkey',str(self.signing_key),'-in',str(frame))
        self.signature_path=self.write(self.signatures/(header['payloadHash']+'.CREATION_ATTESTATION.json'),
                                       core.encoded(dict(header,signature=signature.hex())))

    def opened(self):
        owner=guard.InstalledGuard(self.config_path,self.config_hash)
        ledger=store.Store(self.ledger);self.addCleanup(ledger.close)
        return owner,ledger

    def worker(self,owner,ledger):
        native=adapter.NativeAdapter(owner,ledger,self.clock)
        return core.Worker(ledger,native,self.policy,self.config_hash,'e'*64,321,self.clock)

    def test_actual_tls_grant_introspection_publication_and_restart_readmission(self):
        owner,ledger=self.opened()
        with owner.invocation(),ledger.invocation():
            worker=self.worker(owner,ledger);worker.start();row=worker.step()
            self.assertEqual((row['state'],row['cumulativeAttempts'],row['publications']),('ACTIVE',322,1))
            path=self.output/'token.jwt';s=path.stat()
            self.assertEqual((s.st_uid,s.st_gid,s.st_mode&0o777,s.st_nlink),(0,10001,0o440,1))
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),row['tokenHash'])
        # A separate interpreter really reacquires both locks and reobserves
        # current disk, installation signature, trust and online IAM admission.
        child='''import importlib,json,sys,time
from pathlib import Path
root=Path(sys.argv[1]);sys.path[:0]=[str(root),str(root/'tools/semantic_cohort_admission/cohort-draft')]
from tools.semantic_registry_operational_owner import contract,core,guard,store,adapter
for name in contract.SOURCE_NAMES:importlib.import_module(name)
owner=guard.InstalledGuard(sys.argv[2],sys.argv[3]);c=owner.configuration
p=dict(c['policy']);p['failure_delays']=tuple(p['failure_delays']);policy=core.RenewalPolicy(**p)
clock=lambda:('fixture-current-boot',time.time(),time.monotonic())
ledger=store.Store(c['destinations']['ledgerRoot'])
try:
 with owner.invocation(),ledger.invocation():
  native=adapter.NativeAdapter(owner,ledger,clock)
  row=core.Worker(ledger,native,policy,sys.argv[3],c['predecessorInputsHash'],321,clock).start()
  print(json.dumps({'reason':row['reason'],'cumulativeAttempts':row['cumulativeAttempts']}))
finally:ledger.close()
'''
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',child,str(ROOT),str(self.config_path),self.config_hash],
                              capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        resumed=json.loads(result.stdout)
        self.assertEqual(resumed['reason'],'CURRENT_PUBLICATION_READMITTED')
        self.assertEqual(resumed['cumulativeAttempts'],322)
        self.assertEqual(sum(p.endswith('/token') for p,_ in self.calls),1)
        self.assertEqual(sum(p.endswith('/introspect') for p,_ in self.calls),2)

    def test_second_actual_renewal_after_real_wait_keeps_cumulative_accounting(self):
        owner,ledger=self.opened()
        with owner.invocation(),ledger.invocation():
            worker=self.worker(owner,ledger);worker.start();first=worker.step()
            until=first['nextMono']
            while time.monotonic()<until:threading.Event().wait(min(1,until-time.monotonic()))
            second=worker.step()
        self.assertEqual((first['cumulativeAttempts'],second['cumulativeAttempts']),(322,323))
        self.assertEqual(second['publications'],2);self.assertEqual(second['state'],'ACTIVE')
        self.assertNotEqual(first['tokenHash'],second['tokenHash'])
        self.assertNotEqual(first['attemptId'],second['attemptId'])
        self.assertEqual(sum(p.endswith('/token') for p,_ in self.calls),2)

    def test_failed_online_admission_after_actual_grant_never_publishes_or_replays(self):
        self.reject=True;owner,ledger=self.opened()
        with owner.invocation(),ledger.invocation():
            worker=self.worker(owner,ledger);worker.start()
            with self.assertRaises(Exception):worker.step()
            self.assertEqual(ledger.read()['state'],'BLOCKED')
            self.assertEqual(ledger.read()['cumulativeAttempts'],322)
        self.assertFalse((self.output/'token.jwt').exists())
        owner2,ledger2=self.opened()
        with owner2.invocation(),ledger2.invocation():self.assertEqual(self.worker(owner2,ledger2).start()['state'],'BLOCKED')
        self.assertEqual(sum(p.endswith('/token') for p,_ in self.calls),1)

    def test_actual_signature_corruption_or_policy_replacement_denies_before_network(self):
        raw=self.signature_path.read_bytes();value=json.loads(raw);value['signature']='0'*128
        self.write(self.signature_path,core.encoded(value))
        with self.assertRaises(Exception):self.opened()
        self.write(self.signature_path,raw)
        value=json.loads(self.trust.read_bytes());value['keys'][0]['state']='REVOKED'
        self.write(self.trust,core.encoded(value))
        with self.assertRaises(Exception):self.opened()
        self.assertEqual(self.calls,[])

    def test_public_iam_bundle_preserves_exact_trust_and_rejects_unreviewed_ca(self):
        from tools.semantic_registry_operational_owner.installation import public_ca_bundle
        context=ssl.create_default_context(cadata=self.ca.read_text('ascii'))
        expected=self.config['ownerInputs']['tlsTrustHash']
        raw=public_ca_bundle(self.profile,expected,context)
        self.assertTrue(raw.startswith(b'-----BEGIN CERTIFICATE-----'))
        with self.assertRaisesRegex(core.Denied,'RETAINED_IAM_TRUST_SET_REQUIRED'):
            public_ca_bundle(self.profile,'f'*64,context)
        self.assertEqual(self.calls,[])

    def test_fence_change_or_actual_token_replacement_denies_without_new_grant(self):
        owner,ledger=self.opened()
        with owner.invocation(),ledger.invocation():
            worker=self.worker(owner,ledger);worker.start();worker.step()
            self.write(self.fence,core.encoded({'fixtureOwner':'replaced'}))
            with self.assertRaisesRegex(core.Denied,'FENCE_CHANGED'):worker.step()
        self.assertEqual(sum(p.endswith('/token') for p,_ in self.calls),1)


if __name__=='__main__':unittest.main()
