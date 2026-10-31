"""Actual HTTP/TLS/private stdin/netns FD and mounted-view token read.

Gateway/caller scopes and journal phases are explicit synthetic fixtures here;
this transport qualification does not attest a production caller or Registry.
"""
import copy,hashlib,json,os,ssl,sys,threading,unittest
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit,parse_qs
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_current_admission as fixture
from tools.semantic_registry_recovery_execution import core as c,semantic_request as s,gateway as g

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        self.server.calls.append({'path':self.path,
            'sameWorkloadBearer':self.headers.get('Authorization')=='Bearer FIXTURE_ORIGINAL_SERVICE_TOKEN'})
        status=self.server.status
        if not self.server.calls[-1]['sameWorkloadBearer']:status=403
        q=parse_qs(urlsplit(self.path).query)
        value={'semantic_id':q.get('semanticId',[''])[0],'semantic_version':self.server.version,
            'revision_id':q.get('revisionId',[''])[0],'publication_set_id':q.get('publicationSetId',[''])[0],
            'status':self.server.reference_state}
        raw=json.dumps(value).encode();self.send_response(status)
        if status==302:self.send_header('Location','http://127.0.0.1:1/forbidden-fallback')
        self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        if self.server.callback:self.server.callback()

class ServiceRequest(unittest.TestCase):
    native=fixture.CurrentAdmission.native;write=fixture.CurrentAdmission.write
    binding=fixture.CurrentAdmission.binding;sign=fixture.CurrentAdmission.sign
    resign=fixture.CurrentAdmission.resign
    def setUp(self):
        fixture.CurrentAdmission.setUp(self)
        server=HTTPServer(('127.0.0.1',0),Handler);self.server=server
        server.calls=[];server.status=200;server.version='1';server.reference_state='ACTIVE';server.callback=None
        self.token=self.root/'service.jwt';self.token.write_text('FIXTURE_ORIGINAL_SERVICE_TOKEN\n');self.token.chmod(0o600)
        self.ref={'semanticId':'urn:fixture:città','semanticVersion':'1',
            'revisionId':'00000000-0000-0000-0000-000000000001',
            'publicationSetId':'00000000-0000-0000-0000-000000000002'}
        configuration={'semanticReferenceBindings':[self.ref],
            'semanticMapping':{'semanticRefs':[self.ref['semanticId']+'@1']}}
        sha='sha256:'+hashlib.sha256(json.dumps(configuration,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        version='00000000-0000-0000-0000-000000000003'
        self.profile_request={'caller':{'fixture':'synthetic'},'origin':'http://127.0.0.1:'+str(server.server_address[1]),
            'tokenTarget':str(self.token),'tokenSource':fixture.file_profile(self.token),
            'pythonExecutable':{'path':str(Path(sys.executable).resolve()),
                'sha256':hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()},
            'ca':None,'peerCertificateSha256':None,'references':[self.ref],'frozenConfigurationHash':sha,
            'onboardingVersionId':version,'frozenConfiguration':{'configurationHash':sha,'onboardingVersionId':version,
                'state':'APPROVED','configuration':configuration}}
        self.caller={'Id':'c'*64,'State':{'Pid':os.getpid()}}
        gateway=g.CurrentGateway.__new__(g.CurrentGateway);gateway.lifecycle=self.lifecycle
        gateway.budget=self.budget;gateway.scope={'explicitFixture':True};gateway.verify=lambda **kwargs:None
        self.gateway=gateway
        # Only constructor/source-contract checks run with this fixture guard;
        # the production scope/Engine/native admission guards are not bypassed
        # by any production factory or entrypoint.
        with patch.object(s.OriginalSemanticRequest,'guard',return_value=self.caller):
            self.request=s.OriginalSemanticRequest(gateway,self.profile_request)
        self.request.guard=lambda:copy.deepcopy(self.caller)
        self.server_thread=threading.Thread(target=server.serve_forever,daemon=True)
        self.server_thread.start();self.addCleanup(self.close_server)

    def close_server(self):self.server.shutdown();self.server.server_close();self.server_thread.join(timeout=3)
    def final_phase(self):
        row={'nextStage':11,'newGeneration':self.store.read()['newGeneration']}
        p=patch.object(self.lifecycle,'journal',return_value=row);p.start();self.addCleanup(p.stop)

    def test_exact_get_uses_mounted_service_bearer_private_stdin_and_all_identity_fields(self):
        with patch.object(s.subprocess,'Popen',wraps=s.subprocess.Popen) as launch:
            result=self.request._get(self.ref)
        self.assertEqual(result['status'],200);self.assertTrue(result['exactActiveReferenceMatched'])
        self.assertTrue(self.server.calls[0]['sameWorkloadBearer'])
        self.assertEqual(parse_qs(urlsplit(self.server.calls[0]['path']).query),
            {k:[self.ref[k]] for k in ('semanticId','revisionId','publicationSetId')})
        self.assertEqual(self.budget.read()['counts']['semanticGets'],1)
        argv=launch.call_args.args[0];self.assertNotIn('FIXTURE_ORIGINAL_SERVICE_TOKEN',' '.join(argv))
        self.assertNotIn('FIXTURE_ORIGINAL_SERVICE_TOKEN',str(launch.call_args.kwargs['env']))
        self.assertEqual(launch.call_args.kwargs['stderr'],s.subprocess.DEVNULL)
        self.assertNotIn('FIXTURE_ORIGINAL_SERVICE_TOKEN',json.dumps(result))

    def test_http502_cannot_finish_and_is_not_automatically_replayed(self):
        self.final_phase();self.server.status=502
        state,proof=self.request.verify()
        self.assertEqual(state,'UNKNOWN');self.assertFalse(proof['originalSemanticGetSucceeded'])
        self.assertEqual(len(self.server.calls),1)

    def test_http200_wrong_version_or_nonactive_status_does_not_finish(self):
        self.final_phase()
        for version,state in [('wrong','ACTIVE'),('1','DEPRECATED'),('1','RETIRED')]:
            self.server.version,self.server.reference_state=version,state
            with self.subTest(version=version,state=state),self.assertRaisesRegex(c.RecoveryDenied,'EXACT_ACTIVE'):
                self.request.verify()

    def test_redirect_and401_do_not_refresh_or_fallback(self):
        self.final_phase()
        for status in (302,401):
            self.server.status=status
            with self.subTest(status=status),self.assertRaisesRegex(c.RecoveryDenied,'EXACT_ACTIVE'):self.request.verify()
        self.assertEqual(len(self.server.calls),2)

    def test403_is_unproven_policy_not_success_or_automatic_retry(self):
        self.final_phase();self.server.status=403
        state,proof=self.request.verify()
        self.assertEqual(state,'UNKNOWN');self.assertTrue(proof['policyAdmissionUnproven'])
        self.assertFalse(proof['originalSemanticGetSucceeded'])
        self.assertEqual(len(self.server.calls),1)
        self.assertTrue(self.server.calls[0]['sameWorkloadBearer'])
        self.assertEqual(self.budget.read()['counts']['semanticGets'],1)

    def test_same_frozen_configuration_references_and_checksum_are_required(self):
        for kind in ('reference','configuration','version','state'):
            profile=copy.deepcopy(self.profile_request)
            if kind=='reference':profile['references'][0]['semanticVersion']='2'
            if kind=='configuration':profile['frozenConfiguration']['configuration']['different']=True
            if kind=='version':profile['onboardingVersionId']='00000000-0000-0000-0000-000000000099'
            if kind=='state':profile['frozenConfiguration']['state']='DRAFT'
            with self.subTest(kind=kind),patch.object(s.OriginalSemanticRequest,'guard',return_value=self.caller):
                with self.assertRaises(c.RecoveryDenied):s.OriginalSemanticRequest(self.gateway,profile)

    def test_token_rotation_during_get_is_not_accepted(self):
        def rotate():
            changed=self.root/'replacement.jwt';changed.write_text('FIXTURE_CHANGED_TOKEN');changed.chmod(0o600)
            os.replace(changed,self.token)
        self.server.callback=rotate
        with self.assertRaises((ValueError,c.RecoveryDenied)):self.request._get(self.ref)
        self.assertEqual(self.budget.read()['counts']['semanticGets'],1)

    def test_current_server_tls_identity_and_certificate_pin_are_enforced(self):
        self.close_server();self._cleanups.pop()  # replace only this fixture server's cleanup
        cert=self.root/'tls.crt';key=self.root/'tls.key'
        self.native('req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),
            '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1')
        key.chmod(0o600);cert.chmod(0o600)
        server=HTTPServer(('127.0.0.1',0),Handler);server.calls=[];server.status=200
        server.version='1';server.reference_state='ACTIVE';server.callback=None
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
        server.socket=context.wrap_socket(server.socket,server_side=True);self.server=server
        self.server_thread=threading.Thread(target=server.serve_forever,daemon=True);self.server_thread.start()
        self.addCleanup(self.close_server)
        self.request.profile.update(origin='https://localhost:'+str(server.server_address[1]),ca=fixture.file_profile(cert),
            peerCertificateSha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest())
        self.assertTrue(self.request._get(self.ref)['exactActiveReferenceMatched'])
        self.request.profile['peerCertificateSha256']='0'*64
        with self.assertRaisesRegex(c.RecoveryDenied,'REQUEST_UNCONFIRMED'):self.request._get(self.ref)
        self.assertEqual(len(server.calls),1)

if __name__=='__main__':unittest.main()
