import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('current_get_diag',ROOT/'scripts/probe-registry-current-caller-get-20261023.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)

class ReadOnlyGet(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.token=self.root/'token';self.token.write_bytes(b'current-fixture-service-token');self.token.chmod(0o600)
        self.ns=self.root/'netns';self.ns.write_bytes(b'namespace-fixture')
        self.meta=list(d.identity(self.token.stat()));parts=self.token.parts
        ancestors=['/']+['/'+'/'.join(parts[1:i])for i in range(2,len(parts))]
        binding={'path':str(self.token),'sha256':'0'*64,'metadata':self.meta,
                 'ancestors':[{'path':p,'identity':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode]}
                              for p in ancestors for s in[Path(p).stat()]]}
        self.profile={'origin':'https://fixture.invalid','pythonExecutable':{'path':'fixture-python','sha256':'0'*64},
            'references':[dict(semanticId='fixture',semanticVersion='1',revisionId='fixture',publicationSetId='fixture')],
            'tokenSource':binding,'tokenTarget':'/run/auth/token','ca':{},'peerCertificateSha256':'0'*64}
        self.status=200;self.matched=True;self.returncode=0;self.payloads=[];self.change=False
        owner=self
        class Child:
            stdin=None;stdout=None
            def __init__(self,*a,**kw):self.returncode=owner.returncode;owner.argv=a[0]
            def communicate(self,payload,timeout):
                owner.payloads.append(json.loads(payload))
                if owner.change:owner.token.write_bytes(b'changed-fixture-service-token')
                return json.dumps({'status':owner.status,'exactActiveReferenceMatched':owner.matched,'bodySha256':'0'*64}).encode(),None
            def poll(self):return self.returncode
            def wait(self,timeout):return self.returncode
        mods={
            'tools.semantic_live_route_diagnostic.reader':types.SimpleNamespace(verify_program=lambda p:None,process_ticks=lambda p:123),
            'tools.semantic_registry_recovery_execution.caller_lookup':types.SimpleNamespace(payload=lambda c,p:{}),
            'tools.ingestion_readiness_patch_execution.private_file':types.SimpleNamespace(read=lambda p:b'fixture-CA'),
            'tools.semantic_registry_recovery_execution.semantic_request':types.SimpleNamespace(CHILD_SOURCE='FIXTURE_ONLY_TRANSPORT')}
        original_open=d.os.open;original_stat=Path.stat
        def opened(path,*a,**kw):return original_open(self.ns if str(path)=='/proc/123/ns/net'else path,*a,**kw)
        def statted(path,*a,**kw):return original_stat(self.ns if str(path)=='/proc/123/ns/net'else path,*a,**kw)
        for p in [patch.dict(d.sys.modules,mods),patch.object(d.subprocess,'Popen',Child),patch.object(d.os,'open',opened),
                  patch.object(Path,'stat',statted),patch.object(d,'mounted_metadata',lambda p,t:self.meta)]:
            p.start();self.addCleanup(p.stop)
        d.REQUEST_ATTEMPTS=0
    def call(self):return d.one_current_get(d.Reader(),self.profile,{'State':{'Pid':123}},self.meta,self.root)
    def test_only_current_mounted_credential_sent_privately_and_success_not_native_acceptance(self):
        r=self.call();self.assertTrue(r['diagnosticGetSucceeded']);self.assertFalse(r['nativeRecoveryJournalCompleted'])
        self.assertFalse(r['currentServiceIdentityIndependentlyVerified']);self.assertEqual(len(self.payloads),1)
        self.assertEqual(self.payloads[0]['token'],'current-fixture-service-token')
        self.assertNotIn('current-fixture-service-token',str(r));self.assertNotIn('current-fixture-service-token',str(self.argv))
        self.assertEqual(self.argv[1:4],['-I','-B','-S'])
    def test_second_get_refused_without_replaying_transport(self):
        self.call()
        with self.assertRaisesRegex(ValueError,'SINGLE_DIAGNOSTIC_GET_ONLY'):self.call()
        self.assertEqual(len(self.payloads),1)
    def test401_not_success_and_not_retried(self):
        self.status=401;self.matched=False;r=self.call()
        self.assertFalse(r['diagnosticGetSucceeded']);self.assertEqual(r['httpStatus'],401);self.assertEqual(len(self.payloads),1)
    def test_transport_failure_keeps_consumed_marker_and_attempt(self):
        self.returncode=1
        with self.assertRaisesRegex(ValueError,'CURRENT_CALLER_GET_TRANSPORT_UNCONFIRMED'):self.call()
        self.assertTrue((self.root/'get-attempt.json').is_file());self.assertEqual(d.REQUEST_ATTEMPTS,1)
    def test_token_rotation_during_request_denies_acceptance(self):
        self.change=True
        with self.assertRaisesRegex(ValueError,'CALLER_OR_CURRENT_TOKEN_CHANGED_DURING_GET'):self.call()
        self.assertEqual(d.REQUEST_ATTEMPTS,1)
    def test_stable_claim_cannot_be_recreated_under_new_launcher(self):
        with patch.object(d,'DIAGNOSTIC_ROOT',str(self.root/'scope')):
            d.claim_diagnostic()
            with self.assertRaisesRegex(ValueError,'CURRENT_CALLER_GET_ALREADY_CLAIMED_NO_REPLAY'):d.claim_diagnostic()
    def test_probe_requires_same_verified_https_origin(self):
        self.profile['origin']='http://fixture.invalid'
        with self.assertRaisesRegex(ValueError,'VERIFIED_ORIGINAL_HTTPS_ORIGIN_REQUIRED'):self.call()
        self.assertEqual(d.REQUEST_ATTEMPTS,0)

if __name__=='__main__':unittest.main()
