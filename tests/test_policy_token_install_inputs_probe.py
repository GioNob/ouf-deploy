"""Actual CA/hostname TLS, no redirect/grant, bounded peer and proposal custody."""
import dataclasses
import json
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools/semantic_policy_token_owner'), str(ROOT), str(ROOT / 'tests')]
import iam_binding_candidate as binding
import iam_install_inputs_probe as probe
from test_iam_token_admission import Fixture
from test_policy_token_mapper_semantics_review import standard, fixture, semantics

class InstallInputsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.issuer = Fixture(self.root); self.addCleanup(self.issuer.close)
        self.raw_connect = socket.create_connection
    def connection(self, address, **kwargs):
        self.assertEqual(address, ('8.8.8.8', 443))
        return self.raw_connect(('127.0.0.1', self.issuer.server.server_port), **kwargs)
    def test_real_tls_discovery_exact_peer_issuer_and_no_grant(self):
        report={'discoveryGetAttempts':0}
        with patch.object(probe,'HOST','iam.fixture.test'), patch.object(probe,'ISSUER',self.issuer.profile.issuer), \
                patch.object(probe.socket,'create_connection',side_effect=self.connection):
            result=probe.peer_discovery('8.8.8.8',self.issuer.context(),report)
        self.assertTrue(result['caAndHostnameVerified']); self.assertTrue(result['issuerDiscoveryMatched'])
        self.assertEqual(report['discoveryGetAttempts'],1)
        self.assertEqual(len(self.issuer.calls),1); self.assertIsNone(self.issuer.calls[0][1])
    def test_redirect_foreign_issuer_untrusted_ca_and_wrong_hostname_are_denied(self):
        for case in ('redirect','issuer','ca','hostname'):
            self.issuer.code=302 if case=='redirect' else 200
            self.issuer.body_mode='changed' if case=='issuer' else None
            context=ssl.create_default_context() if case=='ca' else self.issuer.context()
            host='wrong.fixture.test' if case=='hostname' else 'iam.fixture.test'
            before=len(self.issuer.calls);report={'discoveryGetAttempts':0}
            with patch.object(probe,'HOST',host), patch.object(probe,'ISSUER',self.issuer.profile.issuer), \
                    patch.object(probe.socket,'create_connection',side_effect=self.connection):
                with self.assertRaises((binding.CandidateDenied,ssl.SSLError)):
                    probe.peer_discovery('8.8.8.8',context,report)
            self.assertEqual(report['discoveryGetAttempts'],1)
            self.assertLessEqual(len(self.issuer.calls)-before,1)
    def test_dns_private_empty_or_more_than_eight_peers_do_not_get_adopted(self):
        for ips in ([],['127.0.0.1'],['10.0.0.1'],['8.8.8.'+str(i) for i in range(1,10)]):
            rows=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443)) for ip in ips]
            with patch.object(probe.socket,'getaddrinfo',return_value=rows):
                with self.assertRaises(binding.CandidateDenied):probe.addresses()
    def test_image_identity_or_code_mount_does_not_prove_running_provider_implementation(self):
        for destination in ('/opt/keycloak','/opt/keycloak/providers/custom.jar','/opt/keycloak/lib','/opt/keycloak/data'):
            responses=[{'image':probe.QUALIFIED_IMAGE,'running':True,'mounts':[{'Destination':destination}]},
                {'id':probe.QUALIFIED_IMAGE,'version':'26.0.8','digests':[]}]
            with patch.object(probe,'docker',side_effect=responses): result=probe.artifact()
            self.assertTrue(result['matchesQualifiedDisposableImage'])
            self.assertEqual(result['codeMountObserved'],destination!='/opt/keycloak/data')
            self.assertFalse(result['targetProviderImplementationProven'])
    def candidate(self):
        value=standard(); value['issuerSelection']=probe.ISSUER;value['realm']='ouf'
        ref={**fixture.REF,'issuer':probe.ISSUER};candidate,_=semantics.review(value,'a'*64,ref)
        raw=binding.encoded(candidate)
        path=self.root/('policy-token-iam-binding-'+binding.sha(raw)+'.private.json')
        path.write_bytes(raw);path.chmod(0o600)
        return path,raw
    def test_root_proposal_preserves_candidate_private_peers_and_reconciles_without_reset(self):
        path,raw=self.candidate();image={'imageId':probe.QUALIFIED_IMAGE,'declaredVersion':'26.0.8',
            'matchesQualifiedDisposableImage':True,'codeMountObserved':False,'targetProviderImplementationProven':False,
            'declaredImageIsNotRunningBytecodeProof':True}
        def discovery(address,context,report):
            report['discoveryGetAttempts']+=1
            return {'address':address,'certificateSha256':'b'*64,'caAndHostnameVerified':True,'issuerDiscoveryMatched':True}
        with patch.object(binding,'PARENT',self.root),patch.object(probe,'artifact',return_value=image), \
                patch.object(probe,'addresses',return_value=['8.8.8.8']),patch.object(probe,'peer_discovery',side_effect=discovery):
            first={'privateEvidenceWrites':0,'discoveryGetAttempts':0};probe.observe(str(path),binding.sha(raw),first)
            second={'privateEvidenceWrites':0,'discoveryGetAttempts':0};probe.observe(str(path),binding.sha(raw),second)
        self.assertEqual(first['privateEvidenceWrites'],1);self.assertEqual(second['privateEvidenceWrites'],0)
        saved=Path(first['privateEvidencePath']);self.assertEqual(saved.stat().st_mode&0o777,0o600)
        proposal=binding.decode(saved.read_bytes());self.assertFalse(proposal['runtimeAuthorityIssued'])
        self.assertTrue(proposal['credentialReestablishmentRequired'])
        self.assertNotIn('8.8.8.8',json.dumps(first));self.assertEqual(path.read_bytes(),raw)
    def test_drift_failed_peer_or_unaccepted_candidate_blocks_before_private_write(self):
        for case in ('drift','peer','candidate','hash'):
            path,raw=self.candidate();report={'privateEvidenceWrites':0,'discoveryGetAttempts':0}
            if case=='candidate':
                candidate=binding.decode(raw);candidate['runtimeAuthorityIssued']=True;raw=binding.encoded(candidate);path.write_bytes(raw)
            def peer(address,context,report):
                if case=='peer':raise binding.CandidateDenied('EXACT_ISSUER_DISCOVERY_HTTP_DENIED')
                return {'address':address}
            with patch.object(binding,'PARENT',self.root),patch.object(probe,'artifact',return_value={}), \
                    patch.object(probe,'addresses',side_effect=[['8.8.8.8'],['1.1.1.1']] if case=='drift' else [['8.8.8.8']]), \
                    patch.object(probe,'peer_discovery',side_effect=peer):
                with self.assertRaises(binding.CandidateDenied):
                    probe.observe(str(path),'c'*64 if case=='hash' else binding.sha(raw),report)
            self.assertEqual(report['privateEvidenceWrites'],0)
            path.unlink()

if __name__ == '__main__':unittest.main()
