"""Fresh-scope evidence gates and unchanged native TLS transport.

Historical/configuration inputs in the receipt fixture are synthetic. The
Ed25519 signing/verification, protected files and transport tests are real.
"""
import copy
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3] if Path(__file__).parent.name == 'tests' else Path(__file__).parent
SCRIPT = ROOT / 'scripts/probe-registry-post-network-get-20261024.py'
if not SCRIPT.exists(): SCRIPT = ROOT / 'post-network-get.py'
CAPSULE = ROOT / 'releases/semantic-registry-checkpoint-successor-20261023.py'
if not CAPSULE.exists(): CAPSULE = ROOT / 'capsule.py'
REPAIR = ROOT / 'scripts/repair-registry-network-projection-20261024.py'
if not REPAIR.exists(): REPAIR = ROOT / 'repair.py'
spec = importlib.util.spec_from_file_location('post_network_get', SCRIPT)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
NATIVE = None


def preload():
    global NATIVE
    if NATIVE is None:
        NATIVE = m.legacy().sealed_native_modules(CAPSULE.read_bytes())
    return NATIVE


def load_repair():
    spec = importlib.util.spec_from_file_location('repair_facts_only', REPAIR)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def seal(path):
    path = path.resolve(); parts = path.parts
    parents = ['/'] + ['/' + '/'.join(parts[1:i]) for i in range(2, len(parts))]
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'metadata': list(m.legacy().identity(path.stat())),
            'ancestors': [{'path': p, 'identity': [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode]}
                          for p in parents for s in [Path(p).stat()]]}


class Gate(unittest.TestCase):
    def setUp(self):
        self.r = load_repair()

    def test_retained_transport_bytes_and_child_are_unchanged(self):
        d = m.legacy()
        source = ROOT / 'scripts/probe-registry-current-caller-get-20261023.py'
        if not source.exists(): source = ROOT / 'prior-get.py'
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), m.LEGACY_SOURCE_HASH)
        preload()
        child = sys.modules['tools.semantic_registry_recovery_execution.semantic_request'].CHILD_SOURCE
        self.assertIn("os.setns(fd,0);os.close(fd)", child)
        self.assertIn("context=ssl.create_default_context(cadata=v['ca'])", child)
        self.assertIn("client.request('GET'", child)
        self.assertNotIn('CERT_NONE', child)

    def test_fresh_claim_is_exclusive_and_bound_to_completed_repair(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            with patch.object(m, 'NETWORK_ROOT', directory):
                d = m.legacy(); root = m.new_claim(self.r, d, {'networkReceiptHash': 'a'*64})
                before = (root/'claim.json').read_bytes()
                row = json.loads(before)
                self.assertEqual(row['networkReviewHash'], m.NETWORK_REVIEW)
                self.assertEqual(row['maximumHttpGetAttempts'], 1)
                self.assertFalse(row['oldDiagnosticClaimsReopened'])
                with self.assertRaises(FileExistsError):
                    m.new_claim(self.r, d, {'networkReceiptHash': 'b'*64})
                self.assertEqual((root/'claim.json').read_bytes(), before)

    def test_current_owner_progress_never_resets_or_accepts_expired_token(self):
        row = {'publications': 1, 'cumulativeAttempts': 416, 'state': 'ACTIVE',
               'tokenExpiresWall': time.time()+60, 'version': 285}
        reader = types.SimpleNamespace(ledger=lambda c: row)
        self.assertEqual(m.owner_progress(reader, {}), row)
        baseline = copy.deepcopy(row); row['cumulativeAttempts'] = 415
        with self.assertRaisesRegex(ValueError, 'CURRENT_NORMAL_OWNER'): m.owner_progress(reader, {})
        row.update(cumulativeAttempts=417, publications=0)
        with self.assertRaises(ValueError): m.owner_progress(reader, {}, baseline)
        row.update(publications=1, tokenExpiresWall=time.time()-1)
        with self.assertRaises(ValueError): m.owner_progress(reader, {}, baseline)
        row.update(tokenExpiresWall=time.time()+60, version=284)
        with self.assertRaisesRegex(ValueError, 'REGRESSION'): m.owner_progress(reader, {}, baseline)

    def result(self):
        return dict(complete=True, httpGetAttempts=1, engineGets=4,
            tlsHostnameChainAndPeerPinVerified=True, mountedTokenMetadataMatchesCurrentHostSource=True,
            callerConfigurationAndGenerationMatchReviewed=True, registryRunning=True, registryPaused=False,
            registryRestarting=False, registryDead=False, registryImageMatchesReviewed=True,
            registrySameDurableProcessGeneration=True, registryLiveNetworkEndpointCount=1,
            httpStatus=200, exactActiveReferenceMatched=True, allConfiguredReferencesProven=True)

    def test_exact200_only_proves_resource_not_release_or_continuous_renewal(self):
        row = dict(cumulativeAttempts=416, publications=1)
        for status, match, all_refs, expected in [(200, True, True, True), (200, False, False, False),
                                                  (403, False, False, False), (401, False, False, False),
                                                  (502, False, False, False), (200, True, False, False)]:
            with self.subTest(status=status, match=match, all_refs=all_refs):
                value = self.result(); value.update(httpStatus=status, exactActiveReferenceMatched=match,
                                                   allConfiguredReferencesProven=all_refs)
                result = m.finish(value, row, row, {})
                self.assertEqual(result['originalRequestResource200Proven'], expected)
                for key in ('releaseAcceptance', 'permanentRenewalProven', 'applicationReadinessProven',
                            'nativeRecoveryJournalCompleted', 'runtimeAuthorityIssued'):
                    self.assertFalse(result[key])

    def test_incomplete_or_changed_registry_rejected_after_request(self):
        row = dict(cumulativeAttempts=416, publications=1)
        for key, changed in [('engineGets', 3), ('httpGetAttempts', 2), ('registryDead', True),
                             ('tlsHostnameChainAndPeerPinVerified', False), ('registryLiveNetworkEndpointCount', 0)]:
            value = self.result(); value[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError): m.finish(value, row, row, {})


class RealSignatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = m.legacy(); preload()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.auth = self.root/'authority'; self.auth.mkdir(mode=0o700)
        from tools.semantic_provider_deployment_authentication import signing_bytes
        self.signing_bytes = signing_bytes
        self.key = self.root/'private.pem'
        self.openssl = Path('/usr/bin/openssl').resolve()
        subprocess.run([str(self.openssl), 'genpkey', '-algorithm', 'Ed25519', '-out', str(self.key)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raw = subprocess.check_output([str(self.openssl), 'pkey', '-in', str(self.key), '-pubout', '-outform', 'DER'])
        now = int(time.time()); self.policy = self.root/'policy.json'
        ctx = dict(installationRef='urn:fixture:installation', entityRef='urn:fixture:entity',
                   intentIssuerRef='urn:fixture:issuer', approvalIssuerRef='urn:fixture:issuer', attestorRef='urn:fixture:issuer')
        self.ctx = ctx
        self.write(self.policy, dict(schema='ouf.semantic-deployment-trust-policy.v1',
            installationRef=ctx['installationRef'], entityRef=ctx['entityRef'], keys=[dict(
            keyRef='urn:fixture:key', issuerRef=ctx['attestorRef'],
            roles=['DEPLOYMENT_INTENT', 'FINAL_DEPLOYMENT_APPROVAL', 'CREATION_ATTESTATION'],
            publicKey=raw[-32:].hex(), notBefore=now-10000, expiresAt=now+3600, state='ACTIVE')]))
        version = subprocess.check_output([str(self.openssl), 'version']).decode().split()[1]
        self.review = dict(verification=dict(context=ctx,
            trustPolicy=dict(path=str(self.policy), sha256=hashlib.sha256(self.policy.read_bytes()).hexdigest()),
            openssl=dict(path=str(self.openssl), sha256=hashlib.sha256(self.openssl.read_bytes()).hexdigest(), version=version)),
            unitHash='c'*64, providerPin={'synthetic': True}, projectedAllowlist=['127.0.0.1/32'],
            candidate=dict(address='127.0.0.1', port=443))
        self.install_patch = patch.object(m, 'INSTALL', str(self.root/'installation')); self.install_patch.start(); self.addCleanup(self.install_patch.stop)
        self.review_patch = patch.object(m, 'NETWORK_REVIEW', m.digest(self.review)); self.review_patch.start(); self.addCleanup(self.review_patch.stop)
        r = self.r = load_repair()
        r.CONFIG_HASH = m.digest({'destinations': {'installationRoot': m.INSTALL}})
        # Synthetic history/configuration/paths; real crypto and custody below.
        r.source_check = lambda review: None
        r.scope = lambda review: {'fixtureCompletedScope': True}
        authority = dict(schema=r.AUTHORITY_SCHEMA, scope=r.scope(self.review), issuedAt=now-1800, expiresAt=now-900,
            installationRef=ctx['installationRef'], entityRef=ctx['entityRef'], automaticReplayAllowed=False,
            budgetReset=False, releaseAcceptance=False)
        self.authority = m.encoded(authority); ah = hashlib.sha256(self.authority).hexdigest()
        ap = patch.object(m, 'NETWORK_AUTHORITY', ah); ap.start(); self.addCleanup(ap.stop)
        human = dict(schema=r.HUMAN_SCHEMA, reviewHash=m.NETWORK_REVIEW, authorityHash=ah,
                     decision=r.DECISION, state='ACTIVE', issuedAt=authority['issuedAt'], expiresAt=authority['expiresAt'])
        proof = dict(flow=dict(kernelOriginAuthenticated=True, reply=dict(source='127.0.0.1', sourcePort=443)))
        drop = self.root/'50-IPAddressAllow.conf'; drop.write_bytes(b'[Service]\nIPAddressAllow=127.0.0.1/32\n'); drop.chmod(0o600)
        self.receipt = dict(schema='ouf.registry-network-projection-receipt.v1', reviewHash=m.NETWORK_REVIEW,
            authorityHash=ah, configurationHash=r.CONFIG_HASH, unitBaseHash=self.review['unitHash'],
            providerPinHash=m.digest(self.review['providerPin']), effectiveAllowlist=self.review['projectedAllowlist'],
            persistentProjectionInstalled=True, workerRestarted=False, normalGrantMandateChanged=False,
            managerMutationAttempts=1, ownerLedgerWrites=0, automaticReplayAllowed=False, budgetReset=False,
            releaseAcceptance=False, freshOriginProofHash=m.digest(proof),
            dropInBinding=dict(path='/etc/systemd/system.control/fixture/50-IPAddressAllow.conf', sha256=hashlib.sha256(drop.read_bytes()).hexdigest()))
        self.result = dict(status='NETWORK_PROJECTION_INSTALLED_OWNER_PUBLISHED', complete=True,
            reviewHash=m.NETWORK_REVIEW, kernelNatPathProven=True, originalIamTlsAndDiscoveryProven=True,
            projectedWorkerDiscoveryStatus=200, workerGenerationUnchanged=True, workerRestartedByRepair=False,
            managerRestarts=0, managerMutationAttempts=1, controlledCumulativeGrantAttempts=416,
            newOperationalGrantAttempts=95, publications=1)
        self.values = {'review.json': self.review, 'human.json': human, 'receipt.json': self.receipt,
            'fresh-origin-proof.json': proof, 'result.json': self.result,
            'configuration.json': {'destinations': {'installationRoot': m.INSTALL}}}
        actual_json = r.json_at; actual_read = r.read
        def json_at(path, expected=None):
            value = copy.deepcopy(self.values[Path(path).name])
            if expected is not None: m.require(m.digest(value) == expected, 'FIXTURE_HASH_CHANGED')
            return value
        def read(path, maximum, expected=None):
            if str(path) == self.receipt['dropInBinding']['path']: path = drop
            return actual_read(path, maximum, expected)
        r.json_at = json_at; r.read = read
        self.write(self.auth/'authority.json', authority)
        self.sign(self.authority, 'DEPLOYMENT_INTENT')
        self.sign(self.authority, 'FINAL_DEPLOYMENT_APPROVAL')
        self.sign(m.encoded(self.receipt), 'CREATION_ATTESTATION')

    def write(self, path, value):
        path.write_bytes(m.encoded(value)); path.chmod(0o600)

    def sign(self, raw, role):
        header = dict(schema='ouf.semantic-deployment-detached-signature.v1', algorithm='Ed25519', keyRef='urn:fixture:key',
            role=role, issuerRef=self.ctx['attestorRef'], installationRef=self.ctx['installationRef'],
            entityRef=self.ctx['entityRef'], payloadHash=hashlib.sha256(raw).hexdigest())
        frame = self.root/'frame'; frame.write_bytes(self.signing_bytes(raw, header))
        signature = subprocess.check_output([str(self.openssl), 'pkeyutl', '-sign', '-rawin', '-inkey', str(self.key), '-in', str(frame)])
        self.write(self.auth/(header['payloadHash']+'.'+role+'.json'), {**header, 'signature': signature.hex()})

    def test_real_signed_completed_fact_can_be_read_after_effect_window_expired(self):
        _, _, receipt, result = m.verify_completed(self.r, self.root)
        self.assertEqual(receipt, self.receipt); self.assertEqual(result, self.result)
        self.assertEqual(len(list(self.auth.glob('*.json'))), 4)

    def test_missing_final_signature_and_corrupt_attestation_are_refused(self):
        path = self.auth/(m.NETWORK_AUTHORITY+'.FINAL_DEPLOYMENT_APPROVAL.json')
        before = path.read_bytes(); path.unlink()
        with self.assertRaises(FileNotFoundError): m.verify_completed(self.r, self.root)
        path.write_bytes(before); path.chmod(0o600)
        sigpath = self.auth/(m.digest(self.receipt)+'.CREATION_ATTESTATION.json')
        sig = json.loads(sigpath.read_bytes()); sig['signature'] = '0'*128; self.write(sigpath, sig)
        with self.assertRaisesRegex(Exception, 'DETACHED_SIGNATURE_INVALID'): m.verify_completed(self.r, self.root)

    def test_partial_result_is_not_a_gate_for_new_get(self):
        self.values['result.json']['complete'] = False
        with self.assertRaisesRegex(ValueError, 'COMPLETED_NETWORK_RESULT'): m.verify_completed(self.r, self.root)


@unittest.skipUnless(os.environ.get('OUF_NATIVE_POST_NETWORK_GET') == '1', 'Explicit disposable root/netns/TLS scope required')
class NativeTls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(self.tmp.cleanup); self.root = Path(self.tmp.name)
        self.d = m.legacy(); preload()
        self.token = self.root/'token'; self.token.write_bytes(b'current-fixture-service-token'); self.token.chmod(0o600)
        self.cert = self.root/'cert.pem'; key = self.root/'key.pem'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
            '-out', str(self.cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.cert.chmod(0o600); key.chmod(0o600)
        self.ref = dict(semanticId='fixture', semanticVersion='1', revisionId='00000000-1111-2222-3333-444444444444',
                        publicationSetId='11111111-2222-3333-4444-555555555555')
        self.status = 200; self.match = True; self.calls = []; owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                owner.calls.append((self.command, self.path, self.headers.get('Authorization')))
                body = m.encoded(dict(semantic_id=owner.ref['semanticId'], semantic_version='1',
                    revision_id=owner.ref['revisionId'], publication_set_id=owner.ref['publicationSetId'],
                    status='ACTIVE' if owner.match else 'DRAFT'))
                self.send_response(owner.status); self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def log_message(self, *args): pass
        self.server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(str(self.cert), str(key))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.close)
        python = Path(sys.executable).resolve()
        self.profile = dict(origin='https://127.0.0.1:'+str(self.server.server_port),
            pythonExecutable=dict(path=str(python), sha256=hashlib.sha256(python.read_bytes()).hexdigest()),
            references=[self.ref], tokenSource=seal(self.token), tokenTarget=str(self.token), ca=seal(self.cert),
            peerCertificateSha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.cert.read_text())).hexdigest())
        self.metadata = list(self.d.identity(self.token.stat()))

    def close(self):
        self.server.shutdown(); self.thread.join(timeout=3); self.server.server_close()

    def request(self):
        return self.d.one_current_get(self.d.Reader(), self.profile, {'State': {'Pid': os.getpid()}},
                                      self.metadata, self.root)

    def test_real_namespace_tls_current_token_and_exact_reference_no_replay(self):
        result = self.request(); self.assertTrue(result['allConfiguredReferencesProven'])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][2], 'Bearer current-fixture-service-token')
        self.assertIn('/api/semantic/v1/references:resolve?', self.calls[0][1])
        with self.assertRaisesRegex(ValueError, 'SINGLE_DIAGNOSTIC_GET_ONLY'): self.request()
        self.assertNotIn('current-fixture-service-token', m.encoded(result).decode())

    def test_bad_peer_pin_fails_before_any_http(self):
        self.profile['peerCertificateSha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'TRANSPORT_UNCONFIRMED'): self.request()
        self.assertEqual(self.calls, []); self.assertTrue((self.root/'get-attempt.json').exists())


if __name__ == '__main__': unittest.main()
