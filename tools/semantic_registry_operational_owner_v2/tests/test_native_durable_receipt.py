"""Durable dated installation receipt (task-30a, D-029, D-031) with real Ed25519 and a real mandate ledger.

Reuses the native owner fixture: real root custody, real OpenSSL, real guard.
Only the trust windows, the ledger generations and attestedAt are varied.
"""
import hashlib
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch

import test_native_transport as fixture_transport
from tools.semantic_registry_operational_owner_v2 import core, guard
from tools.semantic_authority_mandates import mandates as M
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator, signing_bytes


OK = {'keyNotRevoked': True, 'custodyIntact': True, 'noOpenSecurityIncident': True}


@unittest.skipUnless(os.environ.get('OUF_NATIVE_OPERATIONAL_OWNER') == '1', 'Explicit disposable native root scope required')
class DurableReceipt(unittest.TestCase):
    def setUp(self):
        self.f = fixture_transport.NativeOwner(methodName='runTest')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.now = int(time.time())

    def rebuild(self, not_before, expires_at, attested_at, schema='ouf.registry-operational-token-installation-receipt.v2'):
        f = self.f
        value = json.loads(f.trust.read_bytes())
        for key in value['keys']:
            key.update(notBefore=not_before, expiresAt=expires_at)
        f.write(f.trust, core.encoded(value))
        f.config['verification']['trustPolicy'] = f.binding(f.trust)
        f.config_path.chmod(0o600)
        f.write(f.config_path, core.encoded(f.config))
        f.config_hash = hashlib.sha256(f.config_path.read_bytes()).hexdigest()
        f.receipt['configurationHash'] = f.config_hash
        f.receipt['schema'] = schema
        f.receipt['attestedAt'] = attested_at
        f.write(f.install / 'installed.json', core.encoded(f.receipt))
        for old in f.signatures.iterdir():
            old.unlink()
        f.sign_receipt()

    def open(self):
        return guard.InstalledGuard(self.f.config_path, self.f.config_hash)

    def denied(self, code):
        with self.assertRaises(core.Denied) as caught:
            self.open()
        self.assertEqual(str(caught.exception), code)

    def generation(self, state='ACTIVE', not_before=None, days=30, preconditions=OK):
        nb = self.now - 10 if not_before is None else not_before
        return M.write_generation(str(self.f.mandate_root), self.f.config['verification']['trustPolicy'],
                                  self.f.ctx['installationRef'], self.f.ctx['entityRef'],
                                  [{'keyRef': 'fixture-attestor-key', 'notBefore': nb, 'expiresAt': nb + days * 86400,
                                    'state': state}], preconditions, 'renewal-job', '9' * 64)

    def test_valid_during_mandate(self):
        self.assertIsInstance(self.open(), guard.InstalledGuard)

    def test_valid_after_generation_zero_expired_when_attested_inside_it(self):
        self.rebuild(self.now - 7200, self.now - 3600, self.now - 5000)
        self.assertIsInstance(self.open(), guard.InstalledGuard)

    def test_attested_outside_any_mandate_or_in_future(self):
        self.rebuild(self.now - 7200, self.now - 3600, self.now - 3000)
        self.denied('ATTESTOR_MANDATE_AT_ATTESTATION_REQUIRED')
        self.rebuild(self.now - 7200, self.now + 3600, self.now - 8000)
        self.denied('ATTESTOR_MANDATE_AT_ATTESTATION_REQUIRED')
        self.rebuild(self.now - 7200, self.now + 3600, self.now + 1000)
        self.denied('RECEIPT_ATTESTED_IN_FUTURE')

    def test_renewal_generation_covers_later_attestation(self):
        self.rebuild(self.now - 7200, self.now - 3600, self.now - 20)
        self.denied('ATTESTOR_MANDATE_AT_ATTESTATION_REQUIRED')
        self.generation(not_before=self.now - 60)
        # A generation issued at `now` is in force from its issuedAt onwards.
        self.rebuild(self.now - 7200, self.now - 3600, int(time.time()))
        self.assertIsInstance(self.open(), guard.InstalledGuard)

    def test_revocation_stops_even_an_old_receipt(self):
        self.assertIsInstance(self.open(), guard.InstalledGuard)
        self.generation(state='REVOKED', not_before=self.now - 60,
                        preconditions={**OK, 'keyNotRevoked': False})
        self.denied('ATTESTOR_KEY_REVOKED')

    def test_invalid_ledger_stops_the_worker(self):
        self.f.write(self.f.mandate_root / ('.tmp-1-' + '0' * 32), b'partial')
        self.denied('MANDATE_TEMPORARY_ENTRY_PRESENT')
        (self.f.mandate_root / ('.tmp-1-' + '0' * 32)).unlink()
        self.f.write(self.f.mandate_root / '2.json', b'{}')
        self.denied('MANDATE_GENERATION_GAP')

    def test_v1_or_undated_receipt_refused(self):
        self.rebuild(self.now - 60, self.now + 3600, self.now - 30,
                     schema='ouf.registry-operational-token-installation-receipt.v1')
        self.denied('DATED_INSTALLATION_RECEIPT_REQUIRED')
        self.f.receipt['schema'] = 'ouf.registry-operational-token-installation-receipt.v2'
        del self.f.receipt['attestedAt']
        self.f.write(self.f.install / 'installed.json', core.encoded(self.f.receipt))
        self.denied('DATED_INSTALLATION_RECEIPT_REQUIRED')

    def test_wrong_role_scope_or_domain(self):
        f = self.f
        raw = core.encoded(f.receipt)
        path = f.signatures / (hashlib.sha256(raw).hexdigest() + '.CREATION_ATTESTATION.json')
        for change, code in (({'role': 'DEPLOYMENT_INTENT'}, 'EXACT_DETACHED_SIGNATURE_REQUIRED'),
                             ({'installationRef': 'other-installation'}, 'EXACT_DETACHED_SIGNATURE_REQUIRED'),
                             ({'domain': True}, 'DETACHED_SIGNATURE_INVALID')):
            header = dict(schema='ouf.semantic-deployment-detached-signature.v1', algorithm='Ed25519',
                          keyRef='fixture-attestor-key', role='CREATION_ATTESTATION', issuerRef=f.ctx['attestorRef'],
                          installationRef=f.ctx['installationRef'], entityRef=f.ctx['entityRef'],
                          payloadHash=hashlib.sha256(raw).hexdigest())
            wrong_domain = change.pop('domain', False)
            header.update(change)
            frame = signing_bytes(raw, header)
            if wrong_domain:
                frame = b'OUF-SEMANTIC-PROVIDER-B1B2-EVIDENCE\x00V1\x00' + frame[len(b'OUF-DEPLOYMENT-EVIDENCE\x00V1\x00'):]
            frame_path = f.write(f.root / 'frame', frame)
            signature = f.native('pkeyutl', '-sign', '-rawin', '-inkey', str(f.signing_key), '-in', str(frame_path))
            path.unlink()
            f.write(path, core.encoded(dict(header, signature=signature.hex())))
            with self.subTest(change=change or 'domain'):
                self.denied(code)

    def test_ledger_changed_during_verification(self):
        original = DetachedAuthenticator.verify
        fixture = self

        def racing(self_, *args):
            original(self_, *args)
            fixture.generation(not_before=fixture.now - 60)

        with patch.object(DetachedAuthenticator, 'verify', racing):
            self.denied('MANDATE_LEDGER_CHANGED_DURING_VERIFICATION')


if __name__ == '__main__':
    unittest.main()
