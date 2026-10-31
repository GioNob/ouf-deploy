"""Contract tests only; actual JVM/PostgreSQL/IAM execution is a separate test."""
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest
from urllib.parse import parse_qs, urlsplit
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
import jvm_fixture_inputs as fixture


def decode(segment):
    return base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))


class JvmFixtureInputContracts(unittest.TestCase):
    NOW = 1792713600

    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def test_real_rsa_signature_verifies_with_published_jwk_and_tampering_fails(self):
        claims = fixture.service_claims('https://iam.disposable.test:8443', self.NOW)
        token = fixture.rs256_jwt(self.key, claims)
        head, payload, signature = token.split('.')
        jwk = fixture.public_jwk(self.key)
        public = rsa.RSAPublicNumbers(int.from_bytes(decode(jwk['e']), 'big'),
                                     int.from_bytes(decode(jwk['n']), 'big')).public_key()
        public.verify(decode(signature), (head + '.' + payload).encode('ascii'),
                      padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(json.loads(decode(payload)), claims)
        self.assertEqual(json.loads(decode(head))['kid'], jwk['kid'])
        with self.assertRaises(InvalidSignature):
            public.verify(decode(signature), (head + '.' + payload + 'A').encode('ascii'),
                          padding.PKCS1v15(), hashes.SHA256())

    def test_policy_hash_covers_exact_inner_json_and_not_the_envelope(self):
        envelope = fixture.policy_envelope(self.NOW)
        # This is the byte contract used by Jackson's JsonNode writer: object
        # insertion order, compact separators and integer numbers, no sorting.
        transported = json.loads(json.dumps(envelope, indent=2))
        body = json.dumps(transported['bundle'], separators=(',', ':')).encode()
        self.assertEqual(hashlib.sha256(body).hexdigest(), envelope['contentHash'])
        self.assertNotEqual(hashlib.sha256(fixture.compact(envelope)).hexdigest(),
                            envelope['contentHash'])
        transported['bundle']['grants'][0]['tenantId'] = 'other-tenant'
        self.assertNotEqual(hashlib.sha256(fixture.compact(transported['bundle'])).hexdigest(),
                            envelope['contentHash'])
        self.assertEqual(set(envelope), {'bundleId', 'bundleVersion', 'activatedAt', 'bundle', 'contentHash'})
        self.assertEqual(envelope['bundleId'], envelope['bundle']['bundleId'])
        self.assertEqual(envelope['bundleVersion'], envelope['bundle']['version'])

    def test_service_claim_and_policy_bind_same_identity_with_read_only_authority(self):
        claims = fixture.service_claims('https://iam.disposable.test', self.NOW)
        bundle = fixture.policy_envelope(self.NOW)['bundle']
        descriptor, = bundle['capabilities']
        grant, = bundle['grants']
        self.assertEqual(claims['ouf_actor_type'], 'SERVICE')
        self.assertEqual(descriptor['allowedActors'], ['SERVICE'])
        self.assertEqual(claims['tenant_id'], grant['tenantId'])
        self.assertEqual(claims['sub'], grant['subjectId'])
        self.assertEqual(claims['client_id'], grant['servicePrincipalId'])
        self.assertEqual(claims['scope'], 'ouf.semantic.read')
        self.assertEqual(descriptor['capabilityId'], claims['scope'])
        self.assertEqual(descriptor['operation'], 'EXECUTE')
        self.assertEqual(claims['exp'] - claims['iat'], 600)
        self.assertEqual(claims['aud'], ['ouf-api-gateway'])
        self.assertEqual(claims['acr'], '1')
        self.assertEqual(claims['externalRoleRefs'], [])

    def test_insecure_issuer_or_unbounded_window_cannot_enter_tls_fixture(self):
        for issuer in ('http://iam.disposable.test', 'https://user:secret@iam.disposable.test',
                       'https://iam.disposable.test?override=1', 'https://iam.disposable.test#fragment',
                       'https:///missing-host'):
            with self.subTest(issuer=issuer), self.assertRaises(ValueError):
                fixture.service_claims(issuer, self.NOW)
        for seconds in (0, -1, 3601, True, 1.5):
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                fixture.policy_envelope(self.NOW, seconds)
        with self.assertRaises(ValueError):
            fixture.public_jwk(rsa.generate_private_key(public_exponent=65537, key_size=1024))

    def test_seed_and_exact_reference_use_same_fixture_ids_and_immutable_order(self):
        reference = fixture.reference()
        sql = fixture.seed_sql()
        query = parse_qs(urlsplit(fixture.resolve_path()).query, strict_parsing=True)
        self.assertEqual(query, {key: [reference[key]] for key in
                                ('semanticId', 'revisionId', 'publicationSetId')})
        for value in (fixture.ARTIFACT_ID, fixture.REVISION_ID, fixture.PUBLICATION_SET_ID):
            self.assertEqual(str(uuid.UUID(value)), value)
            self.assertIn("'" + value + "'", sql)
        self.assertTrue(sql.startswith('BEGIN;\n'))
        self.assertTrue(sql.endswith('COMMIT;\n'))
        self.assertIn("'ACTIVE','" + reference['semanticVersion'] + "'", sql)
        self.assertLess(sql.index("'BUILDING'"), sql.index('INSERT INTO ouf_sem.semantic_publication_member'))
        self.assertLess(sql.index('INSERT INTO ouf_sem.semantic_publication_member'), sql.index("status='PUBLISHED'"))
        self.assertIn("'" + fixture.SEMANTIC_ID + ':' + fixture.REVISION_ID + "'::bytea", sql)
        self.assertNotRegex(sql.upper(), r'\b(DROP|DELETE|TRUNCATE|ALTER|GRANT)\b|ON\s+CONFLICT')
        self.assertNotIn('UPDATE ouf_sem.artifact_revision', sql)
        self.assertEqual(set(re.findall(r'(?:INSERT INTO|UPDATE)\s+(ouf_sem\.\w+)', sql)), {
            'ouf_sem.semantic_artifact', 'ouf_sem.artifact_revision', 'ouf_sem.artifact_active_revision',
            'ouf_sem.semantic_publication_set', 'ouf_sem.semantic_publication_member'})


if __name__ == '__main__':
    unittest.main()
