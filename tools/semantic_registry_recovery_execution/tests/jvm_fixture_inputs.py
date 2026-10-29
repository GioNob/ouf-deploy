"""Inputs for a disposable production Registry JVM, never target configuration.

The contracts below were read at ouf-semantic-registry commit
eccef11a97367f20e278db40b9ed6f45dd980c37: SemanticReadRuntimeTest,
SemanticIamSecurityConfiguration, SemanticAuthorizationBoundary,
AuthorizationPolicy, ActiveBundleRefresher, and migrations V1/V2.  The SQL
preloads already-published fixture data; it does not qualify the HUMAN/THS
publication flow.  A successful helper invocation proves no runtime health.

These helpers perform no filesystem, network, process or database operations.
The native test must execute the SQL only against its disposable PostgreSQL,
serve the policy over verified TLS, and send the signed SERVICE JWT through
the actual configured caller/Gateway path to the production Registry JVM.
"""
import base64
from datetime import datetime, timezone
import hashlib
import json
from urllib.parse import urlencode, urlsplit


REGISTRY_SOURCE = 'GioNob/ouf-semantic-registry@eccef11a97367f20e278db40b9ed6f45dd980c37'
SEMANTIC_ID = 'urn:ouf:fixture:postboot'
ARTIFACT_ID = 'b0b00000-0000-4000-8000-000000000001'
REVISION_ID = 'b0b00000-0000-4000-8000-000000000002'
PUBLICATION_SET_ID = 'b0b00000-0000-4000-8000-000000000003'
SEMANTIC_VERSION = '1.0.0'
SERVICE_SUBJECT = 'disposable-ingestion-subject'
SERVICE_CLIENT = 'disposable-ingestion'
TENANT = 'disposable-tenant'
AUDIENCE = 'ouf-api-gateway'
CAPABILITY = 'ouf.semantic.read'
BUNDLE_ID = 'disposable-postboot-policy'
KEY_ID = 'disposable-postboot-rsa'


def compact(value):
    """The fixture uses ASCII keys/strings and integer numbers only.

    Preserving insertion order matches ObjectMapper.writeValueAsBytes(JsonNode)
    in ActiveBundleRefresher; the bundle hash covers the inner object only.
    """
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def reference():
    return {'semanticId': SEMANTIC_ID, 'semanticVersion': SEMANTIC_VERSION,
            'revisionId': REVISION_ID, 'publicationSetId': PUBLICATION_SET_ID}


def resolve_path():
    return '/api/semantic/v1/references:resolve?' + urlencode({
        name: value for name, value in reference().items() if name != 'semanticVersion'})


def seed_sql():
    """Exact fixed fixture IDs; duplicates fail rather than adopting prior data."""
    return f"""BEGIN;
INSERT INTO ouf_sem.semantic_artifact
 (artifact_id,semantic_id,artifact_type,namespace,local_name,owner_ref,
  authority_ref,origin_kind,created_at,retired_at)
VALUES ('{ARTIFACT_ID}','{SEMANTIC_ID}','PROPERTY','postboot-fixture','value',
 'disposable-fixture','disposable-fixture','OUF',transaction_timestamp(),NULL);
INSERT INTO ouf_sem.artifact_revision
 (revision_id,artifact_id,revision_no,lifecycle_status,semantic_version,
  label_json,description_json,definition_json,content_hash,created_by_subject,published_at)
VALUES ('{REVISION_ID}','{ARTIFACT_ID}',1,'ACTIVE','{SEMANTIC_VERSION}',
 '{{"it":"Postboot fixture"}}'::jsonb,'{{"it":"Disposable published reference"}}'::jsonb,
 '{{}}'::jsonb,encode(public.digest('disposable-postboot-reference'::bytea,'sha256'),'hex'),
 'disposable-fixture',transaction_timestamp());
INSERT INTO ouf_sem.artifact_active_revision
 (artifact_id,revision_id,activated_at,activated_by_subject)
VALUES ('{ARTIFACT_ID}','{REVISION_ID}',transaction_timestamp(),'disposable-fixture');
INSERT INTO ouf_sem.semantic_publication_set
 (publication_set_id,publication_no,checksum,created_at,created_by_subject,status)
VALUES ('{PUBLICATION_SET_ID}',nextval('ouf_sem.publication_no_seq'),
 encode(public.digest('{PUBLICATION_SET_ID}'::bytea,'sha256'),'hex'),
 transaction_timestamp(),'disposable-fixture','BUILDING');
INSERT INTO ouf_sem.semantic_publication_member
 (publication_set_id,semantic_id,revision_id)
VALUES ('{PUBLICATION_SET_ID}','{SEMANTIC_ID}','{REVISION_ID}');
UPDATE ouf_sem.semantic_publication_set
SET checksum=encode(public.digest('{SEMANTIC_ID}:{REVISION_ID}'::bytea,'sha256'),'hex'),
 status='PUBLISHED' WHERE publication_set_id='{PUBLICATION_SET_ID}';
COMMIT;
"""


def _window(now, valid_seconds):
    if type(now) is not int or now <= 0:
        raise ValueError('fixture epoch must be a positive integer')
    if type(valid_seconds) is not int or not 1 <= valid_seconds <= 3600:
        raise ValueError('fixture validity must be finite and at most one hour')
    return now, now + valid_seconds


def _instant(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def policy_envelope(now, valid_seconds=600):
    now, until = _window(now, valid_seconds)
    bundle = {'bundleId': BUNDLE_ID, 'version': 1, 'publishedAt': _instant(now),
        'capabilities': [{'capabilityId': CAPABILITY, 'operation': 'EXECUTE',
                          'requiredScope': CAPABILITY, 'allowedActors': ['SERVICE']}],
        'grants': [{'grantId': 'disposable-ingestion-semantic-read',
                    'capabilityId': CAPABILITY, 'tenantId': TENANT,
                    'subjectId': SERVICE_SUBJECT, 'servicePrincipalId': SERVICE_CLIENT,
                    'organizationId': None, 'validFrom': _instant(now - 1),
                    'validUntil': _instant(until)}]}
    return {'bundleId': BUNDLE_ID, 'bundleVersion': 1, 'activatedAt': _instant(now),
            'bundle': bundle, 'contentHash': hashlib.sha256(compact(bundle)).hexdigest()}


def service_claims(issuer, now, valid_seconds=600):
    now, until = _window(now, valid_seconds)
    origin = urlsplit(issuer)
    if (origin.scheme != 'https' or not origin.hostname or origin.username
            or origin.password or origin.query or origin.fragment):
        raise ValueError('disposable IAM issuer must use verified HTTPS')
    return {'iss': issuer, 'sub': SERVICE_SUBJECT, 'aud': [AUDIENCE],
            'iat': now, 'nbf': now - 1, 'exp': until,
            'tenant_id': TENANT, 'ouf_actor_type': 'SERVICE',
            'client_id': SERVICE_CLIENT, 'acr': '1', 'scope': CAPABILITY,
            'externalRoleRefs': []}


def _base64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=')


def public_jwk(private_key, kid=KEY_ID):
    """Accepts the native fixture's cryptography RSA private key in memory."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
        raise ValueError('disposable RSA signing key must be at least 2048 bits')
    public = private_key.public_key().public_numbers()
    integer = lambda n: _base64url(n.to_bytes((n.bit_length() + 7) // 8, 'big')).decode('ascii')
    return {'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': kid,
            'n': integer(public.n), 'e': integer(public.e)}


def rs256_jwt(private_key, claims, kid=KEY_ID):
    """Signs the disposable caller token; never substitutes a runtime principal."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    public_jwk(private_key, kid)
    message = (_base64url(compact({'alg': 'RS256', 'typ': 'JWT', 'kid': kid}))
               + b'.' + _base64url(compact(claims)))
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return (message + b'.' + _base64url(signature)).decode('ascii')
