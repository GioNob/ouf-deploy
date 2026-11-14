"""Durable installation receipt verification (D-029, D-031).

A dated receipt stays valid if its CREATION_ATTESTATION signature verifies
with the attestor key of the immutable base anchor, the mandate ledger shows
that key ACTIVE for that role and issuer at `attestedAt`, and the key was never
revoked. A missed renewal never stops the worker; a revocation always does.
Read-only: no signing key, no ledger write, no network.
"""
import hashlib
import re
import time
from .core import require


SIGNATURE_FIELDS = {'schema', 'algorithm', 'keyRef', 'role', 'issuerRef', 'installationRef', 'entityRef',
                    'payloadHash', 'signature'}
CLOCK_SKEW_SECONDS = 300
ROLE = 'CREATION_ATTESTATION'


def public_code(error, fallback):
    reason = str(error)
    return reason if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason) else fallback


def verify_receipt(raw, attested_at, verification, signature_directory, crypto, clock=time.time):
    """Return True only when the dated receipt is durably attested; never prints inputs."""
    from tools.semantic_authority_mandates import mandates as M
    from tools.semantic_provider_deployment_authentication import signing_bytes
    from .guard import protected_file
    ctx = verification['context']
    require(type(attested_at) is int and attested_at >= 0, 'DATED_INSTALLATION_RECEIPT_REQUIRED')
    now = clock()
    require(attested_at <= now + CLOCK_SKEW_SECONDS, 'RECEIPT_ATTESTED_IN_FUTURE')
    ledger = M.MandateLedger(verification['trustPolicy'], verification['mandateLedgerRoot'],
                             ctx['installationRef'], ctx['entityRef'], clock)
    try:
        ledger.refresh()
        require(ledger.view()['anchor']['schema'] == M.BASE_ANCHOR_SCHEMA, 'BASE_MANDATE_ANCHOR_REQUIRED')
        snapshot = ledger.snapshot()
        path = signature_directory / (hashlib.sha256(raw).hexdigest() + '.' + ROLE + '.json')
        signature_raw = protected_file(path, 4096, modes=(0o400, 0o600))
        record = M.decode(signature_raw, 4096)
        require(set(record) == SIGNATURE_FIELDS and record['schema'] == 'ouf.semantic-deployment-detached-signature.v1'
                and record['algorithm'] == 'Ed25519' and M.identity(record['keyRef'])
                and (record['role'], record['issuerRef'], record['installationRef'], record['entityRef'],
                     record['payloadHash'])
                == (ROLE, ctx['attestorRef'], ctx['installationRef'], ctx['entityRef'], hashlib.sha256(raw).hexdigest())
                and type(record['signature']) is str and re.fullmatch('[0-9a-f]{128}', record['signature']),
                'EXACT_DETACHED_SIGNATURE_REQUIRED')
        require(record['keyRef'] in ledger.view()['keys'], 'ATTESTOR_MANDATE_AT_ATTESTATION_REQUIRED')
        require(not ledger.ever_revoked(record['keyRef']), 'ATTESTOR_KEY_REVOKED')
        mandate = ledger.at(record['keyRef'], attested_at)
        require(mandate['state'] == 'ACTIVE' and ROLE in mandate['roles'] and mandate['issuerRef'] == ctx['attestorRef']
                and mandate['notBefore'] <= attested_at < mandate['expiresAt'],
                'ATTESTOR_MANDATE_AT_ATTESTATION_REQUIRED')
    except M.MandateDenied as error:
        require(False, public_code(error, 'MANDATE_LEDGER_UNPROVEN'))
    header = {k: v for k, v in record.items() if k != 'signature'}
    try:
        crypto.verify(signing_bytes(raw, header), bytes.fromhex(mandate['publicKey']), bytes.fromhex(record['signature']))
    except Exception as error:
        require(False, public_code(error, 'DETACHED_SIGNATURE_INVALID'))
    try:
        ledger.refresh()
        require(ledger.snapshot() == snapshot, 'MANDATE_LEDGER_CHANGED_DURING_VERIFICATION')
    except M.MandateDenied as error:
        require(False, public_code(error, 'MANDATE_LEDGER_UNPROVEN'))
    require(protected_file(path, 4096, modes=(0o400, 0o600)) == signature_raw, 'AUTHENTICATION_REVOKED_DURING_VERIFICATION')
    return True
