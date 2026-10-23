"""Pure installation material compiler. No signing, file writes or service start.

The authenticated installer must create these exact bytes and a real scoped
installation attestation. A proposal alone cannot start the runtime worker.
"""
import copy
import ssl
import time
from .core import require, digest
from .contract import SCHEMA, absolute


def public_ca_bundle(profile, expected_trust_hash, context):
    """Freeze the already approved IAM certificate set, without ambient extras.

    Preparation supplies the current issuer context. Neither a caller API CA
    nor a newly discovered root can silently replace the retained IAM trust.
    Returns public PEM bytes only, without writing files or making requests.
    """
    from tools.semantic_policy_token_owner.iam_admission import PinnedIamOpener
    clock=lambda:(time.time(),time.monotonic())
    original=PinnedIamOpener(profile,clock,context=context)
    require(original.trust_digest()==expected_trust_hash,'RETAINED_IAM_TRUST_SET_REQUIRED')
    certificates=sorted(context.get_ca_certs(binary_form=True))
    require(1<=len(certificates)<=1024,'BOUNDED_IAM_CA_SET_REQUIRED')
    raw=''.join(ssl.DER_cert_to_PEM_cert(cert) for cert in certificates).encode('ascii')
    require(len(raw)<=4194304,'BOUNDED_IAM_PUBLIC_CA_BUNDLE_REQUIRED')
    replay=ssl.create_default_context(cadata=raw.decode('ascii'))
    require(PinnedIamOpener(profile,clock,context=replay).trust_digest()==expected_trust_hash,
            'EXACT_EXPLICIT_IAM_TRUST_REPRODUCTION_REQUIRED')
    return raw


def configuration(proposal, *, sources, fence_binding, common_lock_identity, verification):
    require(type(proposal) is dict and proposal.get('schema')==SCHEMA
            and proposal.get('runtimeAuthorityIssued') is False
            and proposal.get('targetApplyAuthorized') is False
            and proposal.get('priorControlledGrantAttempts')==321,
            'REVIEWED_OPERATIONAL_INSTALLATION_PROPOSAL_REQUIRED')
    require(type(sources) is list and bool(sources), 'COMPLETE_OPERATIONAL_EXECUTION_BINDINGS_REQUIRED')
    for source in sources:
        require(type(source) is dict and set(source)=={'path','sha256','maximumBytes'},
                'EXACT_OPERATIONAL_EXECUTION_BINDING_REQUIRED')
        absolute(source['path'])
        require(type(source['sha256']) is str and len(source['sha256'])==64
                and set(source['sha256'])<=set('0123456789abcdef')
                and type(source['maximumBytes']) is int and 1<=source['maximumBytes']<=67108864,
                'BOUNDED_OPERATIONAL_EXECUTION_BINDING_REQUIRED')
    require(len({s['path'] for s in sources})==len(sources), 'UNIQUE_OPERATIONAL_EXECUTION_BINDINGS_REQUIRED')
    require(type(fence_binding) is dict and set(fence_binding)=={'path','value'}
            and type(fence_binding['value']) is dict,
            'EXACT_OPERATIONAL_SUCCESSOR_FENCE_REQUIRED')
    absolute(fence_binding['path'])
    require(type(common_lock_identity) is list and len(common_lock_identity)==9
            and all(type(v) is int and v>=0 for v in common_lock_identity),
            'EXACT_OPERATIONAL_COMMON_LOCK_IDENTITY_REQUIRED')
    require(type(verification) is dict and set(verification)=={'trustPolicy','openssl','context'},
            'PUBLIC_OPERATIONAL_RECEIPT_VERIFICATION_REQUIRED')
    require(proposal['sourceManifestHash']==digest(proposal['sourceManifest']),
            'OPERATIONAL_SOURCE_MANIFEST_CHANGED')
    return copy.deepcopy(dict(schema='ouf.registry-operational-token-configuration.v1',
        proposalHash=digest(proposal), sourceManifest=proposal['sourceManifest'], sources=sources,
        ownerInputs=proposal['ownerInputs'], policy=proposal['policy'], destinations=proposal['destinations'],
        priorControlledAttempts=321, predecessorInputsHash=proposal['inputsBinding']['sha256'],
        fenceBinding=fence_binding, commonLockIdentity=common_lock_identity,
        verification=verification, tlsCa=proposal['publicTlsCaBinding']))
