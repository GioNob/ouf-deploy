"""Pure installation material compiler. No signing, file writes or service start.

The authenticated installer must create these exact bytes and a real scoped
installation attestation. A proposal alone cannot start the runtime worker.
"""
import copy
from .core import require, digest
from .contract import SCHEMA, absolute


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
