"""Bind public Java trust bytes to the exact prepared material and IAM owner.

Pure compilation. Root custody, current owner installation/receipts and native
TLS admission remain separate. A caller-provided hash is not authority.
"""
import copy
import hashlib
from .audit import digest,env,path,require
from .public_truststore import build,_ca_certificates


def compile_trust(prepared,material_binding,owner_configuration,owner_binding,iam_pem,provider_pem,now):
    for binding,value in ((material_binding,prepared),(owner_binding,owner_configuration)):
        require(type(binding) is dict and set(binding)=={'path','sha256'}
                and digest(value)==binding['sha256'],'EXACT_PRIVATE_TRUST_INPUT_BINDINGS_REQUIRED')
        path(binding['path'])
    require(prepared.get('schema')=='ouf.m2-discovery-private-material-role-preparation.v1'
            and all(prepared.get(k) is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized',
                'historicalAuthorityReused','automaticReplayAllowed','budgetReset')),
            'EXACT_UNADMITTED_MATERIAL_ROLE_INPUTS_REQUIRED')
    roles=prepared.get('installationRoleMap',{});selected=prepared.get('selectedInstallationObservations',{})
    current=prepared.get('currentObservations',{})
    require(set(roles)==set(selected)=={'semantic','mcp','apisix','gateway-owner'}
            and len(set(roles.values()))==4 and len(current)==13
            and all(selected[role]==current.get(alias) for role,alias in roles.items()),
            'ONE_EXACT_SELECTED_INSTALLATION_VIEW_REQUIRED')
    c=owner_configuration
    require(c.get('schema')=='ouf.registry-operational-token-configuration.v1'
            and type(c.get('ownerInputs')) is dict and type(c.get('tlsCa')) is dict
            and set(c['tlsCa'])=={'path','sha256'},'EXACT_EXISTING_IAM_OWNER_CONFIGURATION_REQUIRED')
    path(c['tlsCa']['path'])
    require(type(iam_pem) is bytes and hashlib.sha256(iam_pem).hexdigest()==c['tlsCa']['sha256'],
            'IAM_PUBLIC_BUNDLE_MUST_MATCH_OWNER_CONFIGURATION')
    semantic=env(selected['semantic']);profile=c['ownerInputs']['iamProfile']
    require(profile['issuer']==semantic['OUF_IAM_ISSUER']
            and profile['token_endpoint']==semantic['OUF_SCHEMA_GOV_TOKEN_ENDPOINT'],
            'EXACT_SAME_CONFIGURED_IAM_ISSUER_AND_TOKEN_ENDPOINT_REQUIRED')
    ca_fingerprints=sorted(hashlib.sha256(v[0]).hexdigest() for v in _ca_certificates(iam_pem))
    require(digest(ca_fingerprints)==c['ownerInputs']['tlsTrustHash'],
            'EXACT_EXISTING_IAM_OWNER_CA_TRUST_DIGEST_REQUIRED')
    provider=prepared['preparedCopies']['publicProviderCa']
    path(provider['path'])
    require((provider['uid'],provider['gid'],provider['mode'])==(0,0,0o600)
            and provider['sha256']==prepared['projectionPlan']['publicTrustInput']['sha256'],
            'PREPARED_PUBLIC_PROVIDER_CA_COPY_PROVENANCE_REQUIRED')
    raw,receipt=build(iam_pem,ca_fingerprints,provider_pem,provider['sha256'],now)
    receipt=copy.deepcopy(receipt)
    receipt.update(schema='ouf.discovery-bound-public-trust-proposal.v1',
        materialBinding=copy.deepcopy(material_binding),iamOwnerConfigurationBinding=copy.deepcopy(owner_binding),
        iamTrustDigest=c['ownerInputs']['tlsTrustHash'],iamPublicCaBinding=copy.deepcopy(c['tlsCa']),
        providerPublicCaBinding={'path':provider['path'],'sha256':provider['sha256']},
        currentFileCustodyProvenHere=False,currentOwnerAdmissionProvenHere=False,
        installationRoleMapHash=digest(roles),automaticReplayAllowed=False,budgetReset=False)
    return raw,receipt
