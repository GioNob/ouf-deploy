"""Issue bounded role records ONLY from an explicitly approved root mandate.

Existing authority keys/policy only. No image inspection, implicit acceptance,
key generation, runtime configuration, container operation or lease grant.
The root mandate's author owns publisher/dependency and complete frame review.
"""
import copy
import os
import re
from pathlib import Path
import time

from authenticate_provider_transaction import AUTHORITIES, TARGETS, TransactionDenied, require, same
from assemble_provider_profiles import digest, encoded
from compile_creation_frame_policy import compile_policy
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator, decode, private_bytes
from tools.semantic_provider_deployment_protocol import window, validate_intent, identity
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_installer_approval import publish_once

INPUTS = {'template','launch','context','framePolicy','preparerTemplate','deploymentConstraints',
          'provenanceEvidence','dependencyEvidence'}
SCOPES = {'installer':['TARGET_REVIEW','DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'],
          'attestor':['LIVE_NODE_ACCEPTANCE']}


def issue_role_authority(role, mandate_binding, explicitly_approved_hash, records, authority,
                         sources, observer_raw, verifier, output_directory, clock=time.time, *, validate_only=False):
    """The approved hash is explicit root invocation, NOT a CI/acceptance flag.

    Read the root-private operator mandate; its exact scope must match all
    independently prepared documents. The caller must pin target authority and
    source custody before calling this helper, just as for CreationIntentIssuer.
    Claim is published before the first authority-key read. No retry in place.
    """
    stage='VERIFY_EXPLICIT_ROOT_ROLE_MANDATE'
    require(os.geteuid()==0,stage,'ROOT_ROLE_ISSUANCE_REQUIRED',role)
    require(type(verifier) is DetachedAuthenticator and role in TARGETS and set(records)==INPUTS,
            stage,'EXACT_ROLE_ISSUANCE_INPUTS_REQUIRED',role)
    require(authority['authorities']==AUTHORITIES and set(authority['keyBindings'])==set(authority['keyRefs'])=={'installer','attestor'},
            stage,'EXISTING_SEPARATE_ROLE_AUTHORITIES_REQUIRED',role)
    require(type(explicitly_approved_hash) is str and re.fullmatch('[0-9a-f]{64}',explicitly_approved_hash)
            and set(mandate_binding)=={'path','sha256'} and mandate_binding['sha256']==explicitly_approved_hash,
            stage,'EXPLICIT_APPROVED_ROOT_MANDATE_HASH_REQUIRED',role)
    mandate_raw=private_bytes(Path(mandate_binding['path']))
    require(digest(mandate_raw)==explicitly_approved_hash,stage,'ROOT_ROLE_MANDATE_HASH_DRIFT',role)
    mandate=decode(mandate_raw,131072)
    ctx=authority['authorities'];target=TARGETS[role]
    source_hashes={**{name:digest(raw) for name,raw in sources.items()},'frame-observer.py':digest(observer_raw)}
    input_hashes={name:digest(raw) for name,raw in records.items()}
    expected={'schema':'ouf.semantic-provider-transaction-role-mandate.v1','role':role,
        'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],**target,
        'inputHashes':input_hashes,'sourceClosureHash':digest(encoded(source_hashes)),
        'roleSigningScopes':SCOPES,'state':'ACTIVE',
        'decision':'ACCEPT_PROVIDER_IMAGE_AND_COMPLETE_FRAME_AND_CONTROLLED_ADMISSION'}
    require(set(mandate)==set(expected)|{'transactionId','approvalRef','issuedAt','expiresAt'},
            stage,'EXACT_ROOT_ROLE_MANDATE_REQUIRED',role)
    same(mandate,expected,stage,'ROOT_ROLE_REVIEW_SCOPE_DRIFT',role)
    require(type(mandate['transactionId']) is str and re.fullmatch('[0-9a-f]{64}',mandate['transactionId'])
            and identity(mandate['approvalRef']),stage,'EXPLICIT_TRANSACTION_AND_APPROVAL_REFS_REQUIRED',role)
    window(mandate,clock())
    values={name:decode(raw,131072) for name,raw in records.items()}
    policy=compile_policy(values['template'],values['launch'],values['context'])
    require(encoded(policy)==records['framePolicy'] and values['context']['containerId']==target['containerId'],
            stage,'INDEPENDENT_COMPLETE_FRAME_REQUIRED',role)
    candidate=values['preparerTemplate']['candidate']
    same(candidate,{'containerId':target['containerId'],'transactionId':mandate['transactionId']},
         stage,'REVIEWED_CANDIDATE_TRANSACTION_DRIFT',role)
    now=int(clock());expires=mandate['expiresAt']
    review={'schema':'ouf.semantic-provider-target-review.v1','issuerRef':ctx['approvalIssuerRef'],
        'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],'role':role,**target,
        **{name+'Hash':sha for name,sha in input_hashes.items()},'sourceClosureHash':mandate['sourceClosureHash'],
        'decision':'ACCEPT_PROVIDER_IMAGE_AND_COMPLETE_FRAME','state':'ACTIVE','issuedAt':now,'expiresAt':expires}
    intent={'schema':'ouf.semantic-deployment-intent.v1','issuerRef':ctx['intentIssuerRef'],
        'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],'containerId':target['containerId'],
        'transactionId':mandate['transactionId'],'artifactHash':digest(records['framePolicy']),
        'deploymentConstraintsHash':digest(records['deploymentConstraints']),
        'transportHash':digest(encoded({k:candidate[k] for k in ('networkBindings','transport','tableName')})),
        'runtimeExecutableHash':candidate['runtimeBinding']['sha256'],'issuedAt':now,'expiresAt':expires,
        'infrastructureAuthorized':True,'creationAuthorized':True,'applicationStartAuthorized':False}
    raw_intent=encoded(intent)
    # Structural validation before keys; actual external verification follows
    # issuance. This exact-byte callback cannot grant target acceptance.
    validate_intent(raw_intent,ctx,lambda raw,*args:raw==raw_intent,clock)
    scope={k:intent[k] for k in ('installationRef','entityRef','containerId','transactionId','artifactHash',
                                'deploymentConstraintsHash','transportHash','runtimeExecutableHash')}
    scope['intentHash']=digest(raw_intent)
    live={'schema':'ouf.semantic-node-live-acceptance-authorization.v1','issuerRef':ctx['attestorRef'],**scope,
        'applicationHash':digest(encoded(policy['expectedOci'])),'rootfsSeal':copy.deepcopy(target['runtimeSeal']),
        'generationBinding':'OBSERVED_CREATED','state':'ACTIVE','mandateIssuanceAuthorized':True,
        'attestationAuthorized':True,'completeCreationAccepted':True,'issuedAt':now,'expiresAt':expires}
    final={'schema':'ouf.semantic-final-approval-mandate.v1','issuerRef':ctx['approvalIssuerRef'],**scope,
        'approvalRef':mandate['approvalRef'],'state':'ACTIVE','issuanceAuthorized':True,
        'applicationStartAuthorized':True,'issuedAt':now,'expiresAt':expires}
    payloads={'review':encoded(review),'intent':raw_intent,'liveAuthorization':encoded(live),'finalMandate':encoded(final)}
    if validate_only:
        # Pair-wide preflight can validate both independent root mandates before
        # either key is read. This mode publishes/signs nothing and confers no
        # authority. Actual issuance still repeats custody/window checks.
        return {'role':role,'mandateHash':explicitly_approved_hash,
                'recordHashes':{name:digest(raw) for name,raw in payloads.items()},
                'signaturesIssued':0,'privateKeysRead':0,'notReleaseAcceptance':True}
    filenames={'review':'review.json','intent':'intent.json','liveAuthorization':'live-authorization.json','finalMandate':'final-mandate.json'}
    directory=Path(output_directory)
    require(all(not os.path.lexists(directory/name) for name in filenames.values()),
            stage,'EXISTING_ROLE_AUTHORITY_EVIDENCE_PRESERVED',role)
    claim={'schema':'ouf.semantic-provider-role-issuance-claim.v1','state':'ISSUING','mandateHash':explicitly_approved_hash,
        'role':role,'containerId':target['containerId'],'transactionId':mandate['transactionId'],
        'recordHashes':{name:digest(raw) for name,raw in payloads.items()},'startPerformed':False}
    publish_once(directory/'role-issuance-claim.json',encoded(claim),'DO_NOT_REPLAY_TARGET_ROLE_ISSUANCE')
    policy_raw=verifier.read_policy()
    bindings={}
    for name,signature_role,key,issuer in (
        ('review','FINAL_DEPLOYMENT_APPROVAL','installer',ctx['approvalIssuerRef']),
        ('intent','DEPLOYMENT_INTENT','installer',ctx['intentIssuerRef']),
        ('liveAuthorization','CREATION_ATTESTATION','attestor',ctx['attestorRef']),
        ('finalMandate','FINAL_DEPLOYMENT_APPROVAL','installer',ctx['approvalIssuerRef'])):
        stage='ISSUE_TARGET_ROLE_RECORD'
        window(mandate,clock())
        require(private_bytes(Path(mandate_binding['path']))==mandate_raw and verifier.read_policy()==policy_raw,
                stage,'ROOT_MANDATE_OR_POLICY_CHANGED_DURING_ISSUANCE',role)
        raw=payloads[name]
        signer=ExistingEd25519Signer(authority['keyBindings'][key],authority['keyRefs'][key],verifier,
            {'role':signature_role,'issuerRef':issuer,'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef']})
        signature=signer.sign(raw)
        signature_path=verifier.signature_directory/(digest(raw)+'.'+signature_role+'.json')
        publish_once(signature_path,signature,'EXISTING_TARGET_ROLE_SIGNATURE_PRESERVED')
        path=directory/filenames[name];publish_once(path,raw,'EXISTING_TARGET_ROLE_RECORD_PRESERVED')
        require(verifier(raw,signature_role,issuer,ctx['installationRef'],ctx['entityRef']) is True,
                stage,'ISSUED_TARGET_ROLE_RECORD_UNPROVEN',role)
        bindings[name]={'path':str(path),'sha256':digest(raw)}
    window(mandate,clock())
    require(private_bytes(Path(mandate_binding['path']))==mandate_raw and verifier.read_policy()==policy_raw,
            stage,'ROOT_MANDATE_OR_POLICY_CHANGED_DURING_ISSUANCE',role)
    receipt={'schema':'ouf.semantic-provider-role-authority-issuance.v1','role':role,'status':'ROLE_RECORDS_ISSUED',
        'mandateHash':explicitly_approved_hash,'records':bindings,'signaturesIssued':4,'keysGenerated':0,
        'runtimeChanged':False,'containerLifecycleOperations':0,'startPerformed':False,'notReleaseAcceptance':True}
    publish_once(directory/'role-issuance-receipt.json',encoded(receipt),'EXISTING_ROLE_ISSUANCE_RECEIPT_PRESERVED')
    return receipt
