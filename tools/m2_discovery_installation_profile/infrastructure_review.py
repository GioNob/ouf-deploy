"""Recompile the exact gate/provider/worker parent-review components offline.

Existing provider binding validation checks protected ancestor metadata. There
are no private content reads, runtime owner effects, admission or execution.
The Registry child, current cohort admission and capability-publication review
remain separate. Existing runtime owners consume these exact component schemas.
"""
import copy,os,stat
from pathlib import Path
from .custody_capture import decode,digest,encoded,require
from . import private_review as cohort
from .native_profile import DiscoveryProfile
from .gate_peer_window import window_scope
from .provider_installation_template import recompile as provider_template
from .provider_creation import creation_scope,creation_component,provider_sequence_scope
from .provider_profiles import recompile_scope,PROFILE_V2,FULL_HANDOFF_WINDOW
from .provider_runtime_installation import runtime_scope
from .provider_materialized_admission import admission_scope
from .lease_installation_template import recompile as worker_template
from .lease_materialization import paired_native_inputs
from .lease_start_owner import start_scope
from .lease_file_installation import publication_scope
from .lease_registration import registration_scope,registered_component
from .lease_attestation import issuance_scope,attested_component
from .lease_installation_phase import sequence_scope,sequenced_component
from tools.semantic_provider_deployment_protocol import identity
from tools.semantic_registry_operational_owner.guard import protected_file,private_json
from tools.semantic_registry_operational_owner.installation import directory,new_file

SCHEMA='ouf.discovery-infrastructure-review-inputs.v1'
MAXIMUM=4194304
MISSING=['SIGNED_REGISTRY_CHILD_AND_CURRENT_HUMAN_BINDINGS',
    'FULL_CURRENT_COHORT_TLS_IAM_DB_TRUST_FENCING_AND_CUSTODY',
    'CURRENT_PRIVATE_FILE_ARCHIVE_GATEWAY_AND_EXECUTABLE_CUSTODY',
    'GOVERNED_CAPABILITY_PUBLICATION_AND_COMPLETE_PARENT_REVIEW',
    'APPLICATION_E2E_BOOT_ROTATION_AND_TWO_CLIENT_ACCEPTANCE']


def shape(value,fields,reason):
    require(type(value) is dict and set(value)==set(fields),reason)


def _paths(base,provider,worker,start,managed,issuance,sequence,gate,creation,provider_sequence):
    p=provider['profile'];c=worker['configurationTemplate']
    roots=[gate['journalDirectory'],creation['journalDirectory'],p['journalDirectory'],p['registryRoot'],
        p['crypto']['signatureDirectory'],provider_sequence['journalDirectory'],start['journalDirectory'],
        managed['installation']['publication']['journalDirectory'],managed['registration']['journalDirectory'],
        issuance['journalDirectory'],issuance['signatureDirectory'],issuance['observationRoot'],sequence['journalDirectory'],
        worker['installationRoot'],c['ledgerRoot'],worker['sandboxRoot'],
        *base['inputs']['images']['journalDirectories'].values(),
        base['inputs']['gateway']['journalDirectory'],base['inputs']['mcp']['journalDirectory'],
        base['inputs']['mcp']['readinessDirectory']]
    paths=[cohort.absolute(p) for p in roots]
    require(all(not a.is_relative_to(b) and not b.is_relative_to(a)
        for i,a in enumerate(paths) for b in paths[i+1:]),'DISTINCT_INFRASTRUCTURE_AND_COHORT_OWNER_ROOTS_REQUIRED')
    selection=base['inputs']['registry']['selection'];gateway=base['inputs']['gateway']['plan']
    protected=[p['sourceRoot'],p['priorRuntimeConfigurationBinding']['path'],p['crypto']['policyBinding']['path'],
        p['preparerTemplate']['lockFile'],p['preparerTemplate']['coordinationJournal'],
        *worker['signingKeyPaths'],*[v['source'] for v in selection['files'].values()],
        selection['configtree']['source'],selection['renewable_token']['source'],
        *[v['archivePath'] for v in base['inputs']['images']['images']],
        gateway['oldConfigBinding']['path'],gateway['newConfigBinding']['path'],
        provider['template']['runtimeBinding']['path'],p['pythonBinding']['path'],p['frameSourceBinding']['path'],
        p['crypto']['opensslBinding']['path'],provider['runtime']['wrapperBinding']['path'],
        *p['preparerTemplate']['commands'].values(),start['manager']['path'],
        *[v['source'] for v in provider['template']['launch']['sources']]]
    guarded=[cohort.absolute(p) for p in protected]
    require(all(not a.is_relative_to(b) and not b.is_relative_to(a) for a in paths for b in guarded),
        'OWNER_ROOTS_MUST_NOT_SHADOW_SIGNING_KEYS_SOURCE_OR_RETAINED_INPUTS')
    return roots,protected


def assemble(inputs,input_hash,baseline):
    shape(inputs,('schema','cohortInputs','gate','provider','worker','context'),
        'EXACT_INFRASTRUCTURE_REVIEW_INPUTS_REQUIRED')
    require(inputs['schema']==SCHEMA and cohort.hashed(input_hash) and digest(inputs)==input_hash
        and len(encoded(inputs))<=MAXIMUM,'HASH_BOUND_INFRASTRUCTURE_REVIEW_REQUIRED')
    g,p,w,context=(inputs[k] for k in ('gate','provider','worker','context'))
    shape(g,('journalDirectory','maximumSeconds'),'EXPLICIT_GATE_SELECTION_REQUIRED')
    shape(p,('template','profile','creationJournalDirectory','runtime','sequenceJournalDirectory'),
        'EXPLICIT_PROVIDER_REVIEW_SELECTION_REQUIRED')
    shape(w,('template','start','publicationDirectory','registration','issuance','sequenceDirectory'),
        'EXPLICIT_WORKER_REVIEW_SELECTION_REQUIRED')
    shape(p['runtime'],('wrapperBinding','commonLockIdentity','nativeReadSeconds'),'EXPLICIT_PROVIDER_RUNTIME_SELECTION_REQUIRED')
    shape(w['start'],('unitName','manager','journalDirectory'),'EXPLICIT_WORKER_START_SELECTION_REQUIRED')
    shape(w['registration'],('unitDirectory','journalDirectory'),'EXPLICIT_WORKER_REGISTRATION_SELECTION_REQUIRED')
    shape(w['issuance'],('directory','signatureDirectory','observationRoot','keyBinding','keyRef'),
        'EXPLICIT_WORKER_ISSUANCE_SELECTION_REQUIRED')
    shape(context,('installationRef','entityRef','intentIssuerRef','approvalIssuerRef','attestorRef'),
        'EXACT_PARENT_IDENTITY_CONTEXT_REQUIRED')
    require(all(identity(v) for v in context.values()),'EXPLICIT_PARENT_IDENTITIES_REQUIRED')
    base=cohort.assemble(inputs['cohortInputs'],digest(inputs['cohortInputs']),baseline)
    declared=base['inputs'];reg=declared['registry'];profile=DiscoveryProfile(reg['request'],**reg['selection'])
    provider=provider_template(p['template']);worker=worker_template(w['template'])
    gate=window_scope(digest(reg['request']),profile.sha256,declared['sourceClosureHash'],
        g['journalDirectory'],g['maximumSeconds'])
    creation=creation_scope(provider,gate,p['creationJournalDirectory'])
    scoped=recompile_scope(provider,creation,p['profile']);recipe=scoped['registryRecipe']
    require(scoped['schema']==PROFILE_V2 and encoded(scoped['handoffWindow'])==encoded(FULL_HANDOFF_WINDOW)
        and scoped['maximumSeconds']<=gate['maximumSeconds'],
        'SEPARATE_FINITE_FULL_HANDOFF_PROFILE_WITHIN_GATE_REQUIRED')
    require(provider['sourceClosureHash']==worker['sourceClosureHash']==recipe['sourceClosureHash']
        ==declared['sourceClosureHash'] and recipe['executionProfileHash']==profile.sha256
        and recipe['template']==base['registry']['template'] and recipe['launch']==base['registry']['launch']
        and recipe['dockerContext']==base['registry']['contextTemplate'],
        'SAME_INDEPENDENT_REGISTRY_RECIPE_SOURCE_AND_FRAME_REQUIRED')
    c=worker['configurationTemplate']
    require(c['installationInputsHash']==declared['installationInputsHash']
        and c['desiredProfileHash']==declared['desiredProfileHash']
        and c['verification']['context']=={k:context[k] for k in ('installationRef','entityRef','attestorRef')}
        and c['verification']['trustPolicy']['sha256']==scoped['crypto']['policyBinding']['sha256']
        and c['verification']['openssl']==scoped['crypto']['opensslBinding'],
        'SAME_PARENT_INPUTS_DESIRED_PROFILE_AND_PUBLIC_VERIFICATION_REQUIRED')
    paired_native_inputs(worker,scoped,reg['request'],p['runtime']['commonLockIdentity'])
    runtime=runtime_scope(scoped,wrapper_binding=p['runtime']['wrapperBinding'],
        common_lock_identity=p['runtime']['commonLockIdentity'],native_read_seconds=p['runtime']['nativeReadSeconds'])
    admission=admission_scope(worker,provider,creation,scoped)
    provider_sequence=provider_sequence_scope(creation,runtime,admission,journal_directory=p['sequenceJournalDirectory'])
    composed=creation_component(creation,{'schema':'ouf.discovery-composed-provider-installation-scope.v2',
        'creation':creation,'installation':runtime,'admission':admission,'sequence':provider_sequence})
    start=start_scope(worker,unit_name=w['start']['unitName'],manager=w['start']['manager'],
        directory=w['start']['journalDirectory'])
    files=publication_scope(worker,start,w['publicationDirectory'])
    registration=registration_scope(worker,start,unit_directory=w['registration']['unitDirectory'],
        journal_directory=w['registration']['journalDirectory'])
    managed=registered_component(worker,files,registration)
    require(w['issuance']['keyBinding']==scoped['keys']['attestor']
        and w['issuance']['keyRef']==scoped['keyRefs']['attestor'],
        'SAME_REVIEWED_ATTESTOR_BINDING_FOR_PROVIDER_AND_WORKER_REQUIRED')
    issuance=issuance_scope(worker,admission,directory=w['issuance']['directory'],
        signature_directory=w['issuance']['signatureDirectory'],observation_root=w['issuance']['observationRoot'],
        key_binding=w['issuance']['keyBinding'],key_ref=w['issuance']['keyRef'])
    attested=attested_component(worker,managed,issuance)
    sequence=sequence_scope(worker,attested,directory=w['sequenceDirectory'])
    parts={'registryGatePeerWindow':gate,'providerInstallation':composed,
        'operationalLeaseInstallation':sequenced_component(worker,attested,sequence)}
    roots,protected=_paths(base,{**p,'profile':scoped},worker,start,managed,issuance,sequence,gate,creation,provider_sequence)
    require(len(encoded(parts))<=131072,'BOUNDED_PARENT_COMPONENTS_REQUIRED')
    result={'schema':'ouf.discovery-infrastructure-review-fragment.v1','inputHash':input_hash,
        'inputs':copy.deepcopy(inputs),'cohortAssembly':base,'parts':parts,
        'registryRecipeHash':digest(recipe),'storageRoots':roots,'protectedInputs':protected,
        'compilerBinding':{'profile':'UNSEALED_INFRASTRUCTURE_LIBRARY_CALL','publisherTrustAccepted':False},
        'remainingRequirements':list(MISSING),'completeParentReview':False,'inputsAuthenticated':False,
        'nativeAcceptancesProven':False,'signaturesIssued':0,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,
        'applicationE2EProven':False,'releaseAcceptance':False}
    require(len(encoded(result))<=MAXIMUM,'BOUNDED_INFRASTRUCTURE_REVIEW_FRAGMENT_REQUIRED')
    return result


def receipt(result):
    return {'schema':'ouf.discovery-infrastructure-review-receipt.v1','inputHash':result['inputHash'],
        'assemblyHash':digest(result),'partHashes':{k:digest(v) for k,v in result['parts'].items()},
        'cohortAssemblyHash':digest(result['cohortAssembly']),'compilerBindingHash':digest(result['compilerBinding']),
        'parentComponentCount':3,'completeParentReview':False,'inputsAuthenticated':False,
        'nativeAcceptancesProven':False,'signaturesIssued':0,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,
        'applicationE2EProven':False,'releaseAcceptance':False}


def prepare(input_path,input_hash,output_directory,baseline,*,inspect=False,compiler_binding=None):
    require(os.geteuid()==os.getegid()==0,'ROOT_INFRASTRUCTURE_REVIEW_PREPARATION_REQUIRED')
    source,root=cohort.absolute(input_path),cohort.absolute(output_directory)
    require(not source.is_relative_to(root) and not root.is_relative_to(source),'SEPARATE_INFRASTRUCTURE_INPUT_OUTPUT_REQUIRED')
    inputs=cohort.read_input(input_path,input_hash);result=assemble(inputs,input_hash,baseline)
    if compiler_binding is not None:
        b=compiler_binding
        shape(b,('profile','capsuleManifestHash','sourceManifestHash','payloadHash','sourceRevisionClaim','publisherTrustAccepted'),
            'EXACT_INFRASTRUCTURE_COMPILER_BINDING_REQUIRED')
        require(b['profile']=='CLOSED_PRIVATE_REVIEW_CAPSULE' and b['publisherTrustAccepted'] is False
            and all(cohort.hashed(b[k]) for k in ('capsuleManifestHash','sourceManifestHash','payloadHash'))
            and type(b['sourceRevisionClaim']) is str and len(b['sourceRevisionClaim'])==40
            and set(b['sourceRevisionClaim'])<=set('0123456789abcdef'),'EXACT_CLOSED_INFRASTRUCTURE_COMPILER_REQUIRED')
        result['compilerBinding']=copy.deepcopy(b)
    for path in result['storageRoots']+result['protectedInputs']:
        selected=cohort.absolute(path)
        require(not root.is_relative_to(selected) and not selected.is_relative_to(root),
            'REVIEW_OUTPUT_MUST_NOT_SHADOW_OWNER_PATHS')
    public=receipt(result);claim={'schema':'ouf.discovery-infrastructure-preparation-claim.v1',
        'inputHash':input_hash,'assemblyHash':public['assemblyHash'],'automaticReplayAllowed':False}
    if not inspect:
        with directory(root) as fd:
            require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700 and not os.listdir(fd),'EMPTY_PRIVATE_INFRASTRUCTURE_OUTPUT_REQUIRED')
            new_file(fd,'preparation.claim.json',encoded(claim))
            new_file(fd,'assembly.private.json',encoded(result))
            require(cohort.read_input(input_path,input_hash)==inputs,'INFRASTRUCTURE_INPUT_CHANGED_DURING_PREPARATION')
            new_file(fd,'receipt.json',encoded(public))
    with directory(root) as fd:
        require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700
            and set(os.listdir(fd))=={'preparation.claim.json','assembly.private.json','receipt.json'},
            'EXACT_PRIVATE_INFRASTRUCTURE_OUTPUT_REQUIRED')
        require(private_json(root/'preparation.claim.json')==claim
            and decode(protected_file(root/'assembly.private.json',MAXIMUM,modes=(0o600,)))==result
            and private_json(root/'receipt.json')==public,'EXACT_COMPLETED_INFRASTRUCTURE_ASSEMBLY_REQUIRED')
    require(cohort.read_input(input_path,input_hash)==inputs,'INFRASTRUCTURE_INPUT_CHANGED_DURING_PREPARATION')
    return public
