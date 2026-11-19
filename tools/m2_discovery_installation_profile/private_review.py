"""Offline private assembly of four owner proposals, before parent review.

This produces a review FRAGMENT, not a complete parent review or a runnable
installer. Existing native owners still authenticate every private binding,
current cohort/admission and finite authority before any effect.
"""
import copy,hashlib,os,re,stat
from pathlib import Path
from .custody_capture import decode,digest,encoded,require
from .native_profile import DiscoveryProfile,environment
from .frame_inputs import compile_inputs,ENGINE
from .frame import compile_policy,compilation_receipt
from .cohort_images import image_scope
from .gateway_runtime import component as gateway_component
from .mcp_runtime import compile_plan as mcp_plan,component as mcp_component
from compile_file_only_frame_policy import private_bridge_namespace_name
from tools.chatbot_file_cohort.gateway_runtime import APISIX_READINESS_POLICY
from tools.semantic_registry_operational_owner.guard import protected_file,private_json
from tools.semantic_registry_operational_owner.installation import directory,new_file

SCHEMA='ouf.discovery-private-review-inputs.v1'
MAXIMUM=4194304
UNPROVEN=['CURRENT_COMPLETE_COHORT_TLS_IAM_DB_TRUST_AND_FENCING',
    'PROVIDER_GATE_WINDOW_AND_SEALED_WORKER_REVIEW',
    'SIGNED_REGISTRY_CHILD_AND_EXACT_COMPLETE_PARENT_REVIEW',
    'CURRENT_PRIVATE_FILE_ARCHIVE_AND_GATEWAY_CONFIGURATION_CUSTODY',
    'CAPABILITY_PUBLICATION_AND_APPLICATION_E2E', 'BOOT_ROTATION_AND_TWO_CLIENT_ACCEPTANCE']


def hashed(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def absolute(value):
    require(type(value) is str and value.startswith('/') and str(Path(value))==value
        and '..' not in Path(value).parts and value!='/'
        and not any(ord(c)<33 or ord(c)==127 for c in value),'EXACT_PRIVATE_REVIEW_PATH_REQUIRED')
    return Path(value)


def assemble(inputs,input_hash,baseline):
    """Deterministic cross-owner binding; no IO, owner construction or signing."""
    fields={'schema','sourceClosureHash','installationInputsHash','desiredProfileHash',
        'cohortManifestHash','registry','images','gateway','mcp'}
    require(type(inputs) is dict and set(inputs)==fields and inputs['schema']==SCHEMA
        and hashed(input_hash) and digest(inputs)==input_hash and len(encoded(inputs))<=MAXIMUM
        and all(hashed(inputs[k]) for k in ('sourceClosureHash','installationInputsHash',
            'desiredProfileHash','cohortManifestHash')),'EXACT_HASH_BOUND_PRIVATE_REVIEW_INPUTS_REQUIRED')
    r=inputs['registry'];g=inputs['gateway'];m=inputs['mcp']
    require(type(r) is dict and set(r)=={'request','selection','contextTemplate'}
        and type(g) is dict and set(g)=={'plan','journalDirectory'}
        and type(m) is dict and set(m)=={'old','package','cohortId','environmentDelta',
            'journalDirectory','readinessDirectory'},'CLOSED_FOUR_OWNER_PREPARATION_INPUTS_REQUIRED')
    profile=DiscoveryProfile(r['request'],**r['selection'])
    template,launch=compile_inputs(baseline,r['request'],execution_profile=profile,engine_profile=ENGINE)
    context=r['contextTemplate']
    require(type(context) is dict and set(context)=={'schema','bundleParent','metadataParent',
        'networkNamespaceParent','cgroupDriver','storageParent','rootfsLayout'}
        and context['schema']=='ouf.semantic-docker-frame-context.v1'
        and context['rootfsLayout']=='docker-containerd-overlayfs-v1',
        'CID_FREE_REGISTRY_CONTEXT_TEMPLATE_REQUIRED')
    # Compile only a discarded structural validation with a synthetic CID.
    # A real CID/rootfs/native policy must be bound later by the existing owner.
    preview={k:v for k,v in context.items() if k!='rootfsLayout'}
    preview.update(containerId='0'*64,rootfsPath=context['storageParent']+'/rootfs/overlayfs/'+'0'*64,
        networkNamespaceName=private_bridge_namespace_name(r['request']))
    policy=compile_policy(template,launch,preview,execution_profile=profile)
    images=image_scope(inputs['images'])
    request_hash=digest(r['request'])
    require(images['registryCreationRequestHash']==request_hash
        and images['imageIds']['semantic']==r['request']['Image']
        and images['cohortManifestHash']==inputs['cohortManifestHash'],
        'SAME_REGISTRY_IMAGE_REQUEST_AND_COHORT_MANIFEST_REQUIRED')
    selected=inputs['images']['images'][1]
    plan=mcp_plan(old=m['old'],selected_image=selected,package=m['package'],cohort_id=m['cohortId'],
        environment_delta=m['environmentDelta'],registry_request_hash=request_hash,
        cohort_manifest_hash=inputs['cohortManifestHash'])
    mcp=mcp_component(plan,m['journalDirectory'],m['readinessDirectory'])
    values=environment(plan['replacement']['creationRequest']['Env'])
    require(values.get('MCP_OIDC_CLIENT_ID')==r['selection']['mcp_workload'],
        'SAME_REGISTRY_AND_MCP_DISCOVERY_WORKLOAD_REQUIRED')
    gateway=gateway_component(g['plan'],g['journalDirectory']);gp=g['plan']
    require(gp.get('readinessPolicy')==APISIX_READINESS_POLICY and gp.get('runtimeAuthorityIssued') is False
        and gp.get('sameExistingImageRequired') is True
        and gp['creationRequest']['Image']==gp['oldRuntimeBinding']['imageId'],
        'CURRENT_SAME_IMAGE_GATEWAY_PROPOSAL_REQUIRED')
    key=environment(gp['creationRequest']['Env']).get(gp.get('proposalKeyEnvironment'))
    require(type(key) is str and re.fullmatch('[0-9a-f]{64}',key)
        and hashlib.sha256(key.encode()).hexdigest()==gp['proposalKeyHash']
        ==r['selection']['files']['discoveryReceiptKey']['sha256'],
        'SAME_REGISTRY_GATEWAY_DISCOVERY_KEY_CONTENT_REQUIRED')
    require(m['old']['Id']!=gp['oldRuntimeBinding']['containerId'],
        'DISTINCT_MCP_AND_GATEWAY_PREDECESSORS_REQUIRED')
    journals=[*inputs['images']['journalDirectories'].values(),g['journalDirectory'],
        m['journalDirectory'],m['readinessDirectory']]
    paths=[absolute(p) for p in journals]
    require(all(not a.is_relative_to(b) and not b.is_relative_to(a)
        for i,a in enumerate(paths) for b in paths[i+1:]),'DISTINCT_NONSHADOWING_OWNER_JOURNALS_REQUIRED')
    protected=[absolute(v['source']) for v in r['selection']['files'].values()]
    protected += [absolute(r['selection'][k]['source']) for k in ('configtree','renewable_token')]
    protected += [absolute(v['archivePath']) for v in inputs['images']['images']]
    protected += [absolute(gp[k]['path']) for k in ('oldConfigBinding','newConfigBinding')]
    require(all(not a.is_relative_to(b) and not b.is_relative_to(a) for a in paths for b in protected),
        'OWNER_JOURNALS_MUST_NOT_SHADOW_PRIVATE_INPUTS_REQUIRED')
    result={'schema':'ouf.discovery-private-review-assembly.v1','inputHash':input_hash,
        **{k:inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')},
        'inputs':copy.deepcopy(inputs),'registry':{'executionProfile':profile.compiled,
            'template':template,'launch':launch,'contextTemplate':copy.deepcopy(context),
            'structuralValidation':{**compilation_receipt(template,launch,preview,policy),
                'syntheticCidUsedForValidationOnly':True,'nativePolicyPublished':False,
                'actualContainerIdBound':False,'distinctNewRegistryRequiredAtMaterialization':True}},
        'cohortReviewFragment':{'images':images,'gatewayRuntime':gateway,'mcp':mcp},'mcpPlan':plan,
        'compilerBinding':{'profile':'UNSEALED_DIRECT_LIBRARY_CALL','publisherTrustAccepted':False},
        'remainingRequirements':list(UNPROVEN),'completeParentReview':False,
        'inputsAuthenticated':False,'archiveCustodyProven':False,'gatewayNativeConfigurationValidated':False,
        'fullCohortProven':False,'nativeExecutorIntegrated':False,'signaturesIssued':0,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,
        'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    require(len(encoded(result))<=MAXIMUM,'BOUNDED_PRIVATE_REVIEW_ASSEMBLY_REQUIRED')
    return result


def receipt(assembly):
    """Public projection: hashes/counts only; no paths, identities or key data."""
    return {'schema':'ouf.discovery-private-review-assembly-receipt.v1','inputHash':assembly['inputHash'],
        'assemblyHash':digest(assembly),'componentHashes':{k:digest(v) for k,v in
            assembly['cohortReviewFragment'].items()},'registryTemplateHash':digest(assembly['registry']['template']),
        'compilerBindingHash':digest(assembly['compilerBinding']),
        'proposalCount':4,'completeParentReview':False,'inputsAuthenticated':False,
        'signaturesIssued':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'fullCohortProven':False,'applicationE2EProven':False,'automaticReplayAllowed':False,
        'budgetReset':False,'releaseAcceptance':False}


def read_input(path,expected):
    require(hashed(expected),'EXACT_PRIVATE_INPUT_HASH_REQUIRED')
    raw=protected_file(absolute(path),MAXIMUM,modes=(0o600,))
    value=decode(raw);require(digest(value)==expected,'PRIVATE_INPUT_CONTENT_HASH_DRIFT')
    return value


def prepare(input_path,input_hash,output_directory,baseline,*,inspect=False,compiler_binding=None):
    require(os.geteuid()==os.getegid()==0,'ROOT_PRIVATE_REVIEW_PREPARATION_REQUIRED')
    root=absolute(output_directory);source=absolute(input_path)
    require(not source.is_relative_to(root) and not root.is_relative_to(source),
        'DISTINCT_PRIVATE_REVIEW_INPUT_AND_OUTPUT_REQUIRED')
    inputs=read_input(input_path,input_hash);result=assemble(inputs,input_hash,baseline)
    if compiler_binding is not None:
        b=compiler_binding
        require(type(b) is dict and set(b)=={'profile','capsuleManifestHash','sourceManifestHash',
            'payloadHash','sourceRevisionClaim','publisherTrustAccepted'}
            and b['profile']=='CLOSED_PRIVATE_REVIEW_CAPSULE' and b['publisherTrustAccepted'] is False
            and all(hashed(b[k]) for k in ('capsuleManifestHash','sourceManifestHash','payloadHash'))
            and type(b['sourceRevisionClaim']) is str and re.fullmatch('[0-9a-f]{40}',b['sourceRevisionClaim']),
            'EXACT_UNAUTHENTICATED_COMPILER_CAPSULE_BINDING_REQUIRED')
        result['compilerBinding']=copy.deepcopy(b)
    public=receipt(result)
    claim={'schema':'ouf.discovery-private-review-assembly-claim.v1','inputHash':input_hash,
        'assemblyHash':public['assemblyHash'],'automaticReplayAllowed':False}
    for p in [*inputs['images']['journalDirectories'].values(),inputs['gateway']['journalDirectory'],
        inputs['mcp']['journalDirectory'],inputs['mcp']['readinessDirectory'],
        *[v['source'] for v in inputs['registry']['selection']['files'].values()],
        *[inputs['registry']['selection'][k]['source'] for k in ('configtree','renewable_token')],
        *[v['archivePath'] for v in inputs['images']['images']],
        *[inputs['gateway']['plan'][k]['path'] for k in ('oldConfigBinding','newConfigBinding')]]:
        selected=absolute(p)
        require(not root.is_relative_to(selected) and not selected.is_relative_to(root),
            'PRIVATE_OUTPUT_MUST_NOT_SHADOW_OWNER_INPUTS_OR_JOURNALS')
    if not inspect:
        with directory(root) as fd:
            # The durable claim consumes this preparation scope before payload.
            # Existing/partial output is never overwritten or completed here.
            require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700 and not os.listdir(fd),
                'EMPTY_PRIVATE_REVIEW_OUTPUT_REQUIRED_NO_REPLAY')
            new_file(fd,'preparation.claim.json',encoded(claim))
            new_file(fd,'assembly.private.json',encoded(result))
            require(read_input(input_path,input_hash)==inputs,'PRIVATE_REVIEW_INPUT_CHANGED_DURING_PREPARATION')
            new_file(fd,'receipt.json',encoded(public))
    with directory(root) as fd:
        require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700
            and set(os.listdir(fd))=={'preparation.claim.json','assembly.private.json','receipt.json'},
            'EXACT_PRIVATE_REVIEW_OUTPUT_DIRECTORY_REQUIRED')
        require(private_json(root/'preparation.claim.json')==claim
            and decode(protected_file(root/'assembly.private.json',MAXIMUM,modes=(0o600,)))==result
            and private_json(root/'receipt.json')==public,'EXACT_COMPLETED_PRIVATE_REVIEW_ASSEMBLY_REQUIRED')
    require(read_input(input_path,input_hash)==inputs,'PRIVATE_REVIEW_INPUT_CHANGED_DURING_PREPARATION')
    return public
