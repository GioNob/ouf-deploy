"""Compose a fresh six-part review with every current native input binding.

The frozen parent compiler and Registry child bytes remain unchanged. This
compiler validates and binds declarations only: no files, sockets, native
owners, credentials, signatures or execution authority are admitted here.
"""
import base64,copy,os,stat
from urllib.parse import urlsplit
from . import parent_review,current_cohort,current_databases,current_publisher
from . import current_tls,current_iam_workload,current_retirement
from .custody_capture import decode,digest,encoded,require
from .native_profile import DiscoveryProfile
from .parent_authority import review_scope
from .private_review import absolute,hashed
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import protected_file,private_json

SCHEMA='ouf.discovery-current-parent-review-inputs.v1'
BINDERS=(('databases',current_databases.bind_database_inputs),
    ('custody',current_publisher.bind_publisher_inputs),
    ('tlsIam',current_tls.bind_tls_inputs),
    ('iamWorkload',current_iam_workload.bind_iam_workload_inputs),
    ('retirementAndBackup',current_retirement.bind_retirement_inputs))
COMMON=('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')


def assemble(inputs,input_hash,baseline,primitives):
    require(type(inputs) is dict and set(inputs)=={'schema','parentInputs','runtimeInputs','additionalInputs'}
        and inputs['schema']==SCHEMA and hashed(input_hash) and digest(inputs)==input_hash
        and len(encoded(inputs))<=10485760,'EXACT_HASH_BOUND_CURRENT_PARENT_REVIEW_INPUTS_REQUIRED')
    additions=inputs['additionalInputs']
    require(type(additions) is dict and set(additions)==current_cohort.ADDITIONAL_INPUTS,
        'ALL_FIVE_EXACT_CURRENT_NATIVE_INPUT_SETS_REQUIRED')
    original=parent_review.assemble(inputs['parentInputs'],digest(inputs['parentInputs']),baseline,primitives)
    declared=original['infrastructureAssembly']['cohortAssembly']['inputs']
    runtime=copy.deepcopy(inputs['runtimeInputs']);current_cohort.validate_inputs(runtime)
    require(all(runtime[k]==declared[k] for k in COMMON),
        'SAME_COMPLETE_PARENT_AND_CURRENT_RUNTIME_INPUTS_REQUIRED')
    # Existing bindings may be checked, never replaced or silently discarded.
    for name,binder in BINDERS:runtime=binder(runtime,additions[name])
    require(set(runtime['additionalInputsHashes'])==current_cohort.ADDITIONAL_INPUTS,
        'EXACT_COMPLETE_CURRENT_NATIVE_INPUT_BINDINGS_REQUIRED')
    profile=DiscoveryProfile(declared['registry']['request'],**declared['registry']['selection'])
    profile_hash=profile.verify(declared['registry']['request'])
    require(additions['tlsIam']['executionProfileHash']==additions['iamWorkload']['executionProfileHash']==profile_hash,
        'SAME_CURRENT_TLS_IAM_AND_REVIEWED_EXECUTION_PROFILE_REQUIRED')
    require(additions['tlsIam']['trustStoreBindingHash']==digest(declared['registry']['selection']['files']['tlsTrustStore']),
        'SAME_REVIEWED_REGISTRY_PUBLIC_TRUSTSTORE_REQUIRED')
    require(additions['databases']['dockerBinding']==additions['iamWorkload']['dockerBinding'],
        'SAME_REVIEWED_CURRENT_DATABASE_AND_IAM_ENGINE_CLIENT_REQUIRED')
    iam=additions['iamWorkload'];authorization=original['publicationAssembly']['authorizationPlan']['selection']
    refs=profile.selection['references']
    require(authorization['keycloakContainer']==iam['keycloakRuntimeBinding']['containerId']
        and authorization['docker']==iam['dockerBinding'] and authorization['realm']==iam['realm']
        and authorization['issuer']==refs['OUF_IAM_ISSUER']
        and urlsplit(refs['OUF_IAM_ISSUER']).path=='/realms/'+iam['realm']
        and refs['OUF_SCHEMA_GOV_WORKLOAD_SCOPE'] in iam['expectedScopes']
        and refs['OUF_IAM_AUDIENCE'] in iam['expectedAudiences'],
        'SAME_PUBLICATION_AUTHORIZATION_AND_CURRENT_WORKLOAD_IAM_IDENTITIES_REQUIRED')
    require(runtime['peers']['mcp']['runtimeBinding']==original['infrastructureAssembly']['cohortAssembly']['mcpPlan']['replacement']['oldRuntimeBinding']
        and runtime['peers']['apisix']['runtimeBinding']==declared['gateway']['plan']['oldRuntimeBinding'],
        'SAME_REVIEWED_CURRENT_MCP_AND_GATEWAY_PREDECESSORS_REQUIRED')
    child=decode(base64.b64decode(inputs['parentInputs']['registryChild']['authorityBase64'],validate=True))
    require(additions['retirementAndBackup']['backupIntentHash']==child['phaseIntentHashes']['FENCED_BACKUP'],
        'SAME_EXACT_SIGNED_CHILD_BACKUP_INTENT_REQUIRED')
    review=current_cohort.bind_runtime_review(original['review'],runtime);scope=review_scope(review)
    require(review['components']['registryCutover']==original['review']['components']['registryCutover']
        and all(review['components'][k]==v for k,v in original['review']['components'].items() if k!='cohortInstallation'),
        'ONLY_CURRENT_COHORT_REVIEW_BINDING_MAY_CHANGE')
    result=copy.deepcopy(original)
    result.update(schema='ouf.discovery-current-parent-review-assembly.v1',inputHash=input_hash,
        review=review,scope=scope,baseParentAssemblyHash=digest(original),baseParentReviewHash=original['scope']['reviewHash'],
        runtimeInputs=runtime,additionalInputs=copy.deepcopy(additions),
        currentNativeInputsBound=True,currentNativeInputsAuthenticated=False,
        artifactMembershipProven=False,actualWorkloadBearerAdmitted=False,
        nativeCheckpointControllerIntegrated=False)
    require(len(encoded(result))<=20971520,'BOUNDED_CURRENT_PARENT_REVIEW_ASSEMBLY_REQUIRED')
    return result


def receipt(result):
    """Public hashes only; private credentials/paths never enter the receipt."""
    return {'schema':'ouf.discovery-current-parent-review-receipt.v1','inputHash':result['inputHash'],
        'assemblyHash':digest(result),'baseParentAssemblyHash':result['baseParentAssemblyHash'],
        'baseParentReviewHash':result['baseParentReviewHash'],'reviewHash':result['scope']['reviewHash'],
        'componentScopeHashes':copy.deepcopy(result['scope']['componentScopeHashes']),
        'nativeRuntimeInputsHash':digest(result['runtimeInputs']),
        'additionalInputsHashes':copy.deepcopy(result['runtimeInputs']['additionalInputsHashes']),
        'completeParentReviewShape':True,'currentNativeInputsBound':True,
        'currentNativeInputsAuthenticated':False,'currentNativeAdmissionProven':False,
        'artifactMembershipProven':False,'actualWorkloadBearerAdmitted':False,
        'nativeCheckpointControllerIntegrated':False,'publicationExecutorIntegrated':False,
        'signaturesIssued':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'capabilitiesPublished':False,'applicationE2EProven':False,'releaseAcceptance':False}


def protected_references(inputs,result):
    """Declared host paths; container-internal session paths are not host paths."""
    infra=result['infrastructureAssembly'];pub=result['publicationAssembly']['component']
    paths=infra['storageRoots']+infra['protectedInputs']+list(pub['journalDirectories'].values())
    paths+=[inputs['parentInputs']['registryChild']['humanManifestBinding']['path'],
        inputs['runtimeInputs']['engineBinding']['socketPath']]
    additions=inputs['additionalInputs'];db=additions['databases'];custody=additions['custody']
    paths += [db['dockerBinding']['path'],additions['iamWorkload']['dockerBinding']['path'],
        additions['iamWorkload']['readOnlyAdmin']['python']['path'],
        custody['ghExecutable']['path'],custody['trustedRoot']['path']]
    paths += [ref['path'] for ref in additions['tlsIam']['caFiles'].values()]
    for row in db['modules']:
        paths.append(row['artifact']['root']);paths += [r['path'] for r in row['artifact']['files']]
    for row in custody['artifacts']:paths += [row[k]['path'] for k in ('subject','bundle')]
    return paths


def prepare(input_path,input_hash,output_directory,baseline,primitives,*,inspect=False,compiler_binding=None):
    require(os.geteuid()==os.getegid()==0,'ROOT_CURRENT_PARENT_REVIEW_PREPARATION_REQUIRED')
    root,source=absolute(output_directory),absolute(input_path)
    require(not root.is_relative_to(source) and not source.is_relative_to(root),
        'SEPARATE_CURRENT_PARENT_REVIEW_INPUT_OUTPUT_REQUIRED')
    def read():
        value=decode(protected_file(source,10485760,modes=(0o600,)))
        require(digest(value)==input_hash,'CURRENT_PARENT_REVIEW_INPUT_HASH_DRIFT');return value
    inputs=read();result=assemble(inputs,input_hash,baseline,primitives)
    if compiler_binding is not None:
        binding=compiler_binding
        require(type(binding) is dict and set(binding)=={'profile','capsuleManifestHash','sourceManifestHash',
            'payloadHash','sourceRevisionClaim','publisherTrustAccepted'}
            and binding['profile']=='CLOSED_CURRENT_PARENT_REVIEW_CAPSULE'
            and binding['publisherTrustAccepted'] is False
            and all(hashed(binding[k]) for k in ('capsuleManifestHash','sourceManifestHash','payloadHash'))
            and type(binding['sourceRevisionClaim']) is str and len(binding['sourceRevisionClaim'])==40
            and set(binding['sourceRevisionClaim'])<=set('0123456789abcdef'),
            'EXACT_UNAUTHENTICATED_CURRENT_PARENT_COMPILER_REQUIRED')
        result['compilerBinding']=copy.deepcopy(binding)
    for path in protected_references(inputs,result):
        selected=absolute(path)
        require(not root.is_relative_to(selected) and not selected.is_relative_to(root),
            'CURRENT_PARENT_REVIEW_OUTPUT_MUST_NOT_SHADOW_INPUTS_OR_HISTORY')
    raw=encoded(result);require(len(raw)<=20971520,'BOUNDED_CURRENT_PARENT_REVIEW_ASSEMBLY_REQUIRED')
    public=receipt(result);claim={'schema':'ouf.discovery-current-parent-review-claim.v1','inputHash':input_hash,
        'assemblyHash':public['assemblyHash'],'automaticReplayAllowed':False}
    if not inspect:
        with directory(root) as fd:
            require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700 and not os.listdir(fd),
                'EMPTY_PRIVATE_CURRENT_PARENT_REVIEW_OUTPUT_REQUIRED_NO_REPLAY')
            new_file(fd,'preparation.claim.json',encoded(claim));new_file(fd,'assembly.private.json',raw)
            require(read()==inputs,'CURRENT_PARENT_REVIEW_INPUT_CHANGED_DURING_PREPARATION')
            new_file(fd,'receipt.json',encoded(public))
    with directory(root) as fd:
        require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700
            and set(os.listdir(fd))=={'preparation.claim.json','assembly.private.json','receipt.json'},
            'EXACT_PRIVATE_CURRENT_PARENT_REVIEW_OUTPUT_REQUIRED')
        require(private_json(root/'preparation.claim.json')==claim
            and protected_file(root/'assembly.private.json',20971520,modes=(0o600,))==raw
            and private_json(root/'receipt.json')==public,'EXACT_COMPLETED_PRIVATE_CURRENT_PARENT_REVIEW_REQUIRED')
    require(read()==inputs,'CURRENT_PARENT_REVIEW_INPUT_CHANGED_DURING_PREPARATION');return public
