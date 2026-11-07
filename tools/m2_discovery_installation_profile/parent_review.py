"""Assemble all six exact parent review components; never grant execution.

The declared child body and HUMAN file binding remain unauthenticated review
inputs. Runtime verification still requires actual current HUMAN bytes, both
role signatures and each existing native admission. No historical scope reuse.
"""
import base64,hashlib,copy,os,stat
from .custody_capture import decode,digest,encoded,require
from . import infrastructure_review as infrastructure,publication_review as publication
from .private_review import absolute,hashed
from .parent_authority import review_scope,SEMANTICS
from .executor import runtime_sections
from .cohort_images import COMPONENT
from transition_journal import PHASES
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import protected_file,private_json

SCHEMA='ouf.discovery-complete-parent-review-inputs.v1'
REQUIRED_PROOFS=['FULL_CURRENT_COHORT','OCI_ARCHIVES_AND_IMAGE_IDENTITY','PRIVATE_FILE_CUSTODY',
    'GATEWAY_CONFIGURATION_AND_EXECUTABLE_CUSTODY','CURRENT_GATEWAY_AND_MCP_GENERATIONS',
    'DATABASE_V11_V12_BACKUP_AND_PRODUCER_FENCE','TLS_IAM_WORKLOAD_AND_NETWORK',
    'CURRENT_DUAL_ROLE_AND_HUMAN_AUTHORITY','INDEPENDENT_PROVIDER_NATIVE_ADMISSION',
    'CURRENT_SEALED_WORKER_AND_POSITIVE_LEASES','DISTINCT_DISCOVERY_AND_DELEGATION_KEYS',
    'GOVERNED_CAPABILITY_SCOPE_AND_ROLE_PUBLICATION']


def assemble(inputs,input_hash,baseline,primitives):
    publication.shape(inputs,('schema','infrastructureInputs','publicationInputs','registryChild'),
        'EXACT_COMPLETE_DISCOVERY_PARENT_INPUTS_REQUIRED')
    require(inputs['schema']==SCHEMA and hashed(input_hash) and digest(inputs)==input_hash
        and len(encoded(inputs))<=8388608,'HASH_BOUND_COMPLETE_DISCOVERY_PARENT_INPUTS_REQUIRED')
    infra=infrastructure.assemble(inputs['infrastructureInputs'],digest(inputs['infrastructureInputs']),baseline)
    cohort=infra['cohortAssembly'];declared=cohort['inputs'];fragment=cohort['cohortReviewFragment']
    pub=publication.assemble(inputs['publicationInputs'],digest(inputs['publicationInputs']),declared,primitives)
    child=inputs['registryChild']
    publication.shape(child,('authorityBase64','humanManifestBinding','expected'),'EXPLICIT_SEPARATE_REGISTRY_CHILD_REVIEW_REQUIRED')
    expected=child['expected'];publication.shape(expected,('intakeHash','sourceClosureHash','creationRequestHash',
        'predecessorHistoryHash','predecessorIncidentRef'),'EXACT_REGISTRY_CHILD_REVIEW_BINDINGS_REQUIRED')
    binding=child['humanManifestBinding'];publication.shape(binding,('path','sha256'),'EXPLICIT_CHILD_HUMAN_FILE_BINDING_REQUIRED')
    absolute(binding['path'])
    require(all(hashed(v) for v in expected.values()) and hashed(binding['sha256'])
        and expected['sourceClosureHash']==declared['sourceClosureHash']
        and expected['creationRequestHash']==digest(declared['registry']['request']),
        'SAME_PARENT_SOURCE_REQUEST_AND_CHILD_REVIEW_REQUIRED')
    raw=base64.b64decode(child['authorityBase64'],validate=True)
    require(0<len(raw)<=131072,'BOUNDED_DECLARED_REGISTRY_CHILD_REQUIRED');authority=decode(raw)
    components=copy.deepcopy(infra['parts'])
    components['cohortInstallation']={'schema':COMPONENT,
        **{k:declared[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash')},
        **copy.deepcopy(fragment),'currentAdmission':{'schema':'ouf.discovery-current-cohort-review-requirements.v1',
            'cohortManifestHash':declared['cohortManifestHash'],'registryCreationRequestHash':expected['creationRequestHash'],
            'gatewayRuntimeHash':digest(fragment['gatewayRuntime']),'mcpComponentHash':digest(fragment['mcp']),
            'requiredProofs':list(REQUIRED_PROOFS),'mustBeCurrentAtExecution':True,'historicalEvidenceSufficient':False},
        'requiresFullCurrentCohortBeforeRelease':True,'automaticReplayAllowed':False,'budgetReset':False}
    sections=runtime_sections(components['cohortInstallation'])
    fields={'schema','issuedAt','expiresAt','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef',
        'sourceClosureHash','phaseIntentHashes','automaticReplayAllowed','databaseRestoreAuthorized',
        'r12ReplayAuthorized','newDistinctLeaseWorkerRequired'}
    require(type(authority) is dict and set(authority)==fields|set(sections)
        and authority['schema']=='ouf.semantic-cutover-execution-authority.v1'
        and all(authority[k]==v for k,v in expected.items() if k!='intakeHash')
        and all(authority[k]==v for k,v in sections.items())
        and type(authority['phaseIntentHashes']) is dict and set(authority['phaseIntentHashes'])==set(PHASES)
        and all(hashed(v) for v in authority['phaseIntentHashes'].values())
        and authority['phaseIntentHashes']['CREATE_REPLACEMENT']==expected['creationRequestHash']
        and authority['newDistinctLeaseWorkerRequired'] is True
        and all(authority[k] is False for k in ('automaticReplayAllowed','databaseRestoreAuthorized','r12ReplayAuthorized'))
        and type(authority['issuedAt']) is int and type(authority['expiresAt']) is int
        and 0<authority['expiresAt']-authority['issuedAt']<=3600,
        'EXACT_FINITE_THIRTEEN_PHASE_CHILD_WITH_CURRENT_RUNTIME_SCOPES_REQUIRED')
    components['registryCutover']={'schema':'ouf.discovery-registry-child-scope.v1',
        'authorityHash':hashlib.sha256(raw).hexdigest(),'humanManifestHash':binding['sha256'],**copy.deepcopy(expected)}
    components['capabilityPublication']=pub['component']
    roots=[absolute(p) for p in pub['component']['journalDirectories'].values()]
    others=[absolute(p) for p in infra['storageRoots']+infra['protectedInputs']+[binding['path']]]
    require(all(not a.is_relative_to(b) and not b.is_relative_to(a) for a in roots for b in others),
        'PUBLICATION_HISTORY_MUST_NOT_SHADOW_INFRASTRUCTURE_OR_HUMAN_INPUTS')
    review={'schema':'ouf.discovery-parent-installation-review.v1',
        **{k:declared[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash')},
        'predecessorHistoryHash':expected['predecessorHistoryHash'],'components':components,
        'operationalSemantics':copy.deepcopy(SEMANTICS),'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'releaseAcceptance':False}
    scope=review_scope(review)
    return {'schema':'ouf.discovery-complete-parent-review-assembly.v1','inputHash':input_hash,
        'review':review,'scope':scope,'infrastructureAssembly':infra,'publicationAssembly':pub,
        'registryChildReview':copy.deepcopy(child),'completeParentReviewShape':True,
        'inputsAuthenticated':False,'currentNativeAdmissionProven':False,'publicationExecutorIntegrated':False,
        'signaturesIssued':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'capabilitiesPublished':False,'applicationE2EProven':False,'releaseAcceptance':False}


def receipt(result):
    return {'schema':'ouf.discovery-complete-parent-review-receipt.v1','inputHash':result['inputHash'],
        'assemblyHash':digest(result),'reviewHash':result['scope']['reviewHash'],
        'componentScopeHashes':copy.deepcopy(result['scope']['componentScopeHashes']),
        'completeParentReviewShape':True,'inputsAuthenticated':False,'currentNativeAdmissionProven':False,
        'publicationExecutorIntegrated':False,'signaturesIssued':0,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'capabilitiesPublished':False,'applicationE2EProven':False,'releaseAcceptance':False}


def prepare(input_path,input_hash,output_directory,baseline,primitives,*,inspect=False,compiler_binding=None):
    require(os.geteuid()==os.getegid()==0,'ROOT_COMPLETE_PARENT_REVIEW_PREPARATION_REQUIRED')
    root,source=absolute(output_directory),absolute(input_path)
    require(not root.is_relative_to(source) and not source.is_relative_to(root),'SEPARATE_PARENT_REVIEW_INPUT_OUTPUT_REQUIRED')
    def read():
        v=decode(protected_file(source,8388608,modes=(0o600,)))
        require(digest(v)==input_hash,'COMPLETE_PARENT_REVIEW_INPUT_HASH_DRIFT');return v
    inputs=read();result=assemble(inputs,input_hash,baseline,primitives)
    if compiler_binding is not None:
        publication.shape(compiler_binding,('profile','capsuleManifestHash','sourceManifestHash','payloadHash',
            'sourceRevisionClaim','publisherTrustAccepted'),'EXACT_COMPLETE_PARENT_COMPILER_BINDING_REQUIRED')
        require(compiler_binding['profile']=='CLOSED_COMPLETE_PARENT_REVIEW_CAPSULE'
            and compiler_binding['publisherTrustAccepted'] is False
            and all(hashed(compiler_binding[k]) for k in ('capsuleManifestHash','sourceManifestHash','payloadHash'))
            and type(compiler_binding['sourceRevisionClaim']) is str and len(compiler_binding['sourceRevisionClaim'])==40
            and set(compiler_binding['sourceRevisionClaim'])<=set('0123456789abcdef'),
            'EXACT_UNAUTHENTICATED_COMPLETE_PARENT_COMPILER_REQUIRED')
        result['compilerBinding']=copy.deepcopy(compiler_binding)
    infra=result['infrastructureAssembly'];pub=result['publicationAssembly']['component']
    for path in infra['storageRoots']+infra['protectedInputs']+list(pub['journalDirectories'].values())\
        +[inputs['registryChild']['humanManifestBinding']['path']]:
        p=absolute(path)
        require(not root.is_relative_to(p) and not p.is_relative_to(root),'PARENT_REVIEW_OUTPUT_MUST_NOT_SHADOW_INPUTS_OR_HISTORY')
    raw=encoded(result);require(len(raw)<=16777216,'BOUNDED_COMPLETE_PARENT_REVIEW_ASSEMBLY_REQUIRED')
    public=receipt(result);claim={'schema':'ouf.discovery-complete-parent-review-claim.v1','inputHash':input_hash,
        'assemblyHash':public['assemblyHash'],'automaticReplayAllowed':False}
    if not inspect:
        with directory(root) as fd:
            require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700 and not os.listdir(fd),'EMPTY_PRIVATE_PARENT_REVIEW_OUTPUT_REQUIRED_NO_REPLAY')
            new_file(fd,'preparation.claim.json',encoded(claim));new_file(fd,'assembly.private.json',raw)
            require(read()==inputs,'PARENT_REVIEW_INPUT_CHANGED_DURING_PREPARATION')
            new_file(fd,'receipt.json',encoded(public))
    with directory(root) as fd:
        require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700
            and set(os.listdir(fd))=={'preparation.claim.json','assembly.private.json','receipt.json'},
            'EXACT_PRIVATE_COMPLETE_PARENT_REVIEW_OUTPUT_REQUIRED')
        require(private_json(root/'preparation.claim.json')==claim
            and protected_file(root/'assembly.private.json',16777216,modes=(0o600,))==raw
            and private_json(root/'receipt.json')==public,'EXACT_COMPLETED_PRIVATE_PARENT_REVIEW_REQUIRED')
    require(read()==inputs,'PARENT_REVIEW_INPUT_CHANGED_DURING_PREPARATION');return public
