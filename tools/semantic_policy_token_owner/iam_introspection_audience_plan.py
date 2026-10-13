"""Plan the26.7.4 caller-audience prerequisite from retained evidence only.

No IAM calls, credential reads, grant, IAM write, exception disabling or authority.
Role-resolved audiences/global exceptions are not guessed from mapper presence.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import uuid
import iam_binding_candidate as binding
import iam_mapper_semantics_review as semantics

VERSION = '26.7.4'
IMAGE = 'sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c'
NAME = 'ouf-policy-token-self-introspection-audience'
CONTAINER = 'ouf-keycloak'

def image_bindings(report):
    def read(args):
        report['dockerMetadataReads'] = report.get('dockerMetadataReads', 0) + 1
        result = subprocess.run(['/usr/bin/docker', *args], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        binding.require(result.returncode == 0 and 0 < len(result.stdout) <= 65536, 'EXACT_IMAGE_METADATA_UNAVAILABLE')
        return binding.decode(result.stdout)
    selected = read(['inspect','--format','{"image":{{json .Image}},"running":{{json .State.Running}}}',CONTAINER])
    binding.require(selected == {'image':IMAGE,'running':True}, 'CURRENT_SELECTED_IMAGE_DRIFT')
    image = read(['image','inspect','--format','{"id":{{json .Id}},"architecture":{{json .Architecture}},"os":{{json .Os}},"digests":{{json .RepoDigests}}}',IMAGE])
    binding.require(type(image) is dict and set(image) == {'id','architecture','os','digests'} and image['id'] == IMAGE
        and type(image['architecture']) is str and type(image['os']) is str
        and (image['digests'] is None or (type(image['digests']) is list and len(image['digests']) <= 16
             and all(type(v) is str and len(v) <= 512 for v in image['digests']))), 'EXACT_DISTRIBUTION_METADATA_UNPROVEN')
    image['digests'] = sorted(image['digests'] or [])
    official = [d for d in image['digests'] if re.fullmatch(r'(quay\.io/keycloak/keycloak|docker\.io/keycloak/keycloak|keycloak/keycloak)@sha256:[0-9a-f]{64}', d)]
    public = {'imageArchitecture':image['architecture'] if image['architecture'] in {'amd64','arm64'} else 'OTHER_OR_UNPROVEN',
        'imageOs':image['os'] if image['os'] == 'linux' else 'OTHER_OR_UNPROVEN',
        'imageRepositoryDigestCount':len(image['digests']),'recognizedOfficialImageReferences':official,
        'targetProviderImplementationProven':False}
    return image, public

def compile_plan(snapshot, snapshot_hash, proposal, proposal_hash):
    candidate, public = semantics.review(snapshot, snapshot_hash, proposal['bindingCandidate']['reference'])
    binding.require(candidate == proposal['bindingCandidate'] and binding.sha(binding.encoded(candidate)) == proposal['bindingCandidateHash']
        and candidate['reviewReasons'] == [] and proposal['schema'] == 'ouf.policy-token-install-input-proposal.v1'
        and proposal['issuerArtifact']['declaredVersion'] == VERSION and proposal['issuerArtifact']['imageId'] == IMAGE
        and proposal['issuerArtifact']['codeMountObserved'] is False
        and all(proposal[k] is False for k in ('runtimeAuthorityIssued', 'productionApplyReady', 'budgetReset')),
        'EXACT_RETAINED_TARGET_PROPOSAL_REQUIRED')
    sources = [snapshot['client']] + snapshot['defaultScopes'] + [s for s in snapshot['optionalScopes'] if s['name'] in snapshot['requestedScopes']]
    mappers = [m for source in sources for m in source.get('protocolMappers', [])]
    client_id = candidate['clientId']
    binding.require(type(snapshot['client'].get('id')) is str and re.fullmatch('[0-9a-fA-F-]{36}', snapshot['client']['id']),
                    'EXACT_REGISTERED_CLIENT_UUID_REQUIRED')
    explicit = [m for m in mappers if m['protocolMapper'] == 'oidc-audience-mapper'
        and client_id in (m['config'].get('included.client.audience'), m['config'].get('included.custom.audience'))
        and m['config'].get('access.token.claim') == 'true' and m['config'].get('introspection.token.claim') == 'true']
    resolved = any(m['protocolMapper'] == 'oidc-audience-resolve-mapper' for m in mappers)
    mapper_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'ouf-policy-token-self-introspection:'+snapshot['client']['id']))
    desired = {'id': mapper_id, 'name': NAME, 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper',
        'config': {'included.client.audience': client_id, 'access.token.claim': 'true',
                   'introspection.token.claim': 'true', 'id.token.claim': 'false'}}
    if not explicit:
        binding.require(not any(m.get('id') == mapper_id or m.get('name') == NAME for m in snapshot['client'].get('protocolMappers', [])),
                        'MANAGED_MAPPER_INTENT_COLLISION_REQUIRES_REVIEW')
    change = None if explicit else {'operation': 'ADD_EXACT_CALLER_AUDIENCE_MAPPER',
        'resource': 'clients/'+snapshot['client']['id']+'/protocol-mappers/models',
        'proposedMapper': desired, 'introspectionCheckMustRemainEnabled': True,
        'expectedRetainedMetadataHash': snapshot_hash, 'expectedRetainedProposalHash': proposal_hash,
        'requiresFreshIamDriftCheckAndReconciliation': True, 'requiresExistingIamOwnerApproval': True,
        'requiresCurrentApprovedCallerAudienceReconciliation': True,
        'conditionalProposalNotProofThatCurrentTokenFails': True,
        'applyAuthorized': False}
    plan = {'schema': 'ouf.policy-token-introspection-audience-review-plan.v1',
        'sourceProfile': 'keycloak-26.7.4-caller-audience-check.v1', 'proposalHash': proposal_hash,
        'snapshotHash': snapshot_hash, 'bindingCandidateHash': proposal['bindingCandidateHash'],
        'explicitCallerAudienceMapperObserved': bool(explicit),
        'audienceResolveMapperObserved': resolved, 'roleResolvedCallerAudienceProven': False,
        'serverOrClientExceptionProven': False, 'currentBearerIntrospectionProven': False,
        'changeProposal': change, 'plannedIamMutations': 0 if explicit else 1,
        'runtimeAuthorityIssued': False, 'productionApplyReady': False, 'budgetReset': False, 'notReleaseAcceptance': True}
    public = {'explicitCallerAudienceMapperObserved': bool(explicit), 'audienceResolveMapperObserved': resolved,
        'roleResolvedCallerAudienceProven': False, 'serverOrClientExceptionProven': False,
        'currentBearerIntrospectionProven': False, 'plannedIamMutations': plan['plannedIamMutations'],
        'introspectionCheckDisableRequested': False, 'issuerChangeRequested': False,
        'protectedClaimsChangeRequested': False, 'scopeAssignmentChangeRequested': False,
        'existingIamOwnerReviewRequired': not bool(explicit), 'sourceProfile': plan['sourceProfile']}
    return plan, public

def prepare(metadata_path, metadata_hash, proposal_path, proposal_hash, report):
    metadata, proposal = Path(metadata_path), Path(proposal_path)
    binding.require(metadata.parent == proposal.parent == binding.PARENT
        and re.fullmatch(r'policy-token-iam-metadata-[0-9a-f]{32}\.private\.json', metadata.name)
        and re.fullmatch(r'policy-token-install-inputs-[0-9a-f]{64}\.private\.json', proposal.name)
        and all(re.fullmatch('[0-9a-f]{64}', h) for h in (metadata_hash, proposal_hash)), 'EXACT_RETAINED_REFERENCES_REQUIRED')
    with binding.protected_parent() as directory:
        metadata_raw, proposal_raw = binding.read_member(directory, metadata.name), binding.read_member(directory, proposal.name)
        binding.require(binding.sha(metadata_raw) == metadata_hash and binding.sha(proposal_raw) == proposal_hash, 'RETAINED_INPUT_HASH_MISMATCH')
        report['phase'] = 'CALLER_AUDIENCE_REVIEW_PLAN'
        plan, public = compile_plan(binding.decode(metadata_raw), metadata_hash, binding.decode(proposal_raw), proposal_hash)
        report['phase'] = 'EXACT_IMAGE_DISTRIBUTION_METADATA'
        image, image_public = image_bindings(report)
        plan['imageDistributionMetadata'] = image
        public.update(image_public)
        binding.require(binding.read_member(directory, metadata.name) == metadata_raw and binding.read_member(directory, proposal.name) == proposal_raw,
                        'RETAINED_INPUT_CHANGED')
        body = binding.encoded(plan); name = 'policy-token-introspection-review-'+binding.sha(body)+'.private.json'
        report.update(phase='PRIVATE_REVIEW_PLAN_PUBLICATION', privateEvidencePath=str(binding.PARENT/name))
        try: fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        except FileExistsError:
            binding.require(binding.read_member(directory,name) == body, 'REVIEW_PLAN_RECONCILIATION_REQUIRED')
            report['newPlanPublished'] = False
        else:
            report.update(privateEvidenceWrites=1,newPlanPublished=True)
            try:
                os.fchmod(fd,0o600)
                with os.fdopen(os.dup(fd),'wb') as stream:
                    stream.write(body);stream.flush();os.fsync(stream.fileno())
                os.fsync(directory)
                binding.require(binding.identity(os.fstat(fd)) == binding.identity(os.stat(name,dir_fd=directory,follow_symlinks=False)), 'REVIEW_PLAN_MEMBER_CHANGED')
            finally: os.close(fd)
        binding.require(binding.read_member(directory,name) == body,'REVIEW_PLAN_RECONCILIATION_REQUIRED')
        report.update(status='CALLER_AUDIENCE_REVIEW_PLAN_COMPILED',phase='COMPILED_NOT_ACCEPTED',
            privateEvidenceHash=binding.sha(body), **public)

def main():
    parser=argparse.ArgumentParser()
    for field in ('metadata','metadata-sha256','proposal','proposal-sha256'):parser.add_argument('--'+field,required=True)
    args=parser.parse_args()
    report={'schema':'ouf.policy-token-introspection-audience-plan-receipt.v1','phase':'RETAINED_INPUT_READ','status':'BLOCKED',
        'privateEvidenceWrites':0,'credentialFilesRead':0,'mountedTokenFilesRead':0,'providerCalls':0,'tokenGrantRequests':0,
        'iamMutations':0,'serviceMutations':0,'runtimeAuthorityIssued':False,'productionApplyReady':False,
        'baselineRefreshed':False,'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
    try:
        def timeout(*_):raise binding.CandidateDenied('PLAN_DEADLINE')
        signal.signal(signal.SIGALRM,timeout);signal.alarm(45)
        prepare(args.metadata,args.metadata_sha256,args.proposal,args.proposal_sha256,report);code=0
    except Exception as error:
        report['reason']=str(error) if type(error)is binding.CandidateDenied else type(error).__name__
        if isinstance(error,OSError):report['errno']=error.errno
        report['evidencePublicationMayBePartial']=report['phase']=='PRIVATE_REVIEW_PLAN_PUBLICATION';code=1
    finally:signal.alarm(0)
    print(json.dumps(report,sort_keys=True,separators=(',',':')));return code

if __name__=='__main__':raise SystemExit(main())
