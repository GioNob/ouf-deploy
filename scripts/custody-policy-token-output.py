"""Custody one token output child using completed roots and retained review.
No old root creation, IAM calls, credential reads, grant or runtime operation.
"""
import base64
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

CAPSULE_COMMIT = '3391eeb93f31795e229e2b31f1864056d9e8611c'
CAPSULE_SHA = '4a5f2a8b0c4bd511ddc4453da00aa67204d2dfa191f8ce3907123af02cc8195c'
CAPSULE_PATH = 'releases/policy-token-output-custody-migration-capsule-20261014.json'

ROOT_BODY = r'''
import base64,hashlib,json,os,re,signal,stat,sys,time,types
raw=sys.stdin.buffer.read(1048577)
if not 0<len(raw)<=1048576 or hashlib.sha256(raw).hexdigest()!=CAPSULE_SHA:
    raise SystemExit('phase=ROOT_DELIVERY reason=MIGRATION_CAPSULE_HASH_MISMATCH')
payload=json.loads(raw)
if set(payload)!={'schema','sourceCommit','loader','sources','declarationHash'} or payload['schema']!='ouf.policy-token-migration-component-memory-capsule.v1':
    raise SystemExit('phase=ROOT_DELIVERY reason=EXACT_MIGRATION_CAPSULE_REQUIRED')
loader=base64.b64decode(payload['loader'],validate=True)
runtime=types.ModuleType('verified_migration_loader')
exec(compile(loader,'verified-migration-loader','exec'),runtime.__dict__)
entry,manifest=runtime.load_entry(payload['sourceCommit'],
    {name:base64.b64decode(value,validate=True)for name,value in payload['sources'].items()},
    loader,payload['declarationHash'])
import iam_owner_action as owner
import migration_root_custody as roots
import legacy_retirement as legacy
from cutover_authority import CutoverAuthority
binding=roots.binding
governance=owner.governance
ROOT_EVIDENCE_HASH='8b7698791f95d84454a65eb9e80ad3061e9d4c32d6efc427930859320e1f8b0d'
ROOT_SOURCE_HASH='9b78689d3bc4144a005abd5ab7cf8365a7c99e67a0057dfc84d2d27447479623'
INPUT_REVIEW_HASH='92b3276992b3b3ec459e734196671728b8a49a99a02185e2c6f7c1da87ce82a1'
INPUT_REVIEW_SOURCE_HASH='9b1d85c02dd0cf255138156d6334893cd6eeec120864ab80c8efea63e77e1958'

def inspect_absent(action):
    with roots.completed_roots(action.host_raw,ROOT_EVIDENCE_HASH,ROOT_SOURCE_HASH)as identities:
        binding.require(identities['durableRecovery']==action.parent_identity,'OUTPUT_RETAINED_PARENT_DRIFT')
    binding.require(not os.path.lexists(action.path),'UNRECORDED_OUTPUT_REQUIRES_RECONCILIATION_NO_ADOPTION')

def retained_review(directory):
    raw=binding.read_member(directory,'semantic-candidate-installation-input-review-'+INPUT_REVIEW_HASH+'.private.json')
    binding.require(binding.sha(raw)==INPUT_REVIEW_HASH,'EXACT_COMPLETED_INSTALLATION_REVIEW_REQUIRED')
    review=binding.decode(raw)
    binding.require(review.get('schema')=='ouf.semantic-candidate-installation-input-review.v1'
        and review.get('sourceClosureHash')==INPUT_REVIEW_SOURCE_HASH
        and binding.sha(binding.encoded(review.get('sourceClosure')))==INPUT_REVIEW_SOURCE_HASH
        and review.get('completedRootEvidenceHash')==ROOT_EVIDENCE_HASH
        and review.get('rootCreationSourceClosureHash')==ROOT_SOURCE_HASH
        and review.get('retainedHostInputsHash')==legacy.HOST_HASH,'RETAINED_INPUT_LINEAGE_DRIFT')
    binding.require(entry.registry_generation()==review['currentRegistry'],'CURRENT_REVIEWED_REGISTRY_GENERATION_CHANGED')
    return raw

def terminal_decision(review_hash,source_hash,scope):
    phrase='APPROVO OUTPUT TOKEN '+review_hash
    with open('/dev/tty','r',encoding='utf-8')as reader,open('/dev/tty','w',encoding='utf-8')as terminal:
        terminal.write('\nOperazione HUMAN: creare soltanto la directory figlia per l\'output del token.\n'
            'Root:gid10001, modo0750; le tre radici già custodite rimangono root:root/0700.\n'
            'Due firme dell\'installer esistente; limite300 secondi e un tentativo mkdir durevole.\n'
            'Nessuna chiamata IAM, modifica servizi, lettura credenziali, richiesta token o avvio runtime.\n'
            'Un esito parziale richiede riconciliazione: nessun replay o adozione di inode sconosciuti.\n'
            'Directory: '+scope['path']+'\nParent identity hash: '+binding.sha(binding.encoded(scope['parentIdentity']))+
            '\nReview: '+review_hash+'\nSource closure: '+source_hash+'\nScrivi esattamente:\n'+phrase+'\n> ')
        terminal.flush();answer=reader.readline(256)
    binding.require(answer==phrase+'\n','EXPLICIT_OUTPUT_CUSTODY_HUMAN_APPROVAL_NOT_GIVEN')
    return phrase

def execute(report):
    report['phase']='RETAINED_HOST_AND_EXISTING_AUTHORITY_READ'
    with binding.protected_parent()as directory:
        intake,plan,snapshot,profile=owner.inputs(directory)
        host_raw=binding.read_member(directory,'policy-token-migration-host-inputs-'+legacy.HOST_HASH+'.private.json')
        binding.require(binding.sha(host_raw)==legacy.HOST_HASH,'EXACT_RETAINED_MIGRATION_HOST_HASH_REQUIRED')
        host=binding.decode(host_raw)
        input_raw=retained_review(directory)
        # Reuse the previous library closure; verify current bytes before new signing.
        previous_hash=host['ownerReviewHash']
        previous_raw=binding.read_member(directory,'policy-token-iam-action-review-'+previous_hash+'.private.json')
        binding.require(binding.sha(previous_raw)==previous_hash,'RETAINED_OWNER_REVIEW_HASH_DRIFT')
        previous=binding.decode(previous_raw)
        report['phase']='CURRENT_EXECUTING_SOURCE_BINDING'
        library=owner.stdlib_binding()
        binding.require(library==previous['stdlib'],'RETAINED_STDLIB_DRIFT')
        source={'schema':'ouf.policy-token-output-delivery-source-closure.v1','components':manifest,
            'capsuleHash':CAPSULE_SHA,'executingRootBodyHash':ROOT_BODY_HASH,
            'executables':intake['executablesProposedNotAccepted'],
            'installationInputReviewHash':INPUT_REVIEW_HASH,'installationInputReviewSourceClosureHash':INPUT_REVIEW_SOURCE_HASH,
            'stdlibHash':binding.sha(binding.encoded(library))}
        source_hash=binding.sha(binding.encoded(source))
        history={'hostInputsHash':legacy.HOST_HASH,'ownerReviewHash':previous_hash,
            'legacyHistory':host['legacyHistory']}
        provisional={k:binding.sha(binding.encoded(history))for k in
            ('intakeHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef')}
        provisional['sourceClosureHash']=source_hash
        # A typed object for pure scope construction only; never call this unsigned gate.
        verifier=owner.DetachedAuthenticator(governance.POLICY,str(binding.PARENT),intake['executablesProposedNotAccepted']['openssl'])
        gate=CutoverAuthority(verifier,{'path':str(binding.PARENT/'unissued-root-mandate'),'sha256':'0'*64},
            '0'*64,governance.CONTEXT,provisional)
        proposal=roots.TokenOutputCustody(gate,b'{}',host_raw,ROOT_EVIDENCE_HASH,ROOT_SOURCE_HASH)
        report['phase']='OUTPUT_CUSTODY_AND_PRIOR_OPERATION_PREFLIGHT'
        claim_name='policy-token-output-delivery-issuance-'+proposal.operation+'.private.json'
        binding.require(not os.path.lexists(binding.PARENT/claim_name),'OUTPUT_ISSUANCE_ALREADY_CONSUMED_NO_REPLAY')
        binding.require(not os.path.lexists(binding.PARENT/proposal.name),'OUTPUT_OPERATION_ALREADY_RECORDED_NO_NEW_ISSUANCE')
        inspect_absent(proposal)
        review={'schema':'ouf.policy-token-output-delivery-review.v1','sourceClosure':source,
            'sourceClosureHash':source_hash,'lineage':history,'scope':proposal.scope,
            'maximumExistingRoleSignatures':2,'authorityLifetimeSeconds':300,
            'fullOwnerInstallerQualified':False,'runtimeAuthorityIssued':False,
            'productionApplyReady':False,'notReleaseAcceptance':True}
        review_raw=binding.encoded(review);review_hash=binding.sha(review_raw)
        name='policy-token-output-delivery-review-'+review_hash+'.private.json'
        report['phase']='PRIVATE_ROOT_ACTION_REVIEW_PUBLICATION'
        owner.publish(directory,name,review_raw)
        report.update(privateReviewHash=review_hash,privateReviewPath=str(binding.PARENT/name),sourceClosureHash=source_hash)
        report['phase']='EXPLICIT_TERMINAL_HUMAN_DECISION'
        signal.alarm(120)
        phrase=terminal_decision(review_hash,source_hash,proposal.scope)
        signal.alarm(300)
        # Current host/authority checks happen after the human wait and before issuance.
        report['phase']='POST_DECISION_CURRENT_BINDING'
        owner.inputs(directory);inspect_absent(proposal)
        binding.require(retained_review(directory)==input_raw,'INPUT_REVIEW_CHANGED_DURING_HUMAN_DECISION')
        binding.require(owner.stdlib_binding()==library,'STDLIB_CHANGED_DURING_HUMAN_REVIEW')
        binding.require(binding.read_member(directory,name)==review_raw,'ROOT_REVIEW_CHANGED')
        binding.require(binding.read_member(directory,'policy-token-migration-host-inputs-'+legacy.HOST_HASH+'.private.json')==host_raw,
            'RETAINED_HOST_INPUT_CHANGED')
        now=int(time.time())
        expected={'intakeHash':review_hash,'sourceClosureHash':source_hash,
            'creationRequestHash':binding.sha(binding.encoded(proposal.scope)),
            'predecessorHistoryHash':binding.sha(binding.encoded(history)),
            'predecessorIncidentRef':proposal.operation}
        authority={'schema':'ouf.semantic-cutover-execution-authority.v1',
            **{k:v for k,v in expected.items()if k!='intakeHash'},'issuedAt':now,'expiresAt':now+300,
            'policyTokenOutputCustody':proposal.scope}
        authority_raw=binding.encoded(authority)
        # One stable issuance claim per operation, unaffected by a new prompt/job/time.
        claim={'schema':'ouf.policy-token-output-delivery-human-claim.v1','operation':proposal.operation,
            'reviewHash':review_hash,'sourceClosureHash':source_hash,'approvedAt':now,
            'enteredDecision':phrase,'actor':'EXISTING_VPS_OPERATOR_EXPLICIT_TTY_DECISION',
            'state':'ISSUANCE_CONSUMED','executionAuthorityHash':binding.sha(authority_raw)}
        report['phase']='DURABLE_HUMAN_ISSUANCE_RESERVATION'
        binding.require(not os.path.lexists(binding.PARENT/claim_name),'OUTPUT_ISSUANCE_ALREADY_CONSUMED_NO_REPLAY')
        binding.require(owner.publish(directory,claim_name,binding.encoded(claim)),'OUTPUT_ISSUANCE_ALREADY_CONSUMED_NO_REPLAY')
        report['humanIssuanceClaimConsumed']=True
        context_name='policy-token-output-signed-context-'+proposal.operation
        report['phase']='PRIVATE_ROOT_AUTHORITY_PUBLICATION'
        os.mkdir(context_name,0o700,dir_fd=directory);os.fsync(directory)
        context=binding.PARENT/context_name
        child=os.open(context_name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
        try:
            mandate={'schema':'ouf.semantic-cutover-human-mandate.v1','approvalRef':'human-token-output-'+proposal.operation,
                'decision':'APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY','state':'ACTIVE',
                'issuedAt':now,'expiresAt':now+300,'executionAuthorityHash':binding.sha(authority_raw),**expected}
            mandate_raw=binding.encoded(mandate);mandate_hash=binding.sha(mandate_raw)
            owner.publish(child,'human.json',mandate_raw);owner.publish(child,'authority.json',authority_raw)
            verifier=owner.DetachedAuthenticator(governance.POLICY,str(context),intake['executablesProposedNotAccepted']['openssl'])
            gate=CutoverAuthority(verifier,{'path':str(context/'human.json'),'sha256':mandate_hash},
                mandate_hash,governance.CONTEXT,expected)
            report['phase']='EXISTING_INSTALLER_DUAL_ROLE_ISSUANCE'
            for role in ('DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'):
                gate.mandate(authority_raw);owner.inputs(directory);inspect_absent(proposal)
                binding.require(retained_review(directory)==input_raw,'INPUT_REVIEW_CHANGED_BEFORE_ISSUANCE')
                report['installationKeyAccessAttempted']=True
                signer=owner.ExistingEd25519Signer(profile['keyBindings']['installer'],profile['keyRefs']['installer'],verifier,
                    {'role':role,'issuerRef':governance.CONTEXT['intentIssuerRef'if role=='DEPLOYMENT_INTENT'else'approvalIssuerRef'],
                        'installationRef':governance.CONTEXT['installationRef'],'entityRef':governance.CONTEXT['entityRef']})
                envelope=signer.sign(authority_raw)
                owner.publish(child,binding.sha(authority_raw)+'.'+role+'.json',envelope)
                report['signaturesIssued']+=1
            gate(authority_raw)
            operation=roots.TokenOutputCustody(gate,authority_raw,host_raw,ROOT_EVIDENCE_HASH,ROOT_SOURCE_HASH)
            binding.require(operation.scope==proposal.scope,'REVIEWED_OUTPUT_SCOPE_DRIFT')
            report['phase']='GOVERNED_OUTPUT_CUSTODY_CREATION'
            report['outputMutationOutcomeMayBePartial']=True
            result=operation.run()
            # Real device/inode identities stay in the existing protected ledger.
            report.update(status='OUTPUT_CHILD_CUSTODIED_NOT_RUNTIME_ACCEPTED',phase='OUTPUT_CHILD_CUSTODIED',
                outputMutationOutcomeMayBePartial=False,outputEvidencePath=str(binding.PARENT/operation.name),
                outputEvidenceHash=binding.sha(binding.encoded(result)),outputDirectoryPath=str(operation.path),
                outputDirectoryIdentityHash=binding.sha(binding.encoded(result['outputIdentity'])),
                createdOutputDirectoryCount=1,createdMigrationRootCount=0,mkdirAttempts=1,
                completedRootEvidenceHash=ROOT_EVIDENCE_HASH,completedRootCreationReplayed=False,
                inputReviewHash=INPUT_REVIEW_HASH,retainedInputCollectionReplayed=False)
        finally:os.close(child)

def main_root():
    report={'schema':'ouf.policy-token-output-delivery-receipt.v1','status':'BLOCKED','phase':'ROOT_ENTRY',
        'credentialFilesRead':0,'mountedTokenFilesRead':0,'iamMutations':0,'iamMetadataGetAttempts':0,
        'serviceMutations':0,'tokenGrantRequests':0,'providerCalls':0,'signaturesIssued':0,
        'humanIssuanceClaimConsumed':False,'installationKeyAccessAttempted':False,
        'runtimeAuthorityIssued':False,'productionApplyReady':False,'fullOwnerInstallerQualified':False,
        'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
    try:
        binding.require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'ROOT_ISOLATED_NO_SITE_DELIVERY_REQUIRED')
        def deadline(*_):raise binding.CandidateDenied('FINITE_ROOT_DELIVERY_DEADLINE')
        signal.signal(signal.SIGALRM,deadline);signal.alarm(120)
        execute(report);code=0
    except Exception as error:
        reason=str(error)
        report['reason']=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason)else type(error).__name__
        if isinstance(error,OSError):report['errno']=error.errno
        if type(getattr(error,'safe_diagnostics',None))is dict:report['safeDiagnostics']=error.safe_diagnostics
        report['automaticReplayAllowed']=False
        report['preservePrivateEvidence']=True
        code=1
    finally:signal.alarm(0)
    print(binding.encoded(report).decode());return code

if __name__=='__main__':raise SystemExit(main_root())
'''


def main():
    preferred = Path.home() / 'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
    gh = str(preferred) if preferred.is_file() and os.access(preferred, os.X_OK) else shutil.which('gh')
    if not gh:
        raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
    try:
        reply = subprocess.run([gh, 'api', 'repos/GioNob/ouf-deploy/contents/' + CAPSULE_PATH + '?ref=' + CAPSULE_COMMIT,
            '--jq', '.content'], check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
        if len(reply.stdout) > 1500000:
            raise ValueError()
        raw = base64.b64decode(b''.join(reply.stdout.split()), validate=True)
    except Exception:
        raise SystemExit('phase=DELIVERY reason=QUALIFIED_CAPSULE_UNAVAILABLE; no sudo executed') from None
    if not 0 < len(raw) <= 1048576 or hashlib.sha256(raw).hexdigest() != CAPSULE_SHA:
        raise SystemExit('phase=DELIVERY reason=QUALIFIED_CAPSULE_HASH_MISMATCH; no sudo executed')
    body_hash = hashlib.sha256(ROOT_BODY.encode()).hexdigest()
    bootstrap = 'CAPSULE_SHA=' + repr(CAPSULE_SHA) + '\nROOT_BODY_HASH=' + repr(body_hash) + '\n' + ROOT_BODY
    try:
        return subprocess.run(['sudo', '--', '/usr/bin/python3', '-I', '-B', '-S', '-c', bootstrap], input=raw, timeout=560).returncode
    except Exception:
        raise SystemExit('phase=ROOT_EXECUTION reason=ROOT_DELIVERY_RESULT_UNAVAILABLE; preserve evidence, no automatic rerun') from None


if __name__ == '__main__':
    raise SystemExit(main())
