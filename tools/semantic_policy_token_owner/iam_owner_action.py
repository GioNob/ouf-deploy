"""Review-only full closure, then one explicitly approved existing-owner action.

No default approval, runtime token admission, service changes or budget reset.
The sealed launcher supplies the independently recorded HUMAN decision; generic
development permission is never converted to an approval by this component.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sysconfig
import sys
import time
import uuid
import iam_binding_candidate as binding
import iam_governance_intake as governance
from iam_audience_transaction import AudienceTransaction,MapperAdmin,equivalent
from cutover_authority import CutoverAuthority
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer

INTAKE_HASH='850b0cf1a0b6fc6810ecba6d1ac846efc17e440c2660adddbabbdfb3a8fb7b2f'
INTAKE='policy-token-governed-iam-intake-'+INTAKE_HASH+'.private.json'

def publish(directory,name,raw):
    try:fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    except FileExistsError:
        binding.require(binding.read_member(directory,name)==raw,'EXISTING_ACTION_MEMBER_CONFLICT');return False
    try:
        with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.fsync(directory)
    finally:os.close(fd)
    binding.require(binding.read_member(directory,name)==raw,'ACTION_PUBLICATION_RECONCILIATION_REQUIRED');return True

def stdlib_binding():
    root=Path(sysconfig.get_path('stdlib')).resolve(strict=True)
    version=str(sys.version_info.major)+'.'+str(sys.version_info.minor)
    multiarch=sysconfig.get_config_var('MULTIARCH')
    binding.require(type(multiarch)is str and re.fullmatch('[A-Za-z0-9_-]{1,64}',multiarch),'EXACT_PYTHON_MULTIARCH_REQUIRED')
    shared_member='config-'+version+'-'+multiarch+'/libpython'+version+'.so'
    shared_targets={Path(sys.base_prefix)/'lib'/('libpython'+version+'.so.1.0'),
        Path('/usr/lib')/multiarch/('libpython'+version+'.so.1.0')}
    files={};total=0
    for directory,dirs,names in os.walk(root,followlinks=False):
        parent=Path(directory);row=parent.lstat()
        binding.require(stat.S_ISDIR(row.st_mode) and row.st_uid==row.st_gid==0 and not row.st_mode&0o022,'STDLIB_DIRECTORY_CUSTODY_UNPROVEN')
        dirs[:]=sorted(d for d in dirs if d not in {'site-packages','dist-packages','test','tests','idlelib','tkinter'})
        for d in dirs:binding.require(not (parent/d).is_symlink(),'STDLIB_DIRECTORY_LINK_UNPROVEN')
        for name in sorted(names):
            # -S excludes these startup hooks; they are not action dependencies.
            if sys.flags.no_site and name in {'sitecustomize.py','usercustomize.py'}:continue
            if not name.endswith(('.py','.pyc','.so')):continue
            path=parent/name;resolved=path.resolve(strict=True)
            if not (resolved.is_relative_to(root) or (str(path.relative_to(root))==shared_member and resolved in shared_targets) or (name=='sitecustomize.py'
                and resolved==Path('/etc/python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor)+'/sitecustomize.py'))):
                error=binding.CandidateDenied('STDLIB_LINK_DESTINATION_UNPROVEN')
                error.safe_diagnostics={'standardLibraryRelativeMember':str(path.relative_to(root)),
                    'targetCategory':'SYSTEM_APPORT_HOOK' if str(resolved).startswith('/usr/share/apport/') else 'OTHER_OUTSIDE_STDLIB',
                    'noSiteEnabled':bool(sys.flags.no_site)}
                raise error
            for ancestor in resolved.parents:
                info=ancestor.lstat()
                binding.require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and not info.st_mode&0o022,'STDLIB_FILE_ANCESTRY_UNPROVEN')
            before=path.lstat();fd=os.open(resolved,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                row=os.fstat(fd)
                binding.require(before.st_uid==before.st_gid==0 and stat.S_ISREG(row.st_mode) and row.st_uid==row.st_gid==0
                    and not row.st_mode&0o022 and 0<=row.st_size<=16000000,'STDLIB_FILE_CUSTODY_UNPROVEN')
                digest=hashlib.sha256();count=0
                while True:
                    part=os.read(fd,65536)
                    if not part:break
                    digest.update(part);count+=len(part)
                binding.require(count==row.st_size and binding.identity(row)==binding.identity(os.fstat(fd))
                    ==binding.identity(resolved.lstat()) and binding.identity(before)==binding.identity(path.lstat()),'STDLIB_FILE_CHANGED')
                total+=count;binding.require(total<=268435456 and len(files)<4096,'STDLIB_BINDING_UNBOUNDED')
                files[str(path.relative_to(root))]={'resolvedPath':str(resolved),'sha256':digest.hexdigest()}
            finally:os.close(fd)
    binding.require(files,'STDLIB_SOURCE_BINDINGS_REQUIRED')
    return {'root':str(root),'fileHashes':files,'noSiteRequired':True,
        'excludedStartupHooks':['sitecustomize.py','usercustomize.py']}

def inputs(directory):
    intake_raw=binding.read_member(directory,INTAKE)
    binding.require(binding.sha(intake_raw)==INTAKE_HASH,'EXACT_GOVERNANCE_INTAKE_HASH_REQUIRED')
    intake=binding.decode(intake_raw)
    binding.require(intake.get('schema')=='ouf.policy-token-governed-iam-preparation-intake.v1'
        and intake.get('authorityProfile')==governance.PROFILE and intake.get('trustPolicy')==governance.POLICY
        and intake.get('context')==governance.CONTEXT and intake.get('runtimeAuthorityIssued')is False
        and intake.get('productionApplyReady')is False,'EXACT_EXISTING_GOVERNANCE_INTAKE_REQUIRED')
    plan_raw=binding.read_member(directory,governance.PLAN);snapshot_raw=binding.read_member(directory,governance.SNAPSHOT)
    binding.require(binding.sha(plan_raw)==governance.PLAN_HASH and binding.sha(snapshot_raw)==governance.SNAPSHOT_HASH
        and intake['reviewPlanHash']==governance.PLAN_HASH and intake['snapshotHash']==governance.SNAPSHOT_HASH,'EXACT_IAM_REVIEW_LINEAGE_REQUIRED')
    profile_raw=governance.public_input(governance.PROFILE);policy_raw=governance.public_input(governance.POLICY)
    profile,policy=binding.decode(profile_raw),binding.decode(policy_raw)
    governance.authority_metadata(profile,policy,int(time.time()))
    programs=intake['executablesProposedNotAccepted']
    binding.require(set(programs)=={'python','docker','openssl'},'EXACT_OBSERVED_EXECUTABLE_SET_REQUIRED')
    binding.require(str(Path(sys.executable).resolve())==programs['python']['path']
        and str(Path('/usr/bin/docker').resolve())==programs['docker']['path'],'EXECUTED_PROGRAM_ROUTE_DRIFT')
    for value in programs.values():
        binding.require(governance.executable(value['path'])=={k:value[k] for k in ('path','sha256')},'OBSERVED_EXECUTABLE_BINDING_DRIFT')
    return intake,binding.decode(plan_raw),binding.decode(snapshot_raw),profile

def prepare(manifest,report):
    report['phase']='EXACT_GOVERNANCE_INTAKE_AND_APPLY_CLOSURE_READ'
    with binding.protected_parent()as directory:
        intake,plan,snapshot,profile=inputs(directory)
        binding.require(manifest.get('schema')=='ouf.policy-token-iam-action-source-closure.v1'
            and manifest.get('moduleCount')==19 and manifest.get('requiredPythonFlags')==['-I','-B','-S'],
            'EXACT_FULL_IAM_ACTION_CLOSURE_REQUIRED')
        report['phase']='PYTHON_STDLIB_BYTE_BINDING'
        library=stdlib_binding()
        source={'declaration':manifest,'executables':intake['executablesProposedNotAccepted'],
            'stdlibHash':binding.sha(binding.encoded(library)),'stdlibFileCount':len(library['fileHashes'])}
        lineage={'schema':'ouf.policy-token-iam-preparation-lineage.v1','reviewPlanHash':governance.PLAN_HASH,
            'snapshotHash':governance.SNAPSHOT_HASH,'governanceIntakeHash':INTAKE_HASH,'runtimeAccountingAccepted':False}
        review={'schema':'ouf.policy-token-iam-owner-action-review.v1','governanceIntakeHash':INTAKE_HASH,
            'reviewPlanHash':governance.PLAN_HASH,'snapshotHash':governance.SNAPSHOT_HASH,'sourceClosure':source,
            'sourceClosureHash':binding.sha(binding.encoded(source)),'stdlib':library,
            'policyTokenIamPreparation':intake['policyTokenIamPreparation'],'lineage':lineage,
            'maximumIamPostAttempts':1,'maximumExistingRoleSignatures':2,'authorityLifetimeSeconds':240,
            'requiredFirstInvocationWindowSeconds':900,'applySourceClosurePrepared':True,
            'freshHumanApprovalRequired':True,'runtimeAuthorityIssued':False,'productionApplyReady':False,
            'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
        inputs(directory)
        binding.require(stdlib_binding()==library,'STDLIB_CHANGED_DURING_REVIEW_PREPARATION')
        body=binding.encoded(review);digest=binding.sha(body)
        report['phase']='PRIVATE_FULL_ACTION_REVIEW_PUBLICATION'
        wrote=publish(directory,'policy-token-iam-action-review-'+digest+'.private.json',body)
        report.update(status='IAM_ACTION_CLOSURE_PREPARED_REVIEW_ONLY',privateEvidenceWrites=int(wrote),
            privateEvidencePath=str(binding.PARENT/('policy-token-iam-action-review-'+digest+'.private.json')),
            privateEvidenceHash=digest,sourceClosureHash=review['sourceClosureHash'],applySourceModuleCount=19,
            stdlibFileCount=len(library['fileHashes']),applySourceClosurePrepared=True,plannedIamMutations=1)
    return review

def decision_scope(review,review_hash,decision,now):
    binding.require(type(decision)is dict and set(decision)=={'approvalRef','approvedReviewHash','approvedSourceClosureHash',
        'approvedAt','firstInvocationBefore','decision','state'} and decision['decision']=='APPROVE_ONE_EXACT_IAM_CALLER_AUDIENCE_MAPPER'
        and decision['state']=='ACTIVE' and type(decision['approvalRef'])is str
        and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',decision['approvalRef'])
        and decision['approvedReviewHash']==review_hash and decision['approvedSourceClosureHash']==review['sourceClosureHash']
        and type(decision['approvedAt'])is int and type(decision['firstInvocationBefore'])is int
        and decision['approvedAt']<=now<decision['firstInvocationBefore']
        and 0<decision['firstInvocationBefore']-decision['approvedAt']<=900,'EXPLICIT_CURRENT_ONE_MAPPER_HUMAN_DECISION_REQUIRED')

def apply(manifest,review_hash,decision,report):
    # The launcher must independently bind the actual human witness bytes.
    # This function does not infer approval from the presence of a review file.
    report['phase']='EXACT_APPROVED_REVIEW_READ'
    with binding.protected_parent()as directory:
        raw=binding.read_member(directory,'policy-token-iam-action-review-'+review_hash+'.private.json')
        binding.require(binding.sha(raw)==review_hash,'APPROVED_ACTION_REVIEW_HASH_DRIFT');review=binding.decode(raw)
        decision_scope(review,review_hash,decision,int(time.time()))
        intake,plan,snapshot,profile=inputs(directory)
        binding.require(review['sourceClosure']['declaration']==manifest and review['sourceClosure']['executables']==intake['executablesProposedNotAccepted']
            and review['sourceClosureHash']==binding.sha(binding.encoded(review['sourceClosure']))
            and review['policyTokenIamPreparation']==intake['policyTokenIamPreparation']
            and review['stdlib']==stdlib_binding(),'APPROVED_SOURCE_OR_HOST_CLOSURE_DRIFT')
        claim_name='policy-token-iam-approval-'+binding.sha(binding.encoded(decision))+'.private.json'
        # Consumed before any key access. A failed/partial issuance is never
        # repeated automatically, even in a new job or after a restored clock.
        binding.require(not os.path.lexists(binding.PARENT/claim_name),'HUMAN_IAM_ISSUANCE_ALREADY_CONSUMED')
        report['phase']='PRIVATE_HUMAN_ISSUANCE_CLAIM_PUBLICATION'
        first=publish(directory,claim_name,binding.encoded({'schema':'ouf.policy-token-iam-issuance-claim.v1',
            'decisionHash':binding.sha(binding.encoded(decision)),'reviewHash':review_hash,'state':'ISSUANCE_CONSUMED',
            'runtimeAuthorityIssued':False,'budgetReset':False,'r12Touched':False}))
        binding.require(first,'HUMAN_IAM_ISSUANCE_ALREADY_CONSUMED')
        report['privateEvidenceWrites']=None
        report['actionEnvelopeWrites']=1
        report['transactionLedgerWritesIncludedInCount']=False
        report['humanIssuanceClaimConsumed']=True
        report['phase']='CURRENT_COMPLETE_IAM_RECONCILIATION'
        admin=MapperAdmin(snapshot['client']['id']);admin.deadline=time.monotonic()+90
        current=admin.baseline(snapshot);desired=plan['changeProposal']['proposedMapper']
        matches=[m for m in current['client']['protocolMappers'] if m.get('id')==desired['id'] or m.get('name')==desired['name']]
        if matches:
            binding.require(len(matches)==1 and equivalent(matches[0],desired),'CURRENT_MANAGED_MAPPER_CONFLICT')
            current['client']['protocolMappers']=[m for m in current['client']['protocolMappers'] if m.get('id')!=matches[0]['id']]
        binding.require(current==snapshot,'CURRENT_COMPLETE_IAM_BASELINE_DRIFT')
        models=admin.models()
        binding.require(models==snapshot['client']['protocolMappers'] or (len(matches)==1 and
            [m for m in models if m.get('id')!=matches[0]['id']]==snapshot['client']['protocolMappers']),
            'CURRENT_CLIENT_MAPPER_SET_DRIFT')
        decision_scope(review,review_hash,decision,int(time.time()));inputs(directory)
        now=int(time.time());expected={'intakeHash':review_hash,'sourceClosureHash':review['sourceClosureHash'],
            'creationRequestHash':binding.sha(binding.encoded(intake['policyTokenIamPreparation'])),
            'predecessorHistoryHash':binding.sha(binding.encoded(review['lineage'])),
            'predecessorIncidentRef':binding.sha(binding.encoded({'domain':'IAM_CALLER_AUDIENCE',
                'resource':intake['policyTokenIamPreparation']['resource'],'mapperHash':intake['policyTokenIamPreparation']['mapperHash']}))}
        authority={'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in expected.items() if k!='intakeHash'},
            'issuedAt':now,'expiresAt':now+240,'policyTokenIamPreparation':intake['policyTokenIamPreparation'],
            'policyTokenIamFreshReconciliation':{'reviewPlanHash':governance.PLAN_HASH,
                'observedClientMapperSetHash':binding.sha(binding.encoded(models)),'metadataAndCoreDriftChecked':True,'callerAudienceReconciled':True}}
        authority_raw=binding.encoded(authority)
        mandate={'schema':'ouf.semantic-cutover-human-mandate.v1','approvalRef':decision['approvalRef'],
            'decision':'APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY','state':'ACTIVE','issuedAt':now,'expiresAt':now+240,
            'executionAuthorityHash':binding.sha(authority_raw),**expected}
        name='policy-token-iam-signed-context-'+binding.sha(binding.encoded(decision))
        report['phase']='PRIVATE_SIGNED_AUTHORITY_PUBLICATION'
        os.mkdir(name,0o700,dir_fd=directory);os.fsync(directory)
        context=binding.PARENT/name;child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
        try:
            publish(child,'human.json',binding.encoded(mandate));publish(child,'authority.json',authority_raw)
            report['actionEnvelopeWrites']+=2
            # Existing verifier keeps its two-second per-native-call limit;
            # the finite mandate and sealed main deadline bound the operation.
            verifier=DetachedAuthenticator(governance.POLICY,str(context),intake['executablesProposedNotAccepted']['openssl'])
            approved_hash=binding.sha(binding.encoded(mandate))
            gate=CutoverAuthority(verifier,{'path':str(context/'human.json'),'sha256':approved_hash},approved_hash,governance.CONTEXT,expected)
            report['phase']='EXISTING_OWNER_DUAL_ROLE_ISSUANCE';gate.mandate(authority_raw)
            for role in ('DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'):
                gate.mandate(authority_raw);inputs(directory)
                report['installationKeyAccessAttempted']=True
                signer=ExistingEd25519Signer(profile['keyBindings']['installer'],profile['keyRefs']['installer'],verifier,
                    {'role':role,'issuerRef':governance.CONTEXT['intentIssuerRef' if role=='DEPLOYMENT_INTENT' else 'approvalIssuerRef'],
                        'installationRef':governance.CONTEXT['installationRef'],'entityRef':governance.CONTEXT['entityRef']})
                envelope=signer.sign(authority_raw)
                publish(child,binding.sha(authority_raw)+'.'+role+'.json',envelope)
                report['actionEnvelopeWrites']+=1
                report['signaturesIssued']+=1
            gate(authority_raw)
            report['phase']='ONE_SCOPED_IAM_TRANSACTION'
            operation=AudienceTransaction(plan,governance.PLAN_HASH,snapshot,gate,authority_raw)
            report['iamMutationOutcomeUnproven']=True
            result=operation.run();report.update(result);report['iamMutationOutcomeUnproven']=False
            report.update(status='SCOPED_IAM_ACTION_RECONCILED_NOT_RUNTIME_ACCEPTED',phase='APPLIED_RECONCILED',
                iamPreparationAuthorityVerified=True,privateEvidencePath=str(context),privateKeyReadCount=None)
        finally:os.close(child)
    return result

def main(manifest,mode='prepare',review_hash=None,decision=None):
    import signal
    report={'schema':'ouf.policy-token-iam-owner-action-receipt.v1','phase':'SEALED_ACTION_ENTRY','status':'BLOCKED',
        'mode':mode,'privateEvidenceWrites':0,'installationKeyAccessAttempted':False,'privateKeyReadCount':0,
        'signaturesIssued':0,'iamMutations':0,'serviceMutations':0,'credentialFilesRead':0,'mountedTokenFilesRead':0,
        'tokenGrantRequests':0,'providerCalls':0,'runtimeAuthorityIssued':False,'productionApplyReady':False,
        'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
    try:
        binding.require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.dont_write_bytecode and sys.flags.no_site,
            'ROOT_ISOLATED_NO_SITE_ACTION_REQUIRED')
        def timeout(*_):raise binding.CandidateDenied('FINITE_IAM_OWNER_ACTION_DEADLINE')
        signal.signal(signal.SIGALRM,timeout);signal.alarm(300)
        if mode=='prepare':
            binding.require(review_hash is None and decision is None,'PREPARATION_MUST_NOT_RECEIVE_APPROVAL')
            prepare(manifest,report)
        elif mode=='apply':
            binding.require(type(review_hash)is str and re.fullmatch('[0-9a-f]{64}',review_hash),'EXACT_APPROVED_REVIEW_HASH_REQUIRED')
            apply(manifest,review_hash,decision,report)
        else:binding.require(False,'EXACT_ACTION_MODE_REQUIRED')
        code=0
    except Exception as error:
        reason=str(error)
        report['reason']=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason) else type(error).__name__
        if isinstance(error,OSError):report['errno']=error.errno
        if hasattr(error,'safe_diagnostics'):report['safeDiagnostics']=error.safe_diagnostics
        if report['installationKeyAccessAttempted']:report['privateKeyReadCount']=None
        if report.get('iamMutationOutcomeUnproven'):report['iamMutations']=None
        report['evidencePublicationMayBePartial']=report['phase'] in {'PRIVATE_FULL_ACTION_REVIEW_PUBLICATION',
            'PRIVATE_HUMAN_ISSUANCE_CLAIM_PUBLICATION','PRIVATE_SIGNED_AUTHORITY_PUBLICATION',
            'EXISTING_OWNER_DUAL_ROLE_ISSUANCE','ONE_SCOPED_IAM_TRANSACTION'}
        code=1
    finally:signal.alarm(0)
    print(binding.encoded(report).decode());return code
