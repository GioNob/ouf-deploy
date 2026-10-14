"""First finite UNKNOWN-history grant + online admission + protected publication.

No legacy journal initialization or scheduled renewal. This component requires
an already governed credential transaction and prepared root-owned output.
It becomes executable only inside the separately reviewed full source closure.
A published token is not runtime/lease/application acceptance.
"""
import fcntl
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import uuid
import accounting_gap_session as sessions
import credential_transaction as credentials
import migration_root_custody as root_custody
import iam_binding_candidate as evidence
from tools.semantic_policy_token_owner.producer import Binding,CredentialFile,HttpsGrant,AtomicTokenFile,token_response,protected_directory
from tools.semantic_policy_token_owner.iam_admission import IamProfile,PinnedIamOpener,OnlineIamAdmission

def registry_generation():
    """Exact selected metadata only; do not retrieve Env, command or logs."""
    cid='7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147'
    template='{"id":{{json .Id}},"image":{{json .Image}},"pid":{{json .State.Pid}},"startedAt":{{json .State.StartedAt}},"running":{{json .State.Running}},"restartPolicy":{{json .HostConfig.RestartPolicy}},"mounts":{{json .Mounts}}}'
    with tempfile.TemporaryFile()as stdout:
        reply=subprocess.run(['/usr/bin/docker','inspect','--type','container','--format',template,cid],
            stdin=subprocess.DEVNULL,stdout=stdout,stderr=subprocess.DEVNULL,timeout=10,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        stdout.seek(0);raw=stdout.read(65537)
    evidence.require(reply.returncode==0 and 0<len(raw)<=65536,'REVIEW_BOUND_REGISTRY_METADATA_UNAVAILABLE')
    result=json.loads(raw,object_pairs_hook=evidence.unique)
    evidence.require(type(result)is dict and set(result)=={'id','image','pid','startedAt','running','restartPolicy','mounts'}
        and result['id']==cid and result['running']is True and type(result['pid'])is int and result['pid']>0,
        'REVIEW_BOUND_REGISTRY_METADATA_INVALID')
    return result

class FirstControlledGrant:
    @classmethod
    def from_installation_review(cls,authority,authority_raw,host_raw,review_raw,review_hash,review_source_hash,
                                 registration,binding,profile,transport,output_identity,clock=lambda:(time.time(),time.monotonic())):
        """Bind the retained input review without treating it as execution approval.

        The caller still supplies fresh four-scope HUMAN/dual-role authority,
        actual prepared output custody and independent IAM/TLS bindings.
        No collection, directory, credential or budget is created here.
        """
        for value in (review_hash,review_source_hash):
            evidence.require(type(value)is str and re.fullmatch('[0-9a-f]{64}',value),
                'INDEPENDENT_INSTALLATION_REVIEW_HASHES_REQUIRED')
        evidence.require(type(review_raw)is bytes and 0<len(review_raw)<=524288
            and evidence.sha(review_raw)==review_hash,'INSTALLATION_REVIEW_BYTES_HASH_DRIFT')
        review=evidence.decode(review_raw)
        evidence.require(review.get('schema')=='ouf.semantic-candidate-installation-input-review.v1'
            and review.get('sourceClosureHash')==review_source_hash
            and evidence.sha(evidence.encoded(review.get('sourceClosure')))==review_source_hash
            and review.get('targetApplyAuthorized')is False and review.get('runtimeAuthorityIssued')is False
            and review.get('budgetReset')is False and review.get('r12Touched')is False
            and review.get('notReleaseAcceptance')is True and review.get('retainedHostInputsHash')==evidence.sha(host_raw),
            'EXACT_RETAINED_INSTALLATION_INPUT_REVIEW_REQUIRED')
        packages=review.get('packages')
        expected={
            'semantic':('78954f106ea1248c624bf71596785af0b2980480cd58020eb0accd5d1f2df1c6','bdfe0f75a5fc4790a5c5ff36e201c3d99713ecc0'),
            'mcp':('6db692b78f1fde7bc3a30a8727afd4f581b2f8574f00c2fc117b71ea59b2aab4','d43f5604976b07c66d58c5180d871c5656c44d4d'),
            'gateway':('74b4f974adf74401cd592df26ce62dbea9399c8c025b124ee0e11e6d06f9d73a','23b02bd2195d36499b6618750d52dd49d65c9a60')}
        evidence.require(type(packages)is dict and set(packages)==set(expected),'EXACT_REVIEWED_CANDIDATE_SET_REQUIRED')
        for name,(digest,commit)in expected.items():
            record=packages[name];manifest=record.get('manifest',{})
            evidence.require(record.get('archiveSha256')==digest and record.get('rootCustodyEstablished')is False
                and manifest.get('sourceCommit')==commit and manifest.get('module')==name
                and manifest.get('schema')=='ouf.semantic-proposal-unsigned-candidate.v1'
                and manifest.get('signatureIssued')is False and manifest.get('runtimeAuthorityIssued')is False
                and manifest.get('targetApplyAuthorized')is False and manifest.get('notReleaseAcceptance')is True,
                'REVIEWED_CANDIDATE_IDENTITY_OR_AUTHORITY_DRIFT')
        evidence.require(packages['semantic']['manifest'].get('imageId')==
            'sha256:1e2dac4a6619f511056abc91dd153ce7687efc25aec25aa77a6f66c9f2f67cfd',
            'REVIEWED_REGISTRY_CANDIDATE_IMAGE_DRIFT')
        native=review.get('currentRegistry')
        evidence.require(type(native)is dict and set(native)=={'id','image','pid','startedAt','running','restartPolicy','mounts'}
            and native.get('id')=='7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147'
            and native.get('image')=='sha256:f6525f2512c72a600ebcbc7060d55355d86e0627487b655e7c5c6288a0be7fc6'
            and type(native.get('pid'))is int and native['pid']>0 and native.get('running')is True,
            'REVIEWED_PREDECESSOR_REGISTRY_REQUIRED')
        result=cls.from_completed_custody(authority,authority_raw,host_raw,
            review.get('completedRootEvidenceHash'),review.get('rootCreationSourceClosureHash'),
            registration,binding,profile,transport,output_identity,clock)
        result.installation_review=(bytes(review_raw),review_hash,review_source_hash)
        result.scope={**result.scope,'schema':'ouf.policy-token-first-controlled-grant-scope.v3',
            'installationInputReviewHash':review_hash,'installationInputReviewSourceClosureHash':review_source_hash,
            'reviewedCandidateSetHash':evidence.sha(evidence.encoded(packages)),
            'reviewedPredecessorRegistryGenerationHash':evidence.sha(evidence.encoded(native))}
        result.guard_installation_review()
        return result

    @classmethod
    def from_completed_custody(cls,authority,authority_raw,host_raw,root_evidence_hash,root_source_closure_hash,
                               registration,binding,profile,transport,output_identity,clock=lambda:(time.time(),time.monotonic()),*,output_custody=None):
        """Compose from actual retained root identities, without creating or issuing.

        All new effects still require the current four signed migration scopes.
        Output custody remains a separate explicitly prepared binding.
        """
        with root_custody.completed_roots(host_raw,root_evidence_hash,root_source_closure_hash)as identities:
            retirement=credentials.legacy.LegacyRetirement(authority,authority_raw,host_raw)
            selected=identities['ownerCredential']
            transaction=credentials.CredentialTransaction(retirement,authority,authority_raw,registration,
                selected['path'],{key:selected[key]for key in ('device','inode')})
            session=sessions.FirstGapSession(authority,authority_raw,retirement.host['logicalOwnerScopeHash'],
                authority.expected['sourceClosureHash'],lambda:clock()[0],lambda:clock()[1])
            result=cls(session,transaction,binding,profile,transport,output_identity,clock,output_custody=output_custody)
            result.root_receipt=(bytes(host_raw),root_evidence_hash,root_source_closure_hash)
            result.scope={**result.scope,'schema':'ouf.policy-token-first-controlled-grant-scope.v2',
                'completedRootEvidenceHash':root_evidence_hash,'rootCreationSourceClosureHash':root_source_closure_hash}
            if output_custody is not None:
                result.scope.pop('outputDirectoryIdentity')
                result.scope.update(schema='ouf.policy-token-first-controlled-grant-scope.v4',
                    outputCustodyScopeHash=evidence.sha(evidence.encoded(output_custody.scope)))
            return result

    def __init__(self,session,credential_transaction,binding,profile,transport,output_identity,clock=lambda:(time.time(),time.monotonic()),*,output_custody=None):
        evidence.require(type(session)is sessions.FirstGapSession and type(credential_transaction)is credentials.CredentialTransaction
            and session.authority is credential_transaction.authority and session.raw==credential_transaction.raw,
            'SAME_FIRST_SESSION_AND_CREDENTIAL_AUTHORITY_REQUIRED')
        evidence.require(type(binding)is Binding and type(profile)is IamProfile and type(transport)is PinnedIamOpener
            and transport.profile==profile,'CONCRETE_PINNED_IAM_COMPONENTS_REQUIRED')
        profile.match(binding)
        evidence.require(profile.client_id==credential_transaction.registration['clientId']
            and session.scope['logicalOwnerScopeHash']==credential_transaction.scope['logicalOwnerScopeHash'],
            'SAME_LOGICAL_CLIENT_AND_OWNER_REQUIRED')
        evidence.require((type(output_custody)is root_custody.TokenOutputCustody and output_identity is None
            and output_custody.authority is session.authority and output_custody.raw==session.raw
            and str(output_custody.path)==binding.output_directory) or
            (type(output_identity)is dict and set(output_identity)=={'device','inode'}
            and all(type(v)is int and v>=0 for v in output_identity.values())and output_identity['inode']>0),
            'APPROVED_OUTPUT_DIRECTORY_IDENTITY_REQUIRED')
        self.session,self.transaction=session,credential_transaction
        self.binding,self.profile,self.transport,self.clock=binding,profile,transport,clock
        self.output_identity=None if output_identity is None else dict(output_identity)
        self.output_custody=output_custody
        self.root_receipt=None
        self.installation_review=None
        self.credential=CredentialFile(credential_transaction.path/credential_transaction.MEMBER)
        self.admission=OnlineIamAdmission(profile,self.credential,transport,clock)
        self.writer=AtomicTokenFile(binding)
        self.scope={'schema':'ouf.policy-token-first-controlled-grant-scope.v1',
            'operation':'ONE_GRANT_ONLINE_ADMISSION_AND_PROTECTED_PUBLICATION',
            'sessionOperation':session.operation,'sourceClosureHash':session.scope['sourceClosureHash'],
            'credentialOperation':credential_transaction.operation,'credentialScopeHash':evidence.sha(evidence.encoded(credential_transaction.scope)),
            'bindingHash':binding.digest(),'iamProfileHash':profile.digest(),'tlsTrustHash':transport.trust_digest(),
            'outputDirectoryIdentity':self.output_identity,'maximumGrantAttempts':1,
            'automaticRenewalAllowed':False,'runtimeAcceptanceGranted':False}
        self.name='policy-token-first-controlled-grant-'+session.operation+'.private.json'
    def guard_completed_roots(self):
        if self.root_receipt is None:
            evidence.require(self.scope.get('schema')=='ouf.policy-token-first-controlled-grant-scope.v1'
                and 'completedRootEvidenceHash'not in self.scope and 'rootCreationSourceClosureHash'not in self.scope,
                'COMPLETED_ROOT_REVIEW_BINDING_MISSING')
            return
        host_raw,digest,source=self.root_receipt
        evidence.require(self.scope.get('schema')in {'ouf.policy-token-first-controlled-grant-scope.v2','ouf.policy-token-first-controlled-grant-scope.v3','ouf.policy-token-first-controlled-grant-scope.v4'}
            and self.scope.get('completedRootEvidenceHash')==digest
            and self.scope.get('rootCreationSourceClosureHash')==source,'COMPLETED_ROOT_REVIEW_BINDING_DRIFT')
        with root_custody.completed_roots(host_raw,digest,source)as identities:
            selected=identities['ownerCredential']
            evidence.require(selected['path']==str(self.transaction.path)
                and {key:selected[key]for key in ('device','inode')}==self.transaction.directory_identity,
                'MIGRATION_CREDENTIAL_ROOT_BINDING_DRIFT')
    def prepare_output(self):
        evidence.require(type(self.output_custody)is root_custody.TokenOutputCustody,
            'EXPLICIT_GOVERNED_OUTPUT_CUSTODY_REQUIRED')
        self.session.guard()
        evidence.require(evidence.decode(self.session.raw).get('policyTokenFirstControlledGrant')==self.scope,
            'EXPLICIT_SIGNED_FIRST_GRANT_AND_PUBLICATION_REQUIRED')
        row=self.output_custody.run()
        self.output_identity=dict(row['outputIdentity'])
        self.guard_output_custody()
        return row
    def guard_output_custody(self):
        if self.output_custody is None:
            evidence.require(self.scope.get('schema')!='ouf.policy-token-first-controlled-grant-scope.v4',
                'SIGNED_OUTPUT_CUSTODY_BINDING_MISSING')
            return
        output=self.output_custody
        evidence.require(type(output)is root_custody.TokenOutputCustody and output.authority is self.session.authority
            and output.raw==self.session.raw and str(output.path)==self.binding.output_directory
            and self.scope.get('outputCustodyScopeHash')==evidence.sha(evidence.encoded(output.scope)),
            'SIGNED_OUTPUT_CUSTODY_BINDING_DRIFT')
        output.guard()
        with evidence.protected_parent()as directory:
            row=output.validate(evidence.decode(evidence.read_member(directory,output.name)))
        evidence.require(row['state']=='OUTPUT_CUSTODIED_NOT_RUNTIME_ACCEPTED'
            and row['outputIdentity']==self.output_identity,'EXACT_CREATED_OUTPUT_IDENTITY_REQUIRED')

    def guard_installation_review(self):
        if self.installation_review is None:
            evidence.require(self.scope.get('schema')!='ouf.policy-token-first-controlled-grant-scope.v3'
                and 'installationInputReviewHash'not in self.scope,'INSTALLATION_REVIEW_BINDING_MISSING')
            return
        self.guard_completed_roots()
        raw,digest,source=self.installation_review
        evidence.require(evidence.sha(raw)==digest and self.scope.get('schema')=='ouf.policy-token-first-controlled-grant-scope.v3'
            and self.scope.get('installationInputReviewHash')==digest
            and self.scope.get('installationInputReviewSourceClosureHash')==source,'INSTALLATION_REVIEW_SCOPE_DRIFT')
        review=evidence.decode(raw)
        evidence.require(review['sourceClosureHash']==source and evidence.sha(evidence.encoded(review['sourceClosure']))==source
            and self.scope['reviewedCandidateSetHash']==evidence.sha(evidence.encoded(review['packages']))
            and self.scope['reviewedPredecessorRegistryGenerationHash']==evidence.sha(evidence.encoded(review['currentRegistry'])),
            'INSTALLATION_REVIEW_CONTEXT_DRIFT')
        with evidence.protected_parent()as directory:
            evidence.require(evidence.read_member(directory,'semantic-candidate-installation-input-review-'+digest+'.private.json')==raw,
                'RETAINED_INSTALLATION_REVIEW_CHANGED')
        with root_custody.completed_roots(*self.root_receipt)as identities:
            evidence.require(review['completedRoots']==identities,'INSTALLATION_REVIEW_ROOT_IDENTITIES_DRIFT')
        executable=review['sourceClosure']['executables']['docker']
        evidence.require(credentials.governance.executable('/usr/bin/docker')==executable,
            'REVIEW_BOUND_DOCKER_EXECUTABLE_CHANGED')
        observed=registry_generation()
        if observed!=review['currentRegistry']:
            error=evidence.CandidateDenied('REVIEW_BOUND_REGISTRY_GENERATION_CHANGED')
            error.safe_diagnostics={'changedFields':[k for k in observed if observed[k]!=review['currentRegistry'][k]],
                'evidenceLocation':'semantic-candidate-installation-input-review-'+digest+'.private.json',
                'rawMetadataPrinted':False,'automaticReplayAllowed':False}
            raise error
    def migrate(self):
        """Compose the existing operations after root/input execution review.

        No new scheduler, journal or automatic retry. Completed credential
        custody can be reused; an ambiguous rotation or consumed grant cannot.
        The caller still supplies the independently reviewed target policy,
        consumer, directory, TLS and native HUMAN execution bindings.
        """
        phase='MIGRATION_SCOPE_PREFLIGHT'
        try:
            self.guard_installation_review()
            self.guard_output_custody()
            raw=evidence.decode(self.session.raw)
            for key,scope in (
                ('policyTokenLegacyRetirement',self.transaction.retirement.scope),
                ('policyTokenCredentialReestablishment',self.transaction.scope),
                ('policyTokenAccountingGapMigration',self.session.scope),
                ('policyTokenFirstControlledGrant',self.scope)):
                evidence.require(raw.get(key)==scope,'COMPLETE_SIGNED_MIGRATION_SCOPES_REQUIRED')
            self.session.guard()
            self.guard_completed_roots()
            evidence.require(self.binding.digest()==self.scope['bindingHash']
                and self.profile.digest()==self.scope['iamProfileHash']
                and self.transport.trust_digest()==self.scope['tlsTrustHash'],'MIGRATION_CONFIGURATION_OR_TLS_DRIFT')
            # Reject consumed work or ambiguous predecessor effects before
            # touching units, IAM or the issuer. Absence does not create a budget.
            with evidence.protected_parent()as directory:
                try:session=self.session.validate(evidence.decode(evidence.read_member(directory,self.session.name)))
                except FileNotFoundError:session=None
                evidence.require(session is None or session['attemptSlotsConsumed']==0,'FIRST_GRANT_ALREADY_CONSUMED_NO_REPLAY')
                if session is not None:
                    wall,mono=self.clock()
                    evidence.require(session['lastObservedAt']<=wall<session['expiresAt']
                        and session['lastMonotonic']<=mono<session['expiresMonotonic']
                        and session['bootId']==sessions.boot_identity(),'MIGRATION_SESSION_EXPIRED_OR_DRIFTED')
                try:credential=evidence.decode(evidence.read_member(directory,self.transaction.name))
                except FileNotFoundError:credential=None
                if credential is not None:
                    evidence.require(credential.get('schema')=='ouf.policy-token-credential-transaction.v1'
                        and credential.get('operation')==self.transaction.operation and credential.get('scope')==self.transaction.scope
                        and credential.get('state')=='NEW_CREDENTIAL_CUSTODIED_NOT_RUNTIME_ACCEPTED'
                        and credential.get('iamMutationAttemptConsumed')is True and credential.get('credentialPublished')is True,
                        'CREDENTIAL_RECONCILIATION_REQUIRED_NO_AUTOMATIC_REPLAY')
            # Check prepared output before retiring an otherwise functioning writer.
            previous=evidence.PARENT
            try:
                evidence.PARENT=self.transaction.path
                with evidence.protected_parent()as directory:
                    info=os.fstat(directory)
                    evidence.require({'device':info.st_dev,'inode':info.st_ino}==self.transaction.directory_identity
                        and stat.S_IMODE(info.st_mode)==0o700,'MIGRATION_CREDENTIAL_DIRECTORY_CHANGED')
                    if credential is None:evidence.require(os.listdir(directory)==[],'MIGRATION_CREDENTIAL_DIRECTORY_NOT_EMPTY')
            finally:evidence.PARENT=previous
            if credential is not None:
                evidence.require(evidence.sha(self.credential.read().encode())==credential.get('newSecretHash'),
                    'REESTABLISHED_CREDENTIAL_CHANGED')
            self.writer.check_custody()
            with protected_directory(self.binding.output_directory,gid=self.binding.output_gid,mode=0o750)as directory:
                info=os.fstat(directory)
                evidence.require({'device':info.st_dev,'inode':info.st_ino}==self.output_identity
                    and os.listdir(directory)==[],'MIGRATION_OUTPUT_CUSTODY_OR_CONTENT_CHANGED')
            phase='GOVERNED_LEGACY_RETIREMENT'
            self.transaction.retirement.run()
            phase='GOVERNED_CREDENTIAL_REESTABLISHMENT'
            if credential is None:self.transaction.run()
            # run() verifies current local credential bytes against the durable
            # successful transaction. No later IAM GET adopts an ambiguous POST.
            phase='FIRST_CONTROLLED_GRANT_AND_PUBLICATION'
            return self.run()
        except Exception as error:
            reason=str(error)
            detail={'phase':phase,'reason':reason if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason)else type(error).__name__,
                'retirementEvidence':self.transaction.retirement.name,'credentialEvidence':self.transaction.name,
                'sessionEvidence':self.session.name,'automaticRetryPerformed':False,'rawDiagnosticTextPrinted':False}
            if type(getattr(error,'safe_diagnostics',None))is dict:detail['operationDiagnostic']=error.safe_diagnostics
            error.safe_diagnostics=detail
            raise
    def guard(self):
        self.guard_output_custody()
        self.session.guard()
        self.guard_installation_review()
        self.guard_completed_roots()
        evidence.require(evidence.decode(self.session.raw).get('policyTokenFirstControlledGrant')==self.scope,
            'EXPLICIT_SIGNED_FIRST_GRANT_AND_PUBLICATION_REQUIRED')
        evidence.require(self.binding.digest()==self.scope['bindingHash'] and self.profile.digest()==self.scope['iamProfileHash']
            and self.transport.trust_digest()==self.scope['tlsTrustHash'],'FIRST_GRANT_CONFIGURATION_OR_TLS_DRIFT')
        self.transaction.guard()
        with evidence.protected_parent()as directory:
            row=evidence.decode(evidence.read_member(directory,self.transaction.name))
            evidence.require(row.get('schema')=='ouf.policy-token-credential-transaction.v1'
                and row.get('operation')==self.transaction.operation and row.get('scope')==self.transaction.scope
                and row.get('state')=='NEW_CREDENTIAL_CUSTODIED_NOT_RUNTIME_ACCEPTED'
                and row.get('iamMutationAttemptConsumed')is True and row.get('credentialPublished')is True,
                'RECONCILED_GOVERNED_NEW_CREDENTIAL_REQUIRED')
            evidence.require(evidence.sha(self.credential.read().encode())==row.get('newSecretHash'),
                'REESTABLISHED_CREDENTIAL_CHANGED')
        with protected_directory(self.binding.output_directory,gid=self.binding.output_gid,mode=0o750)as directory:
            info=os.fstat(directory)
            evidence.require({'device':info.st_dev,'inode':info.st_ino}==self.output_identity,'FIRST_GRANT_OUTPUT_DIRECTORY_CHANGED')
    def run(self):
        now=self.clock()[1];self.transaction.last_time=now;self.transaction.admin.deadline=now+300
        self.guard()
        with evidence.protected_parent()as directory:
            lock=os.open(self.name+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
            try:
                info=os.fstat(lock)
                evidence.require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0
                    and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'FIRST_GRANT_INVOCATION_CUSTODY_REQUIRED')
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);seal=evidence.identity(info)
                def fence():
                    evidence.require(seal==evidence.identity(os.fstat(lock))
                        ==evidence.identity(os.stat(self.name+'.lock',dir_fd=directory,follow_symlinks=False)),
                        'FIRST_GRANT_INVOCATION_FENCE_CHANGED')
                row=self.session.open()
                evidence.require(row['attemptSlotsConsumed']==0,'FIRST_GRANT_ALREADY_CONSUMED_NO_REPLAY')
                deadline=row['expiresMonotonic'];self.transaction.admin.deadline=deadline
                def current():
                    self.guard();fence()
                    retained=self.session.validate(evidence.decode(evidence.read_member(directory,self.session.name)))
                    wall,mono=self.clock()
                    evidence.require(retained['lastObservedAt']<=wall<retained['expiresAt']
                        and retained['lastMonotonic']<=mono<deadline
                        and retained['bootId']==sessions.boot_identity(),'FIRST_GRANT_SESSION_EXPIRED_OR_DRIFTED')
                current();self.writer.check_custody()
                # A previous or unrelated output must not be silently superseded
                # by the FIRST new-contract publication.
                with protected_directory(self.binding.output_directory,gid=self.binding.output_gid,mode=0o750)as output:
                    evidence.require(os.listdir(output)==[],'FIRST_GRANT_OUTPUT_MUST_BE_EMPTY')
                self.admission.prepare(deadline);current()
                secret=self.credential.read();current()
                consumed=self.session.consume_attempt_slot()
                current();started=self.clock()[1]
                # No automatic retry after reservation, even if the transport
                # later classifies an individual failure as no-effect.
                result=HttpsGrant(self.clock,opener=self.transport).request(self.binding,secret,deadline)
                token,seconds=token_response(result,self.binding);valid_until=started+seconds
                def admit():
                    current()
                    evidence.require(valid_until-self.clock()[1]>=self.binding.minimum_remaining,'FIRST_GRANT_TOKEN_LIFETIME_UNPROVEN')
                    evidence.require(self.admission.admit(token,valid_until,deadline)is True,'ACTUAL_ONLINE_TOKEN_ADMISSION_REQUIRED')
                    current()
                admit();publication=self.writer.publish(token,admit);current()
                receipt={'schema':'ouf.policy-token-first-controlled-grant-result.v1','operation':self.session.operation,
                    'scopeHash':evidence.sha(evidence.encoded(self.scope)),'state':'TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED',
                    'attemptSlotsConsumed':consumed['attemptSlotsConsumed'],'tokenHash':evidence.sha(token.encode()),
                    'publicationReceiptHash':publication,'validUntilMonotonic':valid_until,'bootId':row['bootId'],
                    'legacyHistoricalGrantAttempts':None,'historicalAccountingReconciled':False,'gapRemainsOpen':True,
                    'runtimeAuthorityIssued':False,'productionApplyReady':False,'budgetReset':False,'r12Touched':False,
                    'notReleaseAcceptance':True}
                # An interrupted or partial final receipt is not overwritten.
                current();raw=evidence.encoded(receipt)
                fd=os.open(self.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                try:
                    with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                    os.fsync(directory);current()
                    evidence.require(evidence.read_member(directory,self.name)==raw,'FIRST_GRANT_RESULT_PUBLICATION_UNPROVEN')
                finally:os.close(fd)
                return receipt
            finally:os.close(lock)
