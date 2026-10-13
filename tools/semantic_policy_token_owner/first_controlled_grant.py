"""First finite UNKNOWN-history grant + online admission + protected publication.

No legacy journal initialization or scheduled renewal. This component requires
an already governed credential transaction and prepared root-owned output.
It becomes executable only inside the separately reviewed full source closure.
A published token is not runtime/lease/application acceptance.
"""
import fcntl
import os
import re
import stat
import time
import uuid
import accounting_gap_session as sessions
import credential_transaction as credentials
import iam_binding_candidate as evidence
from tools.semantic_policy_token_owner.producer import Binding,CredentialFile,HttpsGrant,AtomicTokenFile,token_response,protected_directory
from tools.semantic_policy_token_owner.iam_admission import IamProfile,PinnedIamOpener,OnlineIamAdmission

class FirstControlledGrant:
    def __init__(self,session,credential_transaction,binding,profile,transport,output_identity,clock=lambda:(time.time(),time.monotonic())):
        evidence.require(type(session)is sessions.FirstGapSession and type(credential_transaction)is credentials.CredentialTransaction
            and session.authority is credential_transaction.authority and session.raw==credential_transaction.raw,
            'SAME_FIRST_SESSION_AND_CREDENTIAL_AUTHORITY_REQUIRED')
        evidence.require(type(binding)is Binding and type(profile)is IamProfile and type(transport)is PinnedIamOpener
            and transport.profile==profile,'CONCRETE_PINNED_IAM_COMPONENTS_REQUIRED')
        profile.match(binding)
        evidence.require(profile.client_id==credential_transaction.registration['clientId']
            and session.scope['logicalOwnerScopeHash']==credential_transaction.scope['logicalOwnerScopeHash'],
            'SAME_LOGICAL_CLIENT_AND_OWNER_REQUIRED')
        evidence.require(type(output_identity)is dict and set(output_identity)=={'device','inode'}
            and all(type(v)is int and v>=0 for v in output_identity.values())and output_identity['inode']>0,
            'APPROVED_OUTPUT_DIRECTORY_IDENTITY_REQUIRED')
        self.session,self.transaction=session,credential_transaction
        self.binding,self.profile,self.transport,self.clock=binding,profile,transport,clock
        self.output_identity=dict(output_identity)
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
    def migrate(self):
        """Compose the existing operations after root/input execution review.

        No new scheduler, journal or automatic retry. Completed credential
        custody can be reused; an ambiguous rotation or consumed grant cannot.
        The caller still supplies the independently reviewed target policy,
        consumer, directory, TLS and native HUMAN execution bindings.
        """
        phase='MIGRATION_SCOPE_PREFLIGHT'
        try:
            raw=evidence.decode(self.session.raw)
            for key,scope in (
                ('policyTokenLegacyRetirement',self.transaction.retirement.scope),
                ('policyTokenCredentialReestablishment',self.transaction.scope),
                ('policyTokenAccountingGapMigration',self.session.scope),
                ('policyTokenFirstControlledGrant',self.scope)):
                evidence.require(raw.get(key)==scope,'COMPLETE_SIGNED_MIGRATION_SCOPES_REQUIRED')
            self.session.guard()
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
        self.session.guard()
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
