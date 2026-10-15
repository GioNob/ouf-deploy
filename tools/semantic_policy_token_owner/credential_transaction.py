"""One governed credential regeneration with durable no-replay reservation.

Component, not a standalone installer. The sealed caller must bind all executing
bytes, prepare and own the exact destination, and supply current full authority.
Ambiguous regeneration is terminal for automatic mutation: no secret adoption,
new POST, refund or rotation retry is inferred from a later GET.
"""
import fcntl
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import tempfile
import time
import uuid
import iam_binding_candidate as binding
import iam_governance_intake as governance
import legacy_retirement as legacy
from credential_reestablishment import secret_value,stable_registration,verify_reestablishment
from cutover_authority import CutoverAuthority

def bounded_output():
    resource.setrlimit(resource.RLIMIT_FSIZE,(65537,65537))

class SecretAdmin:
    def __init__(self,client):
        binding.require(type(client)is str and re.fullmatch('[0-9a-fA-F-]{36}',client),'EXACT_REGISTERED_CLIENT_UUID_REQUIRED')
        self.resource='clients/'+client;self.deadline=None
    def call(self,operation,suffix=''):
        binding.require(operation in ('get','create') and suffix in ('','/client-secret','/client-secret/rotated')
            and (operation=='get' or suffix=='/client-secret'),'EXACT_CREDENTIAL_OPERATION_REQUIRED')
        remaining=self.deadline-time.monotonic() if self.deadline is not None else 0
        binding.require(remaining>0,'CREDENTIAL_TRANSACTION_DEADLINE')
        argv=['/usr/bin/docker','exec','ouf-keycloak','/opt/keycloak/bin/kcadm.sh',operation,self.resource+suffix,
            '--server','http://localhost:8080','-r','ouf']
        if operation=='create':argv+=['-o']
        with tempfile.TemporaryFile()as out,tempfile.TemporaryFile()as err:
            try:
                result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                    timeout=min(15,remaining),preexec_fn=bounded_output,
                    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            except subprocess.TimeoutExpired:
                denied=binding.CandidateDenied('CREDENTIAL_ADMIN_TIMEOUT_OUTCOME_UNPROVEN')
                denied.safe_diagnostics={'phase':'CREDENTIAL_ADMIN_'+operation.upper(),
                    'category':'COMMAND_TIMEOUT','mutationOutcomeMayBeUnproven':operation=='create',
                    'rawDiagnosticTextPrinted':False,'automaticReplayAllowed':False}
                raise denied from None
            out.seek(0);raw=out.read(65537);err.seek(0);diagnostic=err.read(16385)
        if result.returncode!=0 or not 0<len(raw)<=65536:
            text=diagnostic[:16384].decode('utf-8','replace').lower()
            categories=[label for pattern,label in (
                (r'not logged in|session.*expired|token.*expired|invalid_grant|unauthorized','SESSION_AUTH_FAILURE_TEXT_OBSERVED'),
                (r'forbidden|not authorized|permission denied','PERMISSION_FAILURE_TEXT_OBSERVED'),
                (r'not found|does not exist','RESOURCE_UNAVAILABLE_TEXT_OBSERVED'),
                (r'connection refused|connectexception','CONNECTION_FAILURE_TEXT_OBSERVED'))if re.search(pattern,text)]
            denied=binding.CandidateDenied('CREDENTIAL_ADMIN_COMMAND_OR_RESPONSE_UNPROVEN')
            denied.safe_diagnostics={'phase':'CREDENTIAL_ADMIN_'+operation.upper(),'exitCode':result.returncode,
                'responseEmpty':len(raw)==0,'responseBoundExceeded':len(raw)>65536,
                'diagnosticCategories':categories or ['UNCLASSIFIED_COMMAND_FAILURE'],
                'diagnosticCategoriesAreNotRootCauseProof':True,'diagnosticTextTruncated':len(diagnostic)>16384,
                'rawDiagnosticTextPrinted':False,'mutationOutcomeMayBeUnproven':operation=='create',
                'automaticReplayAllowed':False}
            raise denied
        return binding.decode(raw)

class CredentialTransaction:
    MEMBER='client-secret'
    def __init__(self,retirement,authority,authority_raw,registration,destination,directory_identity):
        binding.require(type(retirement)is legacy.LegacyRetirement and type(authority)is CutoverAuthority
            and retirement.authority is authority and retirement.raw==authority_raw,'SAME_GOVERNED_MIGRATION_AUTHORITY_REQUIRED')
        self.retirement,self.authority,self.raw=retirement,authority,bytes(authority_raw)
        self.registration=binding.decode(binding.encoded(registration));self.registration_hash=binding.sha(binding.encoded(stable_registration(registration)))
        self.path=Path(destination)
        binding.require(str(self.path)==destination and self.path.is_absolute() and '..'not in self.path.parts
            and destination==retirement.host['proposedRootsMetadata']['ownerCredential']['path'],
            'EXACT_REVIEWED_CREDENTIAL_DESTINATION_REQUIRED')
        binding.require(type(directory_identity)is dict and set(directory_identity)=={'device','inode'}
            and all(type(v)is int and v>=0 for v in directory_identity.values())and directory_identity['inode']>0,
            'OWNED_CREDENTIAL_DIRECTORY_IDENTITY_REQUIRED')
        self.directory_identity=dict(directory_identity)
        self.scope={'schema':'ouf.policy-token-credential-reestablishment-scope.v1',
            'operation':'REGENERATE_EXACT_CLIENT_SECRET_ONCE','logicalOwnerScopeHash':retirement.scope['logicalOwnerScopeHash'],
            'hostInputsHash':legacy.HOST_HASH,'sourceClosureHash':authority.expected['sourceClosureHash'],
            'clientUuid':registration['id'],'clientId':registration['clientId'],'registrationHash':self.registration_hash,
            'destination':destination,'directoryIdentity':self.directory_identity,'member':self.MEMBER,
            'maximumIamMutations':1,'legacyCredentialFileReadAllowed':False,'automaticReplayAllowed':False}
        self.operation=binding.sha(binding.encoded({'logicalOwnerScopeHash':self.scope['logicalOwnerScopeHash'],
            'clientUuid':registration['id'],'operation':'FIRST_GOVERNED_CREDENTIAL_REESTABLISHMENT'}))
        self.name='policy-token-credential-transaction-'+self.operation+'.private.json'
        self.admin=SecretAdmin(registration['id'])
    def receipt_schema(self):
        if getattr(self,'pregrant_recovery',None) is not None:
            binding.require(type(self.pregrant_recovery)is legacy.PregrantRecovery
                and self.pregrant_recovery.post_credential
                and self.scope.get('schema')=='ouf.policy-token-credential-reconciliation-scope.v1',
                'TYPED_POST_CREDENTIAL_RECEIPT_REQUIRED')
            return 'ouf.policy-token-credential-reconciliation-receipt.v1'
        return 'ouf.policy-token-credential-transaction.v1'
    def guard(self):
        now=time.monotonic()
        binding.require(self.last_time<=now<self.admin.deadline,'CREDENTIAL_TRANSACTION_CLOCK_OR_DEADLINE')
        self.last_time=now
        previous=binding.PARENT
        try:
            binding.PARENT=self.path
            with binding.protected_parent()as directory:
                info=os.fstat(directory)
                binding.require({'device':info.st_dev,'inode':info.st_ino}==self.directory_identity
                    and stat.S_IMODE(info.st_mode)==0o700,'OWNED_CREDENTIAL_DIRECTORY_CHANGED')
        finally:binding.PARENT=previous
        binding.require(binding.decode(self.raw).get('policyTokenCredentialReestablishment')==self.scope,
            'EXPLICIT_SIGNED_CREDENTIAL_REESTABLISHMENT_REQUIRED')
        binding.require(self.authority(self.raw)is True,'CURRENT_CREDENTIAL_AUTHORITY_REQUIRED')
        self.retirement.guard()
        binding.require(legacy.quiescent(legacy.read_units()),'LEGACY_WRITER_QUIESCENCE_REQUIRED')
        binding.require(governance.executable('/usr/bin/docker')==self.retirement.host['executables']['docker'],
            'CREDENTIAL_ADMIN_EXECUTABLE_CHANGED')
        binding.require(binding.sha(binding.encoded(stable_registration(self.registration)))==self.registration_hash,
            'CREDENTIAL_REGISTRATION_INTENT_DRIFT')
        finished=time.monotonic()
        binding.require(self.last_time<=finished<self.admin.deadline,'CREDENTIAL_GUARD_DEADLINE_OR_CLOCK_DRIFT')
        self.last_time=finished
    def run(self):
        self.last_time=time.monotonic();self.admin.deadline=self.last_time+90
        self.guard()
        if getattr(self,'pregrant_recovery',None) is not None:
            binding.require(type(self.pregrant_recovery)is legacy.PregrantRecovery
                and self.pregrant_recovery.post_credential,'TYPED_POST_CREDENTIAL_RECONCILIATION_REQUIRED')
            return self.pregrant_recovery.credential(self)
        with binding.protected_parent()as evidence:
            retired=binding.decode(binding.read_member(evidence,self.retirement.name))
            binding.require(retired.get('operation')==self.retirement.operation and retired.get('scope')==self.retirement.scope
                and retired.get('state')=='QUIESCENCE_OBSERVED' and retired.get('commandAttemptConsumed')is True,
                'DURABLE_LEGACY_RETIREMENT_REQUIRED')
            # Explicit protected destination only; this component creates no roots.
            previous=binding.PARENT
            try:
                binding.PARENT=self.path
                with binding.protected_parent()as directory:return self._run(evidence,directory)
            finally:binding.PARENT=previous
    def _run(self,evidence,directory):
        info=os.fstat(directory)
        binding.require({'device':info.st_dev,'inode':info.st_ino}==self.directory_identity
            and stat.S_IMODE(info.st_mode)==0o700,'OWNED_CREDENTIAL_DIRECTORY_CHANGED')
        lock=os.open(self.name+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=evidence)
        try:
            info=os.fstat(lock)
            binding.require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0
                and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'CREDENTIAL_FENCE_CUSTODY_REQUIRED')
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);seal=binding.identity(info)
            def fence():
                binding.require(seal==binding.identity(os.fstat(lock))==binding.identity(os.stat(self.name+'.lock',dir_fd=evidence,follow_symlinks=False)),
                    'CREDENTIAL_FENCE_CHANGED')
            def save(row,first=False):
                fence();raw=binding.encoded(row);name=self.name if first else '.'+self.name+'.'+uuid.uuid4().hex
                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=evidence)
                try:
                    with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                    fence()
                    if not first:os.replace(name,self.name,src_dir_fd=evidence,dst_dir_fd=evidence)
                    os.fsync(evidence)
                    binding.require(binding.read_member(evidence,self.name)==raw,'CREDENTIAL_LEDGER_PUBLICATION_UNPROVEN')
                finally:os.close(fd)
            try:row=binding.decode(binding.read_member(evidence,self.name))
            except FileNotFoundError:row=None
            if row is not None:
                # Even a successful earlier rotation is not a fresh invocation
                # permit. The installed owner separately checks accepted custody.
                raise binding.CandidateDenied('CREDENTIAL_ATTEMPT_ALREADY_RESERVED_NO_AUTOMATIC_REPLAY')
            self.guard();fence()
            binding.require(os.listdir(directory)==[],'NEW_CREDENTIAL_DIRECTORY_MUST_BE_EMPTY')
            current=self.admin.call('get')
            binding.require(stable_registration(current)==stable_registration(self.registration),'CURRENT_CREDENTIAL_REGISTRATION_DRIFT')
            old=secret_value(self.admin.call('get','/client-secret'),new=False)
            self.guard();fence()
            row={'schema':'ouf.policy-token-credential-transaction.v1','operation':self.operation,'scope':self.scope,
                'state':'ROTATION_RESERVED_OUTCOME_UNPROVEN','version':0,'iamMutationAttemptConsumed':True,
                'previousSecretHash':binding.sha(old.encode()),'newSecretHash':None,'credentialPublished':False}
            save(row,first=True);self.guard();fence()
            issued=self.admin.call('create','/client-secret')
            readback=self.admin.call('get','/client-secret');after=self.admin.call('get')
            new=verify_reestablishment(self.registration,after,issued,readback,old)
            # Secret response and fresh owner readback must agree; no unrelated
            # GET is allowed to resolve an interrupted regeneration automatically.
            self.guard();fence()
            binding.require(os.listdir(directory)==[],'CREDENTIAL_DESTINATION_CHANGED')
            fd=os.open(self.MEMBER,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=directory)
            try:
                with os.fdopen(os.dup(fd),'wb')as stream:stream.write(new.encode());stream.flush();os.fsync(stream.fileno())
                os.fsync(directory)
                created=os.fstat(fd)
                binding.require(binding.identity(created)==binding.identity(os.stat(self.MEMBER,dir_fd=directory,follow_symlinks=False))
                    and created.st_uid==created.st_gid==0 and stat.S_IMODE(created.st_mode)==0o400 and created.st_nlink==1,
                    'NEW_CREDENTIAL_CUSTODY_UNPROVEN')
                self.guard();fence()
                row.update(state='NEW_CREDENTIAL_CUSTODIED_NOT_RUNTIME_ACCEPTED',version=1,newSecretHash=binding.sha(new.encode()),credentialPublished=True)
                save(row)
            finally:os.close(fd)
            return {'state':row['state'],'iamMutationAttemptsConsumed':1,'credentialPublished':True,
                'runtimeAuthorityIssued':False,'tokenGrantRequests':0,'notReleaseAcceptance':True}
        finally:os.close(lock)
