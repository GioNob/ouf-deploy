"""Guarded protected source staging; NOT runtime installation or activation.

Reuse existing finite HUMAN/dual-role authority and atomic no-replace intake.
No source execution, credential copy, unit change, journal initialization or
grant. Source closure binds destination, commit, exact file hashes and flags.
"""
import copy,fcntl,hashlib,os,re,stat,time
from pathlib import Path
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.bounded_recovery import fingerprint,require
from atomic_review_intake import publish,encoded,read
from cutover_authority import CutoverAuthority

FILES={'bounded-recovery.py','recovery-journal.py','producer.py','supervisor.py',
       'mount-observation.py','source-stage.py','installed-owner.py','worker-entry.py','reporter.py','iam-admission.py'}
FLAGS={'applicationCutoverAuthorized':False,'productionApplyReady':False,
       'runtimeAuthorityIssued':False,'observationsAreHistorical':True}

def declaration(destination,commit,files,*,directory_identity,owner_binding_hash=None):
    require(type(destination) is str and Path(destination).is_absolute()
            and str(Path(destination))==destination and destination!='/'
            and '..' not in Path(destination).parts,'EXPLICIT_PROTECTED_STAGE_DESTINATION_REQUIRED')
    require(type(commit) is str and re.fullmatch('[0-9a-f]{40}',commit)
            and type(files) is dict and 1<=len(files)<=len(FILES) and set(files)<=FILES,
            'CLOSED_BOUNDED_SOURCE_STAGE_REQUIRED')
    require(all(type(raw) is bytes and 0<len(raw)<=131072 for raw in files.values())
            and sum(map(len,files.values()))<=524288,'SOURCE_STAGE_BYTES_UNBOUNDED')
    require(type(directory_identity) is dict and set(directory_identity)=={'device','inode'}
            and type(directory_identity['device']) is int and directory_identity['device']>=0
            and type(directory_identity['inode']) is int and directory_identity['inode']>0,
            'INDEPENDENT_PROTECTED_DESTINATION_IDENTITY_REQUIRED')
    require(owner_binding_hash is None or (type(owner_binding_hash) is str and re.fullmatch('[0-9a-f]{64}',owner_binding_hash)), 'EXACT_RUNTIME_OWNER_BINDING_HASH_REQUIRED')
    return {**({} if owner_binding_hash is None else {'ownerBindingHash':owner_binding_hash}), 'schema':'ouf.native-v11-atomic-review-intake.v1',
            'preparationProfile':'ouf.policy-token-protected-source-stage.v1' if owner_binding_hash is None else 'ouf.policy-token-protected-source-stage.v2',
            'destination':destination,'sourceCommit':commit,
            'directoryIdentity':dict(directory_identity),
            'fileHashes':{name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()},
            **FLAGS,'sourceBodiesExecuted':0,'runtimeRegistered':False,
            'credentialMaterialIncluded':False,'budgetReset':False,'notReleaseAcceptance':True}

class ProtectedTokenSourceStage:
    def __init__(self,manifest,files,authority,authority_raw,*,max_seconds=120,clock=time.monotonic):
        require(type(authority) is CutoverAuthority and type(authority_raw) is bytes,
                'EXISTING_FINITE_HUMAN_DUAL_ROLE_AUTHORITY_REQUIRED')
        require(type(manifest) is dict and type(files) is dict
                and manifest==declaration(manifest.get('destination'),manifest.get('sourceCommit'),files,directory_identity=manifest.get('directoryIdentity'),owner_binding_hash=manifest.get('ownerBindingHash')),
                'EXACT_SOURCE_STAGE_DECLARATION_REQUIRED')
        require(authority.expected['sourceClosureHash']==fingerprint(manifest),
                'HUMAN_REVIEWED_SOURCE_AND_DESTINATION_CLOSURE_REQUIRED')
        require(type(max_seconds) is int and 1<=max_seconds<=120,'FINITE_SOURCE_STAGE_DURATION_REQUIRED')
        self.manifest,self.files=copy.deepcopy(manifest),dict(files)
        self.closure=fingerprint(manifest)
        self.authority,self.raw,self.clock=authority,bytes(authority_raw),clock
        self.started=clock();self.last=self.started;self.deadline=self.started+max_seconds
    def guard(self):
        now=self.clock()
        require(self.last<=now<self.deadline,'SOURCE_STAGE_CLOCK_OR_DEADLINE_UNPROVEN')
        require(fingerprint(self.manifest)==self.closure
                and self.manifest==declaration(self.manifest['destination'],self.manifest['sourceCommit'],self.files,directory_identity=self.manifest['directoryIdentity'],owner_binding_hash=self.manifest.get('ownerBindingHash'))
                and self.authority.expected['sourceClosureHash']==self.closure,
                'SOURCE_STAGE_BYTES_DESTINATION_OR_SCOPE_DRIFT')
        require(self.authority(self.raw) is True,'CURRENT_SOURCE_STAGE_AUTHORITY_REQUIRED')
        finished=self.clock();require(now<=finished<self.deadline,'SOURCE_STAGE_CLOCK_OR_DEADLINE_UNPROVEN')
        self.last=finished
    def stage(self,checkpoint=lambda point:None):
        require(os.geteuid()==os.getegid()==0,'ROOT_ROOT_SOURCE_STAGE_REQUIRED')
        self.guard()
        # Existing destination only; never mkdir/chown/chmod a shared parent.
        with protected_directory(self.manifest['destination']) as directory:
            info=os.fstat(directory)
            require(self.manifest['directoryIdentity']=={'device':info.st_dev,'inode':info.st_ino},
                    'APPROVED_SOURCE_STAGE_DESTINATION_IDENTITY_DRIFT')
            for name,raw in self.files.items():
                self.guard();compile(raw,'<approved-token-owner-source:'+name+'>','exec')
            intent_name='policy-token-source-stage-'+self.closure+'.intent'
            intent_raw=encoded({'schema':'ouf.policy-token-source-stage-intent.v1',
                                'sourceClosureHash':self.closure,'authorityHash':hashlib.sha256(self.raw).hexdigest()})
            created=False
            try:
                fd=os.open(intent_name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory);created=True
            except FileExistsError:
                fd=os.open(intent_name,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                if created:
                    os.fchmod(fd,0o600)
                    with os.fdopen(os.dup(fd),'wb') as stream:stream.write(intent_raw);stream.flush();os.fsync(stream.fileno())
                    os.fsync(directory)
                require(read(Path(self.manifest['destination'])/intent_name,0)==intent_raw,
                        'SOURCE_STAGE_INTENT_HISTORY_DRIFT')
                final=Path(self.manifest['destination'])/('semantic-native-v11-intake-'+self.closure)
                require(created or os.path.lexists(final),'INTERRUPTED_SOURCE_STAGE_RECONCILIATION_REQUIRED')
                held=os.fstat(fd)
                def checked(point):
                    current=os.stat(intent_name,dir_fd=directory,follow_symlinks=False)
                    require((held.st_dev,held.st_ino)==(current.st_dev,current.st_ino)
                            and current.st_uid==current.st_gid==0 and current.st_nlink==1
                            and stat.S_IMODE(current.st_mode)==0o600,'SOURCE_STAGE_FENCE_IDENTITY_DRIFT')
                    self.guard();checkpoint(point);self.guard()
                result=publish(self.manifest['destination'],self.files,self.manifest,0,checked)
                self.guard()
            finally:os.close(fd)
            return {**result,'protectedFileWrites':result['protectedFileWrites']+int(created),
                    'durableIntentCreated':created,'automaticRestagingAllowed':False,
                    'status':'PROTECTED_SOURCE_STAGED_NOT_RUNTIME_INSTALLED',
                    'sourceClosureHash':self.closure,'sourceBodiesExecuted':0,
                    'runtimeRegistered':False,'credentialFilesOpened':0,'privateKeysRead':0,
                    'unitMutations':0,'providerCalls':0,'budgetReset':False,
                    'runtimeAuthorityIssued':False,'productionApplyReady':False,'notReleaseAcceptance':True}

