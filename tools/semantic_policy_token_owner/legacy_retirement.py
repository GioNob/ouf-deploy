"""Governed retirement component; no installer, credentials, grant or restart.

The caller must bind this module and its dependencies into the independently
reviewed executing closure. A chat design approval cannot invoke this component.
One durable command reservation survives crash and reapproval. Subsequent calls
only reconcile observed unit state; they never replay a consumed command.
"""
import copy
from contextlib import contextmanager
import hashlib
from pathlib import Path
import fcntl
import os
import re
import stat
import subprocess
import tempfile
import time
import uuid
import iam_binding_candidate as binding
import iam_governance_intake as governance
from cutover_authority import CutoverAuthority
from accounting_gap_session import boot_identity

UNITS=('ouf-policy-token@semantic.timer','ouf-policy-token@semantic.service')
HOST_HASH='93fa9bc8fe4d90fe445bb310363f11966f9ed89df74d169ad925cda0a157acc4'

def read_units():
    with tempfile.TemporaryFile() as output:
        result=subprocess.run(['/usr/bin/systemctl','show',*UNITS,'--no-pager',
            '--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,Job'],stdin=subprocess.DEVNULL,
            stdout=output,stderr=subprocess.DEVNULL,timeout=10,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        output.seek(0);raw=output.read(8193)
    binding.require(result.returncode==0 and 0<len(raw)<=8192,'LEGACY_UNIT_READ_UNAVAILABLE')
    rows={}
    for block in raw.decode('ascii').strip().split('\n\n'):
        row={}
        for line in block.splitlines():
            key,sep,value=line.partition('=')
            binding.require(sep and key in {'Id','LoadState','ActiveState','SubState','UnitFileState','MainPID','Job'}
                and key not in row,'LEGACY_UNIT_SCHEMA_DRIFT')
            row[key]=value
        binding.require({'Id','LoadState','ActiveState','SubState','UnitFileState','Job'}<=set(row)
            and row['Id'] in UNITS and row['Id'] not in rows,'EXACT_LEGACY_UNITS_REQUIRED')
        rows[row['Id']]=row
    binding.require(set(rows)==set(UNITS),'EXACT_LEGACY_UNITS_REQUIRED')
    return rows

def quiescent(rows):
    # A failed timer is a terminal state, not an active schedule. Preserve its
    # failure evidence; never reset-failed merely to satisfy a status predicate.
    # Permanent masks, no queued Job and the inactive service/PID fence remain
    # mandatory. Runtime/temporary masks and failed services are not admitted.
    return set(rows)==set(UNITS) and all(row.get('LoadState')=='masked'
        and row.get('UnitFileState')=='masked' and row.get('Job')==''
        and (row.get('ActiveState'),row.get('SubState')) in (
            {('inactive','dead'),('failed','failed')} if unit.endswith('.timer') else {('inactive','dead')})
        and row.get('MainPID', '0' if unit.endswith('.timer') else None)=='0'
        for unit,row in rows.items())

class LegacyRetirement:
    def __init__(self,authority,authority_raw,host_raw):
        binding.require(type(authority)is CutoverAuthority and type(authority_raw)is bytes,
            'CURRENT_TYPED_DUAL_ROLE_AUTHORITY_REQUIRED')
        binding.require(type(host_raw)is bytes and binding.sha(host_raw)==HOST_HASH,
            'EXACT_RETAINED_MIGRATION_HOST_HASH_REQUIRED')
        host=binding.decode(host_raw)
        binding.require(host.get('schema')=='ouf.policy-token-migration-host-inputs.v1'
            and host.get('legacyHistory')=={'state':'UNKNOWN','cumulativeGrantAttemptCount':None,
                'reconciled':False,'gapRemainsOpen':True}
            and host.get('runtimeAuthorityIssued')is False,'EXACT_UNKNOWN_HISTORY_HOST_INPUT_REQUIRED')
        logical=host.get('logicalOwnerScopeHash')
        binding.require(type(logical)is str and re.fullmatch('[0-9a-f]{64}',logical),
            'EXACT_LOGICAL_OWNER_SCOPE_REQUIRED')
        units=host.get('legacyUnitsMetadata')
        binding.require(type(units)is list and len(units)==2 and {u.get('Id') for u in units}==set(UNITS),
            'EXACT_RETAINED_LEGACY_UNITS_REQUIRED')
        self.host=host;self.host_raw=host_raw;self.authority=authority;self.raw=authority_raw
        self.scope={'schema':'ouf.policy-token-legacy-retirement-scope.v1',
            'hostInputsHash':HOST_HASH,'logicalOwnerScopeHash':logical,
            'sourceClosureHash':authority.expected['sourceClosureHash'],
            'operation':'MASK_AND_STOP_EXACT_LEGACY_UNITS','units':list(UNITS),
            'maximumCommandAttempts':1,'automaticUnmaskOrRestartAllowed':False}
        # Stable across host reviews, source versions, decisions and process IDs.
        self.operation=binding.sha(binding.encoded({'logicalOwnerScopeHash':logical,'units':list(UNITS),
            'operation':'FIRST_GOVERNED_LEGACY_RETIREMENT'}))
        self.name='policy-token-legacy-retirement-'+self.operation+'.private.json'
    def guard(self):
        binding.require(binding.sha(binding.encoded(self.host))==HOST_HASH,'HOST_INPUT_DRIFT')
        binding.require(binding.decode(self.raw).get('policyTokenLegacyRetirement')==self.scope,
            'EXPLICIT_SIGNED_LEGACY_RETIREMENT_SCOPE_REQUIRED')
        binding.require(self.authority(self.raw)is True,'CURRENT_HUMAN_AND_DUAL_ROLE_AUTHORITY_REQUIRED')
        binding.require(boot_identity()==self.host['kernelBootId'],'MIGRATION_BOOT_CHANGED')
        binding.require(governance.executable('/usr/bin/systemctl')==self.host['executables']['systemctl'],
            'SYSTEMCTL_EXECUTABLE_CHANGED')
        if getattr(self,'pregrant_recovery',None) is not None:
            binding.require(type(self.pregrant_recovery)is PregrantRecovery,'TYPED_PREGRANT_RECOVERY_REQUIRED')
            self.pregrant_recovery.guard()
    def run(self):
        self.guard()
        if getattr(self,'pregrant_recovery',None) is not None:
            return self.pregrant_recovery.retirement(self)
        with binding.protected_parent() as directory:
            binding.require(binding.read_member(directory,'policy-token-migration-host-inputs-'+HOST_HASH+'.private.json')
                ==self.host_raw,'RETAINED_HOST_INPUT_CHANGED')
            lock=os.open(self.name+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
            try:
                info=os.fstat(lock)
                binding.require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                    and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'RETIREMENT_FENCE_CUSTODY_REQUIRED')
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                seal=binding.identity(info)
                def fence():
                    binding.require(seal==binding.identity(os.fstat(lock))
                        ==binding.identity(os.stat(self.name+'.lock',dir_fd=directory,follow_symlinks=False)),
                        'RETIREMENT_FENCE_CHANGED')
                def save(row,first=False):
                    fence();raw=binding.encoded(row);name=self.name if first else '.'+self.name+'.'+uuid.uuid4().hex
                    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                    try:
                        with os.fdopen(os.dup(fd),'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                        fence()
                        if not first:os.replace(name,self.name,src_dir_fd=directory,dst_dir_fd=directory)
                        os.fsync(directory)
                        binding.require(binding.read_member(directory,self.name)==raw,'RETIREMENT_PUBLICATION_UNPROVEN')
                    finally:os.close(fd)
                try:row=binding.decode(binding.read_member(directory,self.name))
                except FileNotFoundError:row=None
                self.guard();fence();observed=read_units()
                if row is not None:
                    binding.require(set(row)=={'schema','operation','scope','commandAttemptConsumed','state','version'}
                        and row['schema']=='ouf.policy-token-legacy-retirement.v1' and row['operation']==self.operation
                        and row['scope']==self.scope and row['commandAttemptConsumed']is True
                        and type(row['version'])is int and row['version']>=0
                        and row['state']in {'COMMAND_RESERVED_OUTCOME_UNPROVEN','QUIESCENCE_OBSERVED'},
                        'RETAINED_RETIREMENT_DRIFT')
                    binding.require(quiescent(observed),'RETIREMENT_RECONCILIATION_REQUIRED_NO_COMMAND_REPLAY')
                else:
                    baseline={u['Id']:u for u in self.host['legacyUnitsMetadata']}
                    binding.require({unit:{key:row[key] for key in baseline[unit]} for unit,row in observed.items()}
                        ==baseline,'LEGACY_UNIT_BASELINE_CHANGED')
                    self.guard();fence()
                    row={'schema':'ouf.policy-token-legacy-retirement.v1','operation':self.operation,'scope':self.scope,
                        'commandAttemptConsumed':True,'state':'COMMAND_RESERVED_OUTCOME_UNPROVEN','version':0}
                    save(row,first=True)
                    self.guard();fence()
                    # Any timeout/nonzero/crash leaves the durable reservation.
                    # No automatic retry or rollback can re-enable the writer.
                    result=subprocess.run(['/usr/bin/systemctl','mask','--now',*UNITS],stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20,
                        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
                    binding.require(result.returncode==0,'RETIREMENT_COMMAND_OUTCOME_REQUIRES_RECONCILIATION')
                    observed=read_units()
                    binding.require(quiescent(observed),'RETIREMENT_QUIESCENCE_UNPROVEN')
                self.guard();fence()
                if row['state']!='QUIESCENCE_OBSERVED':
                    row.update(state='QUIESCENCE_OBSERVED',version=row['version']+1);save(row)
                return dict(row)
            finally:os.close(lock)


# Fixed, explicitly reviewed predecessor recovery; no new runtime module.
SOURCE='95749a8ef316856e16c44c1d7aa3b6791b408993'
AUTHORITY='83d70a33518b7bf7c1ca2904d715623294bb8132d5db1373381ab7ea001f2072'
REVIEW='6ff5430760e93ab51a26313a18198f094ded12760954fb8a4fcf53db5b3274a0'
CONTEXT='chatbot-file-cohort-signed-3f1e74ca1de7962018be8e1d6dd023f685ea208a70aa5e2e2078f92961d7fd4c'
PROFILE='ouf.policy-token-pregrant-reconciliation.v1'
GATEWAY_RECORD_HASH='d9a7427d73867801fda31acbba4b1df3d7dafd4e99d35cd1cdbb2b5d7816448a'
CODE=Path('/usr/local/libexec/ouf-policy-token')
RECORD_HASHES={
    'installation':'ff7de4da5b1503e109891b7f00aaf2a7df2709e2aac89e0e6e61a8c4e442fca2',
    'retirement':'38c670782408fd6843350f549eaeffe1b59adae7b923b907d4ccdad373424b7c',
    'output':'0d176ef0fa749df76cbd636a944e1b420b33201b65741c652c9ad5c376fa01ce',
    'stageIntent':'47f8ecd2d5cd70564cd9062fe093634f93083691e79a94abcb6697659a4428d7',
    'stageIntake':'e6f5140a6c63048b8ccd5f6c5d0b758ced5da9ef6d7c05f16180bf8f309cea94'}
ROOTS={'ownerRecovery':('/var/lib/ouf/policy-token/semantic',0,0o700),
    'credential':('/etc/ouf/policy-token/credentials/semantic',0,0o700),
    'output':('/var/lib/ouf/policy-token/semantic/token-output',10001,0o750)}

def digest(value):return binding.sha(binding.encoded(value))

@contextmanager
def protected_directory(path):
    """Hold root-owned private ancestry without importing the worker package."""
    path=Path(path)
    binding.require(os.geteuid()==os.getegid()==0 and path.is_absolute()
        and path!=Path('/') and '..' not in path.parts and len(path.parts)<=32,
        'PREGRANT_PRIVATE_PARENT_REQUIRED')
    fds=[];seals=[]
    try:
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK
        parent=os.open('/',flags);fds.append(parent)
        for part in path.parts[1:]:
            before=os.stat(part,dir_fd=parent,follow_symlinks=False)
            binding.require(stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==0
                and not before.st_mode&0o022,'PREGRANT_PRIVATE_PARENT_CUSTODY_REQUIRED')
            child=os.open(part,flags,dir_fd=parent);fds.append(child)
            binding.require(binding.identity(before)==binding.identity(os.fstat(child)),
                'PREGRANT_PRIVATE_PARENT_CHANGED')
            seals.append((parent,part,child,(before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode)))
            parent=child
        binding.require(stat.S_IMODE(os.fstat(parent).st_mode)==0o700,
            'PREGRANT_PRIVATE_PARENT_MODE_REQUIRED')
        yield parent
        for parent,part,child,seal in seals:
            for current in (os.fstat(child),os.stat(part,dir_fd=parent,follow_symlinks=False)):
                binding.require(seal==(current.st_dev,current.st_ino,current.st_uid,current.st_gid,current.st_mode),
                    'PREGRANT_PRIVATE_PARENT_CHANGED')
    finally:
        for fd in reversed(fds):os.close(fd)

def private(path,expected=None):
    path=Path(path)
    guard=binding.protected_parent() if path.parent==binding.PARENT else protected_directory(path.parent)
    with guard as directory:
        raw=binding.read_member(directory,path.name)
        binding.require(len(raw)<=262144 and binding.read_member(directory,path.name)==raw,
            'PREGRANT_RECORD_CHANGED_DURING_READ')
    binding.require(expected is None or binding.sha(raw)==expected,'PREGRANT_RETAINED_RECORD_DRIFT')
    return raw

def directory_binding(path,gid,mode):
    # Root recovery/credential/output identities are also checked by the root
    # custody owner. No inode adoption or permission repair is performed here.
    path=Path(path)
    binding.require(path.resolve()==path,'PREGRANT_ROOT_SYMLINK_DENIED')
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        binding.require(info.st_uid==0 and info.st_gid==gid and stat.S_IMODE(info.st_mode)==mode,
            'PREGRANT_ROOT_CUSTODY_DRIFT')
        return {'path':str(path),'device':info.st_dev,'inode':info.st_ino,'uid':0,'gid':gid,'mode':mode}
    finally:os.close(fd)

def names(scopes):
    logical=scopes['policyTokenLegacyRetirement']['logicalOwnerScopeHash']
    owner=digest({'logicalOwnerScopeHash':logical,'operation':'FIRST_COMPLETE_TOKEN_OWNER_INSTALLATION'})
    retire=digest({'logicalOwnerScopeHash':logical,'units':list(UNITS),
        'operation':'FIRST_GOVERNED_LEGACY_RETIREMENT'})
    output_scope=scopes['policyTokenOutputCustody']
    out=digest({'logicalOwnerScopeHash':logical,'operation':'FIRST_GOVERNED_TOKEN_OUTPUT_CHILD',
        'path':output_scope['path']})
    first=scopes['policyTokenFirstControlledGrant']
    return {
        'installation':binding.PARENT/('policy-token-owner-installation-'+owner+'.private.json'),
        'retirement':binding.PARENT/('policy-token-legacy-retirement-'+retire+'.private.json'),
        'output':binding.PARENT/('policy-token-output-custody-'+out+'.private.json'),
        'credential':binding.PARENT/('policy-token-credential-transaction-'+first['credentialOperation']+'.private.json'),
        'session':binding.PARENT/('policy-token-first-gap-session-'+first['sessionOperation']+'.private.json'),
        'grant':binding.PARENT/('policy-token-first-controlled-grant-'+first['sessionOperation']+'.private.json')}

def retained_pregrant(review,authority_hash):
    """Immutable original pregrant facts; absence is checked by its phase owner."""
    binding.require(digest(review)==REVIEW and authority_hash==AUTHORITY
        and review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and Path(review['scopes']['finiteActionProcess']['authorityDirectory']).name==CONTEXT,
        'EXACT_PREGRANT_PREDECESSOR_REQUIRED')
    scopes=review['scopes'];paths=names(scopes);records={};bindings={}
    for label in ('installation','retirement','output'):
        raw=private(paths[label],RECORD_HASHES[label]);records[label]=binding.decode(raw)
        bindings[label]={'path':str(paths[label]),'sha256':binding.sha(raw)}
    binding.require(records['installation']=={
        'schema':'ouf.policy-token-owner-installation-intent.v1',
        'operation':records['installation']['operation'],'scope':scopes['policyTokenOwnerInstallation'],
        'authorityHash':AUTHORITY,'state':'RESERVED_OUTCOME_UNPROVEN','automaticReplayAllowed':False},
        'EXACT_PREGRANT_INSTALLATION_RESERVATION_REQUIRED')
    binding.require(records['retirement']['scope']==scopes['policyTokenLegacyRetirement']
        and records['retirement']['state']=='COMMAND_RESERVED_OUTCOME_UNPROVEN'
        and records['retirement']['commandAttemptConsumed']is True and records['retirement']['version']==0,
        'EXACT_PREGRANT_RETIREMENT_RESERVATION_REQUIRED')
    output=records['output']
    binding.require(output['scope']==scopes['policyTokenOutputCustody']
        and output['state']=='OUTPUT_CUSTODIED_NOT_RUNTIME_ACCEPTED'
        and output['mkdirAttemptConsumed']is True and output['version']==1,
        'COMPLETED_PREGRANT_OUTPUT_CUSTODY_REQUIRED')
    closure=scopes['policyTokenOwnerInstallation']['stageManifestHash']
    code=CODE
    stage=code/('semantic-native-v11-intake-'+closure)
    for label,path in (('stageIntent',code/('policy-token-source-stage-'+closure+'.intent')),
                       ('stageIntake',stage/'intake.json')):
        raw=private(path,RECORD_HASHES[label]);bindings[label]={'path':str(path),'sha256':binding.sha(raw)}
        records[label]=binding.decode(raw)
    manifest=records['stageIntake']
    FILES={'bounded-recovery.py','recovery-journal.py','producer.py','supervisor.py',
        'mount-observation.py','source-stage.py','installed-owner.py','worker-entry.py','reporter.py','iam-admission.py'}
    binding.require(digest(manifest)==closure and set(manifest['fileHashes'])==FILES
        and records['stageIntent']=={'schema':'ouf.policy-token-source-stage-intent.v1',
            'sourceClosureHash':closure,'authorityHash':AUTHORITY},'PREGRANT_SOURCE_STAGE_DRIFT')
    for name,expected in manifest['fileHashes'].items():
        private(stage/name,expected)
        bindings['source:'+name]={'path':str(stage/name),'sha256':expected}
    roots={label:directory_binding(*value) for label,value in ROOTS.items()}
    binding.require(output['outputIdentity']=={key:roots['output'][key] for key in ('device','inode')},
        'PREGRANT_OUTPUT_IDENTITY_DRIFT')
    recovery_root=Path(ROOTS['ownerRecovery'][0])
    absent=[str(paths[key]) for key in ('credential','session','grant')]
    absent += [str(paths['installation'])+'.completed']
    absent += [str(recovery_root/name) for name in
        ('recovery.json','owner-first-grant.json','owner-session.json','owner-admission.json')]
    result={'schema':PROFILE,'predecessorSource':SOURCE,'predecessorAuthorityHash':AUTHORITY,
        'predecessorReviewHash':REVIEW,'recordBindings':bindings,
        'predecessorScopes':{key:copy.deepcopy(scopes[key]) for key in
            ('policyTokenOwnerInstallation','policyTokenOutputCustody','policyTokenLegacyRetirement')},
        'absentRecords':sorted(absent),'rootBindings':roots,
        'priorRetirementCommandAttempts':1,'priorOutputMkdirAttempts':1,
        'priorCredentialMutationAttempts':0,'priorGrantAttempts':0,
        'automaticReplayAllowed':False,'budgetReset':False}
    return result

def observe(review,authority_hash):
    result=retained_pregrant(review,authority_hash)
    admission(result)
    binding.require(quiescent(read_units()),'PREGRANT_LEGACY_QUIESCENCE_REQUIRED')
    return result

def admission(proof):
    for path in proof['absentRecords']:
        binding.require(not os.path.lexists(path),'PREGRANT_EFFECT_HISTORY_PRESENT_NO_CONTINUATION')
    binding.require(set(os.listdir(ROOTS['ownerRecovery'][0]))=={'token-output'}
        and not os.listdir(ROOTS['credential'][0]) and not os.listdir(ROOTS['output'][0]),
        'PREGRANT_OWNER_OR_CREDENTIAL_HISTORY_PRESENT')

class PregrantRecovery:
    def __init__(self,authority,authority_raw,proof):
        binding.require(type(authority)is CutoverAuthority and type(authority_raw)is bytes,
            'CURRENT_TYPED_PREGRANT_AUTHORITY_REQUIRED')
        self.authority,self.raw=authority,bytes(authority_raw)
        self.proof=copy.deepcopy(proof);self.hash=digest(self.proof);self.owner_scope=None
        self.post_credential=self.proof.get('schema')==POST_PROFILE
        old_review=binding.decode(private(binding.PARENT/(POST_CONTEXT if self.post_credential else CONTEXT)/'review.json',
            POST_REVIEW if self.post_credential else REVIEW))
        # Re-observe while still effect-free; arbitrary proof dictionaries cannot
        # replace the fixed original records or absence/identity requirements.
        observed=observe_post_credential(old_review,POST_AUTHORITY) if self.post_credential else observe(old_review,AUTHORITY)
        binding.require(observed==self.proof,'EXACT_CURRENT_PREGRANT_PROOF_REQUIRED')
        self.continuation=('policy-token-owner-post-credential-continuation-'+POST_AUTHORITY if self.post_credential
            else 'policy-token-owner-pregrant-continuation-'+AUTHORITY)+'.private.json'

    def guard(self):
        binding.require(self.owner_scope is not None and digest(self.proof)==self.hash
            and self.owner_scope.get('pregrantRecovery')==self.proof,
            'EXACT_SIGNED_PREGRANT_RECOVERY_REQUIRED')
        binding.require(binding.decode(self.raw).get('policyTokenOwnerInstallation')==self.owner_scope
            and self.owner_scope['sourceClosureHash']==self.authority.expected['sourceClosureHash'],
            'EXACT_SIGNED_PREGRANT_OWNER_SCOPE_REQUIRED')
        binding.require(self.authority(self.raw)is True,'CURRENT_PREGRANT_HUMAN_AND_DUAL_ROLE_AUTHORITY_REQUIRED')
        for record_ref in self.proof['recordBindings'].values():private(record_ref['path'],record_ref['sha256'])
        binding.require({label:directory_binding(*value) for label,value in ROOTS.items()}
            ==self.proof['rootBindings'],'PREGRANT_ROOT_IDENTITIES_CHANGED')
        if self.post_credential:
            binding.require(credential_metadata()==self.proof['credentialMetadata'],
                'POST_CREDENTIAL_FILE_METADATA_CHANGED')

    def admit(self):
        self.guard()
        if self.post_credential:post_credential_admission(self.proof)
        else:admission(self.proof)
        binding.require(quiescent(read_units()),'PREGRANT_LEGACY_QUIESCENCE_REQUIRED')

    def configure(self,output,retirement):
        for component,label,operation,count_key in (
            (output,'output','REUSE_COMPLETED_TOKEN_OUTPUT_CHILD','maximumMkdirAttempts'),
            (retirement,'retirement','OBSERVE_PREVIOUSLY_MASKED_AND_STOPPED_UNITS','maximumCommandAttempts')):
            component.scope={**component.scope,'operation':operation,count_key:0,
                'pregrantRecoveryHash':self.hash,'predecessorRecord':copy.deepcopy(self.proof['recordBindings'][label])}
            component.name='policy-token-'+label+'-pregrant-reconciliation-'+AUTHORITY+'.private.json'
            if self.post_credential:
                component.name='policy-token-'+label+'-post-credential-reconciliation-'+POST_AUTHORITY+'.private.json'
            component.pregrant_recovery=self

    def configure_first(self,first,actor):
        if not self.post_credential:return
        binding.require(type(actor)is dict and set(actor)=={'issuer','tenant','subject'}
            and all(type(v)is str and 1<=len(v)<=256 and not any(c.isspace() for c in v) for v in actor.values()),
            'CURRENT_SELECTED_HUMAN_BUDGET_ACTOR_REQUIRED')
        transaction=first.transaction
        transaction.scope={**transaction.scope,'schema':'ouf.policy-token-credential-reconciliation-scope.v1',
            'operation':'REUSE_EXACT_COMPLETED_CREDENTIAL',
            'maximumIamMutations':0,'pregrantRecoveryHash':self.hash,
            'predecessorRecord':copy.deepcopy(self.proof['recordBindings']['credential'])}
        transaction.name='policy-token-credential-post-credential-reconciliation-'+POST_AUTHORITY+'.private.json'
        transaction.pregrant_recovery=self
        first.scope['credentialScopeHash']=digest(transaction.scope)
        session=first.session
        session.scope={**session.scope,'schema':'ouf.policy-token-new-first-grant-budget-scope.v1',
            'operation':'OPEN_NEW_WINDOW_AFTER_EXPIRED_UNUSED_FIRST_SESSION',
            'newBudget':{'actor':copy.deepcopy(actor),'reason':'CONFIRMED_HTTP_RESPONSE_LIFETIME_FAILURE_BEFORE_GRANT',
                'predecessorSession':copy.deepcopy(self.proof['recordBindings']['session']),
                'priorGrantAttempts':0,'maximumCumulativeGrantAttempts':1,'automaticRenewalAllowed':False}}
        session.name='policy-token-first-gap-session-post-credential-'+POST_AUTHORITY+'.private.json'
        session.pregrant_recovery=self

    def publish(self,name,row):
        self.guard()
        with binding.protected_parent() as directory:
            fd=os.open(name+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
            try:
                info=os.fstat(fd)
                binding.require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                    and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'PREGRANT_RECEIPT_FENCE_CUSTODY_REQUIRED')
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                def fence():
                    binding.require(binding.identity(os.fstat(fd))==binding.identity(info)
                        ==binding.identity(os.stat(name+'.lock',dir_fd=directory,follow_symlinks=False)),
                        'PREGRANT_RECEIPT_FENCE_CHANGED')
                raw=binding.encoded(row);self.guard();fence()
                try:existing=binding.read_member(directory,name)
                except FileNotFoundError:
                    target=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                    try:
                        with os.fdopen(os.dup(target),'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                        os.fsync(directory)
                    finally:os.close(target)
                    existing=binding.read_member(directory,name)
                binding.require(existing==raw,'PREGRANT_RECONCILIATION_RECEIPT_DRIFT')
                fence();self.guard()
                return copy.deepcopy(row)
            finally:os.close(fd)

    def output(self,component):
        self.guard()
        row=binding.decode(private(self.proof['recordBindings']['output']['path'],
            self.proof['recordBindings']['output']['sha256']))
        current=self.proof['rootBindings']['output']
        binding.require(row['outputIdentity']=={key:current[key] for key in ('device','inode')},
            'PREGRANT_OUTPUT_IDENTITY_DRIFT')
        # Preserve the original consumed attempt and its monotonic timestamps.
        # Current authority permits only custody observation, never another mkdir.
        row['scope']=copy.deepcopy(component.scope)
        component.validate(row)
        return self.publish(component.name,row)

    def retirement(self,component):
        self.guard()
        binding.require(quiescent(read_units()),'PREGRANT_LEGACY_QUIESCENCE_REQUIRED')
        row=binding.decode(private(self.proof['recordBindings']['retirement']['path'],
            self.proof['recordBindings']['retirement']['sha256']))
        row.update(scope=copy.deepcopy(component.scope),state='QUIESCENCE_OBSERVED',version=1)
        return self.publish(component.name,row)

    def prepare_credential(self,first):
        if not self.post_credential:return
        # Current authority only: observe the consumed retirement, then adopt
        # the exact successful local credential receipt. No IAM admin call.
        first.transaction.retirement.run()
        first.transaction.run()

    def credential(self,component):
        self.guard()
        row=binding.decode(private(self.proof['recordBindings']['credential']['path'],
            self.proof['recordBindings']['credential']['sha256']))
        previous=binding.PARENT
        try:
            binding.PARENT=component.path
            with binding.protected_parent() as directory:
                info=os.stat(component.MEMBER,dir_fd=directory,follow_symlinks=False)
                binding.require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                    and stat.S_IMODE(info.st_mode)==0o400 and info.st_nlink==1 and 0<info.st_size<=4096,
                    'RETAINED_COMPLETED_CREDENTIAL_CUSTODY_REQUIRED')
                fd=os.open(component.MEMBER,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
                try:
                    raw=os.read(fd,4097)
                    binding.require(binding.identity(info)==binding.identity(os.fstat(fd))
                        ==binding.identity(os.stat(component.MEMBER,dir_fd=directory,follow_symlinks=False))
                        and len(raw)==info.st_size and binding.sha(raw)==row['newSecretHash'],
                        'RETAINED_COMPLETED_CREDENTIAL_BYTES_CHANGED')
                finally:os.close(fd)
        finally:binding.PARENT=previous
        row['scope']=copy.deepcopy(component.scope)
        row['schema']=component.receipt_schema()
        return self.publish(component.name,row)

# Fixed follow-up to the completed credential / unused session readback. No
# generic adoption of an arbitrary in-flight installation is provided.
POST_SOURCE='4a65b9326c15d9758ecba1793965617a2a92e43e'
POST_AUTHORITY='2c35198422227b7db0894ca37ee4d70947ae56fcce813f8d0d1ab9a81c9b5733'
POST_REVIEW='261f9e998acaded184ec9be41a1be1dbd862c4c8b3c57d961cce6820a578b184'
POST_CONTEXT='chatbot-file-cohort-signed-eff1b6915816bcfc409b16e1d24b9eb342b1c38e3d6ae80e362ac893c5480d0b'
POST_PROFILE='ouf.policy-token-post-credential-reconciliation.v1'
POST_CREDENTIAL_ID=(65028,4161549,86)
POST_RECORD_HASHES={
    'postContinuation':'6bdf577601a0b4275b52c2758e7bb5493024682cdea12f1f46a62e8ee75d6dc7',
    'postOutput':'c5d6d3bc78d65c18127058b8e236246f5cfde87d93ddc5aac5d7f8f6471880a7',
    'postRetirement':'3b054f15c49ff43e9de9a6fb5aa642dad8ad23757130af2a9cdd236cb83538d5',
    'credential':'a9fa6304781bff2c9a795d16520881401a49124db869de87338f8978251436ae',
    'session':'2879325cd95434413f29dc4058d945e16d0bbc71eaf29d44176c705b5ca6ce0c',
    'postStageIntent':'a654074cc01bf4c702041591907614e1ca22a6ee34ff37b6b0e4abadf084dc53',
    'postStageIntake':'0ff3cf4f630709a74c089b4aa75359aa27d62176a9c0975d8f9db90a831b99bf'}

def credential_metadata():
    path=Path(ROOTS['credential'][0])/'client-secret'
    binding.require(path.resolve()==path,'POST_CREDENTIAL_SYMLINK_DENIED')
    info=path.lstat()
    binding.require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
        and stat.S_IMODE(info.st_mode)==0o400 and info.st_nlink==1
        and (info.st_dev,info.st_ino,info.st_size)==POST_CREDENTIAL_ID,
        'EXACT_POST_CREDENTIAL_METADATA_REQUIRED')
    return {'device':info.st_dev,'inode':info.st_ino,'bytes':info.st_size,
        'uid':0,'gid':0,'modeOctal':'0400','links':1,
        'mtimeNs':info.st_mtime_ns,'ctimeNs':info.st_ctime_ns}

def post_credential_admission(proof):
    for path in proof['absentRecords']:
        binding.require(not os.path.lexists(path),'POST_CREDENTIAL_LATER_EFFECT_HISTORY_PRESENT')
    binding.require(set(os.listdir(ROOTS['ownerRecovery'][0]))=={'token-output'}
        and set(os.listdir(ROOTS['credential'][0]))=={'client-secret'}
        and not os.listdir(ROOTS['output'][0]),'POST_CREDENTIAL_OWNER_OR_OUTPUT_HISTORY_PRESENT')
    session=binding.decode(private(proof['recordBindings']['session']['path'],
        proof['recordBindings']['session']['sha256']))
    binding.require(session['attemptSlotsConsumed']==0 and session['state']=='NEW_FINITE_SESSION'
        and session['bootId']==boot_identity() and time.time()>=session['expiresAt']
        and time.monotonic()>=session['expiresMonotonic'],
        'POST_CREDENTIAL_UNUSED_SESSION_MUST_BE_EXPIRED_UNCHANGED')
    binding.require(credential_metadata()==proof['credentialMetadata'],'POST_CREDENTIAL_METADATA_DRIFT')

def observe_post_credential(review,authority_hash):
    binding.require(digest(review)==POST_REVIEW and authority_hash==POST_AUTHORITY
        and review['sourceClosure']['declaration']['sourceCommit']==POST_SOURCE
        and Path(review['scopes']['finiteActionProcess']['authorityDirectory']).name==POST_CONTEXT,
        'EXACT_POST_CREDENTIAL_PREDECESSOR_REQUIRED')
    original=binding.decode(private(binding.PARENT/CONTEXT/'review.json',REVIEW))
    seed=retained_pregrant(original,AUTHORITY)
    scopes=review['scopes'];owner=scopes['policyTokenOwnerInstallation']
    binding.require(owner.get('pregrantRecovery')==seed,'POST_CREDENTIAL_ORIGINAL_RECOVERY_PROOF_DRIFT')
    result=copy.deepcopy(seed);bindings=result['recordBindings'];paths=names(scopes)
    records={}
    fixed={
        'postContinuation':binding.PARENT/('policy-token-owner-pregrant-continuation-'+AUTHORITY+'.private.json'),
        'postOutput':binding.PARENT/('policy-token-output-pregrant-reconciliation-'+AUTHORITY+'.private.json'),
        'postRetirement':binding.PARENT/('policy-token-retirement-pregrant-reconciliation-'+AUTHORITY+'.private.json'),
        'credential':paths['credential'],'session':paths['session']}
    for label,path in fixed.items():
        raw=private(path,POST_RECORD_HASHES[label]);records[label]=binding.decode(raw)
        bindings[label]={'path':str(path),'sha256':binding.sha(raw)}
    continuation=records['postContinuation']
    binding.require(continuation.get('scope')==owner and continuation.get('authorityHash')==POST_AUTHORITY
        and continuation.get('state')=='RESERVED_OUTCOME_UNPROVEN'
        and continuation.get('automaticReplayAllowed')is False,
        'EXACT_POST_CREDENTIAL_INSTALLATION_RESERVATION_REQUIRED')
    for label,key,state in (('postOutput','policyTokenOutputCustody','OUTPUT_CUSTODIED_NOT_RUNTIME_ACCEPTED'),
                           ('postRetirement','policyTokenLegacyRetirement','QUIESCENCE_OBSERVED'),
                           ('credential','policyTokenCredentialReestablishment','NEW_CREDENTIAL_CUSTODIED_NOT_RUNTIME_ACCEPTED'),
                           ('session','policyTokenAccountingGapMigration','NEW_FINITE_SESSION')):
        binding.require(records[label].get('scope')==scopes[key] and records[label].get('state')==state,
            'EXACT_POST_CREDENTIAL_COMPLETED_COMPONENT_REQUIRED')
    credential=records['credential'];session=records['session']
    binding.require(credential.get('iamMutationAttemptConsumed')is True
        and credential.get('credentialPublished')is True and credential.get('version')==1
        and session.get('sessionDecisionHash')==POST_AUTHORITY and session.get('attemptSlotsConsumed')==0
        and session.get('version')==0,'POST_CREDENTIAL_ZERO_GRANT_COMPLETED_ROTATION_REQUIRED')
    for label,path,expected in (
        ('originalReview',binding.PARENT/CONTEXT/'review.json',REVIEW),
        ('postReview',binding.PARENT/POST_CONTEXT/'review.json',POST_REVIEW),
        ('postAuthority',binding.PARENT/POST_CONTEXT/'authority.json',POST_AUTHORITY)):
        raw=private(path,expected);bindings[label]={'path':str(path),'sha256':binding.sha(raw)}
        if label=='postAuthority':
            old_authority=binding.decode(raw)
            binding.require(all(old_authority.get(k)==v for k,v in scopes.items()),'POST_CREDENTIAL_SIGNED_SCOPE_DRIFT')
    closure=owner['stageManifestHash'];stage=CODE/('semantic-native-v11-intake-'+closure)
    binding.require(closure==POST_RECORD_HASHES['postStageIntake'],'EXACT_POST_CREDENTIAL_SOURCE_MANIFEST_REQUIRED')
    for label,path in (('postStageIntent',CODE/('policy-token-source-stage-'+closure+'.intent')),
                       ('postStageIntake',stage/'intake.json')):
        raw=private(path,POST_RECORD_HASHES[label]);records[label]=binding.decode(raw)
        bindings[label]={'path':str(path),'sha256':binding.sha(raw)}
    manifest=records['postStageIntake'];files=manifest['fileHashes']
    binding.require(digest(manifest)==closure and manifest['sourceCommit']==POST_SOURCE
        and set(files)=={key.split(':',1)[1] for key in seed['recordBindings'] if key.startswith('source:')}
        and records['postStageIntent']=={'schema':'ouf.policy-token-source-stage-intent.v1',
            'sourceClosureHash':closure,'authorityHash':POST_AUTHORITY},'POST_CREDENTIAL_SOURCE_STAGE_DRIFT')
    for name,expected in files.items():
        private(stage/name,expected);bindings['postSource:'+name]={'path':str(stage/name),'sha256':expected}
    result.update(schema=POST_PROFILE,predecessorSource=POST_SOURCE,predecessorAuthorityHash=POST_AUTHORITY,
        predecessorReviewHash=POST_REVIEW,originalPregrantProofHash=digest(seed),
        priorCredentialMutationAttempts=1,priorGrantAttempts=0,
        credentialMetadata=credential_metadata())
    result['absentRecords']=[path for path in seed['absentRecords']
        if path not in (str(paths['credential']),str(paths['session']))]
    result['absentRecords'].append(str(fixed['postContinuation'])+'.completed')
    post_credential_admission(result)
    binding.require(quiescent(read_units()),'POST_CREDENTIAL_LEGACY_QUIESCENCE_REQUIRED')
    return result
