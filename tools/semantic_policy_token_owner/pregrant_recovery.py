"""Explicit recovery of the retained stopped installation BEFORE any grant.

Preserve every predecessor file. Only the independently reviewed successor may
publish observation receipts and reserve one continuation. No service command,
credential operation, first-grant slot or finite-process claim is replayed here.
"""
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import stat

import iam_binding_candidate as evidence
import legacy_retirement as legacy
from tools.semantic_policy_token_owner.producer import protected_directory

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

def digest(value):return evidence.sha(evidence.encoded(value))

def private(path,expected=None):
    path=Path(path)
    guard=evidence.protected_parent() if path.parent==evidence.PARENT else protected_directory(path.parent)
    with guard as directory:
        raw=evidence.read_member(directory,path.name)
        evidence.require(len(raw)<=262144 and evidence.read_member(directory,path.name)==raw,
            'PREGRANT_RECORD_CHANGED_DURING_READ')
    evidence.require(expected is None or evidence.sha(raw)==expected,'PREGRANT_RETAINED_RECORD_DRIFT')
    return raw

def directory_binding(path,gid,mode):
    # Root recovery/credential/output identities are also checked by the root
    # custody owner. No inode adoption or permission repair is performed here.
    path=Path(path)
    evidence.require(path.resolve()==path,'PREGRANT_ROOT_SYMLINK_DENIED')
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        evidence.require(info.st_uid==0 and info.st_gid==gid and stat.S_IMODE(info.st_mode)==mode,
            'PREGRANT_ROOT_CUSTODY_DRIFT')
        return {'path':str(path),'device':info.st_dev,'inode':info.st_ino,'uid':0,'gid':gid,'mode':mode}
    finally:os.close(fd)

def names(scopes):
    logical=scopes['policyTokenLegacyRetirement']['logicalOwnerScopeHash']
    owner=digest({'logicalOwnerScopeHash':logical,'operation':'FIRST_COMPLETE_TOKEN_OWNER_INSTALLATION'})
    retire=digest({'logicalOwnerScopeHash':logical,'units':list(legacy.UNITS),
        'operation':'FIRST_GOVERNED_LEGACY_RETIREMENT'})
    output_scope=scopes['policyTokenOutputCustody']
    out=digest({'logicalOwnerScopeHash':logical,'operation':'FIRST_GOVERNED_TOKEN_OUTPUT_CHILD',
        'path':output_scope['path']})
    first=scopes['policyTokenFirstControlledGrant']
    return {
        'installation':evidence.PARENT/('policy-token-owner-installation-'+owner+'.private.json'),
        'retirement':evidence.PARENT/('policy-token-legacy-retirement-'+retire+'.private.json'),
        'output':evidence.PARENT/('policy-token-output-custody-'+out+'.private.json'),
        'credential':evidence.PARENT/('policy-token-credential-transaction-'+first['credentialOperation']+'.private.json'),
        'session':evidence.PARENT/('policy-token-first-gap-session-'+first['sessionOperation']+'.private.json'),
        'grant':evidence.PARENT/('policy-token-first-controlled-grant-'+first['sessionOperation']+'.private.json')}

def observe(review,authority_hash):
    """Read-only preparation, called after stopped/expired process validation."""
    evidence.require(digest(review)==REVIEW and authority_hash==AUTHORITY
        and review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and Path(review['scopes']['finiteActionProcess']['authorityDirectory']).name==CONTEXT,
        'EXACT_PREGRANT_PREDECESSOR_REQUIRED')
    scopes=review['scopes'];paths=names(scopes);records={};bindings={}
    for label in ('installation','retirement','output'):
        raw=private(paths[label],RECORD_HASHES[label]);records[label]=evidence.decode(raw)
        bindings[label]={'path':str(paths[label]),'sha256':evidence.sha(raw)}
    evidence.require(records['installation']=={
        'schema':'ouf.policy-token-owner-installation-intent.v1',
        'operation':records['installation']['operation'],'scope':scopes['policyTokenOwnerInstallation'],
        'authorityHash':AUTHORITY,'state':'RESERVED_OUTCOME_UNPROVEN','automaticReplayAllowed':False},
        'EXACT_PREGRANT_INSTALLATION_RESERVATION_REQUIRED')
    evidence.require(records['retirement']['scope']==scopes['policyTokenLegacyRetirement']
        and records['retirement']['state']=='COMMAND_RESERVED_OUTCOME_UNPROVEN'
        and records['retirement']['commandAttemptConsumed']is True and records['retirement']['version']==0,
        'EXACT_PREGRANT_RETIREMENT_RESERVATION_REQUIRED')
    output=records['output']
    evidence.require(output['scope']==scopes['policyTokenOutputCustody']
        and output['state']=='OUTPUT_CUSTODIED_NOT_RUNTIME_ACCEPTED'
        and output['mkdirAttemptConsumed']is True and output['version']==1,
        'COMPLETED_PREGRANT_OUTPUT_CUSTODY_REQUIRED')
    closure=scopes['policyTokenOwnerInstallation']['stageManifestHash']
    code=CODE
    stage=code/('semantic-native-v11-intake-'+closure)
    for label,path in (('stageIntent',code/('policy-token-source-stage-'+closure+'.intent')),
                       ('stageIntake',stage/'intake.json')):
        raw=private(path,RECORD_HASHES[label]);bindings[label]={'path':str(path),'sha256':evidence.sha(raw)}
        records[label]=evidence.decode(raw)
    manifest=records['stageIntake']
    from tools.semantic_policy_token_owner.source_stage import FILES
    evidence.require(digest(manifest)==closure and set(manifest['fileHashes'])==FILES
        and records['stageIntent']=={'schema':'ouf.policy-token-source-stage-intent.v1',
            'sourceClosureHash':closure,'authorityHash':AUTHORITY},'PREGRANT_SOURCE_STAGE_DRIFT')
    for name,expected in manifest['fileHashes'].items():
        private(stage/name,expected)
        bindings['source:'+name]={'path':str(stage/name),'sha256':expected}
    roots={label:directory_binding(*value) for label,value in ROOTS.items()}
    evidence.require(output['outputIdentity']=={key:roots['output'][key] for key in ('device','inode')},
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
    admission(result)
    evidence.require(legacy.quiescent(legacy.read_units()),'PREGRANT_LEGACY_QUIESCENCE_REQUIRED')
    return result

def admission(proof):
    for path in proof['absentRecords']:
        evidence.require(not os.path.lexists(path),'PREGRANT_EFFECT_HISTORY_PRESENT_NO_CONTINUATION')
    evidence.require(set(os.listdir(ROOTS['ownerRecovery'][0]))=={'token-output'}
        and not os.listdir(ROOTS['credential'][0]) and not os.listdir(ROOTS['output'][0]),
        'PREGRANT_OWNER_OR_CREDENTIAL_HISTORY_PRESENT')

class PregrantRecovery:
    def __init__(self,action,proof):
        from tools.semantic_policy_token_owner.owner_installation import AggregateAction
        evidence.require(type(action)is AggregateAction,'REAL_PREGRANT_AGGREGATE_ACTION_REQUIRED')
        self.action=action;self.proof=copy.deepcopy(proof);self.hash=digest(self.proof);self.owner_scope=None
        old_review=evidence.decode(private(evidence.PARENT/CONTEXT/'review.json',REVIEW))
        # Re-observe while still effect-free; arbitrary proof dictionaries cannot
        # replace the fixed original records or absence/identity requirements.
        evidence.require(observe(old_review,AUTHORITY)==self.proof,'EXACT_CURRENT_PREGRANT_PROOF_REQUIRED')
        self.continuation='policy-token-owner-pregrant-continuation-'+AUTHORITY+'.private.json'

    def guard(self):
        evidence.require(self.owner_scope is not None and digest(self.proof)==self.hash
            and self.owner_scope.get('pregrantRecovery')==self.proof,
            'EXACT_SIGNED_PREGRANT_RECOVERY_REQUIRED')
        self.action.guard('policyTokenOwnerInstallation',self.owner_scope)
        for binding in self.proof['recordBindings'].values():private(binding['path'],binding['sha256'])
        evidence.require({label:directory_binding(*value) for label,value in ROOTS.items()}
            ==self.proof['rootBindings'],'PREGRANT_ROOT_IDENTITIES_CHANGED')

    def admit(self):
        self.guard();admission(self.proof)
        evidence.require(legacy.quiescent(legacy.read_units()),'PREGRANT_LEGACY_QUIESCENCE_REQUIRED')

    def configure(self,output,retirement):
        for component,label,operation,count_key in (
            (output,'output','REUSE_COMPLETED_TOKEN_OUTPUT_CHILD','maximumMkdirAttempts'),
            (retirement,'retirement','OBSERVE_PREVIOUSLY_MASKED_AND_STOPPED_UNITS','maximumCommandAttempts')):
            component.scope={**component.scope,'operation':operation,count_key:0,
                'pregrantRecoveryHash':self.hash,'predecessorRecord':copy.deepcopy(self.proof['recordBindings'][label])}
            component.name='policy-token-'+label+'-pregrant-reconciliation-'+AUTHORITY+'.private.json'
            component.pregrant_recovery=self

    def publish(self,name,row):
        self.guard()
        with evidence.protected_parent() as directory:
            fd=os.open(name+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
            try:
                info=os.fstat(fd)
                evidence.require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                    and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'PREGRANT_RECEIPT_FENCE_CUSTODY_REQUIRED')
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                def fence():
                    evidence.require(evidence.identity(os.fstat(fd))==evidence.identity(info)
                        ==evidence.identity(os.stat(name+'.lock',dir_fd=directory,follow_symlinks=False)),
                        'PREGRANT_RECEIPT_FENCE_CHANGED')
                raw=evidence.encoded(row);self.guard();fence()
                try:existing=evidence.read_member(directory,name)
                except FileNotFoundError:
                    target=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                    try:
                        with os.fdopen(os.dup(target),'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                        os.fsync(directory)
                    finally:os.close(target)
                    existing=evidence.read_member(directory,name)
                evidence.require(existing==raw,'PREGRANT_RECONCILIATION_RECEIPT_DRIFT')
                fence();self.guard()
                return copy.deepcopy(row)
            finally:os.close(fd)

    def output(self,component):
        self.guard()
        row=evidence.decode(private(self.proof['recordBindings']['output']['path'],
            self.proof['recordBindings']['output']['sha256']))
        current=self.proof['rootBindings']['output']
        evidence.require(row['outputIdentity']=={key:current[key] for key in ('device','inode')},
            'PREGRANT_OUTPUT_IDENTITY_DRIFT')
        # Preserve the original consumed attempt and its monotonic timestamps.
        # Current authority permits only custody observation, never another mkdir.
        row['scope']=copy.deepcopy(component.scope)
        component.validate(row)
        return self.publish(component.name,row)

    def retirement(self,component):
        self.guard()
        evidence.require(legacy.quiescent(legacy.read_units()),'PREGRANT_LEGACY_QUIESCENCE_REQUIRED')
        row=evidence.decode(private(self.proof['recordBindings']['retirement']['path'],
            self.proof['recordBindings']['retirement']['sha256']))
        row.update(scope=copy.deepcopy(component.scope),state='QUIESCENCE_OBSERVED',version=1)
        return self.publish(component.name,row)
