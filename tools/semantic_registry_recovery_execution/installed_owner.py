"""Reconstruct exactly one reviewed installed observer; never start its worker.

The reference is selected by signed input, not by scanning names or journals.
Existing source, directory identity, counters, boot/session, legacy fence and
ACTIVE admission are checked by the unchanged InstalledTokenOwner. No token or
credential is read by construction and no grant/renewal method is exposed here.
"""
import copy,json,os
from pathlib import Path
from .core import require,digest,validate_plan
from .authorization import cutover_type,scope as recovery_scope
from tools.ingestion_readiness_patch_execution import private_file
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner
from tools.semantic_policy_token_owner.producer import Binding,CredentialFile,protected_directory
from tools.semantic_policy_token_owner.iam_admission import IamProfile,PinnedIamOpener,OnlineIamAdmission
from tools.semantic_lease_recovery.recovery_journal import Journal

CONFIGURATION={'schema','binding','iamProfile','tlsTrustHash','journalPolicyHash','renewalProfile',
    'intervalSeconds','credentialPath','journalPath','journalDirectoryIdentity','contextRef',
    'generationRef','legacyUnits'}

def owner_scope(plan,reference):
    validate_plan(plan)
    require(type(reference) is dict and set(reference)=={'schema','configuration','manifest'}
        and reference['schema']=='ouf.semantic-registry-retained-installed-owner-reference.v1',
        'EXACT_REVIEWED_INSTALLED_OWNER_REFERENCE_REQUIRED')
    c=reference['configuration']
    require(type(c) is dict and set(c) in (CONFIGURATION,CONFIGURATION|{'workerSessionHash'})
        and c['schema']=='ouf.installed-policy-token-owner-binding.v1',
        'COMPLETE_EXISTING_INSTALLED_OWNER_CONFIGURATION_REQUIRED')
    private_file.validate(reference['manifest'],maximum=65536)
    return {'schema':'ouf.semantic-registry-recovery-installed-owner-scope.v1',
        'planHash':digest(plan),'logicalOperationRef':plan['logicalOperationRef'],
        'referenceHash':digest(reference),'ownerBindingHash':digest(c),
        'journalPath':c['journalPath'],'journalDirectoryIdentity':copy.deepcopy(c['journalDirectoryIdentity']),
        'operation':'OBSERVE_EXISTING_ACTIVE_OWNER_ONLY','maximumGrantAttempts':0,
        'automaticWorkerStartAllowed':False,'automaticWaitAllowed':False,'budgetReset':False}

def _manifest(profile):
    with private_file.opened(profile,maximum=65536) as fd:
        raw=bytearray()
        while len(raw)<=65536:
            block=os.read(fd,65536)
            if not block:break
            raw.extend(block)
    def unique(pairs):
        value={}
        for key,item in pairs:require(key not in value,'DUPLICATE_INSTALLED_OWNER_MANIFEST_KEY');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique)

def build_observer(plan,reference,authority,raw):
    expected=owner_scope(plan,reference)
    require(type(authority) is cutover_type() and type(raw) is bytes and authority(raw) is True,
        'CURRENT_TYPED_HUMAN_AUTHORITY_FOR_INSTALLED_OBSERVER_REQUIRED')
    signed=json.loads(raw)
    require(signed.get('semanticRegistryRecovery')==recovery_scope(plan)
        and signed.get('semanticRegistryRecoveryInstalledOwner')==expected,
        'EXACT_SIGNED_CURRENT_INSTALLED_OWNER_REFERENCE_REQUIRED')
    c=copy.deepcopy(reference['configuration']);manifest=_manifest(reference['manifest'])
    require(manifest.get('ownerBindingHash')==expected['ownerBindingHash'],
        'RETAINED_SOURCE_MANIFEST_MUST_BIND_SAME_INSTALLED_OWNER')
    # Resolve neither a newer owner nor another journal on failure. Opening the
    # existing private directory performs no initialization or lock creation.
    with protected_directory(c['journalPath']) as fd:
        s=os.fstat(fd)
        require(c['journalDirectoryIdentity']=={'device':s.st_dev,'inode':s.st_ino},
            'EXACT_RETAINED_OWNER_JOURNAL_DIRECTORY_REQUIRED')
    binding=Binding(**c['binding']);p=copy.deepcopy(c['iamProfile'])
    for name in ('required_scopes','allowed_scopes','peer_addresses'):p[name]=tuple(p[name])
    profile=IamProfile(**p);profile.match(binding)
    credential=CredentialFile(Path(c['credentialPath']));transport=PinnedIamOpener(profile)
    require(transport.trust_digest()==c['tlsTrustHash'],'CURRENT_INSTALLED_OWNER_TLS_TRUST_CHANGED')
    admission=OnlineIamAdmission(profile,credential,transport)
    owner=InstalledTokenOwner(binding,credential,admission,Journal(c['journalPath']),c['contextRef'],
        c['generationRef'],manifest,authority,raw,observer=True)
    require(digest(owner.configuration)==expected['ownerBindingHash']
        and owner_scope(plan,reference)==expected,'RECONSTRUCTED_INSTALLED_OWNER_BINDING_CHANGED')
    owner.guard(binding.digest())
    require(authority(raw) is True and _manifest(reference['manifest'])==manifest,
        'INSTALLED_OWNER_AUTHORITY_OR_MANIFEST_CHANGED_DURING_CONSTRUCTION')
    return owner
