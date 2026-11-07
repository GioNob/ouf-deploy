"""Create-only exact initial provider v4 profiles, never switch or start.

The previous runtime configuration/candidates and consumed deployment journals
are untouched. Only the new owned CID directory and a separate configuration
proposal are published. Partial writes are preserved, not repaired or replayed.
"""
import os,stat
from pathlib import Path
from .custody_capture import digest,encoded,require
from .provider_profiles import ProviderInitialIssuer
from .lease_file_installation import inode
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import private_json,protected_file
from tools.semantic_provider_deployment_authentication import private_bytes

MUTABLE_INITIAL={'adapter.json','broker-state.json','deployment.json'}

class ProviderProfilePublication:
    def __init__(self,issuer):
        require(type(issuer) is ProviderInitialIssuer,'TYPED_PROVIDER_INITIAL_ISSUER_REQUIRED')
        self.issuer=issuer;self.creation=issuer.creation;self.scope=issuer.scope
        self.root=issuer.root;self.scope_hash=issuer.scope_hash
    def material(self):
        require(type(self.issuer) is ProviderInitialIssuer and self.issuer.creation is self.creation
            and self.scope==self.issuer.scope and self.scope_hash==self.issuer.scope_hash and self.root==self.issuer.root,
            'PROVIDER_PROFILE_PUBLICATION_OWNER_DRIFT')
        require(self.issuer.observe()[0]=='APPLIED','COMPLETE_THREE_PROVIDER_MANDATES_REQUIRED_BEFORE_PUBLICATION')
        return self.issuer.material(private_json(self.root/'issuance-claim.json'))
    def claim(self,material):
        return {'schema':'ouf.discovery-provider-profile-publication-claim.v1','scopeHash':self.scope_hash,
            'issuanceClaimHash':digest(private_json(self.root/'issuance-claim.json')),
            'containerId':material['materialized']['containerId'],
            'fileHashes':{p:__import__('hashlib').sha256(raw).hexdigest() for p,raw in material['files'].items()},
            'directories':material['directories'],'publicationAttempts':1,'automaticReplayAllowed':False}
    def apply(self):
        material=self.material();self.creation.current()
        require(self.creation.observe()[0]=='APPLIED','SAME_UNSTARTED_OWNED_PROVIDER_REQUIRED_BEFORE_PUBLICATION')
        claim=self.claim(material)
        with directory(self.root) as journal:
            new_file(journal,'publication-claim.json',encoded(claim))
            require(not os.path.lexists(material['root']),'EXISTING_PROVIDER_PROFILE_DIRECTORY_PRESERVED')
            for name in material['directories']:
                with directory(Path(name).parent) as parent:
                    os.mkdir(Path(name).name,0o700,dir_fd=parent);os.fsync(parent)
            self.creation.current()
            for name,raw in sorted(material['files'].items()):
                with directory(Path(name).parent) as parent:new_file(parent,Path(name).name,raw)
            # This commit precedes exposing the configuration through the
            # separately scoped runtime-wrapper switch. There is no hidden
            # switch, native command, signing or start in this publisher.
            owned={p:inode(p) for p in [*material['files'],*material['directories']]}
            new_file(journal,'publication-owned.json',encoded(owned))
            self.creation.current();require(self.issuer.observe()[0]=='APPLIED','PROVIDER_MANDATES_CHANGED_DURING_PUBLICATION')
            new_file(journal,'publication-complete.json',encoded(claim))
    def observe(self,*,initial=True):
        """Initial strict readback; completed observation preserves live journals.

        initial=False retains the initial mutable-record proof but never
        compares/restores their old bytes or inodes over the running runtime.
        This is not native running admission or permission to switch/start.
        """
        require(type(initial) is bool,'EXPLICIT_PROVIDER_PUBLICATION_OBSERVATION_MODE_REQUIRED')
        material=self.material()
        if not os.path.lexists(self.root/'publication-claim.json'):
            return 'UNKNOWN',{'ownedPublicationClaimPresent':False,'automaticReplayAllowed':False}
        claim=self.claim(material)
        require(private_json(self.root/'publication-claim.json')==claim,'EXACT_PROVIDER_PUBLICATION_CLAIM_REQUIRED')
        if not os.path.lexists(self.root/'publication-owned.json'):
            return 'UNKNOWN',{'partialPublicationPreserved':True,'automaticReplayAllowed':False}
        owned=private_json(self.root/'publication-owned.json')
        require(set(owned)==set(material['files'])|set(material['directories']),'EXACT_OWNED_PROVIDER_PROFILE_SET_REQUIRED')
        for name in material['directories']:
            with directory(name) as fd:
                require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700 and inode(name)[:5]==owned[name][:5],
                    'OWNED_PROVIDER_PROFILE_DIRECTORY_DRIFT')
        for name,raw in material['files'].items():
            if not initial and Path(name).name in MUTABLE_INITIAL:continue
            try:
                if not raw:
                    require(Path(name).name=='operation.lock','ONLY_EMPTY_PROVIDER_OPERATION_LOCK_ALLOWED')
                    with directory(Path(name).parent):value=private_bytes(Path(name),1)
                else:value=protected_file(name,131072,expected=claim['fileHashes'][name],modes=(0o600,))
            except FileNotFoundError:
                return 'UNKNOWN',{'partialPublicationPreserved':True,'automaticReplayAllowed':False}
            require(value==raw and inode(name)==owned[name],'OWNED_PROVIDER_PROFILE_FILE_DRIFT')
        if os.path.lexists(self.root/'publication-complete.json'):
            require(private_json(self.root/'publication-complete.json')==claim,'PROVIDER_PUBLICATION_COMPLETION_DRIFT')
        # publication-owned.json is the durable commit after all create-only
        # writes; the optional complete marker is only the final acknowledgement.
        # Initial observation before exposing the runtime proposal still checks
        # every STAGED byte. Completed observation retains that commit and never
        # reinitializes mutable records after a lost acknowledgement or start.
        self.issuer.current()
        return 'APPLIED',{'schema':'ouf.discovery-provider-profiles-published.v1','scopeHash':self.scope_hash,
            'claimHash':digest(claim),'ownedInodesHash':digest(owned),'exactInitialLedgerReadback':initial,
            'nativeAdmissionGranted':False,'runtimeSwitchOrStartPerformed':False,'automaticReplayAllowed':False}
