"""Compose already-owned discovery installation; stop before producer release.

No new journal, retry engine, authority or admission flag. Each owner retains its
own one-use effects, invocation fence, ambiguity and original finite budget.
Full-cohort admission and coordinated capability publication remain separate.
"""
from .custody_capture import digest,require
from .installation_application import DiscoveryInstallationApplication
from .cohort_images import DiscoveryImages,checked_component
from .gateway_runtime import DiscoveryGatewayRuntime
from .mcp_runtime import DiscoveryMcpRuntime
from transition_journal import PHASES


class DiscoverySelectedRuntime:
    def __init__(self,*,installation,images,gateway,mcp):
        require(type(installation) is DiscoveryInstallationApplication and type(images) is DiscoveryImages
            and type(gateway) is DiscoveryGatewayRuntime and type(mcp) is DiscoveryMcpRuntime,
            'TYPED_EXISTING_DISCOVERY_RUNTIME_OWNERS_REQUIRED')
        self.installation,self.images,self.gateway,self.mcp=installation,images,gateway,mcp
        self.owner_ids=tuple(map(id,(installation,images,gateway,mcp)))
        self.guard()

    def guard(self):
        install,images,gateway,mcp=self.installation,self.images,self.gateway,self.mcp
        window=images.window
        require(self.owner_ids==tuple(map(id,(install,images,gateway,mcp)))
            and type(install) is DiscoveryInstallationApplication and type(images) is DiscoveryImages
            and type(gateway) is DiscoveryGatewayRuntime and type(mcp) is DiscoveryMcpRuntime
            and gateway.images is mcp.images is images and gateway.window is mcp.window is window
            and gateway.parent is mcp.parent is images.parent is window.parent
            and install.provider.window is window and install.provider.parent is window.parent
            and install.application.discovery_parent is window.parent
            and install.application.transition is window.transition
            and gateway.engine is mcp.engine is images.engine is window.engine
            and gateway.action.authority is mcp.action.authority is window.child
            and gateway.action.raw==mcp.action.raw==window.raw
            and gateway.cohort_component==mcp.cohort_component==checked_component(images.parent,images.scope),
            'SAME_DISCOVERY_PARENT_CHILD_ENGINE_AND_REVIEWED_RUNTIME_OWNERS_REQUIRED')
        install.verify_scope();images.guard();gateway.guard();mcp.guard()

    def held(self,expected=None):
        self.guard();row=self.images.window.transition.read()
        require(row['state']=='READY' and row['nextPhase']==PHASES.index('RELEASE_PRODUCERS')
            and row['creationRequestHash']==self.images.window.request_hash
            and row['transitionAuthorityEvidenceHash']==self.mcp.action.authority_hash,
            'VERIFIED_REGISTRY_WITH_PRODUCERS_HELD_REQUIRED_FOR_SELECTED_RUNTIME')
        require(expected is None or row==expected,'REGISTRY_HELD_HISTORY_CHANGED_DURING_SELECTED_RUNTIME')
        return row

    def apply(self):
        self.guard();image_proof=self.images.apply()
        self.installation.verify_registry_and_hold()
        # The existing transition invocation fence excludes a concurrent release
        # while dependent owners run. This is not the shared lease/network lock;
        # owner pauses propagate immediately and release it, without sleeping.
        with self.images.window.transition.invocation():
            held=self.held()
            gateway_proof=self.gateway.apply();self.held(held)
            mcp_proof=self.mcp.apply();self.held(held)
            # Completion checks may not import or create anything.
            require(self.images.verify()==image_proof,'SELECTED_IMAGE_PROOF_CHANGED_DURING_INSTALLATION')
            require(self.gateway.verify()==gateway_proof and self.mcp.report()==mcp_proof,
                'SELECTED_RUNTIME_GENERATION_OR_COMPLETION_PROOF_CHANGED')
            self.held(held)
        return {'schema':'ouf.discovery-selected-runtime-installation-receipt.v1',
            'componentHash':digest(self.mcp.cohort_component),'parentAuthorityHash':self.images.parent.sha,
            'childAuthorityHash':self.mcp.action.authority_hash,'registryHeldHistoryHash':digest(held),
            'ownerEvidenceHashes':{'images':digest(image_proof),'gateway':digest(gateway_proof),'mcp':digest(mcp_proof)},
            'selectedOwnersVerified':True,'registryReleaseBarrierHeld':True,'producerReleaseDispatched':False,
            'fullCohortProven':False,'capabilitiesPublished':False,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'budgetReset':False,'releaseAcceptance':False}
