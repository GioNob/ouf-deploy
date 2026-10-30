"""Composition/ordering only: component effects and authority leaves modeled.

Actual signatures/journals/native effects are qualified in the component suites.
These tests do not prove current admission, a combined native cohort or E2E.
"""
import copy,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_transaction_profiles'),
    str(ROOT/'tools/semantic_database_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.m2_discovery_installation_profile import selected_runtime as m
from tools.chatbot_file_cohort.containers import CohortPaused


class SelectedRuntime(unittest.TestCase):
    def fixture(self):
        calls=[];engine,child=object(),object()
        image_scope={'schema':'synthetic-image-scope'}
        bindings={'sourceClosureHash':'a'*64,'installationInputsHash':'b'*64,'desiredProfileHash':'c'*64}
        component={'schema':'ouf.discovery-cohort-installation-scope.v1',**bindings,'images':image_scope,
            'mcp':{'schema':'synthetic-mcp'},'gatewayRuntime':{'schema':'synthetic-gateway'},
            'currentAdmission':{'schema':'synthetic-inert-not-admission'},
            'requiresFullCurrentCohortBeforeRelease':True,'automaticReplayAllowed':False,'budgetReset':False}
        parent=SimpleNamespace(scope=bindings,review={'components':{'cohortInstallation':component}},sha='6'*64)
        row={'state':'READY','nextPhase':m.PHASES.index('RELEASE_PRODUCERS'),
            'creationRequestHash':'4'*64,'transitionAuthorityEvidenceHash':'5'*64,'version':42,'effects':[]}
        window=SimpleNamespace(parent=parent,engine=engine,child=child,raw=b'synthetic-child',
            request_hash='4'*64,transition=SimpleNamespace(read=lambda:copy.deepcopy(row)))
        images=object.__new__(m.DiscoveryImages);images.window=window;images.parent=parent
        images.engine=engine;images.scope=image_scope;images.guard=Mock()
        gateway=object.__new__(m.DiscoveryGatewayRuntime);mcp=object.__new__(m.DiscoveryMcpRuntime)
        for owner in (gateway,mcp):
            owner.images=images;owner.window=window;owner.parent=parent;owner.engine=engine
            owner.action=SimpleNamespace(authority=child,raw=window.raw,authority_hash='5'*64)
            owner.cohort_component=copy.deepcopy(component);owner.guard=Mock();owner.initialize=Mock()
        installation=object.__new__(m.DiscoveryInstallationApplication)
        installation.provider=SimpleNamespace(window=window,parent=parent)
        installation.application=SimpleNamespace(transition=window.transition,discovery_parent=parent)
        installation.verify_scope=Mock();installation.release_after_cohort_verification=Mock()
        def operation(name):
            def run():calls.append(name);return {'schema':'synthetic-proof','owner':name.split('-')[0]}
            return Mock(side_effect=run)
        images.apply=operation('images');images.verify=operation('images-verify')
        gateway.apply=operation('gateway');gateway.verify=operation('gateway-verify')
        mcp.apply=operation('mcp');mcp.report=operation('mcp-report')
        installation.verify_registry_and_hold=operation('registry-hold')
        owner=m.DiscoverySelectedRuntime(installation=installation,images=images,gateway=gateway,mcp=mcp)
        return owner,calls,row

    def test_ordered_owners_rechecked_without_release_or_new_initialization(self):
        owner,calls,_=self.fixture();result=owner.apply()
        self.assertEqual(calls,['images','registry-hold','gateway','mcp','images-verify','gateway-verify','mcp-report'])
        self.assertTrue(result['selectedOwnersVerified']);self.assertTrue(result['registryReleaseBarrierHeld'])
        self.assertFalse(result['producerReleaseDispatched']);self.assertFalse(result['fullCohortProven'])
        self.assertFalse(result['capabilitiesPublished']);self.assertFalse(result['targetApplyAuthorized'])
        owner.installation.release_after_cohort_verification.assert_not_called()
        owner.gateway.initialize.assert_not_called();owner.mcp.initialize.assert_not_called()

    def test_different_engine_or_child_cannot_dispatch(self):
        for field in ('engine','child','registry_parent'):
            owner,calls,_=self.fixture()
            if field=='engine':owner.mcp.engine=object()
            elif field=='child':owner.gateway.action.authority=object()
            else:owner.installation.application.discovery_parent=object()
            with self.assertRaisesRegex(ValueError,'SAME_DISCOVERY_PARENT_CHILD_ENGINE'):owner.apply()
            self.assertEqual(calls,[])

    def test_changed_parent_review_cannot_dispatch(self):
        owner,calls,_=self.fixture();owner.images.parent.review['components']['cohortInstallation']['mcp']['changed']=True
        with self.assertRaisesRegex(ValueError,'SAME_DISCOVERY_PARENT_CHILD_ENGINE'):owner.apply()
        self.assertEqual(calls,[])

    def test_registry_not_held_blocks_gateway_and_mcp(self):
        owner,calls,row=self.fixture();row['state']='IN_FLIGHT'
        with self.assertRaisesRegex(ValueError,'VERIFIED_REGISTRY_WITH_PRODUCERS_HELD'):owner.apply()
        self.assertEqual(calls,['images','registry-hold'])

    def test_registry_history_change_during_gateway_blocks_mcp(self):
        owner,calls,row=self.fixture()
        def drift():calls.append('gateway');row['version']+=1;return {'synthetic':True}
        owner.gateway.apply.side_effect=drift
        with self.assertRaisesRegex(ValueError,'REGISTRY_HELD_HISTORY_CHANGED'):owner.apply()
        self.assertEqual(calls,['images','registry-hold','gateway'])

    def test_gateway_pause_stops_dependents_and_preserves_owner_control(self):
        owner,calls,_=self.fixture();owner.gateway.apply.side_effect=CohortPaused('SYNTHETIC_GATEWAY_WAIT')
        with self.assertRaises(CohortPaused):owner.apply()
        owner.mcp.apply.assert_not_called();owner.installation.release_after_cohort_verification.assert_not_called()

    def test_revocation_between_gateway_and_mcp_stops_mcp(self):
        owner,calls,_=self.fixture()
        def revoke():owner.images.guard.side_effect=ValueError('SYNTHETIC_PARENT_REVOKED');return {'synthetic':True}
        owner.gateway.apply.side_effect=revoke
        with self.assertRaisesRegex(ValueError,'SYNTHETIC_PARENT_REVOKED'):owner.apply()
        owner.mcp.apply.assert_not_called()

    def test_changed_completion_proof_never_reports_success_or_releases(self):
        for which in ('images','gateway','mcp'):
            owner,_,_=self.fixture()
            verifier={'images':owner.images.verify,'gateway':owner.gateway.verify,'mcp':owner.mcp.report}[which]
            verifier.side_effect=None;verifier.return_value={'schema':'synthetic-changed-proof'}
            with self.assertRaisesRegex(ValueError,'PROOF_CHANGED'):owner.apply()
            owner.installation.release_after_cohort_verification.assert_not_called()


if __name__=='__main__':unittest.main()
