"""Real parent/child signatures and journals; Docker/application leaves modeled."""
import copy,hashlib,sys,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_cohort_images as image_fixture
import test_chatbot_cohort_gateway_runtime as gateway_fixture
from tools.m2_discovery_installation_profile import gateway_runtime as m
from tools.m2_discovery_installation_profile.gate_peer_window import GatePeerWindow
from cutover_authority import CutoverAuthority
from engine_creation import CreationDenied


class Gateway(unittest.TestCase):
    def fixture(self,*,historical=False,construct=True):
        images_case=image_fixture.Images();images,auth,*_=images_case.fixture();self.addCleanup(images_case.doCleanups)
        gateway_case=gateway_fixture.GatewayRuntime();old,native,_=gateway_case.fixture();self.addCleanup(gateway_case.doCleanups)
        window=images.window;request=window.engine.request
        def engine_request(method,path,body=None):
            if path=='/v1.44/info' or path.startswith('/v1.44/images/'):return request(method,path,body)
            return native.engine.request(method,path,body)
        window.engine.request=engine_request;window.engine.check_socket=native.engine.check_socket
        window.engine.path=native.engine.path
        directory=auth.root/'new-gateway-journal';directory.mkdir(mode=0o700)
        scope=m.component(old.plan,str(directory));auth.review['components']['cohortInstallation']['gatewayRuntime']=scope
        value=m.decode(window.raw);value['gatewayRuntimeInstallation']=scope['runtime']
        if historical:value['applicationRegistryCutover']={'postGrantRecovery':{'retainedNumericGateway':'historical-not-current'}}
        raw=image_fixture.m.encoded(value);human=m.decode(Path(window.child.binding['path']).read_bytes())
        human['executionAuthorityHash']=hashlib.sha256(raw).hexdigest();auth.write(Path(window.child.binding['path']),image_fixture.m.encoded(human))
        binding=auth.binding(Path(window.child.binding['path']))
        child=CutoverAuthority(auth.verifier,binding,binding['sha256'],auth.context,window.child.expected,lambda:auth.now)
        auth.review['components']['registryCutover']={'schema':'ouf.discovery-registry-child-scope.v1',
            'authorityHash':hashlib.sha256(raw).hexdigest(),'humanManifestHash':binding['sha256'],**child.expected}
        for role in ('DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'):auth.sign(raw,role)
        parent=auth.fixture()
        selected=GatePeerWindow(parent=parent,child=child,child_raw=raw,engine=window.engine,
            transition=window.transition,request=window.request,profile=window.profile,store=window.store,directory=window.root)
        images=image_fixture.m.DiscoveryImages(window=selected,plan=images.plan,journals=images.journals,docker_binding=images.docker)
        arguments={'images':images,'plan':old.plan,'journal':m.Journal(directory),'boot':'synthetic-boot'}
        if not construct:return arguments,native,auth
        owner=m.DiscoveryGatewayRuntime(**arguments);owner.transport=old.transport;owner.initialize()
        return owner,native,auth

    def test_existing_owner_executes_once_with_actual_current_parent_and_child(self):
        owner,native,auth=self.fixture();first=owner.apply();history=copy.deepcopy(owner.record())
        owner.apply();self.assertEqual(owner.record(),history)
        self.assertTrue(first['oldContainerRetained']);self.assertEqual(len(native.calls),7)
        self.assertIs(owner.action.authority,owner.images.window.child)
        self.assertIs(owner.engine,owner.images.window.engine)
        self.assertEqual(owner.discovery_scope['runtime'],owner.scope)

    def test_parent_revocation_blocks_internal_resume_even_while_child_is_valid(self):
        owner,native,auth=self.fixture();native.lose_ack='create'
        with self.assertRaises(Exception):owner.apply()
        self.assertEqual(len(native.calls),4)
        auth.write(Path(owner.parent.binding['path']),b'REVOKED_PARENT')
        self.assertTrue(owner.action.guard('gatewayRuntimeInstallation',owner.scope))
        with self.assertRaisesRegex(ValueError,'DISCOVERY_PARENT_HUMAN_DECISION_CHANGED'):owner.apply()
        self.assertEqual(len(native.calls),4)

    def test_child_revocation_also_blocks_without_native_writes(self):
        owner,native,auth=self.fixture()
        auth.write(Path(owner.window.child.binding['path']),b'REVOKED_CHILD')
        with self.assertRaises(Exception):owner.apply()
        self.assertEqual(native.calls,[])

    def test_fresh_unreviewed_journal_cannot_rearm_the_same_plan(self):
        owner,native,auth=self.fixture();directory=auth.root/'unreviewed-gateway-journal';directory.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'EXACT_PARENT_GATEWAY_PLAN_AND_JOURNAL_REQUIRED'):
            m.DiscoveryGatewayRuntime(images=owner.images,plan=owner.plan,journal=m.Journal(directory),boot='synthetic-boot')
        self.assertFalse((directory/'recovery.json').exists());self.assertEqual(native.calls,[])

    def test_consumed_historical_gateway_adoption_is_rejected_before_initialization(self):
        args,native,_=self.fixture(historical=True,construct=False)
        with self.assertRaisesRegex(ValueError,'CURRENT_CHILD_GATEWAY_SCOPE_WITHOUT_HISTORICAL_ADOPTION_REQUIRED'):
            m.DiscoveryGatewayRuntime(**args)
        self.assertFalse(args['journal'].record.exists());self.assertEqual(native.calls,[])

    def test_unknown_connect_is_read_reconciled_without_second_connect(self):
        owner,native,_=self.fixture();native.omit_effect='connect'
        for _ in range(2):
            with self.assertRaises(Exception):owner.apply()
        self.assertEqual(sum(c[0]=='connect' for c in native.calls),1)
        self.assertEqual(owner.record()['effects'][-1]['state'],'CLAIMED')

    def test_regressed_mutable_journal_cannot_dispatch_a_second_connect(self):
        owner,native,auth=self.fixture();native.omit_effect='connect'
        with self.assertRaisesRegex(ValueError,'NETWORK_DRIFT'):owner.apply()
        row=owner.record();self.assertEqual(row['effects'][-1]['step'],'connect')
        self.assertEqual(row['effects'][-1]['state'],'CLAIMED')
        row['effects'].pop();row['version']-=1
        # Deliberate regression in the disposable fixture. There is no runtime
        # repair/reset path: independent dispatch custody must survive this.
        auth.write(owner.journal.record,image_fixture.m.encoded(row))
        with self.assertRaises(FileExistsError):owner.apply()
        self.assertEqual(sum(c[0]=='connect' for c in native.calls),1)

    def test_all_dispatches_bind_both_authorities_and_remain_unchanged_on_reentry(self):
        owner,native,_=self.fixture();owner.apply()
        markers={step:owner.journal.root/(step+'-dispatch.json') for step in m.STEPS if step!='ready'}
        before={step:(p.stat().st_ino,p.read_bytes()) for step,p in markers.items()}
        self.assertEqual(len(before),7)
        for step,path in markers.items():
            self.assertEqual(m.private_json(path),owner.dispatch_claim(step))
            self.assertEqual(m.private_json(path)['parentAuthorityHash'],owner.parent.sha)
            self.assertEqual(m.private_json(path)['childAuthorityHash'],owner.action.authority_hash)
        owner.apply()
        self.assertEqual({step:(p.stat().st_ino,p.read_bytes()) for step,p in markers.items()},before)
        self.assertEqual(len(native.calls),7)

    def test_lost_start_reply_reconstructs_owner_without_another_dispatch(self):
        owner,native,_=self.fixture();native.lose_ack='start'
        with self.assertRaisesRegex(CreationDenied,'ENGINE_OUTCOME_REQUIRES_RECONCILIATION'):owner.apply()
        marker=owner.journal.root/'start-dispatch.json';before=(marker.stat().st_ino,marker.read_bytes())
        self.assertEqual(owner.record()['effects'][-1]['step'],'start')
        resumed=m.DiscoveryGatewayRuntime(images=owner.images,plan=owner.plan,journal=owner.journal,boot=owner.boot)
        resumed.transport=owner.transport;resumed.apply()
        self.assertEqual(sum(c[0]=='start' for c in native.calls),1)
        self.assertEqual((marker.stat().st_ino,marker.read_bytes()),before)

    def test_changed_completed_marker_blocks_further_work(self):
        owner,native,auth=self.fixture();owner.apply();count=len(native.calls)
        marker=owner.journal.root/'connect-dispatch.json';value=m.private_json(marker)
        value['parentAuthorityHash']='f'*64;auth.write(marker,m.encoded(value))
        with self.assertRaisesRegex(ValueError,'DISCOVERY_GATEWAY_DISPATCH_CUSTODY_OR_SCOPE_DRIFT'):owner.apply()
        self.assertEqual(len(native.calls),count)

    def test_unclaimed_direct_mutation_and_concurrent_invocation_cannot_dispatch(self):
        owner,native,_=self.fixture();before=owner.record()
        with self.assertRaisesRegex(ValueError,'CONSUMED_DISCOVERY_GATEWAY_STEP_REQUIRED'):owner.mutation('start')
        with owner.journal.invocation():
            with self.assertRaises(BlockingIOError):owner.apply()
        self.assertFalse(list(owner.journal.root.glob('*-dispatch.json')))
        self.assertEqual(owner.record(),before);self.assertEqual(native.calls,[])

    def test_completed_owner_rejects_a_new_gateway_generation(self):
        owner,native,_=self.fixture();owner.apply();actual=native.find('ouf-apisix')
        actual['State'].update(Pid=9999,StartedAt='2026-10-30T16:00:00Z')
        with self.assertRaisesRegex(ValueError,'STARTED_GENERATION_CHANGED'):owner.apply()
        self.assertEqual(len(native.calls),7)

    def test_real_transport_construction_keeps_parent_and_generation_checks_and_denies_put(self):
        owner,native,auth=self.fixture();owner.apply()
        binding={'runtimeBinding':m.apisix_runtime_binding(owner.generation(),owner.plan.get('runtimeBindingProfile')),
            'configBinding':owner.plan['newConfigBinding'],'adminKeyBinding':owner.plan['adminKeyBinding'],
            'networkNamespace':{'device':1,'inode':2},'transport':'EXACT_APISIX_NETNS_LOOPBACK_HTTP',
            'port':9180,'maximumResponseBytes':1048576,'timeoutSeconds':10,
            'pythonExecutable':owner.plan['pythonExecutable']}
        with patch.object(m.NamespaceAdmin,'observe',return_value=binding):
            channel=m.DiscoveryGatewayRuntime.transport(owner)
            self.assertIs(type(channel),m.DiscoveryGatewayReadOnlyAdmin);channel.check()
            with self.assertRaisesRegex(ValueError,'GATEWAY_ROUTE_WRITES_REQUIRE_SEPARATE'):
                channel.request('PUT','/apisix/admin/routes/fixture',{})
            auth.write(Path(owner.parent.binding['path']),b'REVOKED_TRANSPORT_PARENT')
            with self.assertRaisesRegex(ValueError,'DISCOVERY_PARENT_HUMAN_DECISION_CHANGED'):channel.check()
        self.assertEqual(len(native.calls),7)


if __name__=='__main__':unittest.main()
