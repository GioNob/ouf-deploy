"""Real parent/child signatures, archives and journals; Docker/health leaves modeled."""
import copy,hashlib,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_transaction_profiles'),str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_cohort_images as image_fixture
from test_chatbot_cohort_plan import fixture as old_container
from test_chatbot_cohort_containers import DockerFixture
from tools.m2_discovery_installation_profile import mcp_runtime as m
from tools.m2_discovery_installation_profile.gate_peer_window import GatePeerWindow
from cutover_authority import CutoverAuthority
from transition_journal import Transition


class Mcp(unittest.TestCase):
    def fixture(self,*,historical=False,construct=True,import_images=False):
        case=image_fixture.Images();images,auth,native_images,calls,cli,_=case.fixture();self.addCleanup(case.doCleanups)
        selected=images.plan['images'][1];audit=selected['audit'];old,_,_=old_container('mcp')
        package={'schema':'ouf.unsigned-offline-candidate-package.v1','module':'mcp','runtimeUser':'10005:10005',
            'imageId':audit['imageId'],'sourceCommit':audit['sourceCommit'],
            'artifactFormat':'DOCKER_SAVE_OFFLINE_ARCHIVE_NOT_HOST_OCI_DECLARATION',
            'imageScanGate':'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED',
            'notReleaseAcceptance':True,'signatureIssued':False,'targetApplyAuthorized':False,'vpsOperations':0}
        selected['modulePackageHash']=m.digest(package)
        images.scope=image_fixture.m.image_scope(images.plan)
        images.component=auth.review['components']['cohortInstallation'];images.component['images']=images.scope
        plan=m.compile_plan(old=old,selected_image=selected,package=package,cohort_id='discovery-test',environment_delta={},
            registry_request_hash=images.window.request_hash,cohort_manifest_hash=images.plan['cohortManifestHash'])
        # Only the selected MCP generation is stopped by this explicit fixture.
        old['HostConfig']['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
        old['State'].update(Running=False,Pid=0,Status='exited');old['RestartCount']=0
        native=DockerFixture(auth.root,{old['Id']:old},{'replacements':[plan['replacement']]});self.addCleanup(native.close)
        window=images.window;image_request=window.engine.request
        def request(method,path,body=None):
            if path=='/v1.44/info' or path.startswith('/v1.44/images/'):return image_request(method,path,body)
            return native.engine.request(method,path,body)
        window.engine.request=request;window.engine.check_socket=native.engine.check_socket;window.engine.path=native.engine.path
        directories=[]
        for name in ('mcp-installation','mcp-readiness'):
            path=auth.root/name;path.mkdir(mode=0o700);directories.append(path)
        scope=m.component(plan,*directories);auth.review['components']['cohortInstallation']['mcp']=scope
        value=m.decode(window.raw);value['discoveryMcpInstallation']=scope
        if historical:value['applicationRegistryCutover']={'postGrantRecovery':{'retainedMcp':'historical'}}
        raw=m.encoded(value);human=m.decode(Path(window.child.binding['path']).read_bytes())
        human['executionAuthorityHash']=hashlib.sha256(raw).hexdigest();auth.write(Path(window.child.binding['path']),m.encoded(human))
        binding=auth.binding(Path(window.child.binding['path']))
        child=CutoverAuthority(auth.verifier,binding,binding['sha256'],auth.context,window.child.expected,lambda:auth.now)
        auth.review['components']['registryCutover']={'schema':'ouf.discovery-registry-child-scope.v1',
            'authorityHash':hashlib.sha256(raw).hexdigest(),'humanManifestHash':binding['sha256'],**child.expected}
        for role in ('DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'):auth.sign(raw,role)
        parent=auth.fixture()
        transition_root=auth.root/'current-child-transition';transition_root.mkdir(mode=0o700)
        transition_journal=m.Journal(transition_root)
        initial=Transition.initial(hashlib.sha256(raw).hexdigest(),window.request_hash,parent.scope['predecessorHistoryHash'],'5'*64)
        transition_journal.initialize(initial);transition=Transition(transition_journal,initial['contextHash'])
        window=GatePeerWindow(parent=parent,child=child,child_raw=raw,engine=window.engine,
            transition=transition,request=window.request,profile=window.profile,store=window.store,directory=window.root)
        images=image_fixture.m.DiscoveryImages(window=window,plan=images.plan,journals=images.journals,docker_binding=images.docker)
        images.initialize()
        if import_images:
            with patch.object(image_fixture.m,'subprocess',type('Cli',(),{'run':staticmethod(cli),'DEVNULL':-3})):images.apply()
        else:
            # Independently qualified image owner may reuse already present,
            # exact images: this fixture models those Engine image observations.
            for row in images.plan['images']:
                a=row['audit'];identity=m.runtime_image_id(a)
                native_images[identity]={'Id':identity,'Os':'linux','Architecture':'amd64','Config':copy.deepcopy(a['imageConfig']),
                    'RootFS':{'Type':'layers','Layers':[v['diffId'] for v in a['layers']]}}
            images.apply()
        # Native transition leaves are modeled here; advance its real typed
        # journal with explicit synthetic evidence up to the held release barrier.
        transition=window.transition
        with transition.invocation():
            while transition.read()['nextPhase']<m.PHASES.index('RELEASE_PRODUCERS'):
                row=transition.read();phase=m.PHASES[row['nextPhase']]
                intent=value['phaseIntentHashes'][phase]
                begun=transition.begin(phase,intent,hashlib.sha256(raw).hexdigest(),row['version'])
                transition.reconcile(phase,intent,'APPLIED','2'*64,begun['version'])
        clock=[500.0]
        arguments={'images':images,'plan':plan,'journal':m.Journal(directories[0]),
            'readiness_journal':m.Journal(directories[1]),'monotonic':lambda:clock[0],'boot':'synthetic-boot'}
        if not construct:return arguments,native,auth,clock
        owner=m.DiscoveryMcpRuntime(**arguments);owner.initialize()
        owner.health=lambda row,actual,deadline:{'httpStatus':204,'responseBytes':0}
        return owner,native,auth,clock

    def test_only_mcp_replaced_once_with_preserved_config_and_current_parent_child(self):
        owner,native,_,_=self.fixture(import_images=True);result=owner.apply();history=owner.record();readiness=owner.readiness_journal.read()
        self.assertEqual(owner.apply(),result);self.assertEqual(owner.record(),history)
        self.assertEqual(owner.readiness_journal.read(),readiness)
        self.assertEqual([v[0] for v in native.calls],['rename','create','start','update'])
        self.assertEqual(len(owner.rows),1);self.assertTrue(result['replacementVerified']);self.assertFalse(result['fullCohortProven'])
        actual=native.find('ouf-mcp');self.assertEqual(actual['Mounts'],owner.row['oldMounts'])
        self.assertEqual(actual['Config']['Env'],owner.row['creationRequest']['Env'])
        self.assertIs(owner.action.authority,owner.window.child)

    def test_lost_create_or_start_reply_read_reconciles_without_redispatch(self):
        for stage in ('create','start'):
            owner,native,_,_=self.fixture();native.lose_ack=stage
            with self.assertRaises(Exception):owner.apply()
            self.assertEqual(owner.record()['effects'][-1]['state'],'CLAIMED')
            self.assertTrue(owner.apply()['replacementVerified'])
            self.assertEqual(sum(c[0]==stage for c in native.calls),1)

    def test_unknown_creation_blocks_dependents_and_never_retries(self):
        owner,native,_,_=self.fixture();native.omit_effect='create'
        for _ in range(2):
            with self.assertRaises(Exception):owner.apply()
        self.assertEqual([c[0] for c in native.calls],['rename','create'])
        self.assertEqual(owner.record()['effects'][-1]['state'],'CLAIMED')

    def test_transient_health_wait_retains_budget_after_reconstruction(self):
        owner,native,auth,clock=self.fixture()
        def unavailable(*args):raise m.Temporary('SERVICE_UNAVAILABLE',retry_after=25)
        owner.health=unavailable
        with self.assertRaises(m.CohortPaused):owner.apply()
        before=owner.readiness_journal.read();self.assertEqual((before['state'],before['attempts']),('RETRY_WAIT',1))
        self.assertGreaterEqual(before['nextWall']-auth.now,25)
        other=m.DiscoveryMcpRuntime(images=owner.images,plan=owner.plan,journal=owner.journal,
            readiness_journal=owner.readiness_journal,monotonic=lambda:clock[0],boot='synthetic-boot')
        other.health=lambda *args:self.fail('health must not run before persisted wait')
        with self.assertRaises(m.CohortPaused):other.apply()
        self.assertEqual(other.readiness_journal.read(),before)
        delta=max(before['nextWall']-auth.now,before['nextMonotonic']-clock[0]);auth.now+=delta;clock[0]+=delta
        other.health=lambda *args:{'httpStatus':204,'responseBytes':0}
        self.assertTrue(other.apply()['replacementVerified']);self.assertEqual(other.readiness_journal.read()['attempts'],2)
        self.assertEqual(sum(c[0]=='start' for c in native.calls),1)

    def test_revoked_parent_or_child_blocks_before_native_writes(self):
        for which in ('parent','child'):
            owner,native,auth,_=self.fixture();binding=owner.parent.binding if which=='parent' else owner.window.child.binding
            auth.write(Path(binding['path']),b'REVOKED_MCP_INSTALLATION')
            with self.assertRaises(Exception):owner.apply()
            self.assertFalse(native.calls)

    def test_new_boot_or_monotonic_deadline_cannot_rearm_readiness(self):
        for kind in ('boot','deadline'):
            owner,native,_,clock=self.fixture()
            if kind=='boot':owner.boot='another-boot'
            else:clock[0]=owner.record()['deadlineMonotonic']+1
            with self.assertRaisesRegex(ValueError,'MCP_HISTORY_BOOT_OR_ORIGINAL_DEADLINE_DRIFT'):owner.apply()
            self.assertFalse(native.calls)

    def test_unreviewed_journal_and_historical_adoption_each_rejected(self):
        owner,native,auth,_=self.fixture();path=auth.root/'unreviewed-mcp';path.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'EXACT_PARENT_MCP_PLAN_AND_JOURNALS_REQUIRED'):
            m.DiscoveryMcpRuntime(images=owner.images,plan=owner.plan,journal=m.Journal(path),
                readiness_journal=owner.readiness_journal,boot='synthetic-boot')
        args,native,_,_=self.fixture(historical=True,construct=False)
        with self.assertRaisesRegex(ValueError,'CURRENT_CHILD_MCP_SCOPE_WITHOUT_HISTORICAL_ADOPTION_REQUIRED'):
            m.DiscoveryMcpRuntime(**args)
        self.assertFalse(args['journal'].record.exists());self.assertFalse(native.calls)

    def test_stale_completed_process_generation_denied(self):
        owner,native,_,_=self.fixture();owner.apply();native.find('ouf-mcp')['State']['Pid']+=1
        with self.assertRaisesRegex(ValueError,'COHORT_STARTED_GENERATION_CHANGED'):owner.apply()
        self.assertEqual(len(native.calls),4)

    def test_unknown_health_failure_blocks_instead_of_auto_retry(self):
        owner,native,_,_=self.fixture()
        def invalid(*args):raise ValueError('UNCLASSIFIED_FIXTURE_FAILURE')
        owner.health=invalid
        for _ in range(2):
            with self.assertRaises(m.CohortPaused):owner.apply()
        self.assertEqual((owner.readiness_journal.read()['state'],owner.readiness_journal.read()['attempts']),('BLOCKED',1))
        self.assertEqual(sum(c[0]=='start' for c in native.calls),1)

    def test_registry_history_must_match_this_exact_signed_child(self):
        owner,native,auth,_=self.fixture();row=owner.window.transition.journal.read()
        row['effects'][-1]['intentHash']='f'*64
        auth.write(owner.window.transition.journal.record,m.encoded(row))
        with self.assertRaisesRegex(ValueError,'VERIFIED_REGISTRY_AND_HELD_PRODUCERS_REQUIRED'):owner.apply()
        self.assertFalse(native.calls)

    def test_regressed_mutable_stage_does_not_bypass_exclusive_dispatch(self):
        owner,native,auth,_=self.fixture();native.omit_effect='create'
        with self.assertRaises(Exception):owner.apply()
        row=owner.record();row['effects'].pop();row['version']-=1
        auth.write(owner.journal.record,m.encoded(row))
        with self.assertRaises(FileExistsError):owner.apply()
        self.assertEqual([c[0] for c in native.calls],['rename','create'])

    def test_exhausted_readiness_remains_paused_without_extra_health_or_lifecycle(self):
        owner,native,_,_=self.fixture()
        def unavailable(*args):raise m.Temporary('SERVICE_UNAVAILABLE')
        owner.health=unavailable
        with self.assertRaises(m.CohortPaused):owner.apply()
        before=owner.readiness_journal.read();exhausted={**before,'attempts':128}
        owner.readiness_journal.compare_and_save(before,exhausted)
        owner.health=lambda *args:self.fail('exhausted budget must not run health')
        for _ in range(2):
            with self.assertRaises(m.CohortPaused):owner.apply()
        self.assertEqual((owner.readiness_journal.read()['state'],owner.readiness_journal.read()['attempts']),('PAUSED_EXHAUSTED',128))
        self.assertEqual([c[0] for c in native.calls],['rename','create','start'])


class HealthContract(unittest.TestCase):
    def test_only_empty_204_is_ready_transient_status_honors_retry_after(self):
        from types import SimpleNamespace
        owner=object.__new__(m.DiscoveryMcpRuntime);owner.monotonic=lambda:100;owner.clock=lambda:1000
        actual={'NetworkSettings':{'Networks':{'ouf-backend':{'IPAddress':'172.20.0.9'}}}}
        for status,raw,expected in ((204,b'',None),(200,b'{}',ValueError),(204,b'body',ValueError),
                (500,b'',ValueError),(503,b'',m.Temporary),(429,b'',m.Temporary)):
            response=SimpleNamespace(status=status,read=lambda maximum,body=raw:body,getheader=lambda *args:'25')
            client=SimpleNamespace(request=lambda *a,**kw:None,getresponse=lambda:response,close=lambda:None)
            with patch.object(m.http.client,'HTTPConnection',return_value=client):
                if expected:
                    with self.assertRaises(expected) as error:owner.health({'readinessPath':'/health/ready'},actual,115)
                    if expected is m.Temporary:self.assertEqual(error.exception.retry_after,25)
                else:self.assertEqual(owner.health({'readinessPath':'/health/ready'},actual,115),{'httpStatus':204,'responseBytes':0})


if __name__=='__main__':unittest.main()
