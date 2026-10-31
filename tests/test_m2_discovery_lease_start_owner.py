"""Real finite parent/child signatures and journals; native leaves synthetic.

These protocol tests neither install a worker nor prove actual manager/provider
or node admission. Native worker observation is qualified by a separate fixture.
"""
import copy,os,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_parent_authority as signed
import test_m2_discovery_lease_installation_template as templates
from tools.m2_discovery_installation_profile import lease_start_owner as m


class ObservationPublication(unittest.TestCase):
    def fixture(self):
        from tools.m2_discovery_installation_profile.lease_service import existing_kernel_lock
        t=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(t.cleanup)
        root=Path(t.name);root.chmod(0o700);path=root/'kernel.lock';path.write_bytes(b'');path.chmod(0o600)
        s=path.stat();identity=[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink]
        lock=lambda:existing_kernel_lock(path,identity)
        row={'state':'LEASE_READY','leaseAuthorized':True,'leaseAddresses':[['1.1.1.1']]}
        sets={('inet',0):{'1.1.1.1':10},('bridge',0):{'1.1.1.1':10}}
        backend=types.SimpleNamespace(verify_ownership=lambda _:None,read_sets=lambda _:copy.deepcopy(sets))
        c=types.SimpleNamespace(configuration={'providerFlows':[{}]},owner=types.SimpleNamespace(backend=backend),
            journal=lambda:copy.deepcopy(row),hold_lock=lock)
        return c,path,identity,lock,row,sets

    def test_observer_does_not_deny_concurrent_native_writer_lock(self):
        c,path,identity,lock,row,sets=self.fixture();calls=[]
        def concurrent_writer(_):
            with lock():calls.append('writer-lock-acquired')
            return copy.deepcopy(sets)
        c.owner.backend.read_sets=concurrent_writer
        m.lease_observation.publication_snapshot(c,path,identity)
        self.assertEqual(calls,['writer-lock-acquired']);self.assertEqual(row['state'],'LEASE_READY')

    def test_reader_does_not_compete_with_already_running_writer(self):
        c,path,identity,lock,row,sets=self.fixture()
        with lock():m.lease_observation.publication_snapshot(c,path,identity)
        self.assertEqual(row['state'],'LEASE_READY')

    def test_unproven_publication_membership_or_lock_inode_never_passes(self):
        for case in ('pending','receipt_drift','family','empty','foreign','lock_replaced'):
            with self.subTest(case=case):
                c,path,identity,lock,row,sets=self.fixture()
                if case=='pending':row['state']='LEASE_UPDATING';row['leaseAuthorized']=False
                elif case=='family':sets[('bridge',0)]={'8.8.8.8':10}
                elif case=='empty':sets[('bridge',0)]={}
                elif case=='foreign':row['leaseAddresses']=[['8.8.8.8']]
                elif case=='lock_replaced':
                    q=path.with_name('new');q.write_bytes(b'');q.chmod(0o600);q.replace(path)
                else:
                    def change(_):row['leaseAuthorized']=False;return copy.deepcopy(sets)
                    c.owner.backend.read_sets=change
                with self.assertRaises((ValueError,RuntimeError)):
                    m.lease_observation.publication_snapshot(c,path,identity)

    def test_original_exclusive_observer_forces_actual_recovery_safe_pause_denial(self):
        from bounded_recovery import Recovery,Policy
        c,path,identity,lock,row,sets=self.fixture();records=[]
        def pause():
            with lock():records.append('revoked')
        journal=types.SimpleNamespace(compare_and_save=lambda before,after:records.append(copy.deepcopy(after)))
        recovery=Recovery(journal,types.SimpleNamespace(pause=pause),Policy(),'a'*64,'b'*64,lambda:(10,10),lambda:.5)
        initial=recovery.initial()
        with lock():blocked=recovery.pause(initial,'BLOCKED','AUTHORITY_REVOKED')
        self.assertEqual(blocked['state'],'BLOCKED');self.assertEqual(blocked['reason'],'SAFE_PAUSE_UNPROVEN')
        self.assertEqual(blocked['attempts'],initial['attempts']);self.assertNotIn('revoked',records)
        allowed=recovery.pause(initial,'BLOCKED','AUTHORITY_REVOKED')
        self.assertEqual(allowed['reason'],'AUTHORITY_REVOKED');self.assertIn('revoked',records)


class Start(unittest.TestCase):
    def fixture(self):
        auth=signed.Parent();auth.setUp();self.addCleanup(auth.doCleanups)
        c,r,s,p,options=templates.Template().fixture();auth.review['sourceClosureHash']=options['source_closure_hash']
        auth.review['desiredProfileHash']=c['desiredProfileHash']
        c['verification']['context']={k:auth.context[k] for k in ('installationRef','entityRef','attestorRef')}
        recipe={'schema':'synthetic-independent-node-recipe.v1','imageConfigurationHash':'c'*64,
            'expectedRootfsSeal':{'synthetic':'independent-ci-rootfs'}}
        profile=s['profiles']['registry'];profile.update(nodeRecipeHash=m.digest(recipe),
            imageConfigurationHash=recipe['imageConfigurationHash'],rootfsSealHash=m.digest(recipe['expectedRootfsSeal']))
        options['expected_node_profiles']['registry']={k:profile[k] for k in templates.m.INDEPENDENT_FIELDS}
        actual={'Id':s['peers']['registry']['containerId'],'Image':s['peers']['registry']['imageId'],
            'Config':{'synthetic':True},'HostConfig':{'synthetic':True},'Mounts':[],'NetworkSettings':{},
            'State':{'Pid':s['peers']['registry']['pid'],'StartedAt':s['peers']['registry']['startedAt']}}
        s['peers']['registry']['dockerBindingHash']=m.digest({k:actual[k] for k in m.DOCKER_FIELDS})
        s['nativeProfileHash']=m.digest(s['profiles']);s['generationRef']=templates.m.generation_reference(s)
        template=templates.m.template(c,r,p,**options);proposal=templates.m.materialize(template,s,[1,4,0,0,0o100600,1])
        directory=auth.root/'start';directory.mkdir(mode=0o700)
        evidence=auth.root/'evidence';evidence.mkdir(mode=0o700);store=m.NativeEvidenceStore(evidence)
        manager={'path':'/usr/bin/systemctl','sha256':'e'*64,'maximumBytes':67108864}
        scope=m.start_scope(template,unit_name='ouf-discovery-ci.service',manager=manager,directory=str(directory))
        request={'synthetic':'source-sealed-creation-request'};intent={'creationRequestHash':m.digest(request),
            'nodeRecipeHash':m.digest(recipe),'leaseInstallationScopeHash':m.digest(scope),
            'priorEvidencePhase':'INSTALL_AUTHENTICATED_TRANSPORT'}
        hashes={phase:m.digest(request) if phase=='CREATE_REPLACEMENT' else m.digest(intent) if phase==m.PHASE
            else '4'*64 for phase in m.PHASES}
        child,raw=auth.child(creation_request_hash=m.digest(request),phase_intent_hashes=hashes)
        auth.review['components']['operationalLeaseInstallation']=scope;parent=auth.fixture()
        transition=object.__new__(m.Transition);transition.execution_profile=None;transition.profile_hash=None;transition.context='b'*64
        ah=m.hashlib.sha256(raw).hexdigest()
        row={'state':'IN_FLIGHT','nextPhase':8,'creationRequestHash':m.digest(request),'transitionAuthorityEvidenceHash':ah,
            'effects':[{'phase':phase,'state':'APPLIED' if i<8 else 'IN_FLIGHT','intentHash':hashes[phase],
                'authorityEvidenceHash':ah,'nativeEvidenceHash':'9'*64} for i,phase in enumerate(m.PHASES[:9])]}
        transition.read=lambda:copy.deepcopy(row)
        node=object.__new__(m.DiscoveryNodeOwner);node.transition=transition;node.store=store;node.authority=child
        node.raw=raw;node.request=request;node.recipe=recipe;node.engine=types.SimpleNamespace(inspect=lambda t:copy.deepcopy(actual))
        node.adapter=types.SimpleNamespace(request={'applicationHash':profile['applicationHash']})
        reads=[];node.verify_retained=lambda:(reads.append('current-native-node') or {'synthetic-node-proof':True})
        owner=m.LeaseStartAdapter(parent=parent,authority=child,authority_raw=raw,transition=transition,
            store=store,node_owner=node,template=template,proposal=proposal,scope=scope,intent=intent)
        owner.installed=lambda **kw:reads.append(('installed',kw['before_start']))
        owner.inactive=lambda:reads.append('inactive')
        calls=[];owner.manager=lambda args:calls.append(args)
        observation={'schema':'ouf.discovery-installed-lease-observation.v1',
            'configurationHash':m.digest(proposal['configuration']),'scopeHash':m.digest(proposal['recipe']['scope']),
            'generationRef':s['generationRef'],'managerProcessId':12345,'managerProcessRunning':True,
            'workerCheckpointActive':True,'bothOwnedLeaseFamiliesPositive':True,'recoveryAttempts':1,'publications':1,
            'runtimeAuthorityIssued':False,'applicationReady':False,'containerStartAuthorized':False,'releaseAcceptance':False}
        return owner,auth,intent,row,calls,reads,observation

    def test_one_start_and_independent_observation_do_not_grant_application_start(self):
        owner,auth,intent,row,calls,reads,observation=self.fixture();owner.apply(intent)
        self.assertEqual(calls,[['start','--no-block','ouf-discovery-ci.service']])
        with patch.object(m.lease_observation,'observe',return_value=observation):outcome,evidence=owner.observe(intent)
        self.assertEqual(outcome,'APPLIED');self.assertFalse(evidence['applicationStartAuthorized'])
        self.assertFalse(evidence['runtimeAuthorityIssued']);self.assertEqual(row['nextPhase'],8)
        self.assertGreaterEqual(reads.count('current-native-node'),3)
        with self.assertRaises(FileExistsError):owner.apply(intent)
        self.assertEqual(len(calls),1)

    def test_ambiguous_start_response_is_only_reconciled_without_resending(self):
        owner,auth,intent,row,calls,reads,observation=self.fixture()
        def ambiguous(args):calls.append(args);raise TimeoutError('SYNTHETIC_LOST_START_RESPONSE')
        owner.manager=ambiguous
        with self.assertRaises(TimeoutError):owner.apply(intent)
        with patch.object(m.lease_observation,'observe',return_value=observation):self.assertEqual(owner.observe(intent)[0],'APPLIED')
        self.assertEqual(len(calls),1)

    def test_failed_worker_read_does_not_issue_another_manager_command(self):
        owner,auth,intent,row,calls,reads,observation=self.fixture();owner.apply(intent)
        before=owner.journal.record.read_bytes()
        with patch.object(m.lease_observation,'observe',side_effect=ValueError('NATIVE_LEASE_NOT_READY')):
            outcome,evidence=owner.observe(intent)
        self.assertEqual(outcome,'UNKNOWN');self.assertFalse(evidence['startReplayAllowed'])
        self.assertEqual(evidence['workerObservationFailure'],{
            'schema':'ouf.discovery-worker-observation-failure.v1','kind':'READ_DENIED',
            'reasonCode':'DISCOVERY_WORKER_OBSERVATION_UNPROVEN'})
        self.assertEqual(len(calls),1);self.assertFalse(owner.store.path(m.PHASE).exists())
        self.assertEqual(owner.journal.record.read_bytes(),before)

    def test_known_observation_denial_is_retained_without_a_new_start_or_positive_evidence(self):
        owner,auth,intent,row,calls,reads,observation=self.fixture();owner.apply(intent)
        before=owner.journal.record.read_bytes()
        code='DISCOVERY_WORKER_CHANGED_DURING_OBSERVATION'
        with patch.object(m.lease_observation,'observe',side_effect=ValueError(code)) as reader:
            outcome,evidence=owner.observe(intent)
        self.assertEqual(outcome,'UNKNOWN');self.assertEqual(reader.call_count,1)
        self.assertEqual(evidence['workerObservationFailure']['reasonCode'],code)
        self.assertFalse(evidence['startReplayAllowed']);self.assertEqual(len(calls),1)
        self.assertEqual(owner.journal.record.read_bytes(),before)
        self.assertFalse(owner.store.path(m.PHASE).exists())

    def test_unknown_process_io_and_custom_exception_values_never_leave_the_reader(self):
        class PrivateError(ValueError):
            def __str__(self):raise AssertionError('exception text must not be formatted')
        cases=(
            (ValueError('SYNTHETIC_SECRET_VALUE'),'READ_DENIED'),
            (ValueError('/private/fixture/key=value'),'READ_DENIED'),
            (PrivateError('SYNTHETIC_SECRET_VALUE'),'READ_DENIED'),
            (BlockingIOError(11,'SYNTHETIC_SECRET_VALUE','/private/fixture'),'READ_CONTENTION'),
            (FileNotFoundError(2,'SYNTHETIC_SECRET_VALUE','/private/fixture'),'IO_READ_UNPROVEN'),
            (subprocess.TimeoutExpired(['/private/fixture','key=value'],1,output=b'SYNTHETIC_SECRET_VALUE'),
                'PROCESS_READ_UNPROVEN'),
            (subprocess.CalledProcessError(1,['/private/fixture'],stderr=b'SYNTHETIC_SECRET_VALUE'),
                'PROCESS_READ_UNPROVEN'),
        )
        for error,kind in cases:
            with self.subTest(kind=kind):
                self.assertEqual(m.lease_observation.failure(error),{
                    'schema':'ouf.discovery-worker-observation-failure.v1','kind':kind,
                    'reasonCode':'DISCOVERY_WORKER_OBSERVATION_UNPROVEN'})

    def test_crash_before_dispatch_is_consumed_no_effect_and_never_replayed(self):
        owner,auth,intent,row,calls,reads,observation=self.fixture();owner.journal.initialize(owner.claim())
        self.assertEqual(owner.observe(intent)[0],'NO_EFFECT')
        with self.assertRaises(FileExistsError):owner.apply(intent)
        self.assertEqual(calls,[])

    def test_exact_phase_parent_signatures_and_native_node_are_required_before_dispatch(self):
        for case in ('phase','signature','node'):
            owner,auth,intent,row,calls,reads,observation=self.fixture()
            if case=='phase':row['effects'][-1]['intentHash']='f'*64
            elif case=='signature':(auth.signatures/(owner.parent.sha+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
            else:owner.node_owner.recipe['expectedRootfsSeal']={'unreviewed':True}
            with self.assertRaises((ValueError,FileNotFoundError)):owner.apply(intent)
            self.assertEqual(calls,[])

    def test_private_preinstalled_custody_is_checked_before_effect(self):
        owner,auth,intent,row,calls,reads,observation=self.fixture()
        def denied(**kw):raise ValueError('PREINSTALLED_RECEIPT_REVOKED')
        owner.installed=denied
        with self.assertRaisesRegex(ValueError,'REVOKED'):owner.apply(intent)
        self.assertEqual(calls,[]);self.assertFalse(owner.journal.record.exists())

    def test_reconciliation_keeps_first_receipt_and_requires_nondecreasing_accounting(self):
        owner,auth,intent,row,calls,reads,observation=self.fixture();owner.apply(intent)
        with patch.object(m.lease_observation,'observe',return_value=observation):first=owner.observe(intent)[1]
        observation['publications']=2
        with patch.object(m.lease_observation,'observe',return_value=observation):self.assertEqual(owner.observe(intent)[1],first)
        observation['recoveryAttempts']=0
        with patch.object(m.lease_observation,'observe',return_value=observation),self.assertRaisesRegex(ValueError,'ACCOUNTING_DRIFT'):
            owner.observe(intent)
        self.assertEqual(len(calls),1)

if __name__=='__main__':unittest.main()
