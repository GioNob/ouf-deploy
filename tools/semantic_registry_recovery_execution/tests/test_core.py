import copy,fcntl,importlib.util,json,os,tempfile,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=module('recovery_core',ROOT/'core.py')
proposal_module=module('recovery_proposal_contract',ROOT.parent/'semantic_registry_recovery_composition/compose.py')

class FixturePorts(m.Ports):
    """Isolated simulation only; never a production native gate implementation."""
    def __init__(self):
        self.calls=[];self.denied=False;self.crash=None;self.unknown=set();self.drift=False;self.start_evidence=True;self.http=200
        self.new={'containerId':'a'*64,'bootId':'11111111-2222-3333-4444-555555555555',
                  'pid':4242,'startTicks':12345,'namespaceDevice':4,'namespaceInode':12}
    def guard(self,plan,row,stage):
        if self.denied:raise m.RecoveryDenied('FIXTURE_AUTHORITY_REVOKED')
    def apply(self,plan,row,stage):
        self.calls.append(stage['name'])
        if self.crash==stage['name']:raise OSError('fixture crash after effect')
    def observe(self,plan,row,stage):
        name=stage['name']
        if name in self.unknown:return 'UNKNOWN',{}
        proof={'newGeneration':copy.deepcopy(self.new),'durableNativeStartEvidence':self.start_evidence}
        if self.drift:proof['newGeneration']['namespaceInode']+=1
        if name=='VERIFY_FINAL':proof.update(originalSemanticGetSucceeded=self.http==200,httpStatus=self.http)
        return 'APPLIED',proof


class Tests(unittest.TestCase):
    def setUp(self):
        proposal={'registry':{'containerId':'a'*64},'requiredGates':list(proposal_module.GATES),'unresolvedGateCount':8}
        self.plan=proposal_module.candidate_contract(proposal,'b'*64,'c'*64)
        self.temp=tempfile.TemporaryDirectory(dir=Path.cwd());self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/('semantic-registry-recovery-'+self.plan['logicalOperationRef']);self.root.mkdir(mode=0o700)
        self.store=m.Store(self.root,self.plan['logicalOperationRef']);self.ports=FixturePorts()
        self.times=[100,50]
        initial=m.initial(self.plan,authority_hash='d'*64,expires_unix=900,expires_monotonic=850,
            boot_id=self.ports.new['bootId'],predecessor_history_hash='e'*64,created_unix=100,created_monotonic=50)
        self.store.initialize(initial)
        self.runner=m.Runner(self.plan,self.store,self.ports,boot_id=self.ports.new['bootId'],clock=lambda:tuple(self.times))
    def advance(self,count):
        for _ in range(count):self.runner.step()

    def test_all_stages_only_five_distinct_effects_and_original_request_success(self):
        self.advance(12);row=self.store.read()
        self.assertEqual(row['state'],'COMPLETED');self.assertTrue(row['originalSemanticGetSucceeded'])
        self.assertFalse(row['releaseAcceptance']);self.assertFalse(row['budgetReset'])
        self.assertEqual(self.ports.calls,[name for name,kind in m.ORDER if kind=='EFFECT'])
        self.assertEqual(self.runner.step(),row);self.assertEqual(len(self.ports.calls),5)

    def test_each_ambiguous_effect_is_never_transmitted_again(self):
        for index,(name,kind) in enumerate(m.ORDER):
            if kind!='EFFECT':continue
            with self.subTest(stage=name):
                if self.store.read()['nextStage']<index:self.advance(index-self.store.read()['nextStage'])
                self.ports.crash=name
                with self.assertRaises(OSError):self.runner.step()
                self.assertEqual(self.store.read()['effects'][-1]['state'],'CLAIMED')
                self.ports.crash=None;self.runner.step()
                self.assertEqual(self.ports.calls.count(name),1)

    def test_unknown_start_requires_durable_evidence_and_never_adopts_pid(self):
        self.advance(1);self.ports.crash='START_NEW_WAIT_GATE'
        with self.assertRaises(OSError):self.runner.step()
        self.ports.crash=None;self.ports.unknown.add('START_NEW_WAIT_GATE')
        self.runner.step();self.runner.step()
        self.assertIsNone(self.store.read()['newGeneration']);self.assertEqual(len(self.ports.calls),1)
        self.ports.unknown.clear();self.ports.start_evidence=False
        with self.assertRaisesRegex(m.RecoveryDenied,'DURABLE_FRESH_START_EVIDENCE'):self.runner.step()
        self.assertEqual(len(self.ports.calls),1)

    def test_pid_namespace_change_is_not_accepted_as_same_generation(self):
        self.advance(2);self.ports.drift=True
        with self.assertRaisesRegex(m.RecoveryDenied,'SAME_NEW_GENERATION'):self.runner.step()
        self.assertEqual(self.store.read()['nextStage'],2)

    def test_old_generation_cannot_be_inserted_before_new_start(self):
        row=self.store.read();self.store.cas(row,{**row,'version':row['version']+1,'newGeneration':self.ports.new})
        with self.assertRaisesRegex(m.RecoveryDenied,'NO_HISTORICAL_GENERATION_ADOPTION'):self.runner.step()
        self.assertEqual(self.ports.calls,[])

    def test_revocation_before_effect_leaves_claim_consumed_without_dispatch(self):
        self.advance(1)
        original=self.ports.guard;count=[0]
        def revoke(plan,row,stage):
            count[0]+=1
            if count[0]==2:self.ports.denied=True
            original(plan,row,stage)
        self.ports.guard=revoke
        with self.assertRaises(m.RecoveryDenied):self.runner.step()
        self.assertEqual(self.store.read()['effects'][-1]['state'],'CLAIMED')
        self.assertEqual(self.ports.calls,[])
        self.ports.guard=original;self.ports.denied=False;self.ports.unknown.add('START_NEW_WAIT_GATE')
        self.runner.step();self.assertEqual(self.ports.calls,[])

    def test_expiry_boot_change_and_clock_regression_prevent_dispatch(self):
        for times,boot in (([901,51],self.runner.boot_id),([101,851],self.runner.boot_id),
                           ([99,51],self.runner.boot_id),([101,49],self.runner.boot_id),([101,51],'other-boot')):
            self.times[:]=times;self.runner.boot_id=boot
            with self.subTest(times=times,boot=boot),self.assertRaises(m.RecoveryDenied):self.runner.step()
        self.assertEqual(self.ports.calls,[])

    def test_budget_exhaustion_cannot_reset_or_repeat_effect(self):
        self.advance(1);self.ports.unknown.add('START_NEW_WAIT_GATE');self.runner.step()
        row=self.store.read();self.store.cas(row,{**row,'readAttempts':128,'version':row['version']+1})
        with self.assertRaisesRegex(m.RecoveryDenied,'RECOVERY_READ_BUDGET_EXHAUSTED'):self.runner.step()
        self.assertEqual(len(self.ports.calls),1)
        with self.assertRaisesRegex(m.RecoveryDenied,'EXISTING_RECOVERY_CLAIMS'):
            self.store.initialize({**self.store.read(),'version':0})

    def test_no_new_effect_is_dispatched_after_observation_budget_exhaustion(self):
        self.advance(1);row=self.store.read()
        self.store.cas(row,{**row,'readAttempts':128,'version':row['version']+1})
        with self.assertRaisesRegex(m.RecoveryDenied,'RECOVERY_READ_BUDGET_EXHAUSTED'):self.runner.step()
        self.assertEqual(self.ports.calls,[])
        self.assertEqual(len(self.store.read()['effects']),1)

    def test_concurrent_invocation_and_stale_cas_are_rejected(self):
        old=self.store.read()
        with self.store.lock('invocation.lock'):
            with self.assertRaisesRegex(m.RecoveryDenied,'CONCURRENT_RECOVERY_COMMAND'):self.runner.step()
        self.runner.step()
        with self.assertRaisesRegex(m.RecoveryDenied,'STALE_RECOVERY_WORKER'):
            self.store.cas(old,{**old,'version':old['version']+1})

    def test_journal_symlink_and_replaced_scope_directory_rejected(self):
        file=self.root/'recovery.json';file.rename(self.root/'saved.json');file.symlink_to(self.root/'saved.json')
        with self.assertRaises(OSError):self.store.read()
        file.unlink();(self.root/'saved.json').rename(file)
        self.root.rename(self.root.with_name(self.root.name+'-retained'));self.root.mkdir(mode=0o700)
        with self.assertRaisesRegex(m.RecoveryDenied,'RECOVERY_DIRECTORY_CHANGED'):self.store.read()

    def test_changed_stages_or_plan_authority_flags_rejected(self):
        for key in ('newRuntimeBudgetGranted','runtimeAuthorityIssued','automaticReplayAllowed','effectRetryAllowed'):
            plan=copy.deepcopy(self.plan);plan[key]=True
            with self.subTest(key=key),self.assertRaises(m.RecoveryDenied):m.validate_plan(plan)
        plan=copy.deepcopy(self.plan);plan['stages'][7],plan['stages'][9]=plan['stages'][9],plan['stages'][7]
        with self.assertRaises(m.RecoveryDenied):m.validate_plan(plan)

    def test_http_502_cannot_complete_recovery(self):
        self.advance(11);self.ports.http=502
        with self.assertRaisesRegex(m.RecoveryDenied,'ORIGINAL_SEMANTIC_GET_MUST_BE_VERIFIED'):self.runner.step()
        self.assertFalse(self.store.read()['originalSemanticGetSucceeded']);self.assertEqual(self.store.read()['nextStage'],11)

    def test_applied_evidence_cannot_be_changed_silently(self):
        self.advance(2);row=self.store.read();row['effects'][1]['nativeEvidence']['newGeneration']['pid']+=1
        before=self.store.read();row['version']=before['version']+1;self.store.cas(before,row)
        with self.assertRaisesRegex(m.RecoveryDenied,'RECOVERY_NATIVE_EVIDENCE_CHANGED'):self.runner.step()

    def test_proposed_window_is_finite_and_creates_no_runtime_authority(self):
        for end in (100,1001,float('inf'),float('nan')):
            with self.subTest(end=end),self.assertRaises(m.RecoveryDenied):
                m.initial(self.plan,authority_hash='d'*64,expires_unix=end,expires_monotonic=850,
                    boot_id=self.ports.new['bootId'],predecessor_history_hash='e'*64,created_unix=100,created_monotonic=50)
        with self.assertRaises(TypeError):m.Ports()


if __name__=='__main__':unittest.main()
