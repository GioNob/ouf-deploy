"""Composition boundaries with synthetic native/authority fixtures, not target proof."""
import copy,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
from r12_retirement_adapter import R12RetirementAdapter,R12RetirementChannel,history_progress,encoded
from native_evidence_store import NativeEvidenceStore
from executor_composition_fixture import compose
from cutover_executor import CutoverDenied
from transition_journal import digest,Transition


def history(state='ACTIVE'):
    return {'schema':'ouf.bounded-recovery.v1','contextRef':'a'*64,'generationRef':'b'*64,'policyHash':'c'*64,
            'timeAccountingProfile':'ouf.lease-cumulative-recovery-time.v1','state':state,'attempts':24,'publicationCount':4330,
            'startedWall':100,'startedMonotonic':100,'lastWall':300,'lastMonotonic':300,
            'healthyWallSeconds':100,'healthyMonotonicSeconds':100,'nextWall':None,'nextMonotonic':None,'reason':'RENEWED'}

class Retirement(unittest.TestCase):
    def fixture(self,state='ACTIVE'):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);root.chmod(0o700)
        before=NativeEvidenceStore(root);c=R12RetirementChannel.__new__(R12RetirementChannel)
        c.scope={'authorizationBinding':{'sha256':'9'*64},'workerPid':1234};c.scope_hash=digest(c.scope)
        h=history(state);c.capture={'r12-authorization.json':{'incidentRef':'d'*64}};c.capture_history_hash=digest(h)
        native={'authorizationHash':'9'*64,'history':h,'worker':{'state':state,'workerPid':1234},
                'service':{'ActiveState':'active','SubState':'running','MainPID':'1234'},'lease':{}}
        marks=[];stops=[]
        c.current=lambda:copy.deepcopy(native);c.read=lambda p:Path(p).read_bytes()
        def marker(value,create=False):
            if marks:self.assertEqual(marks[0],value);return True
            if create:marks.append(copy.deepcopy(value));return True
            return False
        c.marker=marker
        def stop(seconds):
            stops.append(seconds);native['service'].update(ActiveState='inactive',SubState='dead',MainPID='0')
            native['history'].update(state='CANCELLED',reason='CANCELLED_BY_OWNER',lastWall=310,lastMonotonic=310)
            native['worker'].update(state='CANCELLED',ready=False,live=False,setsRevoked=True,attempts=24,refreshCount=4330)
            native['lease']={'journalState':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,
                             'providerSetsEmpty':True,'journalAndMembershipConsistent':True,'nativeStructureVerified':True,
                             'flowCount':2,'flows':[{'inetAddressCount':0,'bridgeAddressCount':0} for _ in range(2)]}
        c.stop=stop;intent={'scopeHash':c.scope_hash,'stopTimeoutSeconds':55}
        e,store=compose(self,'STOP_REVOKE_OLD_LEASE',intent,lambda t,s:R12RetirementAdapter(c,t,intent,before,s),predecessor_history=c.capture_history_hash)
        return e,c,native,marks,stops
    def test_cancellation_while_paused_or_exhausted_preserves_history(self):
        for state in ('ACTIVE','RETRY_WAIT','PAUSED_EXHAUSTED','BLOCKED'):
            e,c,native,marks,stops=self.fixture(state);e.run(1);e.run(1)
            self.assertEqual(stops,[55]);self.assertEqual(len(marks),1)
            self.assertEqual(native['history']['attempts'],24);self.assertEqual(native['history']['publicationCount'],4330)
            self.assertFalse(e.t.read()['databaseMayHaveChanged'])
    def test_death_after_stop_reconciles_without_second_stop(self):
        e,c,native,marks,stops=self.fixture();a=e.adapters['STOP_REVOKE_OLD_LEASE'];original=c.stop
        def crash(seconds):original(seconds);raise RuntimeError('fixture-death')
        c.stop=crash
        with self.assertRaises(RuntimeError):e.run(1)
        e.t=Transition(e.t.journal,e.t.context);a.transition=e.t;c.stop=lambda seconds:self.fail('STOP_REPLAYED')
        e.run(1);self.assertEqual(stops,[55])
    def test_marker_stop_gap_remains_ambiguous_without_retransmission(self):
        e,c,native,marks,stops=self.fixture();c.stop=lambda seconds:(_ for _ in ()).throw(RuntimeError('fixture-gap'))
        with self.assertRaises(RuntimeError):e.run(1)
        with self.assertRaises(CutoverDenied):e.run(1)
        self.assertEqual(stops,[]);self.assertEqual(len(marks),1);self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
    def test_misbound_predecessor_blocks_before_effects(self):
        e,c,native,marks,stops=self.fixture();c.capture_history_hash='f'*64
        with self.assertRaisesRegex(ValueError,'PREDECESSOR_HISTORY'):e.run(1)
        self.assertEqual(marks,[]);self.assertEqual(stops,[])
    def test_inactive_service_without_cancelled_history_or_both_empty_families_is_unproven(self):
        for drift in ('live','history','sets','families','refresh'):
            e,c,native,marks,stops=self.fixture();original=c.stop
            def stop(seconds):
                original(seconds)
                if drift=='live':native['worker']['live']=True
                if drift=='history':native['history']['state']='ACTIVE'
                if drift=='sets':native['lease']['providerSetsEmpty']=False
                if drift=='families':native['lease']['flows'][1]['bridgeAddressCount']=1
                if drift=='refresh':native['worker']['refreshCount']=4331
            c.stop=stop
            with self.assertRaises(CutoverDenied):e.run(1)
            with self.assertRaises(CutoverDenied):e.run(1)
            self.assertEqual(stops,[55])
    def test_counter_policy_start_time_and_recovery_cost_reset_are_denied(self):
        for key,value in [('attempts',0),('publicationCount',0),('startedWall',200),('policyHash','f'*64),('healthyWallSeconds',150),('healthyMonotonicSeconds',float('nan'))]:
            old=history();new=copy.deepcopy(old);new[key]=value
            with self.assertRaises(ValueError):history_progress(old,new)
        new=history();new.update(lastWall=400,lastMonotonic=400,healthyWallSeconds=200,healthyMonotonicSeconds=200,publicationCount=4331)
        history_progress(history(),new)

if __name__=='__main__':unittest.main()
