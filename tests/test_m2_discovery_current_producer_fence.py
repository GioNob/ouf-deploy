"""Actual quiescence adapter/store; authority/selected lineage/Engine modeled.

Fixtures prepare quiescence before testing the read-only fence. No target run.
"""
import copy,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_cohort # establish exact production import roots
import test_producer_adapter as fixtures
from tools.m2_discovery_installation_profile import current_producer_fence as m
from application_verification_adapter import ApplicationReadinessChannel
from engine_creation import CreationDenied


class ProducerFence(unittest.TestCase):
    def prepared(self):
        case=fixtures.Producers();self.addCleanup(case.doCleanups)
        executor,engine,states,calls,quiescence=case.fixture(4,restart_policy='unless-stopped');executor.run(2)
        reader,app,row,reads=self.bind(executor,engine,quiescence)
        return reader,app,states,calls,row,reads

    def bind(self,executor,engine,quiescence):
        q=executor.adapters['QUIESCE_PRODUCERS'];request={'explicitModeledRegistryRequest':True}
        ids=[p['containerId'] for p in quiescence['producerBindings']]
        release={'creationRequestHash':m.digest(request),'quiescenceIntentHash':q.intent_hash,
            'retiredContainerIds':ids[:3],'releaseProducerIds':ids[3:],
            'restartPolicies':{ids[3]:{'Name':'no','MaximumRetryCount':0}},'cohortReviewHash':'a'*64}
        readiness=ApplicationReadinessChannel({'databaseContainerId':'b'*64,'databaseUser':'fixture','database':'fixture',
            'databaseOid':1,'flywaySchema':'ouf_sem','flywayHistoryHash':'c'*64,
            'health':{'address':'10.1.2.3','port':8080,'path':'/actuator/health/readiness','timeoutSeconds':1}})
        before=q.store.root.parent/'before';before.mkdir(mode=0o700)
        from native_evidence_store import NativeEvidenceStore
        r=m.ProducerReleaseAdapter(engine,executor.t,request,release,quiescence,q.store,NativeEvidenceStore(before),readiness,Mock())
        app=object.__new__(m.DiscoveryApplication);app.executor=object.__new__(m.DiscoveryExecutor)
        app.executor.adapters={'QUIESCE_PRODUCERS':q,'RELEASE_PRODUCERS':r}
        app.transition=executor.t;app.store=q.store;app.request=request;app.request_hash=m.digest(request)
        app.intents=copy.deepcopy(executor.intents);app.intents.update(RELEASE_PRODUCERS=release,
            RELEASE_OLD_ENDPOINT={'containerId':ids[0]})
        app.intent_hashes={p:m.digest(i) for p,i in app.intents.items()}
        from tools.m2_discovery_installation_profile.custody_capture import encoded
        app.raw=encoded({'phaseIntentHashes':app.intent_hashes});app.verify_scope=Mock()
        row=copy.deepcopy(executor.t.read());retained=copy.deepcopy(row['effects'][1])
        row.update(state='READY',nextPhase=12,creationRequestHash=app.request_hash,
            effects=[{'phase':p,'state':'APPLIED','intentHash':app.intent_hashes[p],'nativeEvidenceHash':'f'*64} for p in m.PHASES[:12]])
        row['effects'][1]=retained;executor.t.read=Mock(return_value=row)
        selected=object.__new__(m.DiscoverySelectedRuntime);selected.installation=SimpleNamespace(application=app)
        selected.images=SimpleNamespace(engine=engine);selected.guard=Mock()
        selected.mcp=SimpleNamespace(plan={'replacement':{'oldRuntimeBinding':{'containerId':ids[1]}}})
        selected.gateway=SimpleNamespace(plan={'oldRuntimeBinding':{'containerId':ids[2]}})
        def held(expected=None):
            m.require(row['state']=='READY' and row['nextPhase']==12 and (expected is None or expected==row),'MODELED_HELD_HISTORY_DRIFT')
            return copy.deepcopy(row)
        selected.held=held;get=engine.request;reads=[]
        def read_only(method,path,body=None):
            self.assertEqual(method,'GET');self.assertIsNone(body);reads.append(path);return get(method,path,body)
        engine.request=read_only
        return m.CurrentProducerFence(selected),app,row,reads

    def test_both_passes_match_retained_quiescence_without_native_mutation_or_release(self):
        reader,app,_,calls,row,reads=self.prepared();before=copy.deepcopy(calls);history=copy.deepcopy(row)
        proof=reader.observe();self.assertEqual(len(reads),8);self.assertEqual(proof['producerInspectionGets'],8)
        self.assertEqual(proof['reviewedProducerCount'],4);self.assertEqual(proof['retiredSelectedPredecessorCount'],3)
        self.assertTrue(proof['currentReviewedProducerFenceObserved'])
        for k in ('completeDatabaseWriterInventoryProvenHere','fullCohortProven','producerReleaseDispatched',
            'nativeMutationDispatched','runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'):
            self.assertIs(proof[k],False)
        self.assertEqual(row,history);self.assertEqual(calls,before)

    def test_running_absent_or_changed_old_generation_never_means_fenced(self):
        for change in ('running','absent','generation','restartPolicy'):
            reader,_,states,_,_,_=self.prepared();cid=next(iter(states))
            if change=='running':states[cid]['State']['Running']=True
            elif change=='absent':del states[cid]
            elif change=='generation':states[cid]['State']['StartedAt']='changed'
            else:states[cid]['HostConfig']['RestartPolicy']={'Name':'unless-stopped','MaximumRetryCount':0}
            with self.subTest(change=change),self.assertRaises((ValueError,CreationDenied)):reader.observe()

    def test_all_three_predecessors_and_immutable_child_intents_are_required_before_get(self):
        reader,app,_,_,_,reads=self.prepared();app.raw=b'{"phaseIntentHashes":{}}'
        with self.assertRaisesRegex(ValueError,'SAME_SIGNED'):reader.observe()
        self.assertEqual(reads,[])
        reader,app,_,_,_,reads=self.prepared();reader.selected.mcp.plan['replacement']['oldRuntimeBinding']['containerId']='e'*64
        with self.assertRaisesRegex(ValueError,'THREE_SELECTED_PREDECESSORS'):reader.observe()
        self.assertEqual(reads,[])

    def test_incomplete_prefix_or_lost_held_barrier_denies_before_get(self):
        for case in ('prefix','release'):
            reader,_,_,_,row,reads=self.prepared()
            if case=='prefix':row['effects'][9]['state']='IN_FLIGHT'
            else:row['nextPhase']=13
            with self.subTest(case=case),self.assertRaises(ValueError):reader.observe()
            self.assertEqual(reads,[])

    def test_drift_between_passes_is_not_retried_or_repaired(self):
        reader,_,states,calls,_,reads=self.prepared();before=copy.deepcopy(calls);original=reader.quiesced.stopped;count=0
        def stopped(pin):
            nonlocal count
            count+=1
            if count==5:states[pin['containerId']]['RestartCount']+=1
            return original(pin)
        reader.quiesced.stopped=stopped
        with self.assertRaisesRegex(ValueError,'DIFFERS_FROM_COMPLETED'):reader.observe()
        self.assertEqual(count,8);self.assertEqual(len(reads),8);self.assertEqual(calls,before)


if __name__=='__main__':unittest.main()
