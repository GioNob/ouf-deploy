"""Actual disposable Docker generations/adapter/store; other lineage modeled.

Only fixture setup/restart/cleanup mutates disposable containers. The production
reader is restricted to Engine GETs throughout; no target is addressed.
"""
import os,shutil,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_producer_fence as fixtures
import native_producer_executor as native
from engine_creation import CreationDenied


class NativeProducerFence(unittest.TestCase):
    @classmethod
    def command(cls,*args):
        return subprocess.check_output([cls.docker,*args],stderr=subprocess.PIPE,timeout=90)
    @classmethod
    def setUpClass(cls):
        if os.geteuid()!=0:raise AssertionError('ROOT_DISPOSABLE_PRODUCER_FIXTURE_REQUIRED')
        cls.docker=str(Path(shutil.which('docker')).resolve())
        cls.command('pull','postgres:17-alpine')
        cls.image=cls.command('image','inspect','postgres:17-alpine','--format','{{.Id}}').decode().strip()

    def prepared(self):
        case=native.NativeProducers();case.image=self.image;self.addCleanup(case.doCleanups)
        executor,engine,pins=case.producers(4,restart_policy='unless-stopped');executor.run(2)
        original=engine.request
        reader,app,row,reads=fixtures.ProducerFence.bind(self,executor,engine,executor.intents['QUIESCE_PRODUCERS'])
        # Restore the fixture's mutating cleanup channel only after assertions.
        self.addCleanup(setattr,engine,'request',original)
        return reader,pins,row,reads

    def test_real_quiesced_generations_and_disabled_restart_policies_match_both_passes(self):
        reader,pins,row,reads=self.prepared();history=fixtures.m.digest(row)
        proof=reader.observe();self.assertEqual(len(reads),8);self.assertEqual(proof['producerInspectionGets'],8)
        self.assertTrue(proof['currentReviewedProducerFenceObserved']);self.assertFalse(proof['nativeMutationDispatched'])
        self.assertFalse(proof['fullCohortProven']);self.assertFalse(proof['completeDatabaseWriterInventoryProvenHere'])
        self.assertEqual(fixtures.m.digest(row),history)
        for pin in pins:
            value=self.command('inspect',pin['containerId'],'--format','{{.State.Status}}/{{.State.Pid}}/{{.HostConfig.RestartPolicy.Name}}').decode().strip()
            self.assertEqual(value,'exited/0/no')

    def test_real_restarted_then_stopped_predecessor_is_denied_without_read_repair(self):
        reader,pins,row,reads=self.prepared();cid=pins[0]['containerId'];history=fixtures.m.digest(row)
        self.command('start',cid);self.command('stop','--time','1',cid)
        before=self.command('inspect',cid)
        with self.assertRaises(CreationDenied):reader.observe()
        self.assertEqual(before,self.command('inspect',cid));self.assertEqual(len(reads),1)
        self.assertEqual(fixtures.m.digest(row),history)


if __name__=='__main__':unittest.main()
