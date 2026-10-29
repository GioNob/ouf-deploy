"""Scheduler changes are not process generations; unsafe transitions deny."""
import io,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/semantic_application_cutover'))
import gated_process_observation as module
from gated_creation_plan import ENTRY

class Process(unittest.TestCase):
    def sample(self,states):
        request={'User':'10001:10001','Entrypoint':ENTRY,'Cmd':['java','-jar','/app/application.jar']}
        observer=module.GatedProcessObservation(request);samples=iter(states);argv=b'java\0-jar\0/app/application.jar\0'
        status=b'Uid:\t10001 10001 10001 10001\nNoNewPrivs:\t1\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n'
        class KernelPath:
            def __init__(self,name):self.name=name
            def __truediv__(self,name):return KernelPath(self.name+'/'+str(name))
            def stat(self):return types.SimpleNamespace(st_ino=42)
            def read_text(self):
                state,ticks=next(samples);return '1234 (fixture) '+state+' '+'0 '*18+str(ticks)
            def open(self,*args):return io.BytesIO(status if self.name.endswith('/status') else argv)
            def read_bytes(self):return argv
        with patch.object(module,'Path',KernelPath):return observer.observe(1234)
    def test_running_sleeping_scheduler_transition_preserves_application_identity(self):
        self.assertEqual(self.sample([('R',12),('S',12)])['processKind'],'APPLICATION_RUNNING')
    def test_changed_start_ticks_blocks_even_with_same_argv(self):
        with self.assertRaisesRegex(ValueError,'GATED_PROCESS_CHANGED_DURING_READ'):self.sample([('R',12),('S',13)])
    def test_stopped_or_zombie_end_state_does_not_prove_application_running(self):
        for state in ('T','t','Z','X'):
            self.assertEqual(self.sample([('R',12),(state,12)])['processKind'],'UNPROVEN')

if __name__=='__main__':unittest.main()
