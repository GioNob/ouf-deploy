"""Exercise actual native stage guards, with no Engine or service effects."""
import copy,sys,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.chat_recovery_update import native as n
class NativeGuards(unittest.TestCase):
 def exercise(self,running=False,started='original',stage='udp.STOP_OLD'):
  actual={'Id':'a'*64,'Image':'sha256:fixture','Config':{},'Mounts':[],
          'HostConfig':{'RestartPolicy':copy.deepcopy(n.NO_RESTART)},
          'State':{'Running':running,'Pid':41 if running else 0,'StartedAt':started}}
  pin={'containerId':actual['Id'],'imageId':actual['Image'],
       'configHash':n.digest({}),'mountsHash':n.digest([]),
       'hostConfigHash':n.digest(actual['HostConfig']),'startedAt':'original'}
  plan={'privateReviewBinding':{'path':'/fixture/review','sha256':'x'},
        'gateway':{'projectionBinding':{'path':'/fixture/projection'}},'humanBinding':{},
        'unchangedApplications':{},'replacements':{'udp':{'oldRuntimeBinding':pin,
        'oldNativeHostConfig':copy.deepcopy(actual['HostConfig'])}}}
  ports=object.__new__(n.NativePorts)
  ports.plan=plan;ports.action=Mock();ports.engine=Mock();ports.gateway=Mock()
  ports.human=Mock();ports.human.current.return_value={}
  ports.database=Mock();ports.route_inventory=Mock()
  ports.inspect=Mock(return_value=actual)
  with patch.object(n,'scope',return_value={}),patch.object(n,'private_file'),patch.object(n,'private_config'),patch.object(n,'runtime',return_value=pin):
   ports.guard_current(stage)
 def test_stopped_generation_can_reconcile_lost_stop_response(self):
  self.exercise()
 def test_still_running_can_receive_its_first_stop(self):
  self.exercise(running=True)
 def test_restarted_generation_cannot_reconcile_old_stop(self):
  with self.assertRaises(Exception):self.exercise(started='different')
 def test_running_after_applied_stop_blocks(self):
  with self.assertRaises(Exception):self.exercise(running=True,stage='BACKUP_UDP')
if __name__=='__main__':unittest.main()
