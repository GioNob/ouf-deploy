import importlib.util,json,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('startup',ROOT/'scripts/read-retained-udp-startup.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Read(unittest.TestCase):
 def state(self):return {'id':'a'*64,'image':'sha256:'+'b'*64,'revision':'c'*40,'state':{
  'Status':'exited','Running':False,'Paused':False,'Restarting':False,'OOMKilled':False,'Dead':False,'ExitCode':1,
  'StartedAt':'2026-10-18T10:00:00Z','FinishedAt':'2026-10-18T10:00:10Z','Error':'PRIVATE_CANARY',
  'Health':{'Log':[{'Output':'PRIVATE_CANARY'}]}},'restartPolicy':{'Name':'no'}}
 def test_sensitive_state_and_logs_are_redacted(self):
  output={'state':m.safe_state(self.state()),'log':m.log_metadata(b'password=PRIVATE_CANARY\nCaused by: java.net.ConnectException: Connection refused token PRIVATE_CANARY\n at org.example.Client.connect(Client.java:19)\n')}
  self.assertNotIn('PRIVATE_CANARY',json.dumps(output));self.assertEqual(output['log']['exceptionClasses'],['java.net.ConnectException'])
  self.assertTrue(output['log']['markers']['connectionRefused']);self.assertEqual(output['log']['stackFrameCount'],1)
 def test_untrusted_class_and_frame_identifiers_are_not_printed(self):
  output=m.log_metadata(b'Caused by: private.PRIVATE_CANARYException: hidden\n at private.PRIVATE_CANARY.run(PRIVATE_CANARY.java:10)\n')
  self.assertNotIn('PRIVATE_CANARY',json.dumps(output));self.assertEqual(output['otherExceptionClassCount'],1)
 def test_health_payload_is_never_returned(self):
  self.assertNotIn('Health',m.safe_state(self.state()));self.assertTrue(m.safe_state(self.state())['engineErrorPresent'])
 def test_fixed_generation_and_no_mutations(self):
  value=self.state();selection={'currentApplications':{'udp':{'containerId':value['id'],'imageId':value['image'],'sourceCommit':value['revision']}}};calls=[]
  def invoke(args):calls.append(args);return b'java.net.ConnectException: PRIVATE_CANARY'if args[0]=='logs'else json.dumps(value).encode()
  with patch.object(m,'invoke',side_effect=invoke):output=m.collect(selection)
  self.assertTrue(output['complete']);self.assertEqual([a[0]for a in calls],['inspect','logs','inspect']);self.assertNotIn('PRIVATE_CANARY',json.dumps(output))
 def test_generation_drift_and_bounds(self):
  value=self.state();selection={'currentApplications':{'udp':{'containerId':value['id'],'imageId':value['image'],'sourceCommit':'d'*40}}}
  with patch.object(m,'invoke',return_value=json.dumps(value).encode()):
   with self.assertRaises(ValueError):m.collect(selection)
  with self.assertRaises(ValueError):m.log_metadata(b'x'*524289)
 def test_port_and_network_overlap_are_only_candidate_evidence(self):
  target=self.state();target.update(bindings={'8092/tcp':[{'HostIp':'0.0.0.0','HostPort':'18092'}]},
    networks={'fixture':{'IPAMConfig':{'IPv4Address':'10.1.2.3'}}})
  other=self.state();other.update(id='d'*64,bindings=target['bindings'],ports=target['bindings'],networks=target['networks'])
  with patch.object(m,'invoke',side_effect=[json.dumps(other['id']).encode(),json.dumps(other).encode()]),patch('subprocess.run',return_value=type('Reply',(),{'returncode':0,'stdout':b'LISTEN 0 4096 0.0.0.0:18092 0.0.0.0:*\n'})()):
   result=m.network_conflicts(target,target['id'])
  self.assertEqual(result['candidateConflicts'][0]['containerId'],other['id'])
  self.assertEqual(result['candidateConflicts'][0]['networkAddressOverlapCount'],1)
  self.assertFalse(result['ownerStopOrRestartPerformed'])
if __name__=='__main__':unittest.main()
