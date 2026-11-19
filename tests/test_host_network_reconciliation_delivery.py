"""Immutable host delivery: exact bytes, flags and fail-before-effect CLI probes."""
import ast,hashlib,json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=(('tools/host_network_reconciliation.py','owner.py'),('scripts/reconcile-host-network-20261018.py','bootstrap.py'),('releases/host-network-reconciliation-20261018.json','installation.json'),('releases/host-network-reconciliation-execution-20261018.json','execution.json'),('scripts/read-source-revision-boot-guard.py','guard_reader.py'),('releases/source-revision-boot-read-selection-20261018.json','guard_selection.json'),('scripts/read-preboot-network-contract.py','contracts.py'),('releases/preboot-network-contract-read-selection-20261018.json','contracts_selection.json'))
class Delivery(unittest.TestCase):
 def body(self):
  text=(ROOT/'scripts/launch-host-network-reconciliation-20261018.sh').read_text()
  return text.split("<<'OUF_VERIFIED_HOST_NETWORK_CORRECTION'",1)[1].split('\n',1)[1].rsplit('\nOUF_VERIFIED_HOST_NETWORK_CORRECTION',1)[0]
 def test_syntax_and_all_eight_exact_source_bindings(self):
  ast.parse(self.body());script=(ROOT/'scripts/launch-host-network-reconciliation-20261018.sh').read_text()
  for path,name in SPEC:self.assertIn(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),script)
  self.assertIn('maximumEngineWrites',self.body());self.assertIn('source=17d4cf452a445a1fa96824c6ce7b46339133f914',script)
 def cli(self,corrupt=False,isolated=True):
  self.assertFalse(Path('/etc/ouf/deploy-snapshots').exists(),'CLI probe forbidden on an installed OUF host')
  temp=tempfile.TemporaryDirectory(dir='/root');self.addCleanup(temp.cleanup);case=Path(temp.name);case.chmod(0o700)
  for path,name in SPEC:(case/name).write_bytes((ROOT/path).read_bytes());(case/name).chmod(0o600)
  if corrupt:(case/'owner.py').write_bytes(b'raise RuntimeError("PRIVATE_CANARY_EXECUTED")\n')
  args=['/usr/bin/python3',*(['-I']if isolated else[]),'-B','-S','-',str(case)]
  result=subprocess.run(args,input=self.body().encode(),capture_output=True,timeout=20)
  self.assertEqual(result.returncode,2);self.assertNotIn(b'PRIVATE_CANARY',result.stdout+result.stderr);self.assertEqual(result.stderr,b'')
  self.assertFalse(Path('/etc/ouf/host-network-reconciliation-20261018.json').exists());return json.loads(result.stdout)
 @unittest.skipUnless(os.environ.get('OUF_NETWORK_DELIVERY_TEST')=='1','closed root CI fixture only')
 def test_corrupt_executable_never_runs_or_reaches_target(self):
  result=self.cli(corrupt=True);self.assertEqual(result['reason'],'DELIVERY_CHANGED');self.assertFalse(result['complete'])
 @unittest.skipUnless(os.environ.get('OUF_NETWORK_DELIVERY_TEST')=='1','closed root CI fixture only')
 def test_valid_payload_wrong_environment_stops_before_any_host_operation(self):
  result=self.cli();self.assertEqual(result['errorClass'],'FileNotFoundError');self.assertFalse(result['complete']);self.assertFalse(result['runtimeAuthorityIssued'])
 @unittest.skipUnless(os.environ.get('OUF_NETWORK_DELIVERY_TEST')=='1','closed root CI fixture only')
 def test_nonisolated_interpreter_rejected_before_payload_reads(self):
  result=self.cli(isolated=False);self.assertEqual(result['reason'],'ISOLATED_HOST_ADMINISTRATOR_REQUIRED')
if __name__=='__main__':unittest.main()
