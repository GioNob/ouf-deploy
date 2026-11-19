"""Postboot BLOCKED is native revocation, never permission to start providers."""
import copy,hashlib,importlib.util,json,os,sys,types,unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
b=load('provider_bootstrap',ROOT/'scripts/reconcile-host-network-20261018.py')
m=load('provider_owner',ROOT/'tools/host_network_reconciliation.py')
class NativeProvider(unittest.TestCase):
 def fixture(self):
  root=Path(os.environ['OUF_GATEWAY_SOURCE']);sys.path.insert(0,str(root));self.addCleanup(sys.path.remove,str(root))
  core=load('actual_native_boot_core',root/'tools/semantic_provider_boot_coordination.py')
  restorer=load('actual_native_empty_restorer',root/'scripts/restore_semantic_runtime_boot_guard.py')
  binding={k:'a'*64 for k in ('transactionId','configurationHash','leaseStructureHash')}
  journal={'schema':'ouf.semantic-lease-coordination.v1',**binding,'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[]]}
  class Coordinator:
   configuration={'providerFlows':[{}]}
   hold_lock=lambda self:nullcontext()
   def journal(self):return copy.deepcopy(journal)
   def publish(self,before,after):self_outer.assertEqual(before,journal);journal.clear();journal.update(copy.deepcopy(after))
  self_outer=self
  result=core.prepare_docker_boot(Coordinator(),lambda:set(),lambda:{'startAuthorized':False,'restored':True,'leaseStructureReconciliationRequired':True,'leaseStructureHash':'b'*64})
  self.assertTrue(result['leaseStructureReconciliationRequired']);self.assertEqual(journal['state'],'BLOCKED');self.assertFalse(journal['leaseAuthorized'])
  tables={family:{'nftables':[{'table':{'family':family,'name':'fixture_guard','handle':1}},{'set':{'family':family,'table':'fixture_guard','name':'provider_0','type':'ipv4_addr','elem':[]}}]}for family in ('inet','bridge')}
  coordinated={'binding':binding,'kernel':{'providerFlows':[{}]},'nftPath':'/fixture/nft','commonLockFile':'/fixture/lock','journalFile':'/fixture/owner.json'}
  boot={'kernel':copy.deepcopy(coordinated['kernel']),'nftPath':coordinated['nftPath'],'lockFile':coordinated['commonLockFile'],'journalFile':'/fixture/empty.json','transactionId':'c'*64,'expectedFootprint':restorer.footprint(tables)}
  empty={'schema':'ouf.semantic-runtime-transition.v1','state':'RUNTIME_EMPTY','startAuthorized':False,'transactionId':boot['transactionId'],'configurationHash':'e'*64}
  profile={'sourceHashes':{},'coordinatedConfiguration':'/fixture/coordinated.json','coordinatedConfigurationHash':'d'*64,'bootConfiguration':'/fixture/boot.json','bootConfigurationHash':'e'*64,'bootGuardFile':'/fixture/restorer.py','bootGuardHash':hashlib.sha256((root/'scripts/restore_semantic_runtime_boot_guard.py').read_bytes()).hexdigest()}
  values={'/fixture/profile.json':profile,'/fixture/coordinated.json':coordinated,'/fixture/boot.json':boot,'/fixture/owner.json':journal,'/fixture/empty.json':empty}
  def known(path,digest,name):
   self.assertEqual(digest,profile['bootGuardHash']);return restorer
  reader=types.SimpleNamespace(parse=json.loads,sealed=lambda path,h:json.dumps(values[str(path)]).encode(),read=lambda path:json.dumps(values[str(path)]).encode(),load_known=known)
  report={'loadedBinding':{'profile':'/fixture/profile.json','sha256':'f'*64,'source':'/fixture/source/scripts/guard.py'}}
  self.enterContext(patch.object(restorer,'validate',return_value='validated: exercised separately by native reader tests'))
  self.enterContext(patch.object(restorer,'membership',return_value={'inet','bridge'}))
  self.enterContext(patch.object(restorer,'tables',side_effect=lambda _:copy.deepcopy(tables)))
  # Mutation functions deliberately trap any attempt to repair or adopt here.
  self.enterContext(patch.object(restorer,'restore',side_effect=AssertionError('MUTATION_FORBIDDEN')))
  return reader,report,journal,empty,tables,boot
 def test_actual_native_missing_tables_transition_stays_blocked_with_empty_proof(self):
  reader,report,journal,_,_,_=self.fixture();before=copy.deepcopy(journal)
  result=b.prove_empty_provider(reader,report,m)
  self.assertEqual(result,{'ownerState':'BLOCKED','emptyKernelProven':True,'providerStartAllowed':False,'nativeReconciliationStillRequired':True});self.assertEqual(journal,before)
 def test_active_unknown_missing_or_nonboolean_authority_never_admitted(self):
  reader,report,journal,_,_,_=self.fixture();before=copy.deepcopy(journal)
  for key,value in (('leaseAuthorized',True),('startAuthorized',True),('startAuthorized',0),('state','LEASE_READY'),('state','UNREVIEWED')):
   journal.clear();journal.update(copy.deepcopy(before));journal[key]=value
   with self.subTest(key=key,value=value),self.assertRaises(ValueError):b.prove_empty_provider(reader,report,m)
  journal.clear();journal.update(before);del journal['startAuthorized']
  with self.assertRaises(ValueError):b.prove_empty_provider(reader,report,m)
 def test_nonempty_lease_receipts_rejected(self):
  reader,report,journal,_,_,_=self.fixture();journal['leaseAddresses']=[['192.0.2.1']]
  with self.assertRaisesRegex(ValueError,'EMPTY_LEASE'):b.prove_empty_provider(reader,report,m)
 def test_actual_native_empty_check_rejects_live_elements_even_when_footprint_matches(self):
  reader,report,_,_,tables,boot=self.fixture();tables['inet']['nftables'][1]['set']['elem']=['192.0.2.1']
  with self.assertRaisesRegex(ValueError,'EMPTY_KERNEL'):b.prove_empty_provider(reader,report,m)
 def test_structure_and_transition_binding_drift_rejected(self):
  reader,report,_,empty,tables,boot=self.fixture();empty['configurationHash']='0'*64
  with self.assertRaisesRegex(ValueError,'TRANSITION_BINDING'):b.prove_empty_provider(reader,report,m)
  empty['configurationHash']='e'*64;tables['inet']['nftables'][0]['table']['name']='foreign'
  with self.assertRaisesRegex(ValueError,'EMPTY_KERNEL'):b.prove_empty_provider(reader,report,m)
if __name__=='__main__':unittest.main()
