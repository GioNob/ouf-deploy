import copy
import importlib.util
from pathlib import Path
import sys
import types
import unittest

base=Path(__file__).resolve().parent
root=base.parent/'semantic_cohort_admission/cohort-draft'
if not root.exists():root=base.parent/'admission-integration/cohort-draft'
package=types.ModuleType('tools');package.__path__=[str(root/'tools')];sys.modules['tools']=package
from tools.materialize_semantic_shared_faces import materialize,validate_global_guard
from tools.semantic_provider_preexec import digest
from tools.semantic_provider_deployment_admission import live_profile,application_hash
from tools.semantic_provider_peer_bindings import declaration

KERNEL={'tableName':'global_test','guardedInterfaces':['isolated0'],'existingInterfaces':['shared0'],
 'staticFlows':[{'purpose':'DNS','source':'198.19.60.2','destination':'198.19.60.10','protocol':'udp','port':53}],
 'providerFlows':[{'endpointRef':'schema','endpoint':'https://schema.example/sparql','source':'198.19.60.2',
 'addresses':[],'allowedPrivateAddresses':[],'leaseSeconds':30,'resolutionEvidenceRef':'fresh-owner'}]}
ATTACH={'workloadRef':'adapter','interface':'vethadapter','ifindex':10,'bridge':'isolated0',
 'mac':'02:42:c6:13:00:02','ipv4':'198.19.60.2','bindingRef':'adapter-egress'}
POLICY={'schema':'ouf.semantic-shared-faces.v2','tableName':'composed_test','attachments':[ATTACH],
 'flows':[],'globalLeaseGuard':{'configurationHash':digest(KERNEL),'tableName':'global_test','bridges':['isolated0']}}

class Composition(unittest.TestCase):
 def test_complete_guard_scope_and_source_are_required(self):
  validate_global_guard(POLICY,KERNEL)
  for field,value in [('configurationHash','0'*64),('tableName','foreign'),('bridges',['shared0'])]:
   bad=copy.deepcopy(POLICY);bad['globalLeaseGuard'][field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):validate_global_guard(bad,KERNEL)
  bad=copy.deepcopy(KERNEL);bad['staticFlows']=[];bad['providerFlows']=[]
  policy=copy.deepcopy(POLICY);policy['globalLeaseGuard']['configurationHash']=digest(bad)
  with self.assertRaisesRegex(ValueError,'SOURCE_UNBOUND'):validate_global_guard(policy,bad)
 def test_shared_bridge_cannot_delegate_to_lease_guard(self):
  kernel=copy.deepcopy(KERNEL);kernel['existingInterfaces'].append('isolated0')
  policy=copy.deepcopy(POLICY);policy['globalLeaseGuard']['configurationHash']=digest(kernel)
  with self.assertRaisesRegex(ValueError,'SCOPE_DRIFT'):validate_global_guard(policy,kernel)
 def test_unbound_bridge_and_duplicate_delegation_are_rejected(self):
  for bridges in (['other0'],['isolated0','isolated0']):
   bad=copy.deepcopy(POLICY);bad['globalLeaseGuard']['bridges']=bridges
   with self.subTest(bridges=bridges),self.assertRaises(ValueError):materialize(bad)
 def test_source_identity_and_ipv4_checks_precede_delegation(self):
  raw=materialize(POLICY)['nftRules']
  self.assertIn('ether saddr != 02:42:c6:13:00:02 counter drop',raw)
  self.assertIn('ip saddr 198.19.60.2 counter accept',raw)
  self.assertNotIn('ct state established counter accept',raw)
  self.assertIn('counter drop',raw)
 def test_node_profile_keeps_all_nics_and_binds_guard_in_signed_scope(self):
  nic={'interface':'egress0','bridge':'isolated0','mac':ATTACH['mac'],'ipv4':ATTACH['ipv4'],
       'workloadRef':'adapter','bindingRef':'adapter-egress','leaseGuard':{k:POLICY['globalLeaseGuard'][k] for k in ('tableName','configurationHash')}}
  oci={'linux':{'namespaces':[{'type':'network'}]},'process':{'args':['fixture']}}
  candidate={'containerId':'a'*64,'transactionId':'b'*64,'bundlePath':'/root/bundle',
   'applicationHash':application_hash(oci),'networkBindings':[nic],'transport':[],'tableName':'composed_test'}
  # The protocol's transport requires a bounded nonempty list; a real target
  # also includes DNS and gateway bindings. Use one exact DNS fixture binding.
  candidate['transport']=[{'purpose':'DNS','authorityRef':'ci-installer','source':ATTACH['ipv4'],
   'destination':'198.19.60.10','port':53,'protocol':'udp','peerIngress':{'kind':'ROUTED','ifindex':11}}]
  children=[{'ifname':'egress0','ifindex':2,'link_index':10,'address':ATTACH['mac'],
   'addr_info':[{'family':'inet','local':ATTACH['ipv4']}]}]
  hosts=[{'ifname':'vethadapter','ifindex':10,'link_index':2,'master':'isolated0'}]
  profile=live_profile(candidate,oci,'/root/netns',900,children,hosts)
  self.assertEqual(len(profile['namespaceLinks']),1)
  self.assertEqual(profile['policy']['schema'],'ouf.semantic-shared-faces.v2')
  validate_global_guard(profile['policy'],KERNEL)
  decl=declaration({'containerId':'a'*64,'applicationHash':application_hash(oci),'networkBindings':[nic]})
  self.assertEqual(decl['networkBindings'][0]['leaseGuard'],nic['leaseGuard'])

if __name__=='__main__':unittest.main()
