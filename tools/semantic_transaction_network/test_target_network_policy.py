import copy
import unittest
from build_target_network_policy import assemble, NetworkDenied, digest

class PolicyTest(unittest.TestCase):
 def inputs(self):
  kernel={'tableName':'ouf_sem_provider','guardedInterfaces':['oufsp-int','oufsp-egress'],
   'existingInterfaces':['br-113b5f0a3c53','docker0'],'staticFlows':[{'purpose':'GATEWAY_ADAPTER','source':'172.21.0.2','destination':'172.21.0.3','protocol':'tcp','port':9443}],
   'providerFlows':[{'endpointRef':'schema-gov','endpoint':'https://schema.gov.it/sparql','source':'172.22.0.3','addresses':['1.2.3.4'],'leaseSeconds':30,'resolutionEvidenceRef':'fresh-lease-owner','allowedPrivateAddresses':[]}]}
  projection=copy.deepcopy(kernel);projection['providerFlows'][0].pop('addresses')
  network={'status':'NETWORK_INPUTS_CAPTURED','kernel':projection,
   'providerEndpoint':{'hostname':'schema.gov.it','path':'/sparql','port':443},
   'oidcIssuerEndpoint':{'hostname':'auth.ouf-lab.it','path':'/realms/ouf','port':443},'commonLockFile':'/run/ouf-semantic-boot-guard/guard.lock'}
  peer={'status':'EXISTING_PEER_PORT_CAPTURED','container':'ouf-semantic','address':'172.18.0.6',
   'mac':'b2:96:a1:e2:c1:8d','bridge':'br-113b5f0a3c53','hostIfindex':110}
  return network,kernel,peer
 def test_separate_source_roles_empty_leases_and_shared_static_ingress(self):
  inputs=self.inputs();result=assemble(*inputs)
  self.assertEqual([v['source'] for v in result['kernel']['providerFlows']],['172.22.0.3','172.22.0.2'])
  self.assertTrue(all(v['addresses']==[] and v['allowedPrivateAddresses']==[] for v in result['kernel']['providerFlows']))
  self.assertEqual(result['kernel']['staticFlows'],inputs[1]['staticFlows'])
  self.assertEqual(inputs[1]['providerFlows'][0]['addresses'],['1.2.3.4'])
  self.assertNotIn('leaseGuard',result['networkBindings']['southbound'][0])
  self.assertEqual(result['semanticIngress']['peerIngress'],{'kind':'BRIDGE_PORT','ifindex':110})
  self.assertFalse(result['startAuthorized'])
 def test_signed_dedicated_bindings_use_new_exact_kernel_not_projection(self):
  result=assemble(*self.inputs())
  for role in result['networkBindings'].values():
   for nic in role:
    if 'leaseGuard' in nic:self.assertEqual(nic['leaseGuard']['configurationHash'],digest(result['kernel']))
  self.assertNotEqual(result['originalKernelHash'],digest(self.inputs()[0]['kernel']))
 def test_issuer_or_shared_peer_drift_has_specific_diagnosis(self):
  for change in ('issuer','peer'):
   n,k,p=self.inputs()
   if change=='issuer':n['oidcIssuerEndpoint']['hostname']='different.example'
   else:p['address']='172.18.0.7'
   with self.subTest(change=change),self.assertRaises(NetworkDenied) as error:assemble(n,k,p)
   self.assertIn(error.exception.diagnosis['reason'],('OIDC_ISSUER_SCOPE_DRIFT','SEMANTIC_PEER_BINDING_REQUIRED'))
if __name__=='__main__':unittest.main()
