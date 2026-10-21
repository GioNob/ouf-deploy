import copy
import unittest
from read_provider_transaction_network_inputs import projection, endpoint, InputDenied

class NetworkProjection(unittest.TestCase):
    def inputs(self):
        adapter={'provider':{'endpoint':'https://schema.example.test/sparql', 'unusedSecret':'NEVER_PRINT_ME'},
            'listenAddress':'0.0.0.0','listenPort':9443}
        binding={'routes':{'issuer':'https://identity.example.test/realms/test','oidcSecretRef':'NEVER_PRINT_ME'},'adapter':adapter}
        plan={'schema':'ouf.semantic-provider-runtime-plan.v1','adapterConfiguration':adapter,
            'tlsIdentities':{'adapterHostname':'adapter-v2','southboundHostname':'southbound-v2'},'extraSecret':'NEVER_PRINT_ME'}
        coord={'schema':'ouf.semantic-coordinated-owner-runtime.v1',
            'kernel':{'tableName':'test_guard','guardedInterfaces':['test0'],'existingInterfaces':['shared0'],
                'staticFlows':[{'purpose':'DNS','source':'172.22.0.3','destination':'46.38.252.230','protocol':'udp','port':53}],
                'providerFlows':[{'endpointRef':'provider','endpoint':'https://schema.example.test/sparql',
                    'source':'172.22.0.3','leaseSeconds':30,'resolutionEvidenceRef':'fresh-owner','allowedPrivateAddresses':[]}]},
            'dns':{'resolvers':['46.38.252.230'],'resolverPort':53,'timeoutSeconds':2,'maxLeaseSeconds':30,'applyBudgetSeconds':1},
            'binding':{k:'a'*64 for k in ('transactionId','configurationHash','leaseStructureHash')},
            'expectedStructureHash':'a'*64,'journalFile':'/root/coordination.json','commonLockFile':'/root/guard.lock',
            'extraSecret':'NEVER_PRINT_ME'}
        return binding,plan,coord
    def test_only_required_network_fields_leave_private_inputs(self):
        import json
        report=projection(*self.inputs())
        self.assertNotIn('NEVER_PRINT_ME',json.dumps(report))
        self.assertEqual(report['oidcIssuerEndpoint']['hostname'],'identity.example.test')
        self.assertFalse(report['startAuthorized']);self.assertFalse(report['acceptanceGranted'])
    def test_credential_query_fragment_urls_are_rejected(self):
        for url in ('https://user:password@example.test/x','https://example.test/x?token=secret','https://example.test/x#secret'):
            with self.subTest(url=url),self.assertRaisesRegex(InputDenied,'CREDENTIAL_FREE_HTTPS_ENDPOINT_REQUIRED'):
                endpoint(url)
    def test_mismatched_plan_is_diagnosed_before_projection(self):
        binding,plan,coord=self.inputs();plan=copy.deepcopy(plan);plan['adapterConfiguration']['listenPort']=9444
        with self.assertRaisesRegex(InputDenied,'ADAPTER_NETWORK_PLAN_DRIFT'):projection(binding,plan,coord)

if __name__=='__main__': unittest.main()
