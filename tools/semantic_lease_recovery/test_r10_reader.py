import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('r10_seconds_reader',Path(__file__).with_name('reader.py'))
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)


class Tests(unittest.TestCase):
    def fixture(self,ttl):
        tables={f:{'nftables':[{'set':{'family':f,'table':'fixture','name':'provider_0',
          'flags':['timeout'],'type':'ipv4_addr','elem':[{'elem':{'val':'1.1.1.1','expires':ttl}}]}}]}
          for f in ('inet','bridge')}
        binding={'transactionId':'a'*64,'configurationHash':'b'*64,'leaseStructureHash':'c'*64}
        flow={'source':'10.77.0.2','leaseSeconds':30,'allowedPrivateAddresses':[],
              'endpoint':'https://fixture.invalid/','endpointRef':'fixture'}
        owner={'kernel':{'providerFlows':[flow],'tableName':'fixture'},'binding':binding,'pollSeconds':15,
               'expectedStructureHash':reader.sha(reader.encoded(reader.structure(tables)))}
        journal={'schema':'ouf.semantic-lease-coordination.v1',**binding,'state':'LEASE_READY',
                 'leaseAuthorized':True,'startAuthorized':False,'leaseAddresses':[['1.1.1.1']]}
        return owner,journal,tables
    def test_observed_seconds_preserved_in_active_projection(self):
        result=reader.lease_projection(*self.fixture(27))
        self.assertEqual(result['flows'][0]['minRemainingTtlSeconds'],27)
        self.assertTrue(result['journalAndMembershipConsistent'])
    def test_zero_milliseconds_bool_string_and_negative_ttl_are_unproven(self):
        for ttl in (0,27000,True,'27s',-1):
            with self.assertRaises(reader.ReadDenied):reader.lease_projection(*self.fixture(ttl))


if __name__=='__main__':unittest.main()
