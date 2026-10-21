import copy
import unittest
from probe_installed_nft_units import expiry


class Tests(unittest.TestCase):
    def data(self):
        return {'nftables':[{'set':{'family':'inet','table':'fixture','name':'unit_probe',
             'type':'ipv4_addr','flags':['timeout'],'elem':[{'elem':{'val':'198.51.100.1','timeout':30,'expires':29}}]}}]}
    def test_exact_seconds_fixture(self): self.assertEqual(expiry(self.data(),'inet','fixture'),29)
    def test_milliseconds_string_bool_and_zero_never_promoted(self):
        for ttl in (29000,'29',True,0,31):
            value=self.data();value['nftables'][0]['set']['elem'][0]['elem']['expires']=ttl
            with self.assertRaises(RuntimeError):expiry(value,'inet','fixture')
    def test_timeout_must_be_exact_seconds_30(self):
        for timeout in (30000,'30',True,29):
            value=self.data();value['nftables'][0]['set']['elem'][0]['elem']['timeout']=timeout
            with self.assertRaises(RuntimeError):expiry(value,'inet','fixture')
    def test_other_family_or_duplicate_element_denied(self):
        value=self.data()
        with self.assertRaises(RuntimeError):expiry(value,'bridge','fixture')
        value['nftables'][0]['set']['elem']*=2
        with self.assertRaises(RuntimeError):expiry(value,'inet','fixture')


if __name__=='__main__':unittest.main()
