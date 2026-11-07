import copy
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('cleanup_lab33',ROOT/'scripts/run-storage-generation33-lateral-isolation.py')
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
c=lab.cleanup

class CleanupTests(unittest.TestCase):
    def fixture(self,root):
        payload=lab.stream.body()[:c.CHUNK_BYTES];size=len(payload)+10
        (root/'ouf-identity-fixture_6.dat').write_bytes(b'\x03'+b'\0'*7+struct.pack('>IQiI',0x12345678,4,size,len(payload))+payload+b'\0'*24)
        obs=lab.stream.persisted_prefix(root)
        chunk=c.identify(root,obs)
        (root/'ouf-identity-fixture_6.idx').write_bytes(struct.pack('>QIi',4,1,size))
        return obs,chunk,payload

    def test_only_one_additional_role_link_is_enabled(self):
        self.assertEqual(lab.allow_links(True)-lab.ALLOW,{('s3','volume',28080)})
        self.assertEqual(lab.allow_links(),lab.ALLOW)
        self.assertEqual(sum(x[3] for x in lab.matrix(True)),11)
        self.assertEqual(lab.nft_rules('client'),lab.nft_rules('client',True))
        self.assertIn('ip daddr 172.30.233.11 tcp dport 28080 accept',lab.nft_rules('s3',True))
        self.assertIn('ip saddr 172.30.233.13 tcp dport 28080 accept',lab.nft_rules('volume',True))

    def test_grpc_counters_precede_established_accept(self):
        for role in ('s3','volume'):
            rules=lab.nft_rules(role,True)
            self.assertLess(rules.index('counter name cleanup_grpc_bytes'),rules.index('ct state established,related accept'))
            self.assertEqual(rules.count('policy drop;'),3)
            self.assertIn('other_denied reject',rules)

    def test_chunk_identity_is_bound_to_complete_payload_and_header(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);obs,chunk,payload=self.fixture(root)
            self.assertEqual(chunk['fileId'],'6,0412345678');self.assertEqual(chunk['needleOffset'],8)
            self.assertEqual(chunk['dataSha256'],c.sha(payload))
            self.assertEqual(chunk['dataBytes'],c.CHUNK_BYTES)

    def test_wrong_hash_offset_and_multiple_matches_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);obs,_,_=self.fixture(root)
            for field,value in (('sha256','0'*64),('offset',29),('file','../bad.dat')):
                bad=copy.deepcopy(obs);bad['matches'][0][field]=value
                with self.assertRaises(ValueError):c.identify(root,bad)
            bad=copy.deepcopy(obs);bad['matches']*=2
            with self.assertRaises(ValueError):c.identify(root,bad)

    def test_invalid_version_or_truncated_needle_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);obs,_,_=self.fixture(root);p=root/'ouf-identity-fixture_6.dat';raw=p.read_bytes()
            for bad in (b'\x01'+raw[1:],raw[:40]):
                p.write_bytes(bad)
                with self.assertRaises(ValueError):c.identify(root,obs)

    def test_live_then_tombstoned_index_preserves_original_entry(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);_,chunk,_=self.fixture(root)
            before=c.index_state(root,chunk);self.assertFalse(before['tombstoned'])
            with (root/'ouf-identity-fixture_6.idx').open('ab') as f:f.write(struct.pack('>QIi',4,524295,-1))
            after=c.index_state(root,chunk);self.assertTrue(after['tombstoned'])
            self.assertEqual(after['matchingEntries'][0],before['matchingEntries'][0]);self.assertEqual(after['indexBytes'],32)

    def test_wrong_original_and_non_tombstone_second_record_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);_,chunk,_=self.fixture(root);p=root/'ouf-identity-fixture_6.idx';raw=p.read_bytes()
            for bad in (struct.pack('>QIi',4,2,chunk['needleSize']),raw+b'x',raw+struct.pack('>QIi',4,10,0),raw+struct.pack('>QIi',4,10,50),raw*3):
                p.write_bytes(bad)
                with self.assertRaises(ValueError):c.index_state(root,chunk)

    def test_symlink_index_or_dat_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);obs,chunk,_=self.fixture(root)
            for suffix in ('idx','dat'):
                p=root/('ouf-identity-fixture_6.'+suffix);target=root/('target.'+suffix);p.rename(target);p.symlink_to(target)
                with self.assertRaises(ValueError):
                    c.index_state(root,chunk) if suffix=='idx' else c.identify(root,obs)

    def test_direct_get_requires_exact_chunk_before_and_404_after(self):
        with tempfile.TemporaryDirectory() as temp:
            _,chunk,payload=self.fixture(Path(temp))
            for expected,status,body in (('present',200,payload),('absent',404,b'not found')):
                connection=Mock();response=connection.getresponse.return_value;response.status=status;response.read.return_value=body
                with patch.object(c.http.client,'HTTPConnection',return_value=connection):value=c.read_chunk('172.30.233.11',chunk,expected)
                connection.request.assert_called_once_with('GET','/'+chunk['fileId'],headers={'Connection':'close'})
                self.assertEqual(value['status'],status);self.assertEqual(value['mutatingRequests'],0)

    def test_wrong_chunk_or_ambiguous_status_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            _,chunk,payload=self.fixture(Path(temp))
            for expected,status,body in (('present',200,b'x'+payload[1:]),('present',404,b''),('absent',200,payload),('absent',500,b''),('absent',403,b'')):
                connection=Mock();response=connection.getresponse.return_value;response.status=status;response.read.return_value=body
                with patch.object(c.http.client,'HTTPConnection',return_value=connection),self.assertRaises(ValueError):c.read_chunk('172.30.233.11',chunk,expected)

    def test_namespace_pin_binds_exact_live_inode(self):
        with tempfile.TemporaryDirectory() as temp:
            command=Mock(side_effect=['','12345'])
            value=lab.pin_network_namespace('123',Path(temp)/'pin','net:[12345]',command)
            self.assertEqual(value,{'namespace':'net:[12345]','sourcePid':123,'bindMountVerified':True})
            self.assertEqual(command.call_args_list[0].args[0][3:5],['--bind','/proc/123/ns/net'])

    def test_wrong_namespace_pin_is_released_before_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            command=Mock(side_effect=['','999',''])
            with self.assertRaisesRegex(ValueError,'PINNED_NAMESPACE_IDENTITY'):
                lab.pin_network_namespace('123',Path(temp)/'pin','net:[12345]',command)
            self.assertEqual(command.call_args_list[-1].args[0][2],'umount')

    def test_symlink_or_invalid_pid_cannot_pin_namespace(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'pin';path.symlink_to(Path(temp)/'missing');command=Mock()
            with self.assertRaises(ValueError):lab.pin_network_namespace('123',path,'net:[12345]',command)
            with self.assertRaises(ValueError):lab.pin_network_namespace('../host',Path(temp)/'fresh','net:[12345]',command)
            command.assert_not_called()

    def test_cleanup_mode_rejects_combined_faults(self):
        for flag in ('crash_volume','crash_filer','crash_master','crash_all','interrupt_stream'):
            with self.assertRaisesRegex(ValueError,'ONE_CRASH_ROLE'):
                lab.run(None,None,None,None,cleanup_stream=True,**{flag:True})

if __name__=='__main__':unittest.main()
