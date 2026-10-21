import copy
import unittest
from unittest.mock import patch
import namespace_generation as m

class Tests(unittest.TestCase):
    def binding(self):
        return {'sandboxKey':'/var/run/docker/netns/'+'a'*12,'canonicalPath':'/run/docker/netns/'+'a'*12,
                'device':4,'inode':5,'generation':{'pid':123,'startTicks':8,'namespaceInode':5}}
    def test_same_pid_nsfs_identity_and_ticks_required(self):
        b=self.binding()
        with patch.object(m,'ticks',return_value=8),patch.object(m,'handle_identity',return_value={'device':4,'inode':5}):
            self.assertEqual(m.generation(b,123),b['generation'])
            with self.assertRaises(ValueError):m.generation(b,124)
        with patch.object(m,'ticks',return_value=9):
            with self.assertRaises(ValueError):m.generation(b,123)
        with patch.object(m,'ticks',return_value=8),patch.object(m,'handle_identity',return_value={'device':4,'inode':6}):
            with self.assertRaises(ValueError):m.generation(b,123)
    def test_changed_sandbox_and_nonrunning_metadata_denied(self):
        b=self.binding();data={'sandboxKey':b['sandboxKey'],'state':{'Pid':123,'Running':True}}
        m.verify_metadata(data,b)
        for key,value in [('sandboxKey','foreign'),('state',{'Pid':123,'Running':False}),('state',{'Pid':124,'Running':True})]:
            row=copy.deepcopy(data);row[key]=value
            with self.assertRaises(ValueError):m.verify_metadata(row,b)
    def test_root_capture_requires_same_proc_and_handle_inode(self):
        b=self.binding();data={'sandboxKey':b['sandboxKey'],'state':{'Pid':123,'Running':True}}
        with patch.object(m.Path,'resolve',return_value=m.Path(b['canonicalPath'])),patch.object(m,'handle_identity',return_value={'device':4,'inode':5}):
            self.assertEqual(m.capture(data,b['generation'],lambda pid:b['generation']),b)
        with patch.object(m.Path,'resolve',return_value=m.Path(b['canonicalPath'])),patch.object(m,'handle_identity',return_value={'device':4,'inode':6}):
            with self.assertRaises(ValueError):m.capture(data,b['generation'],lambda pid:b['generation'])
    def test_untrusted_paths_denied_before_file_open(self):
        for path in ['/tmp/namespace','/run/docker/netns/../other','/run/docker/netns/default','/proc/123/ns/net']:
            with self.assertRaises(ValueError):m.handle_identity(path)

if __name__=='__main__':unittest.main()
