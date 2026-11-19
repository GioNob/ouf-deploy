import copy,importlib.util,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('mac',BASE/'tools/acquisition_read_native/retained_mac.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class ExactTransition(unittest.TestCase):
    def setUp(self):
        self.before={'Id':'a'*64,'Image':'sha256:'+'b'*64,'Name':'/fixture-mcp','Config':{'MacAddress':'02:42:ac:44:01:07','Env':['PRIVATE=not-output'],'Hostname':'fixture','Cmd':['server']},'HostConfig':{'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'Privileged':False},'Mounts':[],'State':{'Running':True,'Pid':123,'StartedAt':'fixture-generation'},'NetworkSettings':{'Networks':{'fixture':{'MacAddress':'02:42:ac:44:01:07'}}}}
        self.after=copy.deepcopy(self.before);del self.after['Config']['MacAddress'];self.after['State'].update(Running=False,Pid=0);self.after['NetworkSettings']['Networks']={};self.after['HostConfig']['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
    def verify(self):return m.verify_detached(self.before,self.after,expected_name='/fixture-mcp')
    def test_exact_absence_preserves_input_and_has_no_raw_mac(self):
        before=copy.deepcopy(self.before);after=copy.deepcopy(self.after);r=self.verify();self.assertEqual(before,self.before);self.assertEqual(after,self.after);self.assertFalse(r['originalHashesRewritten']);self.assertNotIn('02:42',m.encoded(r).decode());self.assertNotIn('PRIVATE',m.encoded(r).decode())
    def test_empty_null_or_different_mac_after_detach_is_not_absence(self):
        for value in(None,'','02:42:ac:44:01:08'):
            self.after['Config']['MacAddress']=value
            with self.assertRaisesRegex(m.MacTransitionDenied,'ONLY_PROVEN'):self.verify()
    def test_absent_empty_null_malformed_or_foreign_legacy_before_denied(self):
        for value in(None,'','wrong','00:00:00:00:00:00','01:42:ac:44:01:07','02:42:ac:44:01:08'):
            self.before['Config']['MacAddress']=value
            with self.assertRaises(m.MacTransitionDenied):self.verify()
        del self.before['Config']['MacAddress']
        with self.assertRaises(m.MacTransitionDenied):self.verify()
    def test_other_config_delta_even_default_like_is_denied(self):
        for field,value in(('Hostname','other'),('Env',[]),('Cmd',None),('AttachStdin',False)):
            after=copy.deepcopy(self.after);self.after['Config'][field]=value
            with self.assertRaisesRegex(m.MacTransitionDenied,'ONLY_PROVEN'):self.verify()
            self.after=after
    def test_running_or_attached_old_container_denied(self):
        self.after['State'].update(Running=True,Pid=123)
        with self.assertRaisesRegex(m.MacTransitionDenied,'STOPPED'):self.verify()
        self.after['State'].update(Running=False,Pid=0);self.after['NetworkSettings']['Networks']={'fixture':{}}
        with self.assertRaisesRegex(m.MacTransitionDenied,'NO_ENDPOINTS'):self.verify()
    def test_identity_startedat_mounts_hostconfig_and_name_drift_denied(self):
        for change in('Id','Image','Name','StartedAt','Mounts','HostConfig'):
            original=copy.deepcopy(self.after)
            if change=='StartedAt':self.after['State']['StartedAt']='other'
            elif change=='Mounts':self.after['Mounts']=[{'Destination':'/different'}]
            elif change=='HostConfig':self.after['HostConfig']['Privileged']=True
            else:self.after[change]='other'
            with self.assertRaises(m.MacTransitionDenied):self.verify()
            self.after=original
if __name__=='__main__':unittest.main()
