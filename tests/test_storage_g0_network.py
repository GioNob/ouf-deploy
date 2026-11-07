import copy,json,os,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
from tools.storage_planning import g0_network as n,g0_package as p
import test_storage_g0_package as base
put=base.put

class NetworkTest(unittest.TestCase):
 setUp=base.PackageTest.setUp
 save=base.PackageTest.save
 check=base.PackageTest.check
 def binding(self):
  pin={'pid':4242,'startTicks':123,'namespaces':{'net':[4,101],'mnt':[4,102]}}
  return {'schema':'ouf.storage-g0-network-binding.v1','operationId':'fixture','installationRef':'fixture','bootId':'11111111-1111-1111-1111-111111111111','targets':{r:{**self.config['roles'][r],'process':copy.deepcopy(pin)} for r in ('minio','postgres')}}
 def install(self):
  b=self.binding();b['targets']['postgres']['process']['pid']+=1
  self.config['schema']='ouf.storage-g0-package-input.v2';self.config['networkBindingFile']=put(self.inputs/'network.json',b)
  f=Path(self.config['connectionFiles']['s3']);v=json.loads(f.read_text());v['connection'].update(endpoint='http://127.0.0.1:9000',allowLoopbackHttp=True);put(f,v);self.save();return b
 def test_v2_check_binds_network_without_process_or_provider_observation(self):
  self.install()
  with patch.object(n,'process_pin',side_effect=AssertionError('process read')):r=self.check()[-1]
  self.assertIn('network',r['boundInputSha256']);self.assertEqual(r['targetReads'],0);self.assertFalse(r['targetCommandAuthorized'])
 def test_wrong_role_image_denied(self):
  b=self.install();b['targets']['postgres']['nativeImage']='sha256:'+'f'*64;put(Path(self.config['networkBindingFile']),b);self.assertRaises(ValueError,self.check)
 def test_v2_never_silently_falls_back_to_host(self):
  self.install();self.config['networkBindingFile']=None;self.save();self.assertRaises(ValueError,self.check)
 def test_network_profile_must_not_route_remote_database(self):
  self.install();f=Path(self.config['connectionFiles']['udp']);v=json.loads(f.read_text());v.update(host='db.example',hostaddr='192.0.2.1',sslmode='verify-full',rootCertificateFile=put(self.inputs/'ca',b'fixture'));put(f,v);self.assertRaises(ValueError,self.check)
 def test_reused_owner_pid_denied(self):
  b=self.binding();self.assertRaises(ValueError,n.validate,b,'fixture','fixture',self.config['roles'])
 def test_changed_boot_denied_before_pidfd_open(self):
  b=self.binding();b['bootId']='00000000-0000-0000-0000-000000000000'
  with patch.object(n,'boot_id',return_value='11111111-1111-1111-1111-111111111111'),patch.object(n.os,'pidfd_open',side_effect=AssertionError('opened')):
   self.assertRaises(ValueError,n.PinnedNetwork(b,'minio').__enter__)
 def test_changed_owner_start_denied(self):
  b=self.binding();old=copy.deepcopy(b['targets']['minio']['process']);b['targets']['minio']['process']['startTicks']+=1
  with patch.object(n,'boot_id',return_value=b['bootId']),patch.object(n,'process_pin',return_value=old):self.assertRaises(ValueError,n.PinnedNetwork(b,'minio').__enter__)
 def real_binding(self):
  b=self.binding();b['bootId']=n.boot_id();b['targets']['minio']['process']=n.process_pin(os.getpid());return b
 @unittest.skipUnless(os.environ.get('GITHUB_ACTIONS')=='true' and os.geteuid()==0,'native Linux root CI only')
 def test_real_pidfd_and_network_fd_closed(self):
  with n.PinnedNetwork(self.real_binding(),'minio') as pin:netfd,pidfd=pin.netfd,pin.pidfd;pin.check()
  self.assertRaises(OSError,os.fstat,netfd);self.assertRaises(OSError,os.fstat,pidfd)
 @unittest.skipUnless(os.environ.get('GITHUB_ACTIONS')=='true' and os.geteuid()==0,'native Linux root CI only')
 def test_wrong_network_fd_denied(self):
  with n.PinnedNetwork(self.real_binding(),'minio') as pin:
   b=self.real_binding();b['targets']['minio']['process']['namespaces']['net'][1]+=1
   self.assertRaises(ValueError,n.fd_check,b,'minio',pin.netfd,pin.pidfd)
 def test_child_output_is_bounded(self):
  with self.assertRaisesRegex(ValueError,'G0_NETWORK_CHILD_OUTPUT_LIMIT'):n.run_child([sys.executable,'-c','print("x"*9000)'],{'PATH':'/usr/bin:/bin'},(),3,lambda:None)
 def test_child_deadline_kills_session(self):
  started=time.monotonic()
  with self.assertRaisesRegex(ValueError,'G0_NETWORK_CHILD_DEADLINE'):n.run_child([sys.executable,'-c','import time;time.sleep(30)'],{'PATH':'/usr/bin:/bin'},(),.25,lambda:None)
  self.assertLess(time.monotonic()-started,3)
 @unittest.skipUnless(os.environ.get('GITHUB_ACTIONS')=='true' and os.geteuid()==0,'native Linux root CI only')
 def test_deadline_also_kills_descendant(self):
  file=self.root/'descendant.pid';code='import subprocess,time;from pathlib import Path;p=subprocess.Popen(["/usr/bin/python3","-c","import time;time.sleep(30)"]);Path('+repr(str(file))+').write_text(str(p.pid));time.sleep(30)'
  with self.assertRaisesRegex(ValueError,'G0_NETWORK_CHILD_DEADLINE'):n.run_child([sys.executable,'-c',code],{'PATH':'/usr/bin:/bin'},(),1,lambda:None)
  pid=int(file.read_text());until=time.monotonic()+3
  while True:
   try:dead=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(') ',1)[1].split()[0]=='Z'
   except FileNotFoundError:dead=True
   if dead:break
   self.assertLess(time.monotonic(),until);time.sleep(.05)
 @unittest.skipUnless(os.environ.get('GITHUB_ACTIONS')=='true' and os.geteuid()==0,'native Linux root CI only')
 def test_owner_exit_during_child_holds_without_replay(self):
  owner=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
  try:
   b=self.real_binding();b['targets']['minio']['process']=n.process_pin(owner.pid)
   with n.PinnedNetwork(b,'minio') as pin:
    owner.terminate();owner.wait(timeout=3);self.assertRaises((ValueError,OSError),pin.check)
  finally:
   if owner.poll() is None:owner.kill();owner.wait()
 def test_wrong_child_route_and_hostname_are_not_fallbacks(self):
  for c in [{'connection':{'endpoint':'http://example.test:9000'}},{'connection':{'endpoint':'http://127.0.0.1:9000/path'}}]:self.assertRaises(ValueError,n.loopback_config,'s3',c)

if __name__=='__main__':unittest.main()
