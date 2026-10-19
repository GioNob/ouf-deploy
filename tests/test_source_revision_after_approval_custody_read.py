import hashlib,importlib.util,json,os,socket,tempfile,threading,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('custody_read',ROOT/'scripts/read-source-revision-after-approval-custody-20261019.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Read(unittest.TestCase):
 def temp(self):return tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent)))
 def test_public_pinned_metadata_matches_but_strict_native_private_custody_fails(self):
  with self.temp()as temp:
   path=Path(temp)/'policy.json';raw=b'{"private":"CREDENTIAL_CANARY"}';path.write_bytes(raw);path.chmod(0o644)
   result=m.probe(path,m.sha(raw));self.assertTrue(result['expectedHashMatches']);self.assertFalse(result['nativePrivateCustodyPass']);self.assertEqual(result['mode'],'0644');self.assertNotIn('CANARY',json.dumps(result));self.assertEqual(path.read_bytes(),raw)
   path.chmod(0o600);self.assertTrue(m.probe(path,m.sha(raw))['nativePrivateCustodyPass'])
 def test_untrusted_writable_or_linked_file_is_not_accepted_or_opened(self):
  with self.temp()as temp:
   path=Path(temp)/'file';path.write_bytes(b'CANARY');path.chmod(0o666);result=m.probe(path,m.sha(b'CANARY'));self.assertIsNone(result['expectedHashMatches']);self.assertFalse(result['nativePrivateCustodyPass'])
   link=Path(temp)/'link';link.symlink_to(path)
   with self.assertRaises(ValueError):m.probe(link,m.sha(b'CANARY'))
 def test_zero_and_claimed_effects_are_reported_without_accepting_or_replaying_authority(self):
  row={'schema':'ouf.source-revision-update-journal.v1','budgetReset':False,'effects':[],'authorityHash':'a'*64,'nextStage':0,'version':0,'expiresAt':time.time()-1,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
  result=m.journal_report(row,{},'a'*64);self.assertEqual(result['effectCount'],0);self.assertTrue(result['expiredByWallClock']);self.assertFalse(result['journalHashPrinted'])
  row['effects']=[{'stage':'onboarding.STOP_OLD','state':'CLAIMED'}];result=m.journal_report(row,{},'a'*64);self.assertEqual(result['effects'][0]['state'],'CLAIMED')
  with self.assertRaises(ValueError):m.journal_report(row,{},'b'*64)
 def test_inventory_preserves_known_authority_locks_and_rejects_unknown_or_symlink(self):
  with self.temp()as temp:
   root=Path(temp);p=root/'authority.json';p.write_bytes(b'{}');p.chmod(0o600);lock=root/'recovery.lock';lock.write_bytes(b'');lock.chmod(0o600)
   report=m.inventory(root);self.assertEqual(set(report),{'authority.json','recovery.lock'});self.assertNotIn('sha256',json.dumps(report))
   unknown=root/'unknown';unknown.write_bytes(b'CANARY');unknown.chmod(0o600)
   with self.assertRaises(ValueError):m.inventory(root)
   unknown.unlink();p.unlink();p.symlink_to(lock)
   with self.assertRaises(ValueError):m.inventory(root)
 def test_exact_plan_engine_get_reads_and_redacts_environment(self):
  with self.temp()as temp:
   root=Path(temp);path=root/'engine.sock';server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(path));path.chmod(0o600);server.listen();requests=[]
   actual={'Id':'a'*64,'Image':'sha256:fixture','Config':{'Env':['SECRET=CREDENTIAL_CANARY']},'HostConfig':{},'Mounts':[],'NetworkSettings':{},'State':{'Pid':123,'StartedAt':'fixture-generation','Running':True,'Paused':False,'Restarting':False}}
   expected={'containerId':actual['Id'],'imageId':actual['Image'],'pid':123,'startedAt':'fixture-generation','configHash':m.digest(actual['Config']),'hostConfigHash':m.digest({}),'mountsHash':m.digest([]),'networkSettingsHash':m.digest({})}
   st=path.stat();plan={'engine':{'socketPath':str(path),'socketBinding':[st.st_dev,st.st_ino,st.st_uid,st.st_gid,st.st_mode&0o777]},'replacements':{'mcp':{'oldRuntimeBinding':expected}},'unchangedApplications':{}}
   def serve():
    client,_=server.accept()
    with client:
     requests.append(client.recv(4096));raw=m.encoded(actual);client.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(raw)).encode()+b'\r\nConnection: close\r\n\r\n'+raw)
   thread=threading.Thread(target=serve);thread.start()
   try:result=m.observe_engine(plan)
   finally:thread.join(10);server.close()
   self.assertTrue(result['mcp']['identityMatchesExpected']);self.assertTrue(requests[0].startswith(b'GET /v1.44/containers/'+b'a'*64+b'/json '));self.assertNotIn('CANARY',json.dumps(result))
if __name__=='__main__':unittest.main()
