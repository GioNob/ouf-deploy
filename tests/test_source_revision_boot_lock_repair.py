import copy,hashlib,importlib.util,json,os,re,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
fixtures=module('boot_read_fixtures',ROOT/'tests/test_source_revision_boot_guard_read.py')
repair=module('lock_repair',ROOT/'scripts/repair-semantic-boot-lock.py')

class Recovery(unittest.TestCase):
 def setUp(self):
  self.fixture=fixtures.Reader('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  self.reader=fixtures.r;self.selection,self.observe,self.ownerpath,_=self.fixture.fixture()
  owner=json.loads(self.ownerpath.read_bytes());self.lock=Path(owner['commonLockFile']);self.lock.unlink()
  journal=Path(owner['journalFile']);stored=json.loads(journal.read_bytes());stored.update(state='QUIESCED',startAuthorized=False);journal.write_text(json.dumps(stored))
  with patch.object(self.reader,'command',side_effect=self.observe):self.before=self.reader.collect(self.selection)
  self.before['units']['fixture-docker.service']['ActiveState']='inactive'
  # The fixture intentionally rejects the bootstrap kernel; transport is simulated here only.
  # The actual pinned native owner validator is exercised unmodified after lock provisioning.
  self.before['nativeBootValidation']={'passed':True,'metadata':True}
  ctx=self.fixture.tmp/'case';self.recovery={'schema':'ouf.semantic-boot-lock-recovery-selection.v1',
   'expectedBootProfileSha256':self.before['loadedBinding']['sha256'],
   'expectedUnitHashes':{self.selection['unitFiles'][0]:repair.sha(Path(self.selection['unitFiles'][0]).read_bytes())},
   'volatileRoots':['/run'],'tmpfilesRule':str(ctx/'tmpfiles.conf'),'tmpfilesExecutable':'/usr/bin/systemd-tmpfiles',
   'tmpfilesSetupUnit':'systemd-tmpfiles-setup.service','systemctl':'/usr/bin/systemctl',
   'systemdAnalyze':'/usr/bin/systemd-analyze','unitFilesToVerify':self.selection['unitFiles'],
   'dropins':{unit:str(ctx/(unit+'.d')/'20-lock.conf')for unit in ('fixture-guard.service','fixture-docker.service')},
   'incidentPointer':str(ctx/'incident.json')}
 def planned(self):
  with patch.object(self.reader,'collect',return_value=copy.deepcopy(self.before)):
   return repair.plan(self.reader,self.selection,self.recovery)
 def after(self):
  after=copy.deepcopy(self.before);after['nativeOwnerReadConfiguration']={'passed':True}
  after['units']['fixture-docker.service']['ActiveState']='active';after['units']['fixture-guard.service']['Result']='success'
  after['ownedTableFamilies']=['bridge','inet'];return after
 def manager(self,argv):
  if argv[0]=='/usr/bin/systemd-tmpfiles':return repair.invoke(argv)
  if len(argv)>1 and argv[1]=='show':
   return ('After=systemd-tmpfiles-setup.service\nRequires=systemd-tmpfiles-setup.service\nNeedDaemonReload=no\nDropInPaths='+self.recovery['dropins'][argv[-1]]+'\n').encode()
  return b''
 def test_plan_has_no_effect_and_rejects_drift(self):
  before={str(p):p.read_bytes()for p in self.fixture.tmp.rglob('*')if p.is_file()}
  self.planned();self.assertEqual(before,{str(p):p.read_bytes()for p in self.fixture.tmp.rglob('*')if p.is_file()})
  for key,changed in (('nftExecutableMatches',False),('ownedTableFamilies',['inet']),('knownBootSource',False)):
   old=self.before[key];self.before[key]=changed
   with self.assertRaises(ValueError):self.planned()
   self.before[key]=old
 def test_existing_lock_and_symlink_are_never_replaced(self):
  self.lock.write_bytes(b'keep')
  with self.assertRaises(ValueError):self.planned()
  self.assertEqual(self.lock.read_bytes(),b'keep');self.lock.unlink();self.lock.symlink_to(self.ownerpath)
  with self.assertRaises(ValueError):self.planned()
  self.assertTrue(self.lock.is_symlink())
 def test_recovery_delivery_pins_and_stops_before_import_on_tamper(self):
  launch=(ROOT/'scripts/launch-semantic-boot-lock-recovery-20261018.sh').read_text()
  loader=re.search(r'(?ms)^import hashlib,json,os,re,signal,stat,sys,traceback,types\n.*?(?=^OUF_VERIFIED_BOOT_RECOVERY$)',launch).group()
  for path in ('scripts/read-source-revision-boot-guard.py','scripts/repair-semantic-boot-lock.py',
               'releases/source-revision-boot-read-selection-20261018.json','releases/semantic-boot-lock-recovery-selection-20261018.json'):
   self.assertIn(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),loader)
  delivery=self.fixture.tmp/'delivery';delivery.mkdir();(delivery/'reader.py').write_text('PRIVATE_CANARY')
  result=subprocess.run([sys.executable,'-I','-B','-S','-',str(delivery)],input=loader.encode(),capture_output=True,timeout=10)
  self.assertEqual(result.returncode,2);self.assertNotIn(b'PRIVATE_CANARY',result.stdout+result.stderr)
  self.assertEqual(json.loads(result.stdout)['reason'],'DELIVERY_CHANGED')
  self.assertFalse(Path(self.recovery['incidentPointer']).exists())
 def test_real_systemd_ordering_is_acyclic(self):
  value=self.planned();units=self.fixture.tmp/'units';units.mkdir()
  for unit,extra in (('fixture-docker.service',''),('fixture-guard.service','Before=fixture-docker.service\n'),
                     ('systemd-tmpfiles-setup.service','')):
   (units/unit).write_text('[Unit]\nDefaultDependencies=no\n'+extra+'[Service]\nType=oneshot\nExecStart=/usr/bin/true\nRemainAfterExit=yes\n')
  for unit,path in self.recovery['dropins'].items():
   directory=units/(unit+'.d');directory.mkdir();(directory/'20-lock.conf').write_bytes(value['files'][Path(path)])
  result=subprocess.run(['/usr/bin/systemd-analyze','verify','--man=no',str(units/'fixture-docker.service'),
     str(units/'fixture-guard.service'),str(units/'systemd-tmpfiles-setup.service')],capture_output=True,
     env={'PATH':'/usr/bin:/bin','LC_ALL':'C','SYSTEMD_UNIT_PATH':str(units)},timeout=20)
  self.assertEqual(result.returncode,0,result.stderr.decode())
 def test_actual_tmpfiles_native_owner_and_simulated_manager_recovery(self):
  value=self.planned();calls=[]
  def call(argv,timeout=20):
   calls.append(argv)
   return self.manager(argv)
  with patch.object(self.reader,'collect',return_value=self.after()):result=repair.apply(self.reader,value,call)
  self.assertTrue(result['complete'],result);self.assertFalse(result['applicationReadinessProven'])
  self.assertEqual([c[1]for c in calls],['verify','--create','daemon-reload','show','show','start'])
  self.assertEqual(json.loads(Path(result['contextPath'],'journal.json').read_bytes())['phase'],'COMPLETE')
  inode=self.lock.stat().st_ino;self.lock.write_bytes(b'kept, never truncated')
  repair.invoke(['/usr/bin/systemd-tmpfiles','--create',self.recovery['tmpfilesRule']])
  self.assertEqual(self.lock.read_bytes(),b'kept, never truncated');self.assertEqual(self.lock.stat().st_ino,inode)
 def test_ambiguous_start_is_not_retried_or_rolled_back(self):
  value=self.planned();calls=[]
  def call(argv,timeout=20):
   calls.append(argv)
   if argv[1]=='start':raise subprocess.TimeoutExpired(argv,timeout)
   return self.manager(argv)
  result=repair.apply(self.reader,value,call)
  self.assertFalse(result['complete']);self.assertEqual(result['phase'],'DOCKER_START_INTENT')
  self.assertTrue(result['reconciliationRequired']);self.assertEqual(len([c for c in calls if c[1]=='start']),1)
  self.assertTrue(self.lock.exists());self.assertTrue(Path(self.recovery['incidentPointer']).exists())
  with self.assertRaises(ValueError):self.planned()
 def test_native_validator_failure_prevents_docker_start(self):
  value=self.planned();calls=[]
  # Change a sealed native source after preparation: no patched validation accepts it.
  source=Path(value['bootBinding']['source']).parents[1]/'tools/semantic_provider_dns.py'
  source.write_bytes(b'changed')
  def call(argv,timeout=20):
   calls.append(argv)
   if argv[1]=='verify':return b''
   if argv[0]=='/usr/bin/systemd-tmpfiles':return repair.invoke(argv,timeout)
   raise AssertionError('manager must not be called')
  result=repair.apply(self.reader,value,call)
  self.assertFalse(result['complete']);self.assertEqual(len(calls),2)
 def test_revocation_in_readback_is_preserved(self):
  value=self.planned();after=self.after();after['ownerJournal']['metadata']['leaseAuthorized']=True
  def call(argv,timeout=20):
   return self.manager(argv)
  with patch.object(self.reader,'collect',return_value=after):result=repair.apply(self.reader,value,call)
  self.assertFalse(result['complete']);self.assertEqual(result['phase'],'READBACK')
 def test_missing_effective_ordering_prevents_start(self):
  value=self.planned();calls=[]
  def call(argv,timeout=20):
   calls.append(argv)
   if argv[1]=='show':return b'After=\nRequires=\nDropInPaths=\nNeedDaemonReload=no\n'
   return self.manager(argv)
  result=repair.apply(self.reader,value,call)
  self.assertFalse(result['complete']);self.assertFalse(any(c[1]=='start'for c in calls))

if __name__=='__main__':unittest.main()
