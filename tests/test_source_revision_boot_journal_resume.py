import copy,importlib.util,json,os,subprocess,tempfile,unittest,uuid,shutil
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
fixtures=load('boot_journal_fixtures',ROOT/'tests/test_source_revision_boot_guard_read.py')
resume=load('boot_journal_resume',ROOT/'scripts/resume-semantic-boot-journal.py')

class Recovery(unittest.TestCase):
 def setUp(self):
  self.fixture=fixtures.Reader('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  self.reader=fixtures.r;self.selection,self.observe,self.ownerpath,_=self.fixture.fixture()
  owner=json.loads(self.ownerpath.read_bytes());self.owner=owner
  previouslock=Path(owner['commonLockFile']);lock=self.fixture.file(self.fixture.tmp/'runtime/guard.lock',previouslock.read_bytes())
  previouslock.unlink();owner['commonLockFile']=str(lock)
  state={'schema':'ouf.semantic-lease-coordination.v1',**owner['binding'],
    'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[]}
  # Complete binding is required by the successor, as by the original native Coordinator.
  owner['binding'].update(transactionId='d'*64,configurationHash='e'*64)
  state.update(owner['binding']);Path(owner['journalFile']).write_text(json.dumps(state))
  self.ownerpath.write_text(json.dumps(owner))
  bootprofile=Path(self.fixture.tmp/'case/boot-profile.json');bp=json.loads(bootprofile.read_bytes())
  bp['coordinatedConfigurationHash']=self.reader.sha(self.ownerpath.read_bytes())
  boot=Path(bp['bootConfiguration']);bv=json.loads(boot.read_bytes());bv['lockFile']=str(lock);boot.write_text(json.dumps(bv))
  bp['bootConfigurationHash']=self.reader.sha(boot.read_bytes())
  bootprofile.write_text(json.dumps(bp));binding={'profile':str(bootprofile),'sha256':self.reader.sha(bootprofile.read_bytes()),
    'source':str(self.fixture.tmp/'case/source/scripts/run_semantic_coordinated_boot_guard.py')}
  bj=Path(bv['journalFile']);j=json.loads(bj.read_bytes());j.update(transactionId=bv['transactionId'],configurationHash=bp['bootConfigurationHash'])
  bj.write_text(json.dumps(j))
  with patch.object(self.reader,'command',side_effect=self.observe):report=self.reader.collect(self.selection)
  # Manager transport and minimal bootstrap kernel are fixtures; use explicit observed metadata.
  report.update(readComplete=True,loadedBinding=binding,knownBootSource=True,nftExecutableMatches=True,
    compilerMatchesProfile=True,restorerMatchesProfile=True,pairedConfigurationMatches={'all':True},
    ownerSourceHashesMatch={'fixture':{'passed':True,'metadata':{'matches':True}}},
    nativeOwnerReadConfiguration={'passed':True},nativeBootValidation={'passed':True},ownedTableFamilies=[])
  report['units']={'fixture-docker.service':{'ActiveState':'inactive'},'fixture-guard.service':{'ActiveState':'failed','Result':'exit-code'}}
  self.before=report
  case=self.fixture.tmp/'stopped';case.mkdir();self.case=case
  artifact=self.fixture.file(self.fixture.tmp/'case/installed.conf',b'installed')
  self.fixture.file(self.fixture.tmp/'case/99-lock.conf',b'lock dependency')
  review={'bootBinding':binding,'artifactHashes':{str(artifact):self.reader.sha(artifact.read_bytes())},'lockFile':owner['commonLockFile']}
  self.fixture.data(case/'review.json',review)
  self.fixture.data(case/'journal.json',{'schema':'ouf.semantic-boot-lock-recovery-journal.v1','phase':'DOCKER_START_INTENT','runtimeAuthorityIssued':False})
  pointer=self.fixture.data(self.fixture.tmp/'pointer.json',{'contextPath':str(case),'reviewSha256':self.reader.sha((case/'review.json').read_bytes())})
  self.profile={'schema':'ouf.boot-journal-recovery-selection.v1','incidentPointer':str(pointer),'stoppedContext':str(case),
    'successorClaim':'successor.json','expectedBootBinding':binding,'installedArtifacts':review['artifactHashes'],
    'originalUnitHashes':{},'managedDropin':str(self.fixture.tmp/'case/new-journal.conf'),'existingGuardDropinName':'99-lock.conf',
    'expectedSandbox':{'ProtectSystem':'strict','ProtectHome':'yes','PrivateTmp':'yes','RuntimeDirectoryPreserve':'yes','ReadWritePaths':'/run/fixture-runtime'},
    'systemdAnalyze':'/usr/bin/systemd-analyze','unitFilesToVerify':self.selection['unitFiles']}
  self.props={**self.profile['expectedSandbox'],'ReadOnlyPaths':'','NeedDaemonReload':'no','DropInPaths':'old.conf','ActiveState':'failed','SubState':'failed','Result':'exit-code'}
 def planned(self):
  with patch.object(self.reader,'collect',return_value=copy.deepcopy(self.before)),patch.object(resume,'properties',return_value=copy.deepcopy(self.props)):
   return resume.preflight(self.reader,self.selection,self.profile)
 def test_read_only_reconciliation_and_minimal_writable_parent(self):
  before={p:p.read_bytes()for p in self.fixture.tmp.rglob('*')if p.is_file()}
  value=self.planned();self.assertEqual(before,{p:p.read_bytes()for p in self.fixture.tmp.rglob('*')if p.is_file()})
  text=value['raw'].decode();self.assertIn('ReadWritePaths='+str(Path(self.owner['journalFile']).parent)+'\n',text)
  self.assertNotIn('\nProtectSystem=',text);self.assertNotIn(str(self.owner['journalFile']),value['siblings'])
  self.assertIn(str(self.fixture.tmp/'case/source'),value['siblings']);self.assertIn(str(self.ownerpath),value['siblings'])
 def test_rejects_wrong_context_or_new_authority(self):
  old=self.profile['stoppedContext'];self.profile['stoppedContext']+='/other'
  with self.assertRaises(ValueError):self.planned()
  self.profile['stoppedContext']=old
  path=Path(self.owner['journalFile']);value=json.loads(path.read_bytes());value['leaseAuthorized']=True;path.write_text(json.dumps(value))
  with self.assertRaises(ValueError):self.planned()
 def test_stopped_history_and_lock_preserved_on_ambiguous_start(self):
  value=self.planned();old=(self.case/'journal.json').read_bytes();inode=value['lock'].stat().st_ino;calls=[]
  afterprops={**self.props,'ReadWritePaths':self.props['ReadWritePaths']+' '+str(value['journal'].parent),
    'ReadOnlyPaths':' '.join(value['siblings']),'DropInPaths':'old.conf '+str(value['target'])}
  def call(argv,**kwargs):
   calls.append(argv)
   if argv[1]=='start':raise subprocess.TimeoutExpired(argv,120)
   return subprocess.CompletedProcess(argv,0,b'',b'')
  with patch.object(resume,'properties',side_effect=[self.props,afterprops]),patch('subprocess.run',side_effect=call):
   result=resume.apply(self.reader,value)
  self.assertFalse(result['complete']);self.assertEqual(result['phase'],'DOCKER_START_INTENT')
  self.assertEqual((self.case/'journal.json').read_bytes(),old);self.assertEqual(value['lock'].stat().st_ino,inode)
  self.assertTrue((self.case/'successor.json').exists());self.assertEqual(sum(c[1]=='start'for c in calls),1)
  with self.assertRaises(ValueError):self.planned()
 def test_does_not_start_if_protection_or_loaded_paths_differ(self):
  value=self.planned();calls=[];bad={**self.props,'ProtectSystem':'no'}
  with patch.object(resume,'properties',side_effect=[self.props,bad]),patch('subprocess.run',side_effect=lambda argv,**kw:(calls.append(argv)or subprocess.CompletedProcess(argv,0,b'',b''))):
   result=resume.apply(self.reader,value)
  self.assertFalse(result['complete']);self.assertFalse(any(c[1]=='start'for c in calls))

class ActualSystemdSandbox(unittest.TestCase):
 def test_actual_native_atomic_journal_with_sibling_mount_protection(self):
  root=Path(tempfile.mkdtemp(prefix='ouf-journal-sandbox-ci-',dir='/var/lib'));root.chmod(0o700)
  self.addCleanup(shutil.rmtree,root)
  source=root/'native.py';source.write_bytes((Path(os.environ['OUF_GATEWAY_SOURCE'])/'tools/semantic_provider_lease_coordination.py').read_bytes());source.chmod(0o600)
  journal=root/'coordination-journal.json';journal.write_text('{"state":"QUIESCED","startAuthorized":false}');journal.chmod(0o600)
  sealed=root/'sealed-profile.json';sealed.write_text('{"private":"fixture"}');sealed.chmod(0o600)
  entry=root/'entry.py';entry.write_text('''import errno,json,sys,types
from pathlib import Path
root=Path(sys.argv[1]);expected=sys.argv[2]=='yes'
m=types.ModuleType('actual_native_coordination');exec(compile((root/'native.py').read_bytes(),str(root/'native.py'),'exec'),m.__dict__)
owner=m.PrivateJournal(root/'coordination-journal.json');before=owner.read();changed={**before,'state':'BLOCKED'}
try:
 owner.write(before,changed);writable=True
except OSError as error:
 assert error.errno==errno.EROFS;writable=False
assert writable==expected
try:
 (root/'sealed-profile.json').write_text('must be denied');protected=False
except OSError as error:
 assert error.errno==errno.EROFS;protected=True
assert protected
print(json.dumps({'nativeJournalWritable':writable,'sealedSiblingProtected':protected,'authorityIssued':False}))
''');entry.chmod(0o600)
  for writable in (False,True):
   command=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--collect','--unit=ouf-journal-ci-'+uuid.uuid4().hex,
     '--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes']
   if writable:command+=['--property=ReadWritePaths='+str(root),'--property=ReadOnlyPaths='+' '.join(map(str,(source,sealed,entry)))]
   command+=['/usr/bin/python3','-I','-B','-S',str(entry),str(root),'yes'if writable else'no']
   result=subprocess.run(command,capture_output=True,timeout=40)
   self.assertEqual(result.returncode,0,result.stderr.decode());report=json.loads(result.stdout)
   self.assertEqual(report['nativeJournalWritable'],writable);self.assertTrue(report['sealedSiblingProtected'])
  self.assertEqual(json.loads(journal.read_bytes())['state'],'BLOCKED')
  self.assertEqual(sealed.read_text(),'{"private":"fixture"}')

if __name__=='__main__':unittest.main()
