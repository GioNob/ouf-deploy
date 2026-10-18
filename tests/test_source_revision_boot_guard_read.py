import ast,hashlib,importlib.util,json,os,re,shutil,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-source-revision-boot-guard.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class Reader(unittest.TestCase):
 def setUp(self):
  self.tmp=Path(tempfile.mkdtemp(prefix='ouf-boot-read-',dir='/run'));self.addCleanup(shutil.rmtree,self.tmp)
 def file(self,path,raw=b'{}',mode=0o600):
  path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode);return path
 def data(self,path,value):return self.file(path,json.dumps(value).encode())
 def test_custody_links_modes_and_bounds(self):
  p=self.file(self.tmp/'value',b'private');self.assertEqual(r.read(p),b'private')
  with self.assertRaises(ValueError):r.read(p,2)
  p.chmod(0o622)
  with self.assertRaises(ValueError):r.read(p)
  p.chmod(0o600);alias=self.tmp/'alias';alias.symlink_to(p)
  with self.assertRaises(OSError):r.read(alias)
  alias.unlink();os.link(p,alias)
  with self.assertRaises(ValueError):r.read(p)
 def test_duplicate_and_hash_drift(self):
  with self.assertRaises(ValueError):r.parse(b'{"x":1,"x":2}')
  p=self.file(self.tmp/'value')
  with self.assertRaises(ValueError):r.sealed(p,'0'*64)
 def test_exact_unit_pair_binding(self):
  base=str(self.tmp);ctx=base+'/case';command=ctx+'/source/scripts/run_semantic_coordinated_boot_guard.py --configuration '+ctx+'/boot-profile.json --configuration-sha256 '+'a'*64+' ;'
  self.assertEqual(r.binding(command,base)['sha256'],'a'*64)
  for bad in (command+command,command.replace('/case/boot-profile','/other/boot-profile'),command.replace('a'*64,'a'*63)):
   with self.assertRaises(ValueError):r.binding(bad,base)
 def test_redaction_and_independent_failure(self):
  report={}
  def failed():raise ValueError('PRIVATE_CANARY')
  r.independent(report,'one',failed);r.independent(report,'two',lambda:True)
  self.assertTrue(report['two']['passed']);self.assertNotIn('PRIVATE_CANARY',json.dumps(report))
  self.assertEqual(r.failure(ValueError('nft executable drift'))['reason'],'NFT_EXECUTABLE_DRIFT')
 def test_operator_memory_loader_hashes_and_tamper_rejection(self):
  launcher=(ROOT/'scripts/launch-source-revision-boot-read-20261018.sh').read_text()
  loader=re.search(r'(?ms)^import hashlib,json,os,signal,stat,sys\n.*?(?=^OUF_VERIFIED_BOOT_READ$)',launcher).group()
  tree=ast.parse(loader);definition=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='verified')
  namespace={'hashlib':hashlib,'os':os,'stat':stat}
  exec(compile(ast.Module(body=[definition],type_ignores=[]),'<actual-memory-loader>','exec'),namespace)
  source=(ROOT/'scripts/read-source-revision-boot-guard.py').read_bytes()
  selection=(ROOT/'releases/source-revision-boot-read-selection-20261018.json').read_bytes()
  for raw in (source,selection):self.assertIn(hashlib.sha256(raw).hexdigest(),loader)
  path=self.file(self.tmp/'delivered',source)
  self.assertEqual(namespace['verified'](path,hashlib.sha256(source).hexdigest()),source)
  path.write_bytes(b'PRIVATE_CANARY')
  with self.assertRaises(ValueError):namespace['verified'](path,hashlib.sha256(source).hexdigest())
  reply=subprocess.run([sys.executable,'-I','-B','-S','-',str(path),str(path)],input=loader.encode(),capture_output=True,timeout=10)
  self.assertEqual(reply.returncode,2);self.assertNotIn(b'PRIVATE_CANARY',reply.stdout+reply.stderr)
  self.assertEqual(json.loads(reply.stdout)['runtimeMutations'],0)
 def fixture(self):
  native=Path(os.environ['OUF_GATEWAY_SOURCE']);ctx=self.tmp/'case';source=ctx/'source'
  for path in native.joinpath('scripts').glob('*.py'):
   if path.name in ('run_semantic_coordinated_lease_owner.py','run_semantic_coordinated_boot_guard.py','restore_semantic_runtime_boot_guard.py'):
    self.file(source/'scripts'/path.name,path.read_bytes())
  cli=r.load_known(source/'scripts/run_semantic_coordinated_lease_owner.py',r.KNOWN['owner'],'fixture_read_only_owner')
  for name in cli.FILES:self.file(source/name,(native/name).read_bytes())
  nft=self.file(ctx/'nft',b'fixture only: never executed',0o700)
  common=self.file(ctx/'common.lock');journal=self.data(ctx/'owner-journal.json',{'state':'BLOCKED','leaseAuthorized':False,'secret':'PRIVATE_CANARY'})
  bootjournal=self.data(ctx/'boot-journal.json',{'schema':'ouf.semantic-runtime-transition.v1','state':'RUNTIME_EMPTY','startAuthorized':False})
  kernel={'tableName':'fixture_guard','providerFlows':[]}
  owner={'schema':'ouf.semantic-coordinated-owner-runtime.v1','kernel':kernel,'dns':{},'expectedStructureHash':'a'*64,
   'nftPath':str(nft),'nftSha256':r.sha(nft.read_bytes()),'readBudgetSeconds':5,'pollSeconds':5,
   'commonLockFile':str(common),'journalFile':str(journal),'binding':{'leaseStructureHash':'a'*64},
   'sourceHashes':{name:r.sha((source/name).read_bytes())for name in cli.FILES}}
  ownerpath=self.data(ctx/'owner.json',owner)
  boot={'schema':'deliberately-invalid-for-read-only-failure-test','nftPath':str(nft),'kernel':kernel,
   'compilerFile':str(source/'tools/materialize_southbound_kernel.py'),'compilerHash':r.KNOWN['compiler'],
   'expectedFootprint':'b'*64,'journalFile':str(bootjournal),'transactionId':'c'*64,'lockFile':str(common)}
  bootpath=self.data(ctx/'boot.json',boot);restorer=source/'scripts/restore_semantic_runtime_boot_guard.py'
  profile={'schema':'ouf.semantic-coordinated-boot-profile.v1',
   'coordinatedConfiguration':str(ownerpath),'coordinatedConfigurationHash':r.sha(ownerpath.read_bytes()),
   'bootConfiguration':str(bootpath),'bootConfigurationHash':r.sha(bootpath.read_bytes()),
   'bootGuardFile':str(restorer),'bootGuardHash':r.sha(restorer.read_bytes())}
  profilepath=self.data(ctx/'boot-profile.json',profile)
  command=str(source/'scripts/run_semantic_coordinated_boot_guard.py')+' --configuration '+str(profilepath)+' --configuration-sha256 '+r.sha(profilepath.read_bytes())+' ;'
  unit=self.file(ctx/'unit',b'[Service]\n')
  selection={'schema':'ouf.source-revision-private-boot-read-selection.v1','privateParent':str(self.tmp),
    'systemctl':'/usr/bin/systemctl','guardUnit':'fixture-guard.service','dockerUnit':'fixture-docker.service','unitFiles':[str(unit)]}
  def observe(argv,maximum=1048576):
   if argv[0]=='/usr/bin/systemctl':
    prop='ExecStart'if argv[-1]=='fixture-guard.service'else'ExecStartPre'
    return subprocess.CompletedProcess(argv,0,('ActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStatus=1\n'+prop+'='+command+'\n').encode(),b'')
   self.assertEqual(argv,[str(nft),'-j','list','tables'])
   return subprocess.CompletedProcess(argv,0,b'{"nftables":[]}',b'')
  return selection,observe,ownerpath,nft
 def test_actual_pinned_native_read_failure_and_remaining_checks(self):
  selection,observe,owner,nft=self.fixture()
  before={p:p.read_bytes()for p in self.tmp.rglob('*')if p.is_file()}
  with patch.object(r,'command',side_effect=observe):report=r.collect(selection)
  self.assertTrue(report['readComplete'],report);self.assertTrue(report['nativeOwnerReadConfiguration']['passed'])
  self.assertFalse(report['nativeBootValidation']['passed']);self.assertEqual(report['nativeBootValidation']['reason'],'BOOT_PROFILE_INVALID')
  self.assertEqual(report['ownedTableFamilies'],[]);self.assertFalse(report['guardRecoveryProven'])
  self.assertEqual(before,{p:p.read_bytes()for p in self.tmp.rglob('*')if p.is_file()})
  self.assertNotIn('PRIVATE_CANARY',json.dumps(report));self.assertEqual(report['guardExecutions'],0)
 def test_nft_drift_is_reported_and_binary_is_not_executed(self):
  selection,observe,owner,nft=self.fixture();nft.write_bytes(b'changed executable')
  with patch.object(r,'command',side_effect=observe)as call:report=r.collect(selection)
  self.assertFalse(report['nftExecutableMatches']);self.assertEqual(call.call_count,2)
  self.assertEqual(report['nativeOwnerReadConfiguration']['reason'],'NFT_EXECUTABLE_DRIFT')
  self.assertTrue(report['readComplete']);self.assertNotIn('ownedTableFamilies',report)

if __name__=='__main__':unittest.main()
