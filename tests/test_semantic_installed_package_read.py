import importlib.util,io,json,pathlib,tempfile,unittest,warnings,zipfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
path=ROOT/'scripts/read-semantic-installed-package-20261108.py'
if not path.exists():path=pathlib.Path(__file__).with_name('read.py')
spec=importlib.util.spec_from_file_location('reader',path);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class PackageRead(unittest.TestCase):
 def fixture(self,count=12):
  files={f'V{i}__fixture.sql':f'-- migration {i}\nSELECT {i};\n'.encode() for i in range(1,count+1)}
  expected={'files':{k:r.sha(v) for k,v in files.items()},'applicationYamlSha256':r.sha(b'fixture: true\n')}
  entries={r.PREFIX+k:v for k,v in files.items()};entries['BOOT-INF/classes/application.yml']=b'fixture: true\n'
  entries['META-INF/MANIFEST.MF']=b'Start-Class: fixture.Main\nSpring-Boot-Version: 4.0.8\nBuild-Jdk-Spec: 21\nSecret-Fixture: never-print-this\n'
  return entries,expected
 def summarize(self,entries,expected):
  stream=io.BytesIO()
  with zipfile.ZipFile(stream,'w') as z:
   for name,raw in entries.items():z.writestr(name,raw)
  stream.seek(0)
  with zipfile.ZipFile(stream) as z:return r.summarize(z,expected)
 def test_complete_and_missing_versions_reported_without_claiming_behavior(self):
  entries,expected=self.fixture();complete=self.summarize(entries,expected)
  self.assertTrue(complete['allMigrationFilesMatchCandidate']);self.assertFalse(complete['classPresenceProvesRuntimeBehavior'])
  for i in (11,12):del entries[r.PREFIX+f'V{i}__fixture.sql']
  result=self.summarize(entries,expected)
  self.assertEqual(result['missingCandidateFiles'],['V11__fixture.sql','V12__fixture.sql']);self.assertFalse(result['allMigrationFilesMatchCandidate'])
  self.assertNotIn('never-print-this',json.dumps(result))
 def test_changed_and_additional_files_are_separate(self):
  entries,expected=self.fixture();entries[r.PREFIX+'V10__fixture.sql']=b'SELECT 999;'
  entries[r.PREFIX+'V13__extra.sql']=b'SELECT 13;'
  result=self.summarize(entries,expected)
  self.assertEqual(result['changedCandidateFiles'],['V10__fixture.sql']);self.assertEqual(result['additionalInstalledFiles'],['V13__extra.sql'])
  self.assertEqual(result['missingCandidateFiles'],[])
 def test_extra_repeatable_and_non_utf8_files_remain_visible(self):
  entries,expected=self.fixture();entries[r.PREFIX+'R__legacy.sql']=b'\xff'
  result=self.summarize(entries,expected)
  self.assertEqual(result['additionalInstalledFiles'],['R__legacy.sql'])
  row=next(x for x in result['migrations'] if x['name']=='R__legacy.sql')
  self.assertFalse(row['utf8Decodable']);self.assertIsNone(row['flywayStyleCrc32Utf8']);self.assertEqual(row['sha256'],r.sha(b'\xff'))
 def test_duplicate_or_unbounded_entries_rejected(self):
  entries,expected=self.fixture();stream=io.BytesIO()
  with warnings.catch_warnings():
   warnings.simplefilter('ignore')
   with zipfile.ZipFile(stream,'w') as z:z.writestr(r.PREFIX+'V1__fixture.sql',b'1');z.writestr(r.PREFIX+'V1__fixture.sql',b'2')
  stream.seek(0)
  with zipfile.ZipFile(stream) as z:
   with self.assertRaisesRegex(RuntimeError,'UNIQUE_BOUNDED'):r.summarize(z,expected)
  entries[r.PREFIX+'V1__fixture.sql']=b' '*2097153
  with self.assertRaisesRegex(RuntimeError,'TOO_LARGE'):self.summarize(entries,expected)
 def test_configuration_values_are_allowlisted(self):
  result=r.declarations({'SPRING_FLYWAY_ENABLED':'true','SPRING_FLYWAY_TARGET':'10','SPRING_FLYWAY_LOCATIONS':'private-secret','SPRING_PROFILES_ACTIVE':'private-secret','DATABASE_PASSWORD':'private-secret'})
  self.assertNotIn('private-secret',json.dumps(result));self.assertEqual(result['properties']['SPRING_FLYWAY_TARGET']['value'],'10')
 def test_file_identity_hash_and_crc_without_extraction(self):
  entries,expected=self.fixture()
  with tempfile.TemporaryDirectory() as tmp:
   path=pathlib.Path(tmp)/'application.jar'
   with zipfile.ZipFile(path,'w') as z:
    for k,v in entries.items():z.writestr(k,v)
   result=r.read_package(path,expected)
   self.assertEqual(result['jarSha256'],r.sha(path.read_bytes()));self.assertEqual(list(pathlib.Path(tmp).iterdir()),[path])
  self.assertEqual(r.crc(b'\xef\xbb\xbfA\r\nB\n'),r.crc(b'A\nB\r'))

if __name__=='__main__':unittest.main(verbosity=2)
