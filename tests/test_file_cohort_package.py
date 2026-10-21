import importlib.util,json,tempfile,unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('cohort',Path(__file__).parents[1]/'scripts/assemble-file-cohort.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

class CohortIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.parts=self.root/'parts';self.parts.mkdir()
        self.lock=json.loads(c.LOCK_PATH.read_text())
        for row in self.lock['modules']:
            d=self.parts/row['module'];d.mkdir()
            manifest={'module':row['module'],'sourceCommit':row['commit'],'repository':'GioNob/'+row['repository'],
                      'artifactKind':row['kind'],'cohortSourceLockSha256':c.sha(c.LOCK_PATH),
                      'scanGate':'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED','targetApplyAuthorized':False,
                      'runtimeAuthorityIssued':False,'imageId':'sha256:'+'a'*64}
            (d/'candidate-manifest.json').write_text(json.dumps(manifest))
            (d/'artifact').write_bytes(b'disposable fixture')
            members={'source.tar','source-inventory.json','trivy-image.json'}
            if row['kind']=='DOCKER_SAVE':
                members|={'image.docker.tar','package-record.json','ouf-mcp' if row['module']=='mcp' else 'application.jar'}
            else:members|={'routes.file-loop.json','compiled-route-declarations.json'}
            for member in members:(d/member).write_bytes(b'explicit disposable package member fixture')

            if row['module']=='semantic':
                (d/'package-record.pre-export.json').write_text('{}')
                (d/'independent-rootfs-seal.json').write_text(json.dumps({'imageId':manifest['imageId'],
                    'sourceCommit':row['commit'],'javaStarted':False,'targetAcceptance':False,
                    'packageRecordHash':c.sha(d/'package-record.pre-export.json')}))
                (d/'file-first-four-mount-boot.json').write_text(json.dumps({'imageId':manifest['imageId'],
                    'status':'DISPOSABLE_BOOT_PASSED','mountCount':4,'providerEnabled':False,'discoveryWorkerEnabled':False}))
            self.rehash(d)
    def rehash(self,d):
        (d/'SHA256SUMS').write_text(''.join(c.sha(p)+'  '+p.name+'\n' for p in sorted(d.iterdir()) if p.name!='SHA256SUMS'))
    def test_exact_full_cohort_assembles(self):
        result=c.assemble(self.parts,self.root/'out')
        self.assertEqual(len(result['modules']),6)
        self.assertFalse(result['runtimeAuthorityIssued'])
    def test_missing_concrete_image_or_binary_cannot_be_hidden_by_valid_hashes(self):
        d=self.parts/'mcp';(d/'image.docker.tar').unlink();self.rehash(d)
        with self.assertRaisesRegex(ValueError,'CONCRETE_MODULE_DELIVERY'):c.assemble(self.parts,self.root/'out')
    def test_staged_old_three_modules_cannot_assemble(self):
        import shutil
        for name in ['ingestion','onboarding','udp']:shutil.rmtree(self.parts/name)
        with self.assertRaisesRegex(ValueError,'EXACT_SIX'):c.assemble(self.parts,self.root/'out')
    def test_hash_valid_stale_source_is_rejected(self):
        d=self.parts/'semantic';p=d/'candidate-manifest.json';v=json.loads(p.read_text());v['sourceCommit']='bdfe0f75a5fc4790a5c5ff36e201c3d99713ecc0';p.write_text(json.dumps(v));self.rehash(d)
        with self.assertRaisesRegex(ValueError,'MIXED_OR_STALE'):c.assemble(self.parts,self.root/'out')
    def test_changed_scanned_bytes_are_rejected(self):
        (self.parts/'mcp'/'artifact').write_text('changed')
        with self.assertRaisesRegex(ValueError,'HASH_MISMATCH'):c.assemble(self.parts,self.root/'out')
    def test_extra_unhashed_file_is_rejected(self):
        (self.parts/'gateway'/'unlisted').write_text('extra')
        with self.assertRaisesRegex(ValueError,'UNDECLARED'):c.assemble(self.parts,self.root/'out')
    def test_symlink_is_rejected(self):
        d=self.parts/'udp';(d/'link').symlink_to('artifact')
        with self.assertRaisesRegex(ValueError,'SYMLINK'):c.assemble(self.parts,self.root/'out')
    def test_seven_mount_old_boot_is_rejected(self):
        d=self.parts/'semantic';p=d/'file-first-four-mount-boot.json';v=json.loads(p.read_text());v['mountCount']=7;p.write_text(json.dumps(v));self.rehash(d)
        with self.assertRaisesRegex(ValueError,'EXACT_FILE_FIRST'):c.assemble(self.parts,self.root/'out')
    def test_other_cohort_source_lock_is_rejected(self):
        d=self.parts/'onboarding';p=d/'candidate-manifest.json';v=json.loads(p.read_text());v['cohortSourceLockSha256']='f'*64;p.write_text(json.dumps(v));self.rehash(d)
        with self.assertRaisesRegex(ValueError,'MIXED_OR_STALE'):c.assemble(self.parts,self.root/'out')

if __name__=='__main__':unittest.main()
