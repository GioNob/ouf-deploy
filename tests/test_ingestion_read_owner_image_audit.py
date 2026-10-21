import copy,gzip,hashlib,importlib.util,io,json,tarfile,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=module('audit',HERE/'audit.py');custody=module('image_custody_fixture',HERE/'image_custody.py')
def tar(entries):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w')as t:
  for name,raw,kind in entries:
   item=tarfile.TarInfo(name);item.mode=0o600;item.type=kind;item.size=len(raw)if kind==tarfile.REGTYPE else 0
   t.addfile(item,io.BytesIO(raw)if kind==tarfile.REGTYPE else None)
 return out.getvalue()
def jar():
 out=io.BytesIO();migration=b'-- public SQL fixture\n';cls=b'public-class-fixture'
 with zipfile.ZipFile(out,'w')as z:
  z.writestr('BOOT-INF/classes/db/migration/V1__fixture.sql',migration)
  for name in('GatewayReadReceiptVerifier','IngestionIamSecurityConfiguration','IngestionIamDisabledConfiguration'):
   z.writestr('BOOT-INF/classes/it/comune/trieste/ouf/ingestion/'+name+'.class',cls)
 raw=out.getvalue();metadata={'migrationInventory':{'V1__fixture.sql':m.sha(migration)},'applicationClasses':{n:m.sha(cls)for n in('GatewayReadReceiptVerifier','IngestionIamSecurityConfiguration','IngestionIamDisabledConfiguration')},'applicationJarSha256':m.sha(raw)}
 return raw,metadata

def image(root,extra=None):
 raw,metadata=jar();layer=tar([('app',b'',tarfile.DIRTYPE),('app/app.jar',raw,tarfile.REGTYPE)]+(extra or []))
 config={'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':['sha256:'+m.sha(layer)]},'config':{'User':'10002:10002','Entrypoint':['java','-jar','/app/app.jar'],'Labels':{'org.opencontainers.image.revision':'a'*40}}}
 config=json.dumps(config).encode();cid=m.sha(config);manifest=json.dumps([{'Config':cid+'.json','Layers':['layer.tar'],'RepoTags':['public:fixture']}]).encode()
 packed=tar([('manifest.json',manifest,tarfile.REGTYPE),(cid+'.json',config,tarfile.REGTYPE),('layer.tar',layer,tarfile.REGTYPE)])
 compressed=gzip.compress(packed,mtime=0);path=root/'image.tar.gz';path.write_bytes(compressed);path.chmod(0o600)
 metadata.update(imageArchiveBytes=len(compressed),imageArchiveSha256=m.sha(compressed),imageId='sha256:'+cid,sourceCommit='a'*40,imageUser='10002:10002',imageEntrypoint=['java','-jar','/app/app.jar'])
 return path,metadata
class Audit(unittest.TestCase):
 def test_real_gzip_tar_rootfs_jar_and_exact_migration_bytes(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   root=Path(d);path,metadata=image(root);before=path.read_bytes();result=m.candidate_audit(path,root,metadata,custody)
   self.assertTrue(result['imageAudit']['archiveByteCustodyProven']);self.assertTrue(result['candidateJar']['migrationFilesUnchanged']);self.assertFalse(result['candidateImageImported'])
   self.assertEqual(path.read_bytes(),before);self.assertEqual(list(root.iterdir()),[path])
 def test_changed_compressed_hash_or_jar_or_class_denies(self):
  for kind in('gzip','jar','class','migration','entrypoint'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory(dir=HERE)as d:
    root=Path(d);path,metadata=image(root)
    if kind=='gzip':metadata['imageArchiveSha256']='0'*64
    if kind=='jar':metadata['applicationJarSha256']='0'*64
    if kind=='class':metadata['applicationClasses']['GatewayReadReceiptVerifier']='0'*64
    if kind=='migration':metadata['migrationInventory']['V1__fixture.sql']='0'*64
    if kind=='entrypoint':metadata['imageEntrypoint']=['unreviewed']
    with self.assertRaises(ValueError):m.candidate_audit(path,root,metadata,custody)
 def test_whiteout_link_and_unsafe_path_denied_without_extraction(self):
  for extra in([('app/.wh.app.jar',b'',tarfile.REGTYPE)],[('app/app.jar',b'',tarfile.SYMTYPE)],[('../escape',b'bad',tarfile.REGTYPE)]):
   with self.subTest(extra=extra),tempfile.TemporaryDirectory(dir=HERE)as d:
    root=Path(d);path,metadata=image(root,extra)
    with self.assertRaises(ValueError):m.candidate_audit(path,root,metadata,custody)
    self.assertEqual(list(root.iterdir()),[path])
 def test_installed_jar_verifies_only_unchanged_iam_classes_but_all_sql(self):
  raw,metadata=jar();metadata['applicationClasses']['GatewayReadReceiptVerifier']='0'*64
  result=m.jar_inventory(raw,metadata,False);self.assertTrue(result['migrationFilesUnchanged']);self.assertFalse(result['candidateClassesVerified'])
  with self.assertRaises(ValueError):m.jar_inventory(raw,metadata,True)
 def test_deleted_or_extra_sql_or_duplicate_jar_member_denies(self):
  raw,metadata=jar()
  for kind in('missing','extra','duplicate'):
   out=io.BytesIO()
   with zipfile.ZipFile(io.BytesIO(raw))as old,zipfile.ZipFile(out,'w')as z:
    for item in old.infolist():
     if kind=='missing'and '/db/migration/'in item.filename:continue
     z.writestr(item.filename,old.read(item))
    if kind=='extra':z.writestr('BOOT-INF/classes/db/migration/V2__unexpected.sql',b'-- extra')
    if kind=='duplicate':z.writestr('duplicate',b'a');z.writestr('duplicate',b'b')
   with self.subTest(kind=kind),self.assertRaises(ValueError):m.jar_inventory(out.getvalue(),metadata,False)
if __name__=='__main__':unittest.main()
