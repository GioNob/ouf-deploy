#!/usr/bin/env python3
"""Verify and extract only pinned CI files, without Docker/image execution."""
import hashlib,json,os,sys,tarfile,zipfile
from pathlib import Path
ZIP_HASH='074bde3ecc348c9c9481683412f2c1ac376b2b2fdae409d688d71397a8c322e8'
ZIP_BYTES=210895493
MANIFEST_HASH='63d96c781cf88f55f672ac65d86de9e7c4b87056801dfd1c32129e638ba32553'
IMAGE_HASH='54d86bbcd2ea47fdbda133699b914674c766bdef8554132a308eae36d38f3358'
IMAGE_BYTES=210893865
JAR_HASH='70c16461ae2a381d9baf3e8788f1403e9a925d86be4802ea928477db93b84f52'
JAR_BYTES=109135566
LAYER='blobs/sha256/b71bc6bd48739a3f761f67280370b1238589eb61ee30ea267d6c687b23de6616'
SOURCE='1b1222ceaa5af85a25c20857e7c8c1b548b12dc1'
TESTED='194b586508c6661b40a74d9c7f99ed3b876f5fbc'
def require(ok,code):
    if not ok:raise ValueError(code)
def checksum(path):
    h=hashlib.sha256()
    with path.open('rb')as stream:
        for block in iter(lambda:stream.read(1048576),b''):h.update(block)
    return h.hexdigest()
def verify(work):
    work=Path(work);require(work.is_absolute()and work.resolve()==work and work.is_dir(),'EXACT_DELIVERY_DIRECTORY_REQUIRED')
    package=work/'package.zip';require(package.stat().st_size==ZIP_BYTES and checksum(package)==ZIP_HASH,'EXACT_TESTED_ZIP_REQUIRED')
    with zipfile.ZipFile(package)as archive:
        require(len(archive.namelist())==3 and set(archive.namelist())=={'image.tar.gz','manifest.json','SHA256SUMS'},'EXACT_ARTIFACT_MEMBERS_REQUIRED')
        require(archive.getinfo('manifest.json').file_size<=65536,'BOUNDED_MANIFEST_REQUIRED')
        raw=archive.read('manifest.json');require(hashlib.sha256(raw).hexdigest()==MANIFEST_HASH,'EXACT_TESTED_MANIFEST_REQUIRED')
        v=json.loads(raw);require(v['reviewedSourceCommit']==SOURCE and v['testedCommit']==TESTED
            and v['archiveSha256']==IMAGE_HASH and v['archiveBytes']==IMAGE_BYTES
            and v['preservedAtomicInstallationOwner']is True and v['targetApplyAuthorized']is False,'EXACT_B0_PRESERVING_CANDIDATE_REQUIRED')
        require(archive.getinfo('image.tar.gz').file_size==IMAGE_BYTES,'EXACT_IMAGE_SIZE_REQUIRED')
        h=hashlib.sha256()
        with archive.open('image.tar.gz')as source,(work/'image.tar.gz').open('xb')as target:
            for block in iter(lambda:source.read(1048576),b''):h.update(block);target.write(block)
            target.flush();os.fsync(target.fileno())
        require(h.hexdigest()==IMAGE_HASH,'EXACT_IMAGE_HASH_REQUIRED')
        with (work/'manifest.json').open('xb')as target:target.write(raw);target.flush();os.fsync(target.fileno())
    found=False
    with tarfile.open(work/'image.tar.gz',mode='r|gz')as archive:
        for entry in archive:
            if entry.name!=LAYER:continue
            require(entry.isfile()and entry.size<=268435456,'EXACT_REGULAR_APPLICATION_LAYER_REQUIRED')
            with tarfile.open(fileobj=archive.extractfile(entry),mode='r|')as layer:
                for item in layer:
                    if item.name not in('app/application.jar','./app/application.jar'):continue
                    require(item.isfile()and item.size==JAR_BYTES and not found,'EXACT_TESTED_APPLICATION_JAR_REQUIRED')
                    h=hashlib.sha256()
                    with (work/'application.jar').open('xb')as target:
                        source=layer.extractfile(item)
                        for block in iter(lambda:source.read(1048576),b''):h.update(block);target.write(block)
                        target.flush();os.fsync(target.fileno())
                    require(h.hexdigest()==JAR_HASH,'EXACT_JAR_HASH_REQUIRED');found=True
    require(found,'TESTED_APPLICATION_JAR_ABSENT')
    return {'status':'CORRECTED_V35_PACKAGE_BYTES_VERIFIED','imageLoaded':False,'databaseMigrations':0,'sourceActivations':0,'humanBudgetsGranted':0,'targetApplyAuthorized':False}
if __name__=='__main__':
    try:
        require(len(sys.argv)==2,'ONE_DELIVERY_DIRECTORY_REQUIRED');result=verify(sys.argv[1]);print(json.dumps(result,sort_keys=True),flush=True)
    except Exception:
        print('{"status":"STOP_PACKAGE_VERIFICATION","targetApplyAuthorized":false}',flush=True);raise SystemExit(2)
