#!/usr/bin/env python3
"""Derive native manifest identities from the exact previously qualified ZIP.
Hosted CI only. No target access or image import. No new publisher authority.
"""
import hashlib,importlib.util,json,sys,tempfile,zipfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('custody',root/'tools/linked_property_rollout/image_custody.py')
custody=importlib.util.module_from_spec(spec);spec.loader.exec_module(custody)
qualified=json.loads((root/'releases/linked-property-qualified-20261017.json').read_text())
lock=json.loads((root/'releases/linked-property-candidate-20261017.json').read_text())
source=Path(sys.argv[1])
assert source.stat().st_size==qualified['package']['artifactBytes'],'QUALIFIED_ZIP_SIZE_DRIFT'
with source.open('rb') as stream:actual,_=custody.hashed(stream,2147483648)
assert 'sha256:'+actual==qualified['package']['githubArtifactDigest'],'QUALIFIED_ZIP_DIGEST_DRIFT'
result={'schema':'ouf.qualified-native-image-identities.v1','qualifiedZipSha256':actual,
 'expectedInstalledNativeImages':{},'sourceCommits':{},'runtimeAuthorityIssued':False}
with zipfile.ZipFile(source) as package:
    names=package.namelist()
    assert len(names)==len(set(names)),'DUPLICATE_ZIP_ENTRIES'
    assert hashlib.sha256(package.read('source-lock.json')).hexdigest()==qualified['package']['sourceLockSha256']
    for row in lock['modules']:
        module=row['module'];prefix='parts/linked-property-part-'+module+'-'+str(qualified['package']['runId'])+'/'
        manifest=json.loads(package.read(prefix+'candidate-manifest.json'))
        assert manifest['sourceCommit']==row['commit'] and manifest['imageId']==qualified['candidateImageIds'][module]
        assert manifest['sourceLockSha256']==qualified['package']['sourceLockSha256']
        checks={}
        for line in package.read(prefix+'SHA256SUMS').decode().splitlines():
            digest,name=line.split('  ',1)
            assert name not in checks
            checks[name]=digest
        name=prefix+'image.docker.tar';assert package.getinfo(name).file_size<=custody.LIMIT
        with tempfile.TemporaryFile() as image:
            with package.open(name) as incoming:
                while True:
                    block=incoming.read(1048576)
                    if not block:break
                    image.write(block)
            image.seek(0)
            audit=custody.archive(image,checks['image.docker.tar'],manifest['imageId'],row['commit'])
        result['expectedInstalledNativeImages'][module]=custody.native_identity(audit)['nativeImageId']
        result['sourceCommits'][module]=row['commit']
Path(sys.argv[2]).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps(result,sort_keys=True))
