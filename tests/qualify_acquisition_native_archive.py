"""Qualify immutable MCP archive -> native tagless archive -> actual Docker load, CI only."""
import hashlib,importlib.util,json,os,subprocess,tempfile,zipfile
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
n=module('native',BASE/'scripts/prepare-acquisition-read-native-execution-20261025.py');p=module('helper',BASE/'tools/acquisition_read_native/plan_helper.py');images=module('images',BASE/'tools/acquisition_read_native/image_custody.py');t=module('transport',BASE/'scripts/transport-acquisition-read-artifacts-20261025.py')
with tempfile.TemporaryDirectory(prefix='ouf-native-archive-ci-',dir='/var/lib')as folder:
    root=Path(folder);descriptor=json.loads((BASE/'releases/acquisition-read-package-case-20261025.json').read_text())['artifacts']['mcp'];t.download('mcp',descriptor,os.environ.pop('GH_TOKEN'),root)
    with zipfile.ZipFile(root/'mcp.zip')as z:raw=z.read('image.tar.gz')
    expected='dd63ba8508949451f7c50f5d8913b1b35cf59650f199b78576fc2bcd1173c9cb';assert hashlib.sha256(raw).hexdigest()==expected
    archive=root/'image.tar.gz';archive.write_bytes(raw);archive.chmod(0o400);output=root/'native';output.mkdir(mode=0o700)
    info=json.loads(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True));profile=n.identity_profile(info)
    fact=n.archive_at(p,images,{'path':str(archive),'sha256':expected,'imageId':descriptor['imageId'],'sourceCommit':descriptor['commit']},output,profile=='CONFIG_AND_NATIVE_MANIFEST')
    subprocess.run(['docker','load','--input',fact['nativeArchive']['path']],stdout=subprocess.DEVNULL,check=True)
    actual=json.loads(subprocess.check_output(['docker','image','inspect',fact['nativeImageId']],text=True))[0];proof=images.loaded(fact['audit'],actual)
    assert proof['imageByteCustodyProven']and n.COUNTS['nativeArchivesPrepared']==1
    try:n.archive_at(p,images,{'path':str(archive),'sha256':'0'*64,'imageId':descriptor['imageId'],'sourceCommit':descriptor['commit']},output,profile=='CONFIG_AND_NATIVE_MANIFEST');raise AssertionError('Changed archive accepted')
    except n.Stop as e:assert str(e)=='EXACT_CI_COMPRESSED_ARCHIVE_HASH_REQUIRED'
    print(json.dumps({'schema':'ouf.acquisition-native-image-custody-ci.v1','complete':True,'sourceArtifactId':descriptor['artifactId'],'sourceArchiveSha256':expected,'imageIdentityProfile':profile,'configurationImageId':descriptor['imageId'],'nativeImageId':fact['nativeImageId'],'exactLoadedImageConfigAndRootfsProven':True,'imageRebuilt':False,'imageRelabelled':False,'applicationStarted':False,'productionRuntimeAccess':False}))
