"""Disposable CI only: exact published semantic bytes, two Docker stores.

No VPS authority or acceptance. Never starts the application image.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/semantic_application_cutover'),str(ROOT)]
from image_custody import archive,tagless_archive,loaded,digest,native_identity,runtime_image_id,unbound_audit
from image_import import Import
from engine_creation import Engine
from tools.semantic_lease_recovery.recovery_journal import Journal

IMAGE='sha256:29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489'
SOURCE='eccef11a97367f20e278db40b9ed6f45dd980c37'
REPORT={'schema':'ouf.published-tagless-import-ci.v1','fixtureOnly':True,
    'chatbotEndToEndProven':False,'targetServiceMutations':0,'sourceCommit':SOURCE,'expectedImageId':IMAGE}

def emit(check,**value):
    print('OUF_TAGLESS_PROBE='+json.dumps(dict(check=check,**value),sort_keys=True),flush=True)

def cli(*args,source=None):
    return subprocess.run([DOCKER,'--host','unix://'+SOCKET,'--config',str(CONFIG),*args],
        stdin=source if source is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        timeout=180,check=False,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})

def main():
    global DOCKER,SOCKET,CONFIG
    assert os.geteuid()==0 and len(sys.argv)==4
    package,stage,SOCKET=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
    DOCKER=str(Path(shutil.which('docker')).resolve())
    stage.mkdir(mode=0o700);CONFIG=stage/'cli';CONFIG.mkdir(mode=0o700)
    info=cli('info','--format','{{json .}}');assert info.returncode==0
    value=json.loads(info.stdout)
    REPORT['engine']={k:value.get(k) for k in ('ServerVersion','Driver','CgroupDriver','Architecture')}
    emit('ENGINE',**REPORT['engine'])
    records=[package/'package-record.json'];assert records[0].is_file()
    record=json.loads(records[0].read_text());assert record['imageId']==IMAGE and record['sourceCommit']==SOURCE
    parent=records[0].parent;source=parent/'image.docker.tar'
    sums=(parent/'SHA256SUMS').read_text().splitlines()
    hashes=[r.split('  ',1)[0] for r in sums if r.endswith('  image.docker.tar')];assert len(hashes)==1
    containerd=value['Driver']=='overlayfs'
    target=stage/'image.tagless.tar'
    with source.open('rb') as raw:
        original=archive(raw,hashes[0],IMAGE,SOURCE)
        with target.open('w+b') as derived:
            derivation=tagless_archive(raw,derived,original,containerd=containerd)
            audit=archive(derived,derivation['derivedArchiveSha256'],IMAGE,SOURCE)
    target.chmod(0o600);assert not audit['repositoryTags']
    if containerd:audit['nativeIdentity']=native_identity(audit)
    expected=runtime_image_id(audit)
    REPORT['nativeImageId']=expected
    if containerd and SOURCE=='eccef11a97367f20e278db40b9ed6f45dd980c37':
        assert expected=='sha256:b61bc39c1593c28404a8258962008c024d13689d7e9b132e6a85619580003ca3','EXACT_RECONCILED_TARGET_MANIFEST_REQUIRED'
    REPORT['archiveSha256']=audit['archiveSha256'];REPORT['archiveBytes']=target.stat().st_size
    emit('ARCHIVE_VALIDATED',sha256=audit['archiveSha256'],archiveBytes=target.stat().st_size)
    info=os.stat(SOCKET,follow_symlinks=False)
    engine=Engine(SOCKET,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))
    assert engine.request('GET','/v1.44/images/'+expected+'/json')[0]==404,'DISPOSABLE_IMAGE_MUST_START_ABSENT'
    directory=stage/'journal';directory.mkdir(mode=0o700);journal=Journal(directory)
    authority=digest({'disposableFixtureOnly':True,'archiveHash':audit['archiveSha256']})
    initial=Import.initial(audit,authority);journal.initialize(initial);owner=Import(journal,initial['contextHash'])
    def inspect(identity):
        code,native=engine.request('GET','/v1.44/images/'+identity+'/json')
        assert code in (200,404);return native if code==200 else None
    def load():
        with target.open('rb') as stream:
            assert archive(stream,audit['archiveSha256'],IMAGE,SOURCE)==unbound_audit(audit)
            stream.seek(0)
            REPORT['stdinPosition']={'buffered':stream.tell(),'descriptor':os.lseek(stream.fileno(),0,os.SEEK_CUR)}
            started=time.monotonic();result=cli('load',source=stream)
        REPORT['load']={'exitCode':result.returncode,'elapsedSeconds':round(time.monotonic()-started,3),
            'stdout':result.stdout[:16384].decode('utf-8','replace'),
            'stderr':result.stderr[:16384].decode('utf-8','replace')}
        # Exact artifact, isolated empty config, local socket; output is CI-only
        # image loading diagnostics. No credentials or target paths are supplied.
        emit('LOAD_RETURNED',**REPORT['load'],stdinPosition=REPORT['stdinPosition'])
        assert result.returncode==0,'DISPOSABLE_LOAD_FAILED'
    if containerd and SOURCE=='eccef11a97367f20e278db40b9ed6f45dd980c37':
        legacy=stage/'legacy.tagless.tar'
        with source.open('rb') as raw,legacy.open('w+b') as derived:
            tagless_archive(raw,derived,original)
        with legacy.open('rb') as stream:seed=cli('load',source=stream)
        assert seed.returncode==0 and inspect(expected) is not None,'EXACT_LEGACY_PREDECESSOR_MUST_LOAD'
        loaded(audit,inspect(expected))
        with owner.invocation():owner.import_once(audit,lambda:(_ for _ in ()).throw(AssertionError('RELOAD_FORBIDDEN')),inspect,lambda _:authority)
        assert journal.read()['effectAttemptCount']==0 and journal.read()['state']=='VERIFIED'
        REPORT['existingLegacyImageReconciledWithoutReload']=True
        assert cli('image','rm',expected).returncode==0
        directory2=stage/'fresh-journal';directory2.mkdir(mode=0o700);journal=Journal(directory2)
        journal.initialize(initial);owner=Import(journal,initial['contextHash'])
    try:
        with owner.invocation():
            proof=owner.import_once(audit,load,inspect,lambda _:authority)
        REPORT['custody']=proof
        create=cli('create','--network','none','--read-only','--entrypoint','/ouf-fixture-never-run',expected)
        assert create.returncode==0,'NATIVE_ID_CONTAINER_CREATE_REQUIRED'
        cid=create.stdout.decode().strip()
        status,container=engine.request('GET','/v1.44/containers/'+cid+'/json')
        assert status==200 and container['Image']==expected and container['State']['Status']=='created'
        assert cli('container','rm',cid).returncode==0
        REPORT['containerCreatedWithExactNativeIdNotStarted']=True
        REPORT['passed']=True
        emit('NATIVE_IDENTITY_PASS',nativeImageId=expected,configurationImageId=IMAGE,
            existingLegacyReconciledWithoutReload=REPORT.get('existingLegacyImageReconciledWithoutReload',False))
    finally:
        REPORT['journal']=journal.read()
        code,native=engine.request('GET','/v1.44/images/'+expected+'/json');REPORT['exactImageGetStatus']=code
        listing=cli('image','ls','--all','--no-trunc','--quiet')
        REPORT['listedImageIds']=sorted(set(listing.stdout.decode().splitlines()))[:64]
        REPORT['candidateReadback']=[]
        for identity in REPORT['listedImageIds']:
            status,current=engine.request('GET','/v1.44/images/'+identity+'/json')
            if status!=200:continue
            config=current.get('Config') or {}
            if (config.get('Labels') or {}).get('org.opencontainers.image.revision')!=SOURCE:continue
            REPORT['candidateReadback'].append({'imageId':identity,
                'configMatches':config==audit['imageConfig'],
                'rootfsMatches':current.get('RootFS')=={'Type':'layers','Layers':[r['diffId'] for r in audit['layers']]},
                'tags':current.get('RepoTags')})

if __name__=='__main__':
    try:
        root=Path(sys.argv[1]);manifest=json.loads((root/'cohort-manifest.json').read_text())
        assert manifest['producer']['sourceCommit']=='8bff54a52a0ce15daccaf2aee932004f106dd178'
        assert int(manifest['producer']['runId'])==38584614991
        pins={'semantic':'eccef11a97367f20e278db40b9ed6f45dd980c37','udp':'b49c0d6f50c574c11684361ce4e8040e9cbddee2',
            'onboarding':'84828f74ac586bae09a78f0fb197b75b1a3d98d1','ingestion':'c48ee4b1873a474e81c6e1be70d393854021e2c1',
            'mcp':'f249b3dcc58c2a96742092d90fa09fd90b705bd0'}
        records={r['module']:r for r in manifest['modules']};results=[]
        original_args=list(sys.argv)
        for module,SOURCE in pins.items():
            record=records[module];assert record['sourceCommit']==SOURCE and record['artifactKind']=='DOCKER_SAVE'
            IMAGE=record['imageId']
            REPORT={'schema':'ouf.published-tagless-import-ci.v2','module':module,'fixtureOnly':True,
                'chatbotEndToEndProven':False,'targetServiceMutations':0,'sourceCommit':SOURCE,'expectedImageId':IMAGE}
            sys.argv=[original_args[0],str(root/module),original_args[2]+'-'+module,original_args[3]]
            main();results.append(REPORT)
        REPORT={'schema':'ouf.five-published-tagless-import-ci.v2','passed':all(r['passed'] for r in results),'modules':results}

    except Exception as error:
        REPORT['passed']=False;REPORT['exceptionType']=type(error).__name__;REPORT['reason']=str(error)[:200]
        emit('FAILURE',exceptionType=type(error).__name__,reason=str(error)[:200])
        raise
    finally:
        Path('tagless-import-report.json').write_text(json.dumps(REPORT,indent=2,sort_keys=True)+'\n')
