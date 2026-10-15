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
from image_custody import archive,tagless_archive,loaded,digest
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
    records=list(package.rglob('package-record.json'));assert len(records)==1
    record=json.loads(records[0].read_text());assert record['imageId']==IMAGE and record['sourceCommit']==SOURCE
    parent=records[0].parent;source=parent/'image.docker.tar'
    sums=(parent/'SHA256SUMS').read_text().splitlines()
    hashes=[r.split('  ',1)[0] for r in sums if r.endswith('  image.docker.tar')];assert len(hashes)==1
    target=stage/'semantic.tagless.tar'
    with source.open('rb') as raw:
        original=archive(raw,hashes[0],IMAGE,SOURCE)
        with target.open('w+b') as derived:
            derivation=tagless_archive(raw,derived,original)
            audit=archive(derived,derivation['derivedArchiveSha256'],IMAGE,SOURCE)
    target.chmod(0o600);assert not audit['repositoryTags']
    REPORT['archiveSha256']=audit['archiveSha256'];REPORT['archiveBytes']=target.stat().st_size
    emit('ARCHIVE_VALIDATED',sha256=audit['archiveSha256'],archiveBytes=target.stat().st_size)
    info=os.stat(SOCKET,follow_symlinks=False)
    engine=Engine(SOCKET,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))
    assert engine.request('GET','/v1.44/images/'+IMAGE+'/json')[0]==404,'DISPOSABLE_IMAGE_MUST_START_ABSENT'
    directory=stage/'journal';directory.mkdir(mode=0o700);journal=Journal(directory)
    authority=digest({'disposableFixtureOnly':True,'archiveHash':audit['archiveSha256']})
    initial=Import.initial(audit,authority);journal.initialize(initial);owner=Import(journal,initial['contextHash'])
    def inspect(identity):
        code,native=engine.request('GET','/v1.44/images/'+identity+'/json')
        assert code in (200,404);return native if code==200 else None
    def load():
        with target.open('rb') as stream:
            assert archive(stream,audit['archiveSha256'],IMAGE,SOURCE)==audit
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
    try:
        with owner.invocation():
            proof=owner.import_once(audit,load,inspect,lambda _:authority)
        REPORT['custody']=proof;REPORT['passed']=True
    finally:
        REPORT['journal']=journal.read()
        code,native=engine.request('GET','/v1.44/images/'+IMAGE+'/json');REPORT['exactImageGetStatus']=code
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
    try:main()
    except Exception as error:
        REPORT['passed']=False;REPORT['exceptionType']=type(error).__name__;REPORT['reason']=str(error)[:200]
        emit('FAILURE',exceptionType=type(error).__name__,reason=str(error)[:200])
        raise
    finally:
        Path('tagless-import-report.json').write_text(json.dumps(REPORT,indent=2,sort_keys=True)+'\n')
