#!/usr/bin/env python3
"""One operator command: authenticated delivery, private intake and actual review.

The source manifest is frozen before publication; the launcher is deliberately
outside its own manifest. The initial operator command pins this launcher's
bytes and exact repository commit. No target command runs before all source
members and the already-qualified cohort archive have been authenticated.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile

REPOSITORY='GioNob/ouf-deploy'
CAPSULE_PATH='releases/chatbot-file-preparation-capsule-20261014.json'
CAPSULE_SHA256='1d6909c5fd88efc7f2ef80de91915d81dd9823328a5631df551f8be42f4e3b4d'
PACKAGE_COMMIT='f31a653ee1da56b29a6171c159f9c601523735b9'
PACKAGE_RUN=38536134146
PACKAGE_SHA256='be55c6eda4485a4c90da9872f63e2533abe21c741c4926ecc129626cc01530f9'
DOWNLOADER_SHA256='f62b16e337e3871a62dc4117a0bd0b0f04a012ae63db62031dabcc723b8a2000'
MAX_SOURCE_BYTES=8*1024**2


def require(ok,reason):
    if not ok:raise ValueError(reason)


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def verified_package(path):
    path=Path(path)
    require(path.is_absolute() and '..' not in path.parts,'EXACT_DELIVERED_ARCHIVE_PATH_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid()
                and not before.st_mode&0o022,'REGULAR_PRIVATE_OPERATOR_ARCHIVE_REQUIRED')
        with os.fdopen(os.dup(fd),'rb') as archive:
            require(hashlib.file_digest(archive,'sha256').hexdigest()==PACKAGE_SHA256,
                    'EXACT_COHORT_ARCHIVE_REQUIRED')
        fingerprint=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        require(fingerprint(before)==fingerprint(os.fstat(fd))==fingerprint(path.lstat()),
                'DELIVERED_ARCHIVE_CHANGED_DURING_VERIFICATION')
    finally:os.close(fd)
    return path


def selected_sources(archive,manifest):
    require(type(manifest) is dict and set(manifest)=={'schema','files'}
        and manifest['schema']=='ouf.chatbot-file-preparation-capsule.v1'
        and type(manifest['files']) is dict and 1<=len(manifest['files'])<=512,
        'EXACT_PREPARATION_CAPSULE_REQUIRED')
    wanted=manifest['files']
    for name,digest in wanted.items():
        require(re.fullmatch(r'[A-Za-z0-9_.\-/]+',name) and str(Path(name))==name
            and not name.startswith('/') and '..' not in Path(name).parts
            and re.fullmatch('[0-9a-f]{64}',digest),'EXACT_SOURCE_MEMBER_AND_DIGEST_REQUIRED')
    result={};total=0;count=0;expanded=0;prefix=None
    with tarfile.open(archive,'r:gz') as source:
        for member in source:
            count+=1;expanded+=member.size
            require(count<=20000 and expanded<=512*1024**2,'SOURCE_ARCHIVE_UNBOUNDED')
            parts=member.name.split('/',1)
            if prefix is None:prefix=parts[0]
            require(parts[0]==prefix,'ONE_SOURCE_ARCHIVE_ROOT_REQUIRED')
            if len(parts)!=2 or parts[1] not in wanted:continue
            name=parts[1]
            require(name not in result and member.isfile() and 0<member.size<=2*1024**2,
                    'REGULAR_UNIQUE_SOURCE_MEMBER_REQUIRED')
            total+=member.size;require(total<=MAX_SOURCE_BYTES,'PREPARATION_SOURCE_CLOSURE_UNBOUNDED')
            with source.extractfile(member) as stream:raw=stream.read(member.size+1)
            require(len(raw)==member.size and hashlib.sha256(raw).hexdigest()==wanted[name],
                    'PREPARATION_SOURCE_HASH_MISMATCH')
            result[name]=raw
    require(set(result)==set(wanted),'PREPARATION_SOURCE_CLOSURE_INCOMPLETE')
    return result


# Independent root-side validation uses the manifest hash embedded in the
# verified launcher. Files from the delivering user's directory are not run.
ROOT_BODY=r'''
import base64,hashlib,json,os,re,stat,sys
from pathlib import Path
def need(ok,reason):
    if not ok:raise SystemExit('phase=ROOT_DELIVERY reason='+reason)
def unique(rows):
    value={}
    for key,item in rows:
        need(key not in value,'DUPLICATE_CAPSULE_KEY');value[key]=item
    return value
need(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.dont_write_bytecode and sys.flags.no_site,
     'ISOLATED_ROOT_DELIVERY_REQUIRED')
need(len(sys.argv)==3 and re.fullmatch('[0-9a-f]{40}',sys.argv[1]),'EXACT_SOURCE_COMMIT_REQUIRED')
commit,archive=sys.argv[1:]
need(Path(archive).is_absolute() and '..' not in Path(archive).parts,'EXACT_DELIVERED_ARCHIVE_PATH_REQUIRED')
raw=sys.stdin.buffer.read(12*1024**2+1)
need(0<len(raw)<=12*1024**2,'CAPSULE_TRANSFER_UNBOUNDED')
payload=json.loads(raw,object_pairs_hook=unique)
need(set(payload)=={'manifest','files'},'EXACT_CAPSULE_TRANSFER_REQUIRED')
manifest_raw=base64.b64decode(payload['manifest'],validate=True)
need(hashlib.sha256(manifest_raw).hexdigest()==EXPECTED,'ROOT_CAPSULE_MANIFEST_HASH_MISMATCH')
manifest=json.loads(manifest_raw,object_pairs_hook=unique)
need(set(manifest)=={'schema','files'} and manifest['schema']=='ouf.chatbot-file-preparation-capsule.v1'
     and set(manifest['files'])==set(payload['files']) and 1<=len(payload['files'])<=512,
     'ROOT_COMPLETE_SOURCE_SET_REQUIRED')
files={name:base64.b64decode(body,validate=True) for name,body in payload['files'].items()}
need(sum(map(len,files.values()))<=8*1024**2,'ROOT_SOURCE_CLOSURE_UNBOUNDED')
for name,body in files.items():
    need(re.fullmatch(r'[A-Za-z0-9_.\-/]+',name) and str(Path(name))==name and not name.startswith('/')
         and '..' not in Path(name).parts and len(Path(name).parts)<=32 and 0<len(body)<=2*1024**2
         and hashlib.sha256(body).hexdigest()==manifest['files'][name],'ROOT_SOURCE_MEMBER_HASH_MISMATCH')
need('scripts/install-chatbot-file-cohort.py' in files,'ROOT_ENTRY_MISSING')
base=Path('/etc/ouf/deploy-snapshots')
held=[]
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK
parent=os.open('/',flags);held.append(parent)
for part in base.parts[1:]:
    child=os.open(part,flags,dir_fd=parent);info=os.fstat(child)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and not info.st_mode&0o022,
         'ROOT_STAGING_PARENT_CUSTODY_REQUIRED')
    held.append(child);parent=child
name='chatbot-file-intake-'+EXPECTED
try:os.mkdir(name,0o700,dir_fd=parent);os.fsync(parent)
except FileExistsError:pass
stage_fd=os.open(name,flags,dir_fd=parent);held.append(stage_fd)
info=os.fstat(stage_fd)
need(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700,'ROOT_PRIVATE_STAGE_REQUIRED')
stage=base/name
def put(directory,name,body):
    try:
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    except FileExistsError:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            s=os.fstat(fd)
            need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
                 and s.st_nlink==1 and s.st_size==len(body),'ROOT_EXISTING_SOURCE_CUSTODY_DRIFT')
            with os.fdopen(os.dup(fd),'rb') as stream:actual=stream.read(len(body)+1)
            need(actual==body,'ROOT_EXISTING_SOURCE_BYTES_DRIFT')
        finally:os.close(fd)
        return
    try:
        with os.fdopen(os.dup(fd),'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
        os.fsync(directory)
    finally:os.close(fd)
directories={'':stage_fd}
for path,body in sorted(files.items()):
    pieces=['source']+list(Path(path).parts)
    rel='';fd=stage_fd
    for piece in pieces[:-1]:
        rel=(rel+'/' if rel else '')+piece
        if rel not in directories:
            try:os.mkdir(piece,0o700,dir_fd=fd);os.fsync(fd)
            except FileExistsError:pass
            child=os.open(piece,flags,dir_fd=fd);held.append(child);info=os.fstat(child)
            need(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700,'ROOT_SOURCE_DIRECTORY_CUSTODY_DRIFT')
            directories[rel]=child
        fd=directories[rel]
    put(fd,pieces[-1],body)
put(stage_fd,'preparation-manifest.json',manifest_raw)
source=stage/'source';entry=source/'scripts/install-chatbot-file-cohort.py'
for fd in reversed(held):os.close(fd)
os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(entry),'--source-directory',str(source),
    '--package-archive',archive,'--staging-directory',str(stage),'--source-commit',commit,
    '--preparation-source-hash',EXPECTED])
'''


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source-commit',required=True)
    parser.add_argument('--package-archive',help='Existing exact qualified ZIP to verify and reuse without downloading it again')
    args=parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}',args.source_commit) and re.fullmatch('[0-9a-f]{64}',CAPSULE_SHA256),
            'FROZEN_EXACT_DELIVERY_SOURCE_REQUIRED')
    preferred=Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
    gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
    require(gh,'EXISTING_GH_UNAVAILABLE_NO_SUDO_EXECUTED')
    def content(path,commit,expected):
        result=subprocess.run([gh,'api',f'repos/{REPOSITORY}/contents/{path}?ref={commit}','--jq','.content'],
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True,timeout=45)
        require(len(result.stdout)<=1048576,'SOURCE_METADATA_UNBOUNDED')
        raw=base64.b64decode(b''.join(result.stdout.split()),validate=True)
        require(hashlib.sha256(raw).hexdigest()==expected,'QUALIFIED_DELIVERY_SOURCE_HASH_MISMATCH')
        return raw
    manifest_raw=content(CAPSULE_PATH,args.source_commit,CAPSULE_SHA256)
    manifest=json.loads(manifest_raw)
    output=Path.home()/('ouf-chatbot-file-delivery-'+CAPSULE_SHA256[:24])
    if not output.exists():output.mkdir(mode=0o700)
    require(output.is_dir() and not output.is_symlink() and output.stat().st_uid==os.getuid()
            and output.stat().st_mode&0o777==0o700,'PRIVATE_OPERATOR_DELIVERY_DIRECTORY_REQUIRED')
    cohort=output/'cohort'
    package_archive=Path(args.package_archive) if args.package_archive else cohort/'cohort.zip'
    if args.package_archive:
        print('Verifico e riutilizzo il pacchetto già scaricato; preparo una nuova capsula privata.',flush=True)
    elif not package_archive.exists():
        downloader=content('scripts/download-file-cohort.py',PACKAGE_COMMIT,DOWNLOADER_SHA256)
        print('Scarico il pacchetto unico già qualificato (circa 1,7 GB).',flush=True)
        argv=sys.argv
        try:
            sys.argv=['download-file-cohort.py','--run',str(PACKAGE_RUN),'--producer-commit',PACKAGE_COMMIT,'--output',str(cohort)]
            namespace={'__name__':'qualified_cohort_downloader'}
            exec(compile(downloader,'<qualified-cohort-downloader>','exec'),namespace)
            namespace['main']()
        finally:sys.argv=argv
    package_archive=verified_package(package_archive)
    source_archive=output/'qualified-source.tar.gz'
    if not source_archive.exists():
        partial=output/'qualified-source.tar.gz.partial'
        with partial.open('xb') as dest:
            subprocess.run([gh,'api',f'repos/{REPOSITORY}/tarball/{args.source_commit}'],
                stdout=dest,stderr=subprocess.DEVNULL,check=True,timeout=300)
            dest.flush();os.fsync(dest.fileno())
        require(0<partial.stat().st_size<=128*1024**2,'BOUNDED_REPOSITORY_SOURCE_ARCHIVE_REQUIRED')
        partial.rename(source_archive)
    sources=selected_sources(source_archive,manifest)
    payload=encoded({'manifest':base64.b64encode(manifest_raw).decode(),
                     'files':{name:base64.b64encode(raw).decode() for name,raw in sources.items()}})
    require(len(payload)<=12*1024**2,'BOUNDED_ROOT_SOURCE_TRANSFER_REQUIRED')
    print('Pacchetto e sorgenti verificati. Avvio preparazione completa e revisione sul VPS.',flush=True)
    root='EXPECTED='+repr(CAPSULE_SHA256)+'\n'+ROOT_BODY
    result=subprocess.run(['sudo','--','/usr/bin/python3','-I','-B','-S','-c',root,
        args.source_commit,str(package_archive)],input=payload,check=False)
    return result.returncode


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        reason=str(error) if type(error) is ValueError else type(error).__name__
        print(json.dumps({'schema':'ouf.chatbot-file-delivery-launcher.v1','status':'BLOCKED',
            'reason':reason,'automaticReplay':False,'notReleaseAcceptance':True},sort_keys=True))
        raise SystemExit(1)
