"""Private extraction of the exact GitHub workflow artifact, without execution."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import zipfile

import iam_binding_candidate as evidence
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.chatbot_file_cohort.plan import digest,require

LIMIT=6*1024**3
MODULES={'semantic','onboarding','ingestion','udp','gateway','mcp'}


def relative(name):
    require(type(name) is str and re.fullmatch('[A-Za-z0-9_.\-/]+',name)
        and not name.startswith('/') and '..' not in Path(name).parts
        and str(Path(name))==name and len(Path(name).parts)<=32,'EXACT_RELATIVE_PACKAGE_MEMBER_REQUIRED')
    return name


def new_directory(parent,name):
    require(re.fullmatch('[A-Za-z0-9_.-]{1,128}',name) and name not in ('.','..'),
            'EXACT_PRIVATE_STAGING_DIRECTORY_NAME_REQUIRED')
    with protected_directory(parent) as fd:
        os.mkdir(name,0o700,dir_fd=fd);os.fsync(fd)
    return Path(parent)/name


def copy_member(stream,path,expected,maximum):
    with protected_directory(path.parent) as parent:
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        total=0;hashed=hashlib.sha256()
        try:
            with os.fdopen(os.dup(fd),'wb') as output:
                while chunk:=stream.read(1048576):
                    total+=len(chunk);require(total<=maximum,'PACKAGE_MEMBER_BYTES_EXCEEDED')
                    hashed.update(chunk);output.write(chunk)
                output.flush();os.fsync(output.fileno())
            require(hashed.hexdigest()==expected,'PRIVATE_PACKAGE_MEMBER_HASH_MISMATCH')
            os.fsync(parent)
        finally:os.close(fd)
    return total


def extract_cohort(archive_path,archive_hash,producer_commit,run_id,destination):
    """The caller pins the run/hash from the authenticated GitHub downloader.

    The input may belong to the delivering user. Only the copied root-private
    bytes are parsed, after their complete digest matches the selected artifact.
    Sigstore is retained and explicitly not claimed as locally verified.
    """
    require(re.fullmatch('[0-9a-f]{64}',archive_hash) and re.fullmatch('[0-9a-f]{40}',producer_commit)
            and type(run_id) is int and run_id>0,'EXACT_SELECTED_SUCCESSFUL_PACKAGE_REQUIRED')
    destination=Path(destination)
    with protected_directory(destination):pass
    source_fd=os.open(archive_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(source_fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=LIMIT,
                'BOUNDED_SELECTED_ARCHIVE_REQUIRED')
        with os.fdopen(os.dup(source_fd),'rb') as source:
            size=copy_member(source,destination/'cohort.zip',archive_hash,LIMIT)
        require(size==info.st_size and evidence.identity(info)==evidence.identity(os.fstat(source_fd)),
                'DELIVERED_ARCHIVE_CHANGED_DURING_COPY')
    finally:os.close(source_fd)
    package=new_directory(destination,'package')
    with zipfile.ZipFile(destination/'cohort.zip') as archive:
        infos=archive.infolist();names=[relative(row.filename) for row in infos]
        require(0<len(infos)<=256 and len(set(names))==len(names)
            and all(not row.is_dir() and ((row.external_attr>>16)&0o170000)!=0o120000 for row in infos)
            and sum(row.file_size for row in infos)<=LIMIT,'EXACT_BOUNDED_COHORT_MEMBER_SET_REQUIRED')
        require(archive.getinfo('COHORT_SHA256SUMS').file_size<=100000,'BOUNDED_COHORT_CHECKSUMS_REQUIRED')
        sums=archive.read('COHORT_SHA256SUMS');declared={}
        for line in sums.decode().splitlines():
            require(re.fullmatch('[0-9a-f]{64}  [A-Za-z0-9_.\-/]+',line),'EXACT_CHECKSUM_LINE_REQUIRED')
            hashed,name=line.split('  ',1);relative(name)
            require(name not in declared,'DUPLICATE_COHORT_CHECKSUM');declared[name]=hashed
        require(set(names)==set(declared)|{'COHORT_SHA256SUMS','COHORT_SHA256SUMS.sigstore.json'},
                'COMPLETE_COHORT_CHECKSUM_CLOSURE_REQUIRED')
        created={package}
        for row in infos:
            target=package/row.filename
            for path in reversed(target.parent.parents):
                if path==package or path.is_relative_to(package):
                    if path not in created:new_directory(path.parent,path.name);created.add(path)
            if target.parent not in created:new_directory(target.parent.parent,target.parent.name);created.add(target.parent)
            with archive.open(row) as source:
                expected=declared.get(row.filename)
                if expected is None:
                    require(row.file_size<=1048576,'BOUNDED_PUBLISHER_ATTESTATION_REQUIRED')
                    raw=source.read(1048577);expected=hashlib.sha256(raw).hexdigest()
                    import io
                    source=io.BytesIO(raw)
                require(copy_member(source,target,expected,row.file_size)==row.file_size,'PACKAGE_SIZE_MISMATCH')
    manifest=evidence.decode((package/'cohort-manifest.json').read_bytes())
    lock_raw=(package/'source-lock.json').read_bytes();lock=evidence.decode(lock_raw)
    require(manifest.get('schema')=='ouf.chatbot-file-cohort-package.v1'
        and manifest.get('sourceLockSha256')==hashlib.sha256(lock_raw).hexdigest()
        and manifest.get('producer',{}).get('sourceCommit')==producer_commit
        and str(manifest['producer']['runId'])==str(run_id)
        and manifest.get('targetApplyAuthorized') is False and manifest.get('runtimeAuthorityIssued') is False,
        'EXACT_UNACCEPTED_SOURCE_LOCKED_COHORT_REQUIRED')
    records={row['module']:row for row in manifest['modules']}
    require(len(manifest['modules'])==len(lock['modules'])==6 and set(records)==MODULES
        and {row['module']:row['commit'] for row in lock['modules']}=={name:row['sourceCommit'] for name,row in records.items()},
        'EXACT_SIX_MODULE_SOURCE_COHORT_REQUIRED')
    for name,row in records.items():
        require(row.get('scanGate')=='PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
            and row.get('cohortSourceLockSha256')==manifest['sourceLockSha256']
            and all(declared.get(name+'/'+member)==hashed for member,hashed in row['files'].items()),
            'MODULE_PACKAGE_CHECKSUM_OR_QUALIFICATION_DRIFT')
    return package,manifest,{'archiveSha256':archive_hash,'producerCommit':producer_commit,'runId':run_id,
        'cohortManifestHash':digest(manifest),'publisherSignatureRetained':True,
        'publisherSignatureLocallyVerified':False,'targetApplyAuthorized':False}


def extract_source(package,record,destination):
    """Only authenticated regular source members, no links or archive extract()."""
    path=Path(package)/record['module']/'source.tar';expected=record['files']['source.tar']
    with path.open('rb') as source:
        require(hashlib.file_digest(source,'sha256').hexdigest()==expected,'AUTHENTICATED_MODULE_SOURCE_REQUIRED')
        source.seek(0);created={Path(destination)};total=0
        with tarfile.open(fileobj=source,mode='r:') as archive:
            seen=set()
            for member in archive:
                name=relative(member.name.rstrip('/'))
                require(name not in seen and len(seen)<20000 and (member.isdir() or member.isfile()),
                        'EXACT_REGULAR_MODULE_SOURCE_MEMBER_REQUIRED');seen.add(name)
                total+=member.size
                require(member.size<=33554432 and total<=268435456,'BOUNDED_MODULE_SOURCE_REQUIRED')
                path=Path(destination)/name
                folders=[path] if member.isdir() else []
                folders+=list(path.parents)
                for folder in sorted((p for p in folders if p.is_relative_to(destination) and p!=Path(destination)),key=lambda p:len(p.parts)):
                    if folder not in created:new_directory(folder.parent,folder.name);created.add(folder)
                if member.isfile():
                    with archive.extractfile(member) as stream:
                        raw=stream.read(member.size+1)
                    require(len(raw)==member.size,'MODULE_SOURCE_SIZE_CHANGED')
                    import io
                    copy_member(io.BytesIO(raw),path,hashlib.sha256(raw).hexdigest(),member.size)
    return str(destination)
