"""Reconstruct expected image rootfs with pinned umoci; never start a runtime.

The receipt proves archive/manifest/config/layer provenance and an offline seal.
It does not accept publisher trust, Docker's init layer or a target deployment.
"""
import argparse
import ast
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import types

OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
OCI_CONFIG = 'application/vnd.oci.image.config.v1+json'
LAYER_TYPES = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip'}
DOCKER_MANIFEST = 'application/vnd.docker.distribution.manifest.v2+json'
DOCKER_CONFIG = 'application/vnd.docker.container.image.v1+json'
DOCKER_LAYER = 'application/vnd.docker.image.rootfs.diff.tar.gzip'

class Denied(ValueError): pass
def require(value, reason):
    if not value: raise Denied(reason)
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def decode(raw):
    def unique(pairs):
        result={}
        for k,v in pairs:
            require(k not in result,'DUPLICATE_JSON_KEY');result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(Denied('NONFINITE_JSON')))
def sha(raw): return hashlib.sha256(raw).hexdigest()
def attributes(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def ancestors(path):
    require(path.is_absolute() and '..' not in path.parts,'ABSOLUTE_PRIVATE_PATH_REQUIRED')
    for parent in path.parents:
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'ROOT_ANCESTOR_REQUIRED')
def private(path,bound=131072):
    path=Path(path);ancestors(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
                and stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=bound,'PRIVATE_FILE_REQUIRED')
        raw=os.read(fd,bound+1)
        require(len(raw)==before.st_size and attributes(before)==attributes(os.fstat(fd))==attributes(path.lstat()),'PRIVATE_FILE_DRIFT')
        return raw
    finally:os.close(fd)
class Budget:
    def __init__(self,seconds=180):self.deadline=time.monotonic()+seconds;self.bytes=0;self.entries=0
    def check(self,size=0):
        self.bytes+=size
        require(time.monotonic()<self.deadline and self.bytes<=17179869184,'OFFLINE_IMAGE_BUDGET_EXCEEDED')
    def remaining(self):
        self.check();return max(0.001,self.deadline-time.monotonic())
def safe_name(name):
    require(type(name) is str and len(name)<=4096 and '\x00' not in name,'ARCHIVE_PATH_REQUIRED')
    if name.startswith('./'):name=name[2:]
    p=PurePosixPath(name)
    require(not p.is_absolute() and '..' not in p.parts and str(p)==name.rstrip('/'),'ARCHIVE_PATH_REQUIRED')
    return str(p)
def write_once(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
def spool_stream(source,layout,budget):
    """Only copy content-addressed blobs; outer tar links are never extracted."""
    layout.mkdir(mode=0o700);(layout/'blobs').mkdir(mode=0o700);(layout/'blobs/sha256').mkdir(mode=0o700)
    seen=set();blobs={};layout_doc=None
    with gzip.GzipFile(fileobj=source) as plain,tarfile.open(fileobj=plain,mode='r|') as archive:
        for item in archive:
            budget.check();budget.entries+=1
            require(budget.entries<=2048 and 0<=item.size<=8589934592,'OUTER_ARCHIVE_UNBOUNDED')
            name=safe_name(item.name);require(name not in seen,'DUPLICATE_ARCHIVE_ENTRY');seen.add(name)
            if item.isdir():
                require(name in ('.','blobs','blobs/sha256'),'UNEXPECTED_ARCHIVE_DIRECTORY')
                archive.members.clear();continue
            require(item.isfile() and name in ('oci-layout','index.json','manifest.json') or
                    item.isfile() and re.fullmatch('blobs/sha256/[0-9a-f]{64}',name),'OUTER_ARCHIVE_ENTRY_DENIED')
            incoming=archive.extractfile(item);h=hashlib.sha256();size=0;parts=[]
            blob=name.startswith('blobs/sha256/')
            if not blob:require(item.size<=131072,'OUTER_METADATA_UNBOUNDED')
            target=layout/name if blob else None
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600) if blob else None
            try:
                while raw:=incoming.read(65536):
                    budget.check(len(raw));size+=len(raw);require(size<=item.size,'OUTER_ENTRY_OVERFLOW');h.update(raw)
                    if blob:
                        view=memoryview(raw)
                        while view:view=view[os.write(fd,view):]
                    else:parts.append(raw)
                require(size==item.size,'OUTER_ENTRY_TRUNCATED')
                if blob:
                    os.fsync(fd);require(name=='blobs/sha256/'+h.hexdigest(),'OCI_BLOB_HASH_DRIFT');blobs['sha256:'+h.hexdigest()]=size
                elif name=='oci-layout':layout_doc=decode(b''.join(parts))
            finally:
                if fd is not None:os.close(fd)
            archive.members.clear()
    require(layout_doc=={'imageLayoutVersion':'1.0.0'},'OCI_LAYOUT_REQUIRED')
    write_once(layout/'oci-layout',canonical(layout_doc));return blobs
def blob_path(layout,digest):
    require(type(digest) is str and re.fullmatch('sha256:[0-9a-f]{64}',digest),'EXACT_SHA256_DESCRIPTOR_REQUIRED')
    return layout/'blobs/sha256'/digest[7:]
def blob_json(layout,digest,blobs):
    require(digest in blobs and 0<blobs[digest]<=131072,'BOUNDED_OCI_DOCUMENT_REQUIRED')
    path=blob_path(layout,digest)
    with path.open('rb') as stream:raw=stream.read(131073)
    require(len(raw)==blobs[digest] and 'sha256:'+sha(raw)==digest,'OCI_DOCUMENT_DRIFT');return decode(raw)
def verify_layout(layout,manifest_digest,config_digest,blobs,budget):
    manifest=blob_json(layout,manifest_digest,blobs)
    require(manifest.get('schemaVersion')==2 and manifest.get('mediaType') in (OCI_MANIFEST,DOCKER_MANIFEST),'OCI_MANIFEST_REQUIRED')
    cfg=manifest.get('config',{})
    require(cfg.get('digest')==config_digest and cfg.get('mediaType') in (OCI_CONFIG,DOCKER_CONFIG)
            and cfg.get('size')==blobs.get(config_digest),'OCI_CONFIG_BINDING_DRIFT')
    config=blob_json(layout,config_digest,blobs)
    require(config.get('os')=='linux' and config.get('architecture')=='amd64','EXACT_IMAGE_PLATFORM_REQUIRED')
    layers=manifest.get('layers');rootfs=config.get('rootfs',{});diffs=rootfs.get('diff_ids')
    require(type(layers) is list and type(diffs) is list and rootfs.get('type')=='layers'
            and 1<=len(layers)<=256 and len(layers)==len(diffs),'ORDERED_IMAGE_LAYERS_REQUIRED')
    for descriptor,expected in zip(layers,diffs):
        digest=descriptor.get('digest');path=blob_path(layout,digest)
        require(digest in blobs and descriptor.get('mediaType') in LAYER_TYPES|{DOCKER_LAYER}
                and descriptor.get('size')==blobs.get(digest),'OCI_LAYER_BINDING_DRIFT')
        blob_path(layout,expected);compressed=hashlib.sha256();plain_hash=hashlib.sha256()
        with path.open('rb') as source:
            while raw:=source.read(65536):budget.check(len(raw));compressed.update(raw)
            require('sha256:'+compressed.hexdigest()==digest,'OCI_LAYER_CHANGED');source.seek(0)
            plain=gzip.GzipFile(fileobj=source) if descriptor['mediaType'].endswith('+gzip') or descriptor['mediaType']==DOCKER_LAYER else source
            while raw:=plain.read(65536):budget.check(len(raw));plain_hash.update(raw)
            if plain is not source:plain.close()
        require('sha256:'+plain_hash.hexdigest()==expected,'OCI_LAYER_DIFF_ID_DRIFT')
    # Umoci consumes OCI descriptor media types. Preserve every original byte
    # and digest; derive a separate descriptor-only OCI view for schema2 Docker.
    view={**manifest,'mediaType':OCI_MANIFEST,'config':{**cfg,'mediaType':OCI_CONFIG},
        'layers':[{**d,'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip' if d['mediaType']==DOCKER_LAYER else d['mediaType']} for d in layers]}
    if view!=manifest:
        view_raw=canonical(view);view_digest='sha256:'+sha(view_raw)
        write_once(blob_path(layout,view_digest),view_raw);view_size=len(view_raw)
    else:view_digest=manifest_digest;view_size=blobs[manifest_digest]
    index={'schemaVersion':2,'manifests':[{'mediaType':OCI_MANIFEST,'digest':view_digest,'size':view_size,
        'annotations':{'org.opencontainers.image.ref.name':'ouf-offline-expected'}}]}
    write_once(layout/'index.json',canonical(index));return diffs
def program(path,expected):
    path=Path(path);ancestors(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and not before.st_mode&0o022
            and before.st_mode&0o111 and before.st_size<=64000000,'TRUSTED_UMOCI_REQUIRED')
        with os.fdopen(fd,'rb',closefd=False) as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
        require(actual==expected and attributes(before)==attributes(os.fstat(fd))==attributes(path.lstat()),'UMOCI_BINARY_DRIFT')
    finally:os.close(fd)
def load_sealer(source,expected):
    """Load the reviewed node sealer with its complete closed source closure."""
    manifest_raw=private(source/'sources.json');require(sha(manifest_raw)==expected,'SEALED_SOURCE_MANIFEST_DRIFT')
    manifest=decode(manifest_raw);hashes=manifest['sourceHashes']
    require(manifest['schema']=='ouf.semantic-cohort-source-draft.v1' and manifest['startAuthorized'] is False and len(hashes)==29,'EXACT_COHORT_SOURCE_MANIFEST_REQUIRED')
    contents={}
    for name,digest in hashes.items():
        require(re.fullmatch('(tools|scripts)/[a-z_]+[.]py',name),'EXACT_SOURCE_PATH_REQUIRED')
        raw=private(source/name);require(sha(raw)==digest,'CLOSED_SOURCE_BYTES_DRIFT');compile(raw,name,'exec');contents[name]=raw
    cli=ast.parse(contents['scripts/semantic_provider_node_attestor.py'])
    assignments=[n for n in cli.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='MODULES' for t in n.targets)]
    require(len(assignments)==1,'EXACT_NODE_MODULE_CLOSURE_REQUIRED');modules=ast.literal_eval(assignments[0].value)
    package=types.ModuleType('tools');package.__path__=[];sys.modules['tools']=package
    for name in modules:
        key='tools/'+name+'.py';require(key in contents,'MISSING_CLOSED_NODE_MODULE')
        module=types.ModuleType('tools.'+name);module.__package__='tools';module.__file__=str(source/key)
        sys.modules[module.__name__]=module;setattr(package,name,module);exec(compile(contents[key],module.__file__,'exec'),module.__dict__)
    require(private(source/'sources.json')==manifest_raw and all(private(source/name)==raw for name,raw in contents.items()),'CLOSED_SOURCE_CHANGED')
    return sys.modules['tools.semantic_provider_node_observation'].rootfs_seal
def prepare(archive,archive_hash,manifest_digest,config_digest,umoci,umoci_hash,source,source_hash,output):
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED');os.umask(0o077)
    ancestors(output/'expected-rootfs.json');info=output.lstat()
    require(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700 and not list(output.iterdir()),'NEW_EMPTY_PRIVATE_OUTPUT_REQUIRED')
    budget=Budget();seal_function=load_sealer(source,source_hash);program(umoci,umoci_hash);ancestors(archive)
    fd=os.open(archive,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as incoming:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
            and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=536870912,'PRIVATE_FROZEN_IMAGE_REQUIRED')
        h=hashlib.sha256()
        while raw:=incoming.read(65536):budget.check();h.update(raw)
        require(h.hexdigest()==archive_hash,'FROZEN_IMAGE_HASH_DRIFT');incoming.seek(0)
        layout=output/'layout';blobs=spool_stream(incoming,layout,budget)
        require(attributes(before)==attributes(os.fstat(fd))==attributes(archive.lstat()),'FROZEN_ARCHIVE_CHANGED')
    diffs=verify_layout(layout,manifest_digest,config_digest,blobs,budget)
    bundle=output/'bundle'
    with tempfile.TemporaryFile() as logs:
        result=subprocess.run([str(umoci),'unpack','--image',str(layout)+':ouf-offline-expected',str(bundle)],
            stdin=subprocess.DEVNULL,stdout=logs,stderr=logs,timeout=budget.remaining(),env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        require(result.returncode==0,'OFFLINE_UMOCI_UNPACK_FAILED')
    program(umoci,umoci_hash)
    limits={'maxEntries':100000,'maxBytes':8589934592,'maxDepth':64};seal=seal_function(bundle/'rootfs',limits,budget)
    receipt={'schema':'ouf.semantic-offline-image-rootfs.v1','archiveSha256':archive_hash,'manifestDigest':manifest_digest,
        'configDigest':config_digest,'diffIds':diffs,'rootfsSeal':seal,'rootfsLimits':limits,'umociSha256':umoci_hash,
        'sourceManifestSha256':source_hash,'offlineImageRootfsReconstructed':True,'targetRootfsCompared':False,
        'dockerInitLayerAccepted':False,'privateKeysRead':0,'signaturesIssued':0,'containerLifecycleOperations':0,
        'imageImportPerformed':False,'providerCalls':0,'acceptanceGranted':False,'startAuthorized':False}
    write_once(output/'expected-rootfs.json',canonical(receipt));return receipt
def apply_docker_init(output,init_tool,init_hash,engine_commit,source,source_hash):
    """Apply the observed engine's own init-layer code to the offline copy only."""
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
    require(engine_commit=='464cd50c3d9e92877d56940ea160de6fca7bea23','EXACT_OBSERVED_ENGINE_SOURCE_REQUIRED')
    raw=private(output/'expected-rootfs.json');base=decode(raw)
    require(base['schema']=='ouf.semantic-offline-image-rootfs.v1' and base['offlineImageRootfsReconstructed'] is True
        and base['startAuthorized'] is False and base['sourceManifestSha256']==source_hash,'EXACT_OFFLINE_IMAGE_PROVENANCE_REQUIRED')
    sealer=load_sealer(source,source_hash);budget=Budget();root=output/'bundle/rootfs'
    require(sealer(root,base['rootfsLimits'],budget)==base['rootfsSeal'],'OFFLINE_IMAGE_ROOTFS_CHANGED')
    program(init_tool,init_hash)
    claim={'schema':'ouf.semantic-offline-docker-init-claim.v1','imageReceiptSha256':sha(raw),'engineCommit':engine_commit,
        'initToolSha256':init_hash,'startAuthorized':False}
    write_once(output/'docker-init-claim.json',canonical(claim))
    with tempfile.TemporaryFile() as logs:
        result=subprocess.run([str(init_tool),str(root)],stdin=subprocess.DEVNULL,stdout=logs,stderr=logs,
            timeout=budget.remaining(),env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        require(result.returncode==0,'OFFLINE_DOCKER_INIT_FAILED')
    program(init_tool,init_hash);require(private(output/'expected-rootfs.json')==raw,'OFFLINE_IMAGE_PROVENANCE_DRIFT')
    receipt={**base,'schema':'ouf.semantic-offline-docker-rootfs.v1','imageRootfsSeal':base['rootfsSeal'],
        'rootfsSeal':sealer(root,base['rootfsLimits'],budget),'imageReceiptSha256':sha(raw),'engineCommit':engine_commit,
        'initToolSha256':init_hash,'offlineDockerInitLayerApplied':True,'targetRootfsCompared':False,
        'dockerInitLayerAccepted':False,'acceptanceGranted':False,'startAuthorized':False}
    write_once(output/'expected-docker-rootfs.json',canonical(receipt));return receipt
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('archive','umoci','source','output'):parser.add_argument('--'+name,required=True,type=Path)
    for name in ('archive-sha256','manifest-digest','config-digest','umoci-sha256','source-manifest-sha256'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--docker-init-tool',required=True,type=Path)
    parser.add_argument('--docker-init-sha256',required=True)
    parser.add_argument('--engine-commit',required=True)
    args=parser.parse_args()
    try:
        result=prepare(args.archive,args.archive_sha256,args.manifest_digest,args.config_digest,args.umoci,args.umoci_sha256,args.source,args.source_manifest_sha256,args.output)
        result=apply_docker_init(args.output,args.docker_init_tool,args.docker_init_sha256,args.engine_commit,args.source,args.source_manifest_sha256)
        print('OUF_OFFLINE_IMAGE_ROOTFS='+json.dumps(result,sort_keys=True));return 0
    except Exception as error:
        reason=str(error) if isinstance(error,Denied) and re.fullmatch('[A-Z0-9_]{1,80}',str(error)) else 'OFFLINE_IMAGE_ROOTFS_UNPROVEN'
        print('OUF_OFFLINE_IMAGE_ROOTFS=BLOCKED REASON='+reason+' PARTIAL_EVIDENCE_RETAINED=true DO_NOT_RERUN_APPLY=true NO_RAW_OUTPUT=true');return 1
if __name__=='__main__':raise SystemExit(main())
