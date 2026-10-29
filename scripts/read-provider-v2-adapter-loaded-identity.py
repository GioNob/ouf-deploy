"""Read-only OCI-to-config identity proof for the imported adapter."""
import gzip,hashlib,json,os,stat,subprocess,tarfile
from pathlib import Path
ARCHIVE=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-stopped-create-a2kbzv6l/images/adapter.image.tar.gz')
ARCHIVE_HASH='8301649b854a01d0306fabb14a5f93dd08eb4b1df98c2af356c0c84773821207'
LOADED='sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc'
CONFIG='sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320'
def require(v,label):
    if not v:raise ValueError(label)
def main():
    require(os.geteuid()==0,'ROOT_REQUIRED')
    fd=os.open(ARCHIVE,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as source:
        a=os.fstat(source.fileno());require(stat.S_ISREG(a.st_mode) and a.st_uid==0 and stat.S_IMODE(a.st_mode)==0o600 and a.st_nlink==1 and a.st_size<536870912,'PRIVATE_ARCHIVE_REQUIRED')
        require(hashlib.file_digest(source,'sha256').hexdigest()==ARCHIVE_HASH,'ARCHIVE_HASH_DRIFT');source.seek(0)
        docs={};entries=0;total=0
        with gzip.GzipFile(fileobj=source) as plain,tarfile.open(fileobj=plain,mode='r|') as archive:
            for item in archive:
                entries+=1;total+=item.size;require(entries<=1024 and total<=8589934592,'ARCHIVE_BOUND')
                if item.isfile() and 0<item.size<=1048576:
                    raw=archive.extractfile(item).read();require(len(raw)==item.size,'ARCHIVE_TRUNCATED')
                    if raw.lstrip().startswith((b'{',b'[')):
                        docs['sha256:'+hashlib.sha256(raw).hexdigest()]=json.loads(raw)
                archive.members.clear()
        b=os.fstat(source.fileno());require(all(getattr(a,k)==getattr(b,k) for k in ('st_ino','st_size','st_mtime_ns','st_ctime_ns')),'ARCHIVE_CHANGED')
    require(CONFIG in docs,'VERIFIED_CONFIG_NOT_FOUND');cfg=docs[CONFIG]
    current=LOADED;chain=[]
    for _ in range(4):
        require(current in docs,'LOADED_DESCRIPTOR_NOT_IN_ARCHIVE');doc=docs[current];chain.append(current)
        require(isinstance(doc,dict),'OCI_DOCUMENT_REQUIRED')
        if 'config' in doc:
            require(doc['config']['digest']==CONFIG,'MANIFEST_CONFIG_MISMATCH');break
        options=[x for x in doc.get('manifests',[]) if (x.get('platform') or {}).get('os')=='linux' and (x.get('platform') or {}).get('architecture')=='amd64']
        if not options and len(doc.get('manifests',[]))==1:options=doc['manifests']
        require(len(options)==1,'SINGLE_PLATFORM_MANIFEST_REQUIRED');current=options[0]['digest'];require(current not in chain,'OCI_CHAIN_CYCLE')
    else:raise ValueError('OCI_CHAIN_BOUND')
    p=subprocess.run(['/usr/bin/docker','-H','unix:///var/run/docker.sock','image','inspect',LOADED],stdin=subprocess.DEVNULL,capture_output=True,timeout=20,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(p.returncode==0 and len(p.stdout)<1048576,'BOUNDED_INSPECT_REQUIRED');rows=json.loads(p.stdout);require(len(rows)==1,'ONE_IMAGE_REQUIRED');image=rows[0]
    require(image['Id']==LOADED and image['Architecture']==cfg['architecture']=='amd64' and image['Os']==cfg['os']=='linux','PLATFORM_IDENTITY_MISMATCH')
    require(image['RootFS']['Layers']==cfg['rootfs']['diff_ids'],'ROOTFS_MISMATCH')
    keys=('Entrypoint','Cmd','Env','WorkingDir','User','Volumes','ExposedPorts','Labels','Healthcheck','StopSignal','Shell')
    require(all(image['Config'].get(k)==cfg['config'].get(k) for k in keys),'STARTUP_CONFIGURATION_MISMATCH')
    report={'schema':'ouf.semantic-provider-v2-loaded-image-identity.v1','role':'adapter','status':'ARCHIVE_MANIFEST_CONFIG_AND_DOCKER_READBACK_MATCH','archiveSha256':ARCHIVE_HASH,'dockerImageId':LOADED,'configDigest':CONFIG,'manifestChain':chain,'rootfsMatches':True,'startupMatches':True,'readOnly':True,'containerLifecycleOperations':0,'imageImportPerformed':False,'secretValuesPrinted':False,'startAuthorized':False,'acceptanceGranted':False}
    print('OUF_ADAPTER_IMAGE_IDENTITY='+json.dumps(report,sort_keys=True,separators=(',',':')))
if __name__=='__main__':
    try:main()
    except Exception as exc:
        label=str(exc) if isinstance(exc,ValueError) and str(exc).replace('_','').isupper() else type(exc).__name__
        print('OUF_ADAPTER_IMAGE_IDENTITY=BLOCKED REASON='+label+' NO_RAW_OUTPUT=true');raise SystemExit(1)
