"""Read fixed signed provider archives and report role-specific startup inputs only."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import tarfile

ROOT=Path('/home/oufadmin/ouf-crypto-v2.zjJNdo')
ROLES={
    'adapter':{'archiveSha256':'8301649b854a01d0306fabb14a5f93dd08eb4b1df98c2af356c0c84773821207','imageId':'sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320'},
    'southbound':{'archiveSha256':'1588c2391f9da45f300d16dd191cfe483dff83f81ed9424baec40201e64d7641','imageId':'sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04'},
}

def require(value):
    if not value: raise ValueError('ROLE_ARCHIVE_UNPROVEN')

def inspect(path, expected):
    sha=expected['imageId'][7:]; paths={sha+'.json','blobs/sha256/'+sha}
    configs=[]; manifests=[]; count=0
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as incoming:
        before=os.fstat(incoming.fileno()); require(stat.S_ISREG(before.st_mode) and 0<before.st_size<=536870912)
        require(hashlib.file_digest(incoming,'sha256').hexdigest()==expected['archiveSha256']); incoming.seek(0)
        with gzip.GzipFile(fileobj=incoming) as plain,tarfile.open(fileobj=plain,mode='r|') as archive:
            for member in archive:
                count+=1; require(count<=4096)
                name=member.name.removeprefix('./')
                if name!='manifest.json' and name not in paths: continue
                require(member.isfile() and 0<member.size<=131072)
                raw=archive.extractfile(member).read()
                if name=='manifest.json': manifests.append(json.loads(raw))
                else:
                    require(hashlib.sha256(raw).hexdigest()==sha); configs.append(json.loads(raw))
        fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
        require(tuple(getattr(before,k) for k in fields)==tuple(getattr(os.fstat(incoming.fileno()),k) for k in fields)==tuple(getattr(path.lstat(),k) for k in fields))
    require(len(configs)==len(manifests)==1 and len(manifests[0])==1 and manifests[0][0]['Config'].removeprefix('./') in paths)
    config=configs[0]; require(config['os']=='linux' and config['architecture']=='amd64')
    cfg=config['config']; require(type(cfg) is dict)
    startup={k:cfg.get(k) for k in ('Entrypoint','Cmd','WorkingDir','User')}
    environment=cfg.get('Env') or []; require(all(type(v) is str and '=' in v for v in environment))
    return {**expected,'bytesVerified':True,'os':'linux','architecture':'amd64','packagedStartup':startup,
        'startupHash':hashlib.sha256(json.dumps(startup,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'packagedEnvironmentNames':sorted({v.split('=',1)[0] for v in environment}),
        'packagedExposedPorts':sorted((cfg.get('ExposedPorts') or {}).keys()),
        'packagedVolumePaths':sorted((cfg.get('Volumes') or {}).keys())}

def main():
    try:
        roles=[{'role':role,**inspect(ROOT/(role+'.image.tar.gz'),facts)} for role,facts in ROLES.items()]
        print('OUF_PROVIDER_ROLE_ARTIFACT_PLAN='+json.dumps({'schema':'ouf.discovery.provider-role-artifact-plan.v1',
            'roles':roles,'scope':'EXACT_REMEDIATED_PROVIDER_ROLE_ARCHIVES','environmentValuesPrinted':False,
            'containerLifecycleOperations':0,'imageImportPerformed':False,'configurationWrites':0,
            'publisherTrustAccepted':False,'acceptanceGranted':False,'startAuthorized':False},sort_keys=True))
        return 0
    except Exception:
        print('OUF_PROVIDER_ROLE_ARTIFACT_PLAN=BLOCKED NO_RAW_OUTPUT=true'); return 1

if __name__=='__main__': raise SystemExit(main())
