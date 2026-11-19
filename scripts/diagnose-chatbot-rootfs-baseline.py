#!/usr/bin/env python3
"""Disposable CI comparison of the frozen Registry image across image stores.

No target access, image rebuild, Java release, signing or runtime acceptance.
Capture the unchanged v1 sealer's complete canonical entry stream for diagnosis.
"""
import argparse,ast,hashlib,json,os,re,stat,subprocess,tempfile,time,uuid,zipfile
from pathlib import Path

PART_SHA='5d28e55ca5541efadec4b93a6396c8f84d21e6db92766b785b1cd8c3fd10db09'
SOURCE='eccef11a97367f20e278db40b9ed6f45dd980c37'
IMAGE='sha256:29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489'
LIMITS={'maxEntries':100000,'maxBytes':8589934592,'maxDepth':64}
TARGETS=['/run/ouf/delegation.key','/run/ouf/proposal.key','/run/ouf/database','/run/ouf/policy']
MOUNT_PROFILES={'ci-original':TARGETS,'retained-registry-v1':[
    '/run/secrets/semantic-read-owner.key','/run/ouf/proposal.key','/run/ouf-semantic-db','/run/ouf-semantic-auth']}
GATE='OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"'
ENTRY=['/bin/sh','-c',GATE,'ouf-gated-application']
JAVA=['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar']

def require(ok,reason):
    if not ok:raise ValueError(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(path):
    with Path(path).open('rb')as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def decode(raw):return json.loads(raw)
def attributes(info):return tuple(getattr(info,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def ancestors(path):
    for parent in Path(path).parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_CONTROLLED_CI_ANCESTRY_REQUIRED')
class Budget:
    def __init__(self,seconds=180):self.end=time.monotonic()+seconds
    def check(self):require(time.monotonic()<self.end,'FINITE_CI_ROOTFS_SCAN_TIMEOUT')

def unpack(part,output):
    require(sha(part)==PART_SHA,'EXACT_RETAINED_SEMANTIC_ARTIFACT_REQUIRED')
    output.mkdir(mode=0o700)
    selected=['candidate-manifest.json','package-record.pre-export.json','independent-rootfs-seal.json','image.docker.tar']
    with zipfile.ZipFile(part)as archive:
        names=archive.namelist();require(len(names)==len(set(names))and len(names)<=64,'BOUNDED_UNIQUE_PACKAGE_REQUIRED')
        for name in selected:
            row=archive.getinfo(name);require(not row.is_dir()and row.file_size<=2147483648 and ((row.external_attr>>16)&0o170000)!=0o120000,'REGULAR_BOUNDED_PACKAGE_MEMBER_REQUIRED')
            with archive.open(row)as source,(output/name).open('xb')as target:
                while raw:=source.read(1048576):target.write(raw)
    record=decode((output/'package-record.pre-export.json').read_bytes());qualified=decode((output/'independent-rootfs-seal.json').read_bytes())
    manifest=decode((output/'candidate-manifest.json').read_bytes())
    require(record['imageId']==qualified['imageId']==manifest['imageId']==IMAGE
        and record['sourceCommit']==qualified['sourceCommit']==manifest['sourceCommit']==SOURCE
        and qualified['packageRecordHash']==sha(output/'package-record.pre-export.json')
        and qualified['limits']==LIMITS and qualified['javaStarted']is False,'FROZEN_PACKAGE_SEAL_BINDING_REQUIRED')
    return record,qualified

def sealer(source_root):
    source=Path(source_root)/'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_node_observation.py'
    raw=source.read_bytes()
    # Exact original v1 function source, not a replacement or normalized seal.
    require(hashlib.sha256(raw).hexdigest()=='5a355a9904b6fc4bf665bb79c438e1cb9f3d11f8c2505b16df9834c046fde9c2','FROZEN_SEALER_SOURCE_REQUIRED')
    tree=ast.parse(raw);tree.body=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='rootfs_seal']
    require(len(tree.body)==1,'ONE_ORIGINAL_SEALER_REQUIRED')
    records={}
    def record(item):
        require(item['path']not in records,'DUPLICATE_ROOTFS_ENTRY');records[item['path']]=item
        return encoded(item)
    ns=dict(os=os,Path=Path,stat=stat,hashlib=hashlib,require=require,ancestors=ancestors,attributes=attributes,encoded=record,PreexecDenied=ValueError)
    exec(compile(tree,'<frozen-original-rootfs-sealer>','exec'),ns)
    return ns['rootfs_seal'],records

def replay(records):
    h=hashlib.sha256(b'OUF-ROOTFS-SEAL\x00V1\x00')
    total=0
    for item in records.values():
        raw=encoded(item);h.update(len(raw).to_bytes(4,'big'));h.update(raw)
        if item['kind']=='file':total+=item['size']
    return {'schema':'ouf.semantic-rootfs-seal.v1','sha256':h.hexdigest(),'entries':len(records),'bytes':total}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--part',type=Path,required=True);parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--profile',choices=['classic','containerd'],required=True)
    parser.add_argument('--mount-profile',choices=tuple(MOUNT_PROFILES),default='ci-original')
    args=parser.parse_args();targets=MOUNT_PROFILES[args.mount_profile]
    require(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true','DISPOSABLE_ROOT_CI_ONLY')
    require(os.environ.get('DOCKER_HOST','')in('','unix:///var/run/docker.sock')and os.environ.get('DOCKER_CONTEXT','')in('','default'),'LOCAL_DISPOSABLE_DAEMON_ONLY')
    args.output.mkdir(mode=0o755);cid=None;name='ouf-rootfs-diagnosis-'+uuid.uuid4().hex
    def docker(*argv):
        r=subprocess.run(['docker',*argv],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=180)
        require(r.returncode==0 and len(r.stdout)<=2097152,'DISPOSABLE_DOCKER_OPERATION_FAILED')
        return r.stdout.decode().strip()
    with tempfile.TemporaryDirectory(prefix='ouf-rootfs-ci-',dir='/var/lib')as directory:
        root=Path(directory);root.chmod(0o755);record,qualified=unpack(args.part,root/'package')
        docker('load','--input',str(root/'package/image.docker.tar'))
        native=decode(docker('image','inspect',record['imageTag']))[0]
        require(native.get('Config',{}).get('Entrypoint')==JAVA and native['Config'].get('User')=='10001:10001'
            and native['Config'].get('Cmd')in(None,[])and native.get('RootFS',{}).get('Type')=='layers'
            and native['Config'].get('Labels',{}).get('org.opencontainers.image.revision')==SOURCE,'EXACT_ORIGINAL_APPLICATION_CONFIGURATION_REQUIRED')
        require(native['Id']==IMAGE if args.profile=='classic'else native['Id'].startswith('sha256:'),'NATIVE_IMAGE_IDENTITY_REQUIRED')
        info=decode(docker('info','--format','{{json .}}'))
        require(info['ServerVersion']=='29.8.1'and info['Driver']==('overlay2'if args.profile=='classic'else'overlayfs'),'EXACT_DISPOSABLE_DOCKER_PROFILE_REQUIRED')
        sources=[]
        for i in range(4):
            p=root/('input'+str(i));sources.append(p)
            if i<2:p.write_bytes((str(i)*64).encode());p.chmod(0o400 if i==0 else 0o440);os.chown(p,10001 if i==0 else 0,10001)
            else:
                p.mkdir(mode=0o500 if i==2 else 0o750);os.chown(p,10001 if i==2 else 0,10001)
                f=p/('OUF_SEM_DB_PASSWORD'if i==2 else'token');f.write_bytes(b'CI_SYNTHETIC_NO_AUTHORITY');f.chmod(0o400 if i==2 else 0o440);os.chown(f,10001 if i==2 else 0,10001)
        arguments=['create','--name',name,'--network','none','--restart','no','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true','--entrypoint',ENTRY[0]]
        for p,target in zip(sources,targets):arguments+=['--mount','type=bind,src='+str(p)+',dst='+target+',readonly']
        try:
            cid=docker(*arguments,native['Id'],*ENTRY[1:],*JAVA);require(re.fullmatch('[a-f0-9]{64}',cid),'EXACT_CI_CONTAINER_REQUIRED')
            docker('start',cid);docker('pause',cid);before=decode(docker('inspect',cid))[0];pid=before['State']['Pid']
            require(before['State']['Running']is True and before['State']['Paused']is True and before['RestartCount']==0,'PAUSED_PREAPPLICATION_CI_GENERATION_REQUIRED')
            cmdline=Path('/proc',str(pid),'cmdline').read_bytes()
            require(cmdline==b'\0'.join(v.encode()for v in [*ENTRY,*JAVA])+b'\0','JAVA_MUST_NOT_HAVE_EXECUTED')
            merged=Path(before['GraphDriver']['Data']['MergedDir'])if args.profile=='classic'else Path(info['DockerRootDir'])/'rootfs/overlayfs'/cid
            process_root=Path('/proc',str(pid),'root')
            require((merged.stat().st_dev,merged.stat().st_ino)==(process_root.stat().st_dev,process_root.stat().st_ino),'SAME_CI_ROOTFS_REQUIRED')
            for p,target in zip(sources,targets):
                view=merged/target.lstrip('/')
                require(view.exists()and(view.stat().st_dev,view.stat().st_ino)!=(p.stat().st_dev,p.stat().st_ino),'CI_BIND_CONTENT_VIEW_DENIED')
            observe,records=sealer(args.source_root);first=observe(merged,LIMITS,Budget())
            observe_again,records_again=sealer(args.source_root);second=observe_again(merged,LIMITS,Budget())
            # The second independent pass uses a fresh recorder to prohibit
            # accidental duplicate entries or a silently different scan order.
            require(first==second==replay(records) and records==records_again,'STABLE_CI_ROOTFS_SEAL_REQUIRED')
            after=decode(docker('inspect',cid))[0]
            require(before==after and Path('/proc',str(pid),'cmdline').read_bytes()==cmdline,'CI_GENERATION_CHANGED')
            result={'schema':'ouf.chatbot-frozen-rootfs-baseline.v1','profile':args.profile,'mountProfile':args.mount_profile,'mountTargets':targets,
                'dockerVersion':info['ServerVersion'],'driver':info['Driver'],
                'partArtifactSha256':PART_SHA,'sourceCommit':SOURCE,'configurationImageId':IMAGE,'nativeImageId':native['Id'],
                'imageArchiveSha256':sha(root/'package/image.docker.tar'),'qualifiedRootfsSeal':qualified['rootfsSeal'],'observedRootfsSeal':first,
                'qualifiedSealMatches':first==qualified['rootfsSeal'],'stableDoubleSeal':True,'javaStarted':False,
                'vpsAccesses':0,'runtimeAuthorityIssued':False,'acceptanceGranted':False,'notReleaseAcceptance':True}
            (args.output/'summary.json').write_bytes(encoded(result)+b'\n')
            (args.output/'entries.json').write_bytes(encoded({'summary':result,'entries':list(records.values())})+b'\n')
            for p in args.output.iterdir():p.chmod(0o644)
            print('FROZEN_ROOTFS_BASELINE='+encoded(result).decode(),flush=True)
        finally:
            if cid:subprocess.run(['docker','rm','--force',cid],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)

if __name__=='__main__':main()

