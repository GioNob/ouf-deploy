#!/usr/bin/env python3
"""Disposable CI-only pre-Java image seal, never target acceptance authority."""
import argparse,hashlib,json,os,pathlib,re,subprocess,sys,tempfile,time,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from gated_creation_plan import ENTRY
from tools.semantic_provider_node_observation import rootfs_seal

LIMITS={'maxEntries':100000,'maxBytes':8589934592,'maxDepth':64}
TARGETS=['/run/ouf/delegation.key','/run/ouf/proposal.key','/run/ouf/database','/run/ouf/policy']
def require(ok,reason):
    if not ok:raise ValueError(reason)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
class Budget:
    def __init__(self):self.until=time.monotonic()+180
    def check(self):require(time.monotonic()<self.until,'CI_ROOTFS_SEAL_DEADLINE')
    def remaining(self,limit=10):self.check();return min(limit,self.until-time.monotonic())
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-record',required=True);parser.add_argument('--image',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();require(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true','ROOT_DISPOSABLE_GITHUB_CI_REQUIRED')
    require(os.environ.get('DOCKER_HOST','') in ('','unix:///var/run/docker.sock')
        and os.environ.get('DOCKER_CONTEXT','') in ('','default'),'LOCAL_DISPOSABLE_DOCKER_REQUIRED')
    record_raw=pathlib.Path(args.package_record).read_bytes();require(len(record_raw)<=131072,'BOUNDED_PACKAGE_RECORD_REQUIRED');record=json.loads(record_raw)
    image=record.get('imageId');require(type(image) is str and re.fullmatch('sha256:[a-f0-9]{64}',image) and record.get('runtimeUser')=='10001:10001'
        and re.fullmatch('[a-f0-9]{40}',record.get('sourceCommit','')),'EXACT_QUALIFIED_IMAGE_RECORD_REQUIRED')
    require(record.get('imageTag')==args.image,'EXACT_QUALIFIED_IMAGE_TAG_REQUIRED');budget=Budget();name='ouf-ci-rootfs-'+uuid.uuid4().hex;cid=None
    def docker(*argv,raw=False):
        budget.check();r=subprocess.run(['docker',*argv],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            timeout=budget.remaining(15),env={k:v for k,v in os.environ.items() if k in ('PATH','DOCKER_HOST','DOCKER_CONTEXT','DOCKER_CONFIG')})
        require(r.returncode==0 and len(r.stdout)<=2097152,'CI_DOCKER_READ_OR_LIFECYCLE_UNPROVEN');return r.stdout if raw else r.stdout.decode().strip()
    with tempfile.TemporaryDirectory(prefix='ouf-ci-rootfs-inputs-') as directory:
        d=pathlib.Path(directory);d.chmod(0o755)
        (d/'policy').mkdir(mode=0o750);os.chown(d/'policy',0,10001)
        (d/'database').mkdir(mode=0o500);os.chown(d/'database',10001,10001)
        for path,value,uid,gid,mode in [(d/'delegation.key','0'*64,10001,10001,0o400),(d/'proposal.key','1'*64,0,10001,0o440),
            (d/'database/OUF_SEM_DB_PASSWORD','ci-only-not-a-target-secret',10001,10001,0o400),(d/'policy/token','ci-only-no-runtime-authority',0,10001,0o440)]:
            path.write_text(value);os.chown(path,uid,gid);path.chmod(mode)
        try:
            native=json.loads(docker('image','inspect',args.image))[0]
            require(native.get('Id')==image and native.get('Config',{}).get('User')=='10001:10001'
                and native['Config'].get('Entrypoint')==['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar']
                and native['Config'].get('Cmd') in (None,[]),'CI_EXACT_IMAGE_LAUNCH_REQUIRED')
            arguments=['create','--name',name,'--network','none','--restart','no','--user','10001:10001','--cap-drop','ALL',
                '--security-opt','no-new-privileges:true','--entrypoint',ENTRY[0]]
            sources=[d/'delegation.key',d/'proposal.key',d/'database',d/'policy']
            for source,target in zip(sources,TARGETS):arguments+=['--mount','type=bind,src='+str(source)+',dst='+target+',readonly']
            arguments += [image,*ENTRY[1:],'java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar']
            cid=docker(*arguments);require(re.fullmatch('[a-f0-9]{64}',cid),'EXACT_CREATED_CI_CONTAINER_REQUIRED')
            docker('start',cid);docker('pause',cid)
            before=json.loads(docker('inspect',cid))[0];merged=before.get('GraphDriver',{}).get('Data',{}).get('MergedDir')
            require(type(merged) is str and merged.startswith('/') and pathlib.Path(merged).is_dir(),'CI_CLASSIC_DOCKER_MERGED_ROOTFS_REQUIRED')
            require(before.get('Image')==image and before['State']['Running'] is True and before['State']['Paused'] is True
                and before.get('RestartCount')==0 and before['Config']['Entrypoint']==[ENTRY[0]]
                and before['Config']['Cmd']==[*ENTRY[1:],'java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar'],
                'CI_EXACT_PAUSED_PREAPPLICATION_GATE_REQUIRED')
            expected=[*ENTRY,'java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar']
            raw=(pathlib.Path('/proc')/str(before['State']['Pid'])/'cmdline').read_bytes()
            require(raw==b'\0'.join(v.encode() for v in expected)+b'\0','CI_GATE_EXECUTED_UNEXPECTED_PROCESS')
            seal=rootfs_seal(pathlib.Path(merged),LIMITS,budget)
            after=json.loads(docker('inspect',cid))[0]
            require(after['Id']==before['Id'] and after['Image']==image and after['State']==before['State']
                and after['GraphDriver']==before['GraphDriver'] and (pathlib.Path('/proc')/str(before['State']['Pid'])/'cmdline').read_bytes()==raw,
                'CI_ROOTFS_GENERATION_CHANGED')
            result={'schema':'ouf.semantic-independent-ci-rootfs-seal.v1','sourceCommit':record['sourceCommit'],'imageId':image,
                'packageRecordHash':hashlib.sha256(record_raw).hexdigest(),'rootfsSeal':seal,'limits':LIMITS,
                'derivation':'CLASSIC_DOCKER_MERGED_ROOTFS_PAUSED_PREAPPLICATION_GATE','gateEntrypoint':ENTRY,'mountTargets':TARGETS,
                'javaStarted':False,'syntheticPrivateInputs':True,'targetAcceptance':False,'runtimeAuthorityIssued':False}
            target=pathlib.Path(args.output)
            with target.open('xb') as stream:stream.write(canonical(result)+b'\n')
            print(json.dumps({'status':'INDEPENDENT_CI_ROOTFS_SEAL_COMPUTED','imageId':image,'rootfsSealHash':seal['sha256'],
                'entries':seal['entries'],'targetAcceptance':False},sort_keys=True))
        finally:
            # Only this invocation's randomly named CI container is removed.
            if cid:
                subprocess.run(['docker','rm','--force',cid],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
if __name__=='__main__':main()
