#!/usr/bin/env python3
"""Start the frozen image in disposable CI; synthetic DB/OIDC, no target access."""
import argparse,importlib.util,json,os,re,subprocess,tempfile,time,uuid,urllib.request,threading,http.server
from pathlib import Path
spec=importlib.util.spec_from_file_location('baseline',Path(__file__).with_name('baseline.py'))
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
EXPECTED={'schema':'ouf.semantic-rootfs-seal.v1','entries':9302,'bytes':1719645735,
          'sha256':'a73d7520737345d67030baaa2405478b3784fc84060f6ec6ccc6109f98ac2f11'}

def main():
    p=argparse.ArgumentParser();p.add_argument('--part',type=Path,required=True);p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--profile');p.add_argument('--mount-profile');a=p.parse_args()
    b.require(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true','DISPOSABLE_ROOT_CI_ONLY')
    b.require(os.environ.get('DOCKER_HOST','')in('','unix:///var/run/docker.sock') and os.environ.get('DOCKER_CONTEXT','')in('','default'),'LOCAL_DAEMON_ONLY')
    a.output.mkdir(mode=0o755);owned=[];network='ouf-running-rootfs-'+uuid.uuid4().hex;server=None
    def docker(*args):
        r=subprocess.run(['docker',*args],stdin=subprocess.DEVNULL,capture_output=True,timeout=180)
        b.require(r.returncode==0 and len(r.stdout)<=2097152,'CI_DOCKER_FAILED_'+args[0]);return r.stdout.decode().strip()
    def inspect(cid):return json.loads(docker('inspect',cid))[0]
    def scan(root):
        observe,entries=b.sealer(a.source_root);seal=observe(root,b.LIMITS,b.Budget());b.require(seal==b.replay(entries),'SEAL_CAPTURE_REQUIRED');return seal,entries
    with tempfile.TemporaryDirectory(prefix='ouf-running-rootfs-',dir='/var/lib')as directory:
        work=Path(directory);work.chmod(0o755);record,qualified=b.unpack(a.part,work/'package')
        b.require(b.sha(work/'package/image.docker.tar')=='a0f1e2252f01a0e4a45c1262f124298000c56d206bdf9953b78bcd6b3ad4017a','FROZEN_ARCHIVE_REQUIRED')
        docker('load','--input',str(work/'package/image.docker.tar'));image=json.loads(docker('image','inspect',record['imageTag']))[0]
        b.require(image['Config']['Entrypoint']==b.JAVA and image['Config']['User']=='10001:10001' and image['Config']['Labels']['org.opencontainers.image.revision']==b.SOURCE,'FROZEN_LAUNCH_REQUIRED')
        info=json.loads(docker('info','--format','{{json .}}'));b.require(info['ServerVersion']=='29.8.1' and info['Driver']=='overlayfs','EXACT_DOCKER_REQUIRED')
        sources=[];targets=b.MOUNT_PROFILES['retained-registry-v1']
        for i in range(4):
            q=work/('input'+str(i));sources.append(q)
            if i<2:q.write_bytes((str(i)*64).encode());q.chmod(0o400 if i==0 else 0o440);os.chown(q,10001 if i==0 else 0,10001)
            else:
                q.mkdir(mode=0o500 if i==2 else 0o750);os.chown(q,10001 if i==2 else 0,10001)
                f=q/('OUF_SEM_DB_PASSWORD'if i==2 else'token');f.write_bytes(b'CI_SYNTHETIC_NO_AUTHORITY');f.chmod(0o400 if i==2 else 0o440);os.chown(f,10001 if i==2 else 0,10001)
        try:
            docker('network','create','--internal',network)
            net=json.loads(docker('network','inspect',network))[0];gateway=net['IPAM']['Config'][0]['Gateway']
            # Public OIDC metadata only: no token endpoint, signing, grants or accounts.
            class Metadata(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    body=json.dumps({'issuer':issuer,'authorization_endpoint':issuer+'/unused','jwks_uri':issuer+'/jwks',
                        'response_types_supported':['code'],'subject_types_supported':['public'],'id_token_signing_alg_values_supported':['RS256']}
                        if self.path.endswith('/.well-known/openid-configuration')else{'keys':[]}).encode()
                    self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
                def log_message(self,*args):pass
            server=http.server.ThreadingHTTPServer((gateway,0),Metadata);issuer='http://'+gateway+':'+str(server.server_port)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            docker('pull','postgres:16');pgimage=json.loads(docker('image','inspect','postgres:16'))[0]
            pg=docker('create','--network',network,'--network-alias','database','--env','POSTGRES_USER=ci',
                '--env','POSTGRES_DB=ouf_semantic','--env','POSTGRES_PASSWORD=CI_SYNTHETIC_NO_AUTHORITY',pgimage['Id']);owned.append(pg);docker('start',pg)
            ready=False
            for _ in range(60):
                r=subprocess.run(['docker','exec',pg,'pg_isready','-U','ci','-d','ouf_semantic'],capture_output=True,timeout=5)
                if r.returncode==0:ready=True;break
                time.sleep(1)
            b.require(ready,'DISPOSABLE_POSTGRES_NOT_READY')
            env={'OUF_SEM_DB_URL':'jdbc:postgresql://database:5432/ouf_semantic','OUF_SEM_DB_USER':'ci',
                'SPRING_CONFIG_IMPORT':'configtree:/run/ouf-semantic-db/','OUF_SCHEMA_GOV_ENABLED':'false','OUF_DISCOVERY_WORKER_ENABLED':'false',
                'OUF_IAM_ENABLED':'true','OUF_IAM_ISSUER':issuer,'OUF_IAM_AUDIENCE':'CI_NO_AUTHORITY',
                'OUF_SEMANTIC_PROPOSAL_RECEIPT_KEY_FILE':'/run/ouf/proposal.key','OUF_SEMANTIC_PROPOSAL_RECEIPT_ISSUER':'CI_NO_AUTHORITY',
                'OUF_SEMANTIC_PROPOSAL_RECEIPT_AUDIENCE':'CI_NO_AUTHORITY','OUF_SEMANTIC_PROPOSAL_RECEIPT_WORKLOAD':'CI_NO_AUTHORITY'}
            args=['create','--network',network,'--restart','no','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true','--entrypoint',b.ENTRY[0]]
            for k,v in sorted(env.items()):args+=['--env',k+'='+v]
            for q,t in zip(sources,targets):args+=['--mount','type=bind,src='+str(q)+',dst='+t+',readonly']
            cid=docker(*args,image['Id'],*b.ENTRY[1:],*b.JAVA);owned.append(cid);docker('start',cid);docker('pause',cid)
            native=inspect(cid);pid=native['State']['Pid'];proc=Path('/proc',str(pid));root=Path(info['DockerRootDir'])/'rootfs/overlayfs'/cid
            b.require(proc.joinpath('cmdline').read_bytes()==b'\0'.join(x.encode()for x in [*b.ENTRY,*b.JAVA])+b'\0','PREJAVA_GATE_REQUIRED')
            pre,baseline=scan(root);b.require(pre==EXPECTED,'INDEPENDENT_RETAINED_BASELINE_REQUIRED')
            docker('unpause',cid);docker('kill','--signal','USR1',cid)
            address=inspect(cid)['NetworkSettings']['Networks'][network]['IPAddress'];url='http://'+address+':8080/actuator/health/liveness'
            live=False
            for _ in range(90):
                if not inspect(cid)['State']['Running']:
                    print(docker('logs','--tail','100',cid));break # disposable synthetic inputs only
                try:
                    with urllib.request.urlopen(url,timeout=1)as response:live=json.load(response).get('status')=='UP'
                    if live:break
                except Exception:pass
                time.sleep(1)
            b.require(live,'FROZEN_JAVA_LIVENESS_NOT_READY')
            b.require(inspect(cid)['State']['Pid']==pid and proc.joinpath('cmdline').read_bytes()==b'\0'.join(x.encode()for x in b.JAVA)+b'\0','SAME_RUNNING_JAVA_GENERATION_REQUIRED')
            observations=[]
            for _ in range(2):
                seal,entries=scan(root)
                changed=[k for k,v in baseline.items()if entries.get(k)!=v];added={k:v for k,v in entries.items()if k not in baseline}
                b.require(not changed,'ORIGINAL_BASELINE_ENTRY_CHANGED')
                observations.append({'seal':seal,'additions':added})
                for k,v in added.items():
                    if v['kind']=='file':
                        raw=(root/k).read_bytes();(a.output/'runtime-file.bin').write_bytes(raw)
                time.sleep(1)
            (a.output/'process-maps.txt').write_text(proc.joinpath('maps').read_text())
            result={'schema':'ouf.chatbot-frozen-running-rootfs-ci.v1','baselineSeal':pre,'observations':observations,
                'moduleSource':b.SOURCE,'configurationImageId':b.IMAGE,'archiveSha256':b.sha(work/'package/image.docker.tar'),
                'sameJavaPid':True,'livenessUp':True,'syntheticDatabase':True,'syntheticOidcMetadata':True,'authorizationBundleAbsent':True,
                'vpsAccesses':0,'runtimeAuthorityIssued':False,'acceptanceGranted':False,'notReleaseAcceptance':True,
                'postgresFixtureImage':pgimage['Id'],'dockerVersion':info['ServerVersion']}
            (a.output/'summary.json').write_bytes(b.encoded(result)+b'\n');print(b.encoded(result).decode())
        finally:
            if server:server.shutdown();server.server_close()
            for cid in reversed(owned):subprocess.run(['docker','rm','--force',cid],capture_output=True,timeout=20)
            subprocess.run(['docker','network','rm',network],capture_output=True,timeout=20)
if __name__=='__main__':main()
