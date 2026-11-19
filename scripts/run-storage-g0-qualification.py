#!/usr/bin/env python3
"""Disposable native qualification of the new read-only G0 collector. No target launcher."""
import argparse,hashlib,json,os,shutil,subprocess,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
MINIO='ghcr.io/datalens-tech/minio@sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2'
MINIO_ID='sha256:69b2ec208575b69597784255eec6fa6a2985ee9e1a47f4411a51f7f5fdd193a9'
def require(ok,code):
 if not ok:raise ValueError(code)
def write(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def command(args,timeout=120):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 require(r.returncode==0,'COMMAND_FAILED:'+args[0]+':'+r.stderr[-4000:]);return r.stdout.strip()
def stage(work):
 require(os.environ.get('GITHUB_ACTIONS')=='true' and not work.exists(),'NEW_ISOLATED_CI_SCOPE')
 work.mkdir(mode=0o700);out=work/'evidence';out.mkdir();scan=work/'scan';scan.mkdir()
 for n in ['go.mod','go.sum']:shutil.copyfile(ROOT/'tools/storage_inventory'/n,scan/n)
 env=dict(os.environ,GOTOOLCHAIN='go1.27.3',GOMAXPROCS='2');cwd=ROOT/'tools/storage_inventory'
 with (out/'unit-tests.jsonl').open('w') as log:subprocess.run(['go','test','-count=1','-json','-run','^TestG0','-skip','Native','.'],cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=300)
 for args in [['test','-c','-o',str(scan/'inventory.test')],['build','-trimpath','-o',str(scan/'inventory'),'.']]:subprocess.run(['go',*args],cwd=cwd,env=env,check=True,timeout=300)
 write(out/'executables.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in scan.iterdir() if p.name not in ['go.mod','go.sum']})
def run(work):
 require(os.environ.get('GITHUB_ACTIONS')=='true','DISPOSABLE_CI_ONLY');out=work/'evidence'
 scan=json.loads((out/'trivy.json').read_text());require(scan.get('SchemaVersion')==2 and scan.get('Results'),'RAW_SCAN_REQUIRED')
 binaries={Path(r['Target']).name for r in scan['Results'] if r.get('Type')=='gobinary'};require({'inventory','inventory.test'}<=binaries,'BOTH_COMPILED_EXECUTABLE_SCANS_REQUIRED')
 require(not any(v.get('Severity','UNKNOWN') in ['HIGH','CRITICAL','UNKNOWN'] for r in scan['Results'] for v in r.get('Vulnerabilities',[]) or []),'G0_TOOL_SECURITY_HELD')
 command(['docker','pull',MINIO],300);require(json.loads(command(['docker','image','inspect',MINIO]))[0]['Id']==MINIO_ID,'EXACT_LEGACY_SOURCE_IMAGE')
 tls=work/'tls';tls.mkdir();data=work/'data';data.mkdir()
 command(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','1','-subj','/CN=OUF synthetic G0','-addext','subjectAltName=IP:127.0.0.1','-keyout',str(tls/'private.key'),'-out',str(tls/'public.crt')]);(tls/'private.key').chmod(0o600)
 name='ouf-g0-'+os.environ['GITHUB_RUN_ID'];created=False
 try:
  command(['docker','run','--detach','--name',name,'--network','none','--user',str(os.getuid())+':'+str(os.getgid()),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','1g','--cpus','2','--pids-limit','128','--log-opt','max-size=8m','--tmpfs','/tmp:rw,noexec,nosuid,size=67108864,mode=1777','--mount','type=bind,src='+str(data)+',dst=/data','--mount','type=bind,src='+str(tls)+',dst=/tls,readonly','-e','MINIO_ROOT_USER=synthetic-g0-admin','-e','MINIO_ROOT_PASSWORD=synthetic-g0-secret-not-production',MINIO_ID,'server','/data','--address',':18443','--console-address',':19001','--certs-dir','/tls']);created=True
  view=json.loads(command(['docker','inspect',name]))[0];host=view['HostConfig'];require(view['State']['Running'] and view['Image']==MINIO_ID and host['NetworkMode']=='none' and host['ReadonlyRootfs'] and host['CapDrop']==['ALL'] and not host['Privileged'] and not host['PortBindings'],'ISOLATED_SOURCE')
  ns=['sudo','-n','nsenter','-t',str(view['State']['Pid']),'-n'];interfaces=json.loads(command(ns+['ip','-j','link']));routes=json.loads(command(ns+['ip','-j','route']));require([x['ifname'] for x in interfaces]==['lo'] and not routes,'NO_EGRESS')
  write(out/'isolation.json',{'image':MINIO_ID,'networkMode':host['NetworkMode'],'interfaces':interfaces,'routes':routes,'publishedPorts':host['PortBindings'],'readOnlyRoot':host['ReadonlyRootfs'],'capDrop':host['CapDrop'],'legacyProductionSecurityGate':'HELD_UNCHANGED','publisherAuthenticatedForLegacyMinio':False})
  readiness='import ssl,urllib.request,time\nc=ssl.create_default_context(cafile='+repr(str(tls/'public.crt'))+')\nend=time.monotonic()+60\nwhile True:\n try:\n  r=urllib.request.urlopen("https://127.0.0.1:18443/minio/health/ready",context=c,timeout=2);assert r.status==200;break\n except Exception:\n  if time.monotonic()>end:raise\n  time.sleep(1)\n'
  command(ns+['python3','-I','-B','-S','-c',readiness],70)
  args=ns+['setpriv','--reuid',str(os.getuid()),'--regid',str(os.getgid()),'--clear-groups','env','OUF_G0_NATIVE_ENDPOINT=https://127.0.0.1:18443','OUF_G0_NATIVE_WORK='+str(work),'OUF_G0_BINARY='+str(work/'scan/inventory'),'OUF_G0_CA='+str(tls/'public.crt'),str(work/'scan/inventory.test'),'-test.v','-test.run=^TestG0NativeMinio$','-test.timeout=600s']
  with (out/'native.log').open('w') as log:r=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,timeout=620)
  require(r.returncode==0,'G0_NATIVE_FAILED');proof=json.loads((out/'native-minio.json').read_text());require(proof['objects']==120 and proof['collection']['complete'] and proof['collection']['verifiedBodies']==120,'ALL_NATIVE_BODY_PROOFS')
 finally:
  if created:
   logs=subprocess.run(['docker','logs',name],capture_output=True,timeout=30);(out/'server.log').write_bytes((logs.stdout+logs.stderr)[-32768:]);command(['docker','stop','--time','30',name],45);state=json.loads(command(['docker','inspect',name]))[0]['State'];write(out/'exit.json',state);command(['docker','rm',name]);require(not state['Running'] and not state['OOMKilled'] and state['ExitCode']==0,'CLEAN_STOP')
def seal(work):
 out=work/'evidence';out.mkdir(parents=True,exist_ok=True)
 sources=[p for p in command(['git','ls-files']).splitlines() if p.startswith('tools/storage_inventory/') or p in ['scripts/run-storage-g0-qualification.py','.github/workflows/storage-g0-qualification.yml']]
 write(out/'source-sha256.json',{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources})
 with tarfile.open(out/'sources.tar.gz','w:gz') as t:
  for p in sources:t.add(ROOT/p,arcname=p,recursive=False)
 (out/'source-commit.txt').write_text(os.environ['GITHUB_SHA']+'\n')
 total=0
 for p in out.iterdir():
  require(p.is_file() and not p.is_symlink(),'REGULAR_PUBLIC_EVIDENCE');b=p.read_bytes();total+=len(b);require(len(b)<=8<<20 and total<=32<<20 and b'-----BEGIN PRIVATE KEY' not in b,'BOUNDED_PUBLIC_EVIDENCE')
 (out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.name!='SHA256SUMS'))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('action',choices=['stage','run','seal']);p.add_argument('work',type=Path);a=p.parse_args();globals()[a.action](a.work.resolve())
