from pathlib import Path
import subprocess,os,json,time,sys
R=Path('/workspace/scratch/98dabd1608e5');S=R/'source32-integrated-stage';E=os.environ.copy();E.update(TMPDIR=str(R/'tmp'),GOTMPDIR=str(S/'go-work'),GOROOT=str(R/'go-toolchain'),GOTOOLCHAIN='local',GOMODCACHE=str(R/'gopath/pkg/mod'),GOCACHE=str(R/'gocache'),GOPATH=str(R/'gopath'),GOPROXY=os.environ.get('OUF_GOPROXY','off'),CGO_ENABLED=os.environ.get('OUF_TEST_CGO','0'),GOOS='linux',GOARCH='amd64')
(S/'go-work').mkdir(exist_ok=True)
source=Path(os.environ.get('OUF_SOURCE_DIR',str(S/'source')));name=sys.argv[1];args=sys.argv[2:];cmd=[str(R/'go-toolchain/bin/go')]+args;start=time.time()
with(S/'evidence'/f'{name}.stdout').open('w')as o,(S/'evidence'/f'{name}.stderr').open('w')as e:p=subprocess.run(cmd,cwd=source,env=E,stdout=o,stderr=e)
(S/'evidence'/f'{name}.command.json').write_text(json.dumps({'command':cmd,'cwd':str(source.relative_to(R)),'exitCode':p.returncode,'elapsedSeconds':round(time.time()-start,3),'CGO_ENABLED':E['CGO_ENABLED'],'GOOS':E['GOOS'],'GOARCH':E['GOARCH'],'GOPROXY':E['GOPROXY'],'GOTMPDIR':E['GOTMPDIR'],'TMPDIR':E['TMPDIR']},indent=2)+'\n');print(name,p.returncode,flush=True)
if p.returncode:print((S/'evidence'/f'{name}.stderr').read_text()[-3000:])
