#!/usr/bin/env python3
import ast,hashlib,json,os,sys,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(b):return hashlib.sha256(b).hexdigest()
def write(p,d):p.write_text(json.dumps(d,sort_keys=True,indent=2)+'\n')
work=Path(sys.argv[1]);out=work/'evidence';out.mkdir(parents=True,exist_ok=True);bundle=work/'input-tools';bundle.mkdir()
profilepath='releases/storage-g0-input-preparation-profile-20261106.json';profile=json.loads((ROOT/profilepath).read_text());deps=profile['unchangedDependencySha256'];assert len(deps)==3 and all(sha((ROOT/p).read_bytes())==h for p,h in deps.items())
rosterpath='tools/m2_discovery_installation_profile/retained_mount_role_correction.py';tree=ast.parse((ROOT/rosterpath).read_text());roster=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ROSTER' for t in n.targets));assert roster==profile['roster']
files=list(deps)+['tools/storage_planning/g0_input_draft.py','scripts/prepare-storage-g0-inputs-20261106.py',profilepath,'docs/OUF_STORAGE_G0_INPUT_PREPARATION_20261106.md']
for p in files:f=bundle/p;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes((ROOT/p).read_bytes())
log=(out/'tests.log').read_bytes();assert b'Ran 14 tests' in log and log.rstrip().endswith(b'OK') and b'skipped' not in log
manifest={'schema':'ouf.storage-g0-input-tools.v1','deployCommit':os.environ['GITHUB_SHA'],'files':{p:sha((bundle/p).read_bytes()) for p in files},'tests':14,'nativeProviderQualification':False,'runtimeAuthorityIssued':False};write(bundle/'tool-manifest.json',manifest)
with tarfile.open(out/'input-tools.tar.gz','w:gz') as t:
 for p in sorted(bundle.rglob('*')):
  if p.is_file():t.add(p,arcname=str(p.relative_to(bundle)),recursive=False)
sources=files+[rosterpath,'scripts/package-storage-g0-inputs-20261106.py','tests/test_storage_g0_input_draft.py','.github/workflows/storage-g0-input-preparation.yml'];write(out/'source-sha256.json',{p:sha((ROOT/p).read_bytes()) for p in sources})
with tarfile.open(out/'sources.tar.gz','w:gz') as t:
 for p in sorted(sources):t.add(ROOT/p,arcname=p,recursive=False)
raw=(out/'input-tools.tar.gz').read_bytes();write(out/'delivery.json',{'schema':'ouf.storage-g0-input-tools-delivery.v1','deployCommit':os.environ['GITHUB_SHA'],'packageSha256':sha(raw),'packageBytes':len(raw),'manifestSha256':sha((bundle/'tool-manifest.json').read_bytes()),'tests':14,'unchangedDependencies':deps,'providerRequests':0,'runtimeAuthorityIssued':False,'targetInputCheckPassed':False,'acceptanceCreditAdded':0})
(out/'SHA256SUMS').write_text(''.join(sha(p.read_bytes())+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.name!='SHA256SUMS'))
