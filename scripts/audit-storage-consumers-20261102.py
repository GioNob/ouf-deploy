#!/usr/bin/env python3
"""Audit bounded public first-party source bodies at six immutable commits."""
import hashlib,json,re,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
expected=json.loads((ROOT/'releases/seaweedfs-public-source-audit-20261102.json').read_text())['modules']
pattern=re.compile(r'minio|s3client|s3://|object://|presign|lake\.s3|staging\.(endpoint|bucket)|aws_|ouf-minio|:9000',re.I)
results=[]
for module in expected:
 repo=module['repository'].split('/')[-1];source=ROOT/'audit-sources'/repo
 assert subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()==module['commit']
 assert not subprocess.check_output(['git','-C',str(source),'status','--porcelain'])
 files=subprocess.check_output(['git','-C',str(source),'ls-tree','-r','--name-only','HEAD'],text=True).splitlines()
 hits=[];scanned=0;excluded=0
 for name in files:
  p=source/name
  if any(part in {'vendor','authorization-sdk','docs','.git'} for part in Path(name).parts) or not p.is_file() or p.is_symlink() or p.stat().st_size>262144:
   excluded+=1;continue
  raw=p.read_bytes()
  try:text=raw.decode('utf-8')
  except UnicodeDecodeError:excluded+=1;continue
  scanned+=1
  lines=[i for i,line in enumerate(text.splitlines(),1) if pattern.search(line)]
  if lines:hits.append({'path':name,'sha256':hashlib.sha256(raw).hexdigest(),'gitBlob':subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD:'+name],text=True).strip(),'matchingLines':lines})
 results.append({'repository':module['repository'],'commit':module['commit'],'scannedTextFiles':scanned,'excludedFiles':excluded,'hits':hits})
out=ROOT/'storage-public-audit';out.mkdir()
record={'schema':'ouf.storage-public-body-audit.v1','modules':results,'targetInventoryComplete':False,'exclusions':['vendor and embedded authorization SDK','documentation','symlinks/non-UTF8/files over256KiB'],'method':'Regex source-body discovery, not semantic proof of absence of indirect consumers','targetOperations':0}
p=out/'audit.json';p.write_text(json.dumps(record,indent=2)+'\n');(out/'SHA256SUMS').write_text(hashlib.sha256(p.read_bytes()).hexdigest()+'  audit.json\n')
print(json.dumps([{'repo':m['repository'],'scanned':m['scannedTextFiles'],'matchingFiles':len(m['hits']),'excluded':m['excludedFiles']} for m in results]))
