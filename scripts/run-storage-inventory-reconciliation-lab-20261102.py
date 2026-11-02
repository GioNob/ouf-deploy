#!/usr/bin/env python3
"""Reuse the independently attested executables; switch only the native fixture."""
import hashlib,json,os,subprocess,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
assert os.environ.get('GITHUB_ACTIONS')=='true'
if sys.argv[1]=='stage':
 out=ROOT/'sw-evaluation';out.mkdir()
 with zipfile.ZipFile(ROOT/'sw-readback/original.zip') as z:
  for name in ['bin/weed','bin/storage-inventory','candidate.json','compiled-packages.json']:
   p=out/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(z.read(name))
 for p in (out/'bin').iterdir():p.chmod(0o500)
 assert hashlib.sha256((out/'bin/storage-inventory').read_bytes()).hexdigest()=='430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8'
elif sys.argv[1]=='run':
 original=ROOT/'scripts/run-seaweedfs-contract-20261102.py';body=original.read_text();old='scripts/test-storage-target-native-20261102.py';new='scripts/test-storage-inventory-reconciliation-native-20261102.py';assert body.count(old)==1
 body=body.replace(old,new);code=compile(body,str(original),'exec');exec(code,{'__name__':'__main__','__file__':str(original)})
else:raise ValueError('EXACT_MODE_REQUIRED')
