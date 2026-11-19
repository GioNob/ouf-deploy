#!/usr/bin/env python3
"""Stage source-hash-bound update code only. Never acquire target authority."""
import hashlib,json,os,re,runpy,sys
from pathlib import Path

def stage(repository,output,commit):
 repository=Path(repository).resolve();output=Path(output)
 assert re.fullmatch('[0-9a-f]{40}',commit)
 assert output.is_absolute() and output.resolve()==output and not output.exists()
 executor=repository/'scripts/execute-chat-recovery-update-20261018.py'
 overlays=runpy.run_path(str(executor))['OVERLAYS']
 files={'execute.py':executor.read_bytes(),
        'runtime.py':(repository/'tools/chat_recovery_update/runtime.py').read_bytes(),
        'case.json':(repository/'releases/chat-recovery-update-selection-20261018.json').read_bytes()}
 hashes={}
 for module,(name,relative) in overlays.items():
  assert re.fullmatch('[A-Za-z0-9_.-]+',name) and name not in files
  source=repository/relative
  assert source.resolve()==source and source.is_file()
  files[name]=source.read_bytes();hashes[module]=hashlib.sha256(files[name]).hexdigest()
 package={'schema':'ouf.chat-recovery-executable-package.v1','sourceCommit':commit,
  'sourceHashes':hashes,'executorSha256':hashlib.sha256(files['execute.py']).hexdigest(),
  'loaderSha256':hashlib.sha256(files['runtime.py']).hexdigest(),
  'caseSha256':hashlib.sha256(files['case.json']).hexdigest()}
 raw=json.dumps(package,sort_keys=True,separators=(',',':')).encode()
 files['package.json']=raw
 output.mkdir(mode=0o700)
 for name,data in files.items():
  with (output/name).open('xb') as stream:
   os.chmod(output/name,0o600);stream.write(data);stream.flush();os.fsync(stream.fileno())
  assert (output/name).read_bytes()==data
 print(json.dumps({'schema':'ouf.chat-recovery-executable-staging.v1','complete':True,
  'codeDirectory':str(output),'sourceCommit':commit,'packageSha256':hashlib.sha256(raw).hexdigest(),
  'fileCount':len(files),'runtimeMutations':0,'runtimeAuthorityIssued':False},sort_keys=True))
 return package
if __name__=='__main__':
 assert len(sys.argv)==4
 stage(*sys.argv[1:])
