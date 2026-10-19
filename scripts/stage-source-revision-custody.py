"""Stage source-only governed continuation; no protected target access."""
import hashlib,json,os,re,sys
from pathlib import Path
FILES={'prepare.py':'scripts/prepare-source-revision-custody-continuation.py','native.py':'tools/source_revision_update/custody_native.py','entry.py':'tools/source_revision_update/custody_entry.py','login.py':'tools/source_revision_update/custody_login.py'}
def stage(repository,directory,commit):
 root=Path(repository).resolve();target=Path(directory)
 if not re.fullmatch('[a-f0-9]{40}',commit)or not target.is_absolute()or target.exists():raise ValueError('EXCLUSIVE_QUALIFIED_STAGE_REQUIRED')
 files={k:(root/v).read_bytes()for k,v in FILES.items()};manifest={'schema':'ouf.source-revision-custody-code.v1','sourceCommit':commit,'files':{k:hashlib.sha256(v).hexdigest()for k,v in files.items()}};files['manifest.json']=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode();target.mkdir(mode=0o700)
 for name,raw in files.items():
  with (target/name).open('xb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(raw);stream.flush();os.fsync(stream.fileno())
 print(json.dumps({'directory':str(target),'manifestSha256':hashlib.sha256(files['manifest.json']).hexdigest(),'sourceCommit':commit,'fileCount':len(files),'runtimeAuthorityIssued':False,'runtimeMutations':0}))
if __name__=='__main__':stage(*sys.argv[1:])
