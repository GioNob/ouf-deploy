"""Stage a bounded private-preparation package; no target reads or authority."""
import hashlib,json,os,re,sys
from pathlib import Path
FILES={
 'entry.py':'tools/source_revision_update/entry.py',
 'login.py':'tools/source_revision_update/login.py',
 'configuration.py':'tools/source_revision_update/configuration.py',
 'reader.py':'scripts/prepare-source-revision-inputs.py',
 'owner.py':'tools/host_network_reconciliation.py',
 'boot_reader.py':'scripts/read-source-revision-boot-guard.py',
 'bootstrap.py':'scripts/reconcile-host-network-20261018.py',
 'policy.py':'scripts/source-revision-postboot-policy.py',
 'prepare.py':'scripts/source-revision-postboot-prepare.py',
 'executor.py':'scripts/execute-source-revision-postboot.py',
 'run.py':'scripts/run-source-revision-postboot.py',
 'guard_selection.json':'releases/source-revision-boot-read-selection-20261018.json',
 'selection.json':'releases/source-revision-postboot-preparation-20261018.json'}
def stage(repository,directory,commit):
 root=Path(repository).resolve();target=Path(directory)
 if not re.fullmatch('[a-f0-9]{40}',commit) or not target.is_absolute() or target.exists():raise ValueError('NEW_PINNED_STAGE_REQUIRED')
 files={name:(root/path).read_bytes() for name,path in FILES.items()}
 manifest={'schema':'ouf.source-revision-postboot-code.v1','sourceCommit':commit,
           'files':{n:hashlib.sha256(v).hexdigest() for n,v in files.items()}}
 files['manifest.json']=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()
 target.mkdir(mode=0o700)
 for name,raw in files.items():
  with (target/name).open('xb') as f:
   os.fchmod(f.fileno(),0o600);f.write(raw);f.flush();os.fsync(f.fileno())
 print(json.dumps({'directory':str(target),'manifestSha256':hashlib.sha256(files['manifest.json']).hexdigest(),
                   'sourceCommit':commit,'fileCount':len(files),'runtimeMutations':0,'runtimeAuthorityIssued':False}))
if __name__=='__main__':stage(*sys.argv[1:])
