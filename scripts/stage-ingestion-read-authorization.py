"""Stage public qualified code only; no privileged target inputs or effects."""
import hashlib,json,os,re,shutil,sys
from pathlib import Path

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def require(ok,reason):
    if not ok:raise ValueError(reason)

def main(root,directory,commit):
    root=Path(root).resolve();directory=Path(directory)
    require(re.fullmatch('[0-9a-f]{40}',commit),'EXACT_CHECKOUT_COMMIT_REQUIRED')
    require(directory.is_absolute() and directory.parent.resolve()==directory.parent,'EXACT_STAGE_PARENT_REQUIRED')
    selected={'prepare.py':'scripts/prepare-ingestion-read-authorization.py',
        'bootstrap.py':'scripts/execute-ingestion-read-authorization.py',
        'reader.py':'scripts/read-source-revision-completed-20261019.py',
        'selection.json':'releases/ingestion-read-administrative-installation-20261019.json'}
    for name in('entry','authority','authorization','login','iam','runtime'):
        selected[name+'.py']='tools/ingestion_read_authorization/'+name+'.py'
    directory.mkdir(mode=0o700)
    hashes={}
    for name,path in selected.items():
        source=root/path
        require(source.resolve()==source and source.is_file() and not source.is_symlink(),'EXACT_CHECKED_OUT_SOURCE_REQUIRED')
        raw=source.read_bytes();require(0<len(raw)<=262144,'BOUNDED_SOURCE_REQUIRED')
        with open(directory/name,'xb')as stream:stream.write(raw)
        os.chmod(directory/name,0o600);hashes[name]=hashlib.sha256(raw).hexdigest()
    manifest={'schema':'ouf.ingestion-read-administrative-code.v1','sourceCommit':commit,'files':hashes,
        'installationSpecific':True,'runtimeAuthorityIssued':False,'privateInputsRead':False}
    raw=encoded(manifest)
    with open(directory/'manifest.json','xb')as stream:stream.write(raw)
    os.chmod(directory/'manifest.json',0o600)
    print(encoded({'schema':'ouf.ingestion-read-administrative-stage-receipt.v1','stagePath':str(directory),
        'sourceCommit':commit,'filesStaged':len(hashes),'manifestSha256':hashlib.sha256(raw).hexdigest(),
        'preparerSha256':hashes['prepare.py'],'runtimeAuthorityIssued':False,'privateInputsRead':False,
        'infrastructureEffects':0,'completedTechnicalPhases':8,'functionalMilestonesProven':4}).decode())
if __name__=='__main__':main(*sys.argv[1:])
