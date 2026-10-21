"""Read-only diagnosis of the retained provider v2 image-import failure."""
import json,os,shutil,stat,subprocess
from pathlib import Path
ROOT=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-stopped-create-a2kbzv6l')
IMAGES={'adapter':'sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320','southbound':'sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04'}
PATTERNS={'DISK_SPACE':('no space left','not enough space'), 'INODES':('inode',), 'ARCHIVE_FORMAT':('invalid tar','invalid archive','unexpected eof','unrecognized image','unsupported media type'), 'DOCKER_API':('client version','api version'), 'STORAGE_DRIVER':('failed to register layer','failed to extract','failed to unpack','snapshotter','overlayfs'), 'PERMISSION':('permission denied','operation not permitted'), 'MEMORY':('out of memory','cannot allocate memory')}
def run(args):
    p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=20,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    if len(p.stdout)+len(p.stderr)>2097152:raise RuntimeError('OUTPUT_BOUND')
    return p

def main():
    if os.geteuid()!=0:raise RuntimeError('ROOT_REQUIRED')
    d=['/usr/bin/docker','-H','unix:///var/run/docker.sock']
    info=run(d+['info','--format','{{json .}}'])
    if info.returncode:raise RuntimeError('DOCKER_INFO_FAILED')
    i=json.loads(info.stdout);usage=shutil.disk_usage(i['DockerRootDir']);fs=os.statvfs(i['DockerRootDir'])
    r={'schema':'ouf.semantic-provider-v2-import-read-only-diagnosis.v1','snapshotDirectory':str(ROOT),'readOnly':True,'imageImportPerformed':False,'containerLifecycleOperations':0,'privateKeysRead':0,'secretValuesPrinted':False,'docker':{'serverVersion':i['ServerVersion'],'storageDriver':i['Driver'],'freeBytes':usage.free,'freeInodes':fs.f_favail},'images':{},'candidateNamesPresent':[],'journalErrorCategories':[]}
    for role,imageid in IMAGES.items():
        p=run(d+['image','inspect','--format','{{.Id}}',imageid]);archive=ROOT/'images'/(role+'.image.tar.gz')
        s=archive.lstat() if archive.exists() else None
        r['images'][role]={'exactImagePresent':p.returncode==0 and p.stdout.decode().strip()==imageid,'frozenArchivePresent':s is not None,'frozenArchiveBytes':s.st_size if s else None,'frozenArchiveRegular':stat.S_ISREG(s.st_mode) if s else False,'createdReceiptPresent':(ROOT/(role+'-created.json')).exists()}
    p=run(d+['ps','-a','--format','{{.Names}}'])
    if p.returncode:raise RuntimeError('CONTAINER_LIST_FAILED')
    r['candidateNamesPresent']=[x for x in p.stdout.decode().splitlines() if x in ('ouf-semantic-provider-v2','ouf-semantic-southbound-v2')]
    p=run(['/usr/bin/journalctl','-u','docker.service','--since','-30 minutes','--no-pager','-n','250','-o','cat'])
    r['journalReadable']=p.returncode==0
    if p.returncode==0:
        logs=p.stdout.decode(errors='replace').lower();r['journalErrorCategories']=sorted(k for k,v in PATTERNS.items() if any(x in logs for x in v))
    print('OUF_IMPORT_DIAGNOSIS='+json.dumps(r,sort_keys=True,separators=(',',':')))
if __name__=='__main__':
    try:main()
    except Exception as e:
        print('OUF_IMPORT_DIAGNOSIS=BLOCKED ERROR_CLASS='+type(e).__name__+' NO_RAW_OUTPUT=true');raise SystemExit(1)
