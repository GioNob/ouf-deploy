#!/usr/bin/env python3
"""Download one successful source-locked cohort using the existing GitHub login.
Only creates a private local delivery directory; never sudo, docker load or apply.
"""
import argparse, hashlib, json, os, re, shutil, subprocess, tempfile, zipfile
from pathlib import Path

REPO='GioNob/ouf-deploy'
LIMIT=6*1024**3

def require(ok, reason):
    if not ok:raise ValueError(reason)

def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=int,required=True);p.add_argument('--producer-commit',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    require(re.fullmatch('[0-9a-f]{40}',a.producer_commit),'EXACT_PRODUCER_COMMIT_REQUIRED')
    preferred=Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
    gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
    require(gh,'EXISTING_GH_UNAVAILABLE')
    def api(endpoint):
        r=subprocess.run([gh,'api',endpoint],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
        require(len(r.stdout)<=4*1024**2,'API_REPLY_UNBOUNDED');return json.loads(r.stdout)
    run=api(f'repos/{REPO}/actions/runs/{a.run}')
    require(run.get('head_sha')==a.producer_commit and run.get('conclusion')=='success'
            and run.get('path')=='.github/workflows/semantic-proposal-candidate-package.yml','EXACT_SUCCESSFUL_PRODUCER_REQUIRED')
    listing=api(f'repos/{REPO}/actions/runs/{a.run}/artifacts?per_page=100')
    require(listing['total_count']<=100,'ARTIFACT_LIST_TRUNCATED')
    candidates=[v for v in listing['artifacts'] if v['name']==f'chatbot-file-cohort-{a.run}']
    require(len(candidates)==1 and not candidates[0]['expired'],'ONE_RETAINED_COHORT_REQUIRED')
    item=candidates[0];digest=item.get('digest','');require(re.fullmatch(r'sha256:[0-9a-f]{64}',digest),'PRODUCER_ARCHIVE_HASH_REQUIRED')
    require(0<item['size_in_bytes']<=LIMIT,'BOUNDED_COHORT_ARCHIVE_REQUIRED')
    output=a.output.absolute();require(not output.exists() and output.parent.is_dir(),'NEW_EXISTING_PARENT_OUTPUT_REQUIRED')
    output.mkdir(mode=0o700)
    archive=output/'cohort.zip.partial'
    with archive.open('xb') as dest:
        subprocess.run([gh,'api',f'repos/{REPO}/actions/artifacts/{item["id"]}/zip'],stdout=dest,stderr=subprocess.DEVNULL,check=True,timeout=900)
    require(archive.stat().st_size==item['size_in_bytes'] and sha(archive)==digest.split(':')[1],'ARCHIVE_HASH_MISMATCH')
    with zipfile.ZipFile(archive) as z:
        names=z.namelist();require(len(names)<=256 and len(set(names))==len(names),'ZIP_MEMBER_SET_INVALID')
        for info in z.infolist():
            name=info.filename;require(not info.is_dir() and re.fullmatch(r'[A-Za-z0-9_.\-/]+',name)
                and not name.startswith('/') and '..' not in Path(name).parts and ((info.external_attr>>16)&0o170000)!=0o120000,'ZIP_PATH_OR_SYMLINK_DENIED')
        require(sum(v.file_size for v in z.infolist())<=LIMIT,'ZIP_CONTENT_UNBOUNDED')
        require(z.getinfo('COHORT_SHA256SUMS').file_size<=100000,'CHECKSUM_LIST_UNBOUNDED')
        declared={}
        for line in z.read('COHORT_SHA256SUMS').decode().splitlines():
            require(re.fullmatch(r'[0-9a-f]{64}  [A-Za-z0-9_.\-/]+',line),'CHECKSUM_LINE_INVALID')
            value,name=line.split('  ',1);require(name not in declared,'DUPLICATE_CHECKSUM_MEMBER');declared[name]=value
        require(set(names)==set(declared)|{'COHORT_SHA256SUMS','COHORT_SHA256SUMS.sigstore.json'},'UNDECLARED_ARCHIVE_MEMBER')
        for name,value in declared.items():
            with z.open(name) as f:require(hashlib.file_digest(f,'sha256').hexdigest()==value,'MEMBER_HASH_MISMATCH')
        manifest=json.loads(z.read('cohort-manifest.json'));lock=json.loads(z.read('source-lock.json'))
        require(manifest['sourceLockSha256']==hashlib.sha256(z.read('source-lock.json')).hexdigest(),'SOURCE_LOCK_MISMATCH')
        require(manifest['producer']['sourceCommit']==a.producer_commit and str(manifest['producer']['runId'])==str(a.run),'PRODUCER_MANIFEST_MISMATCH')
        require(len(lock['modules'])==6 and len(manifest['modules'])==6,'SIX_MODULES_REQUIRED')
        expected={r['module']:r['commit'] for r in lock['modules']};observed={r['module']:r['sourceCommit'] for r in manifest['modules']}
        require(expected==observed and set(expected)=={'semantic','onboarding','ingestion','udp','gateway','mcp'},'COHORT_PIN_MISMATCH')
        require(manifest['targetApplyAuthorized'] is False and manifest['runtimeAuthorityIssued'] is False,'UNEXPECTED_AUTHORITY_CLAIM')
    archive.rename(output/'cohort.zip')
    (output/'delivery-receipt.json').write_text(json.dumps({'schema':'ouf.chatbot-file-cohort-download.v1','status':'HASH_VERIFIED_NOT_EXTRACTED',
        'runId':a.run,'producerCommit':a.producer_commit,'artifactId':item['id'],'archiveSha256':digest.split(':')[1],
        'moduleSources':expected,'publisherSignatureRetained':True,'publisherSignatureLocallyVerified':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'serviceMutations':0,'notReleaseAcceptance':True},sort_keys=True)+'\n')
    print((output/'delivery-receipt.json').read_text().strip())

if __name__=='__main__':
    try:main()
    except Exception as e:
        print(json.dumps({'status':'BLOCKED','reason':str(e) if type(e) is ValueError else type(e).__name__,
                          'automaticRetry':False,'targetApplyAuthorized':False,'serviceMutations':0}))
        raise SystemExit(1)
