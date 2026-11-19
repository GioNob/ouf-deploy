#!/usr/bin/env python3
"""Reproduce a bounded source inventory; never grant runtime writer authority."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

MUTATION=re.compile(r'(?:storage(?:\(\))?|minio|s3)\.(?:put|delete|putObject|deleteObject)\(')

def require(condition,code):
    if not condition:raise ValueError(code)

def digest(data):return hashlib.sha256(data).hexdigest()

def read_bound(root,row):
    relative=PurePosixPath(row['path'])
    require(not relative.is_absolute() and '..' not in relative.parts and '\\' not in row['path'],'SAFE_SOURCE_PATH')
    path=root/relative
    require(path.is_file() and not path.is_symlink(),'REGULAR_SOURCE_REQUIRED:'+row['path'])
    raw=path.read_bytes()
    blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    require(blob==row['gitBlobSha'],'EXACT_GIT_BLOB:'+row['path'])
    if 'sha256' in row:require(digest(raw)==row['sha256'] and len(raw)==row['bytes'],'EXACT_SOURCE_BYTES:'+row['path'])
    return raw

def verify(source_root,index_path):
    raw=index_path.read_bytes();index=json.loads(raw)
    require(index['schema']=='ouf.storage-writer-source-index.v1','INDEX_SCHEMA')
    require(index['targetOperations']==0 and not index['currentRuntimeBindingsVerified']
            and not index['allWritersInventoried'] and not index['releaseAdmitted'],'STATIC_SCOPE_ONLY')
    sources=index['files'];keys=[(r['module'],r['path']) for r in sources]
    require(len(keys)==len(set(keys))==256,'EXACT_UNIQUE_SOURCE_SET')
    require(set(index['expectedJavaFiles'])=={'onboarding','udp','ingestion'},'EXACT_THREE_MODULES')
    matches=[];byte_count=0;counts={}
    for row in sources:
        require(row['module'] in index['expectedJavaFiles'],'KNOWN_MODULE')
        content=read_bound(source_root/row['module'],row);byte_count+=len(content)
        if row['path'].startswith('src/main/java/') and row['path'].endswith('.java'):
            for n,line in enumerate(content.decode().splitlines(),1):
                if MUTATION.search(line):matches.append({'module':row['module'],'path':row['path'],'line':n})
    for module,expected in index['expectedJavaFiles'].items():
        root=source_root/module
        actual={p.relative_to(root).as_posix() for p in (root/'src/main/java').rglob('*.java')}
        listed={r['path'] for r in sources if r['module']==module and r['path'].startswith('src/main/java/') and r['path'].endswith('.java')}
        require(actual==listed and len(actual)==expected,'COMPLETE_MAIN_JAVA_SET:'+module)
        counts[module]=len(actual)
    order=lambda r:(r['module'],r['path'],r['line'])
    require(sorted(matches,key=order)==sorted(index['expectedDirectMutationCallsites'],key=order),'REVIEWED_LEXICAL_MUTATION_CALLSITES')
    retained=index['reportedRetainedOnboarding']
    require(len(retained['equalFiles'])==6 and not retained['currentLiveObservation'],'RETAINED_SOURCE_SCOPE')
    for row in retained['equalFiles']:read_bound(source_root/'onboarding-retained',row)
    return {'schema':'ouf.storage-writer-source-readback.v1','status':'PINNED_SOURCE_MAP_VERIFIED_RUNTIME_OPEN',
            'indexSha256':digest(raw),'sourceFilesVerified':len(sources),'sourceBytesVerified':byte_count,
            'mainJavaFiles':counts,'lexicalMutationCallsitesVerified':len(matches),'retainedOnboardingSourceComparisons':6,
            'sourceInspectionOnly':True,'currentRuntimeBindingsVerified':False,'allWritersInventoried':False,
            'targetOperations':0,'gatesClosed':0,'releaseAdmitted':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources',type=Path,required=True)
    parser.add_argument('--index',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=verify(args.sources,args.index)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('OUF_WRITER_SOURCE_READBACK_JSON='+json.dumps(result,sort_keys=True))
