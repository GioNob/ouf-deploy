#!/usr/bin/env python3
"""Extract the exact retained publisher ZIP in disposable CI, never execute it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner')]
from tools.chatbot_file_cohort.package_custody import extract_cohort,extract_source,new_directory
from tools.chatbot_file_cohort.plan import require

ARCHIVE='be55c6eda4485a4c90da9872f63e2533abe21c741c4926ecc129626cc01530f9'
PRODUCER='f31a653ee1da56b29a6171c159f9c601523735b9'
RUN=38536134146
SOURCES={'onboarding':'84828f74ac586bae09a78f0fb197b75b1a3d98d1',
         'gateway':'bf179e96200deb84942ad32507edef52a4284cd0'}
TEMPLATES=('ops/policy_token/ouf-policy-token@.service','ops/policy_token/ouf-policy-token@.timer')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--archive',required=True)
    parser.add_argument('--destination',required=True)
    args=parser.parse_args()
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.dont_write_bytecode
            and sys.flags.no_site,'ISOLATED_DISPOSABLE_ROOT_QUALIFICATION_REQUIRED')
    destination=Path(args.destination)
    destination.mkdir(mode=0o700)
    print('ORIGINAL_ARTIFACT_PHASE=COMPLETE_COHORT_EXTRACTION',flush=True)
    package,manifest,receipt=extract_cohort(args.archive,ARCHIVE,PRODUCER,RUN,destination)
    records={row['module']:row for row in manifest['modules']}
    inventories={}
    for module,commit in SOURCES.items():
        require(records[module]['sourceCommit']==commit,'EXACT_RETAINED_MODULE_SOURCE_REQUIRED')
        print('ORIGINAL_ARTIFACT_PHASE=SOURCE_EXTRACTION module='+module,flush=True)
        target=new_directory(destination,module+'-source')
        extract_source(package,records[module],target)
        files=[p for p in target.rglob('*') if p.is_file()]
        for path in files:
            info=path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                    and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,
                    'EXTRACTED_SOURCE_PRIVATE_REGULAR_FILE_REQUIRED')
        inventories[module]={'sourceCommit':commit,'sourceArchiveSha256':records[module]['files']['source.tar'],
                             'regularFileCount':len(files)}
        if module=='gateway':
            for name in TEMPLATES:require((target/name).is_file(),'QUALIFIED_SYSTEMD_TEMPLATE_MISSING')
    print(json.dumps({'schema':'ouf.chatbot-file-original-artifact-extraction-qualification.v1',
        'status':'ORIGINAL_ARTIFACT_EXTRACTION_QUALIFIED','artifactId':11880585559,
        'archiveSha256':ARCHIVE,'producerCommit':PRODUCER,'runId':RUN,
        'modulePackageCount':len(records),'sourceArchives':inventories,
        'gatewaySystemdTemplatesVerified':list(TEMPLATES),
        'sourceCodeExecuted':False,'publisherSignatureLocallyVerified':False,
        'serviceMutations':0,'providerCalls':0,'targetCalls':0,'runtimeAuthorityIssued':False,
        'notReleaseAcceptance':True},sort_keys=True,separators=(',',':')),flush=True)


if __name__=='__main__':main()
