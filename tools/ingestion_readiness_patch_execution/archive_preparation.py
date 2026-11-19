"""Finite offline native archive successor. Never imports or contacts a runtime.

Retained parent inputs and compressed image are read through no-follow custody.
New private files/claim are never reused after interruption; preserve on STOP.
"""
import gzip
import hashlib
import os
from pathlib import Path
import stat
import image_custody
from tools.ingestion_readiness_patch_execution import contract as c,custody,private_file,archive_projection
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal

SCHEMA='ouf.ingestion-readiness-native-archive-case.v1'

def case_valid(case):
    c.require(type(case)is dict and set(case)=={'schema','snapshotRoot','parentInputsPath','parentInputsHash',
        'originalCompressedArchiveSha256','configurationImageId','nativeImageId','nativeArchiveSha256',
        'sourceCommit','expectedStageCount'} and case['schema']==SCHEMA,'EXACT_NATIVE_ARCHIVE_PREPARATION_CASE_REQUIRED')
    c.path(case['snapshotRoot']);c.path(case['parentInputsPath'])
    c.require(Path(case['parentInputsPath']).parent.parent==Path(case['snapshotRoot'])
        and Path(case['parentInputsPath']).name=='native-inputs.json'
        and all(c.hashed(case[k]) for k in ('parentInputsHash','originalCompressedArchiveSha256','nativeArchiveSha256'))
        and all(type(case[k])is str and case[k].startswith('sha256:') and c.hashed(case[k][7:])
                for k in ('configurationImageId','nativeImageId'))
        and type(case['sourceCommit'])is str and len(case['sourceCommit'])==40
        and all(x in '0123456789abcdef' for x in case['sourceCommit'])
        and type(case['expectedStageCount'])is int and 12<=case['expectedStageCount']<=19,
        'EXACT_RETAINED_PARENT_AND_NATIVE_ARCHIVE_IDENTITIES_REQUIRED')
    return case

def seal(path):
    selected=Path(path);ancestors=[]
    for p in reversed(selected.parents):
        s=p.lstat();c.require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,
                              'ROOT_PRIVATE_ARCHIVE_ANCESTRY_REQUIRED')
        ancestors.append({'path':str(p),'identity':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode]})
    s=selected.lstat();c.require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1
        and stat.S_IMODE(s.st_mode)==0o400,'IMMUTABLE_ROOT_ARCHIVE_OUTPUT_REQUIRED')
    fd=os.open(selected,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as stream:
        c.require(private_file.metadata(os.fstat(stream.fileno()))==private_file.metadata(s),'ARCHIVE_OUTPUT_FD_CHANGED')
        sha,size=image_custody.hashed(stream,image_custody.LIMIT)
        c.require(private_file.metadata(os.fstat(stream.fileno()))==private_file.metadata(s),'ARCHIVE_OUTPUT_FD_CHANGED')
    c.require(size==s.st_size and private_file.metadata(selected.lstat())==private_file.metadata(s),
              'ARCHIVE_OUTPUT_CHANGED_DURING_SEAL')
    return {'path':str(selected),'sha256':sha,'metadata':private_file.metadata(s),'ancestors':ancestors}

def output(directory,name):
    fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    return os.fdopen(fd,'w+b')

def freeze(stream):
    stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),0o400);os.fsync(stream.fileno())

def prepare(case):
    case_valid(case);root=Path(case['snapshotRoot']);target=root/('ingestion-readiness-native-archive-'+c.digest(case))
    claim=root/('ingestion-readiness-native-archive-'+case['parentInputsHash']+'.claim.json')
    # A repeated or interrupted preparation cannot open the image or parent again.
    with protected_directory(root) as directory:
        c.require(not os.path.lexists(target)and not os.path.lexists(claim),'NATIVE_ARCHIVE_PREPARATION_EXISTS_RECONCILE_ONLY')
    parent=custody.read(case['parentInputsPath'],case['parentInputsHash'])
    image=parent['candidate'];source=image['Config']['Labels']['org.opencontainers.image.revision']
    compressed=parent['candidateFileBindings']['image.tar.gz']
    c.require(image['Id']==case['configurationImageId'] and source==case['sourceCommit']
        and compressed['sha256']==case['originalCompressedArchiveSha256']
        and len(parent['finiteIntentContract']['stages'])==case['expectedStageCount']
        and 'nativeArchiveAudit' not in parent,'EXACT_COMPLETED_ORIGINAL_ARCHIVE_INPUTS_REQUIRED')
    # First validate all existing file metadata; no claim if the source is absent.
    private_file.check_metadata(compressed,maximum=image_custody.LIMIT)
    with protected_directory(root)as directory:
        c.require(not os.path.lexists(target)and not os.path.lexists(claim),'NATIVE_ARCHIVE_PREPARATION_EXISTS_RECONCILE_ONLY')
        Journal(root).create(claim,c.encoded({'schema':SCHEMA,'caseHash':c.digest(case),
            'parentInputsHash':case['parentInputsHash'],'contextPath':str(target),
            'automaticReplayAllowed':False,'runtimeAuthorityIssued':False}))
        Journal(root).sync();os.mkdir(target.name,0o700,dir_fd=directory);os.fsync(directory)
    with protected_directory(target)as directory:
        with private_file.opened(compressed,maximum=image_custody.LIMIT)as selected:
            with os.fdopen(os.dup(selected),'rb')as source_fd, gzip.GzipFile(fileobj=source_fd)as expanded:
                with output(directory,'source-image.tar')as plain:
                    size=0;digest=hashlib.sha256()
                    while True:
                        chunk=expanded.read(min(1048576,image_custody.LIMIT-size+1))
                        if not chunk:break
                        size+=len(chunk);c.require(size<=image_custody.LIMIT,'BOUNDED_EXPANDED_IMAGE_ARCHIVE_REQUIRED')
                        digest.update(chunk);plain.write(chunk)
                    plain.flush();plain.seek(0)
                    audit=image_custody.archive(plain,digest.hexdigest(),case['configurationImageId'],case['sourceCommit'])
                    with output(directory,'native-image.tar')as native:
                        derived=image_custody.tagless_archive(plain,native,audit,containerd=True)
                        c.require(derived['derivedArchiveSha256']==case['nativeArchiveSha256'],
                                  'EXACT_PREQUALIFIED_NATIVE_ARCHIVE_BYTES_REQUIRED')
                        checked=image_custody.archive(native,derived['derivedArchiveSha256'],case['configurationImageId'],case['sourceCommit'])
                        checked['nativeIdentity']=image_custody.native_identity(checked)
                        c.require(image_custody.runtime_image_id(checked)==case['nativeImageId'],
                                  'EXACT_PREQUALIFIED_NATIVE_MANIFEST_REQUIRED')
                        freeze(native)
                    freeze(plain)
        archive=seal(target/'native-image.tar')
        bundle=archive_projection.project(parent,case['parentInputsHash'],checked,archive)
        # Authenticate the immutable parent again after the full archive pass.
        c.require(custody.read(case['parentInputsPath'],case['parentInputsHash'])==parent,'PARENT_CHANGED_DURING_NATIVE_ARCHIVE_PREPARATION')
        with output(directory,'native-inputs.json')as stream:stream.write(c.encoded(bundle));freeze(stream)
        receipt={'schema':'ouf.ingestion-readiness-native-archive-result.v1','status':'NATIVE_ARCHIVE_INPUTS_PREPARED_NO_AUTHORITY',
            'complete':True,'contextPath':str(target),'parentInputsHash':case['parentInputsHash'],
            'bundleHash':c.digest(bundle),'configurationImageId':case['configurationImageId'],'nativeImageId':case['nativeImageId'],
            'nativeArchiveSha256':archive['sha256'],'logicalOperationRef':bundle['finiteIntentContract']['logicalOperationRef'],
            'plannedStages':len(bundle['finiteIntentContract']['stages']),'imageRebuilt':False,'imagesImported':0,
            'oauthRequests':0,'engineRequests':0,'credentialFilesOpened':0,'runtimeAuthorityIssued':False,
            'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False,
            'nativeRuntimeExecutorQualified':False,'databaseAdmissionProven':False,'liveRuntimeReverified':False,
            'targetApplyAuthorized':False,'notReleaseAcceptance':True,
            'completedTechnicalPhases':8,'functionalMilestonesProven':4}
        with output(directory,'complete.json')as stream:stream.write(c.encoded(receipt));freeze(stream)
        os.fsync(directory)
        return receipt
