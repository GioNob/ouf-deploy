"""Create two tagless archives before a concrete discovery parent is reviewed.

No image load, container operation, signing, publisher-trust acceptance or native
admission. One exclusive preparation claim precedes writes. Completed bytes may
be read-reconciled; partial preparation never overwrites or resets its claim.
"""
import os,re
from pathlib import Path
from .custody_capture import digest,encoded,require
from .cohort_images import MODULES,hashed
from image_custody import archive,tagless_archive,native_identity
from engine_creation import Engine
from tools.chatbot_file_cohort.images import private_open,engine_image_profile
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import private_json

USERS={'semantic':'10001:10001','mcp':'10005:10005'}


def input_hash(inputs,output_directory):
    root=Path(output_directory)
    require(root.is_absolute() and str(root)==str(output_directory) and '..' not in root.parts
        and type(inputs) is dict and set(inputs)==set(MODULES),'EXACT_TWO_IMAGE_PREPARATION_INPUTS_REQUIRED')
    paths=[]
    for module in MODULES:
        row=inputs[module]
        require(type(row) is dict and set(row)=={'archivePath','archiveSha256','imageId','sourceCommit','modulePackageHash'}
            and hashed(row['archiveSha256']) and hashed(row['modulePackageHash'])
            and type(row['imageId']) is str and re.fullmatch('sha256:[a-f0-9]{64}',row['imageId'])
            and type(row['sourceCommit']) is str and re.fullmatch('[a-f0-9]{40}',row['sourceCommit']),
            'EXACT_SELECTED_PACKAGE_ARCHIVE_IMAGE_SOURCE_HASHES_REQUIRED')
        path=Path(row['archivePath'])
        require(path.is_absolute() and str(path)==row['archivePath'] and '..' not in path.parts
            and not path.is_relative_to(root),'SEPARATE_EXPLICIT_SELECTED_PACKAGE_ARCHIVE_REQUIRED')
        paths.append(str(path))
    require(len(set(paths))==2,'DISTINCT_SELECTED_PACKAGE_ARCHIVES_REQUIRED')
    return digest({'schema':'ouf.discovery-selected-image-preparation-inputs.v1','inputs':inputs,'outputDirectory':str(root)})


def prepare_archives(*,inputs,output_directory,engine):
    require(type(engine) is Engine,'ACTUAL_PREPARATION_ENGINE_REQUIRED')
    scope=input_hash(inputs,output_directory);root=Path(output_directory)
    profile=engine_image_profile(engine);containerd=profile['profile']=='CONTAINERD_MANIFEST'
    claim={'schema':'ouf.discovery-selected-image-preparation-claim.v1','inputHash':scope,
        'nativeEngineProfile':profile,'imageCount':2,'automaticReplayAllowed':False}
    with directory(root) as fd:new_file(fd,'preparation.claim.json',encoded(claim))
    rows=[]
    for module in MODULES:
        row=inputs[module];destination=root/(module+'.tagless.tar')
        with private_open(row['archivePath']) as source:
            original=archive(source,row['archiveSha256'],row['imageId'],row['sourceCommit'])
            require(original['imageConfig'].get('User')==USERS[module],'EXACT_SELECTED_IMAGE_RUNTIME_USER_REQUIRED')
            with directory(root) as parent:
                target=os.open(destination.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                with os.fdopen(target,'w+b') as output:
                    derived=tagless_archive(source,output,original,containerd=containerd);os.fsync(output.fileno())
                    audited=archive(output,derived['derivedArchiveSha256'],row['imageId'],row['sourceCommit'])
                os.fsync(parent)
        require(audited['repositoryTags']==[],'TAGLESS_SELECTED_IMAGE_PREPARATION_REQUIRED')
        if containerd:audited['nativeIdentity']=native_identity(audited)
        rows.append({'module':module,'archivePath':str(destination),'audit':audited,
            'originalArchiveSha256':row['archiveSha256'],'modulePackageHash':row['modulePackageHash']})
    require(engine_image_profile(engine)==profile and private_json(root/'preparation.claim.json')==claim,
        'IMAGE_PREPARATION_NATIVE_PROFILE_OR_CLAIM_CHANGED')
    receipt={'schema':'ouf.discovery-selected-image-preparation.v1','inputHash':scope,
        'nativeEngineProfile':profile,'images':rows,'imageLoads':0,'publisherTrustAccepted':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False}
    with directory(root) as fd:new_file(fd,'prepared-images.json',encoded(receipt))
    return read_prepared_archives(inputs=inputs,output_directory=root,engine=engine)


def read_prepared_archives(*,inputs,output_directory,engine):
    """Reconcile completed local bytes only; never finish an interrupted write."""
    require(type(engine) is Engine,'ACTUAL_PREPARATION_ENGINE_REQUIRED')
    root=Path(output_directory);scope=input_hash(inputs,root);profile=engine_image_profile(engine)
    claim=private_json(root/'preparation.claim.json');receipt=private_json(root/'prepared-images.json')
    require(claim=={'schema':'ouf.discovery-selected-image-preparation-claim.v1','inputHash':scope,
        'nativeEngineProfile':profile,'imageCount':2,'automaticReplayAllowed':False}
        and receipt.get('schema')=='ouf.discovery-selected-image-preparation.v1'
        and receipt.get('inputHash')==scope and receipt.get('nativeEngineProfile')==profile
        and [r.get('module') for r in receipt.get('images',[])]==list(MODULES)
        and receipt.get('imageLoads')==0 and all(receipt.get(k) is False for k in (
            'publisherTrustAccepted','runtimeAuthorityIssued','targetApplyAuthorized','automaticReplayAllowed')),
        'EXACT_COMPLETED_SELECTED_IMAGE_PREPARATION_REQUIRED')
    for module,row in zip(MODULES,receipt['images']):
        expected=inputs[module]
        require(row['archivePath']==str(root/(module+'.tagless.tar'))
            and row['originalArchiveSha256']==expected['archiveSha256']
            and row['modulePackageHash']==expected['modulePackageHash'],'SELECTED_PREPARATION_SOURCE_DRIFT')
        with private_open(expected['archivePath']) as source:
            original=archive(source,expected['archiveSha256'],expected['imageId'],expected['sourceCommit'])
        with private_open(row['archivePath']) as source:
            actual=archive(source,row['audit']['archiveSha256'],expected['imageId'],expected['sourceCommit'])
        if profile['profile']=='CONTAINERD_MANIFEST':actual['nativeIdentity']=native_identity(actual)
        require(actual==row['audit'] and actual['repositoryTags']==[]
            and actual['imageConfig']==original['imageConfig'] and actual['imageConfig'].get('User')==USERS[module],
            'PREPARED_SELECTED_IMAGE_BYTES_OR_CONFIG_DRIFT')
    require(engine_image_profile(engine)==profile,'IMAGE_PREPARATION_NATIVE_PROFILE_CHANGED')
    return receipt
