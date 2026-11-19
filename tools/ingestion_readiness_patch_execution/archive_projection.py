"""Pure successor projection after independent byte audit of a tagless archive.

Caller must authenticate parent bytes and audit/re-envelope/re-audit the archive.
This never opens files, imports an image, issues authority or changes the parent.
The logical operation and cumulative history survive the manifest adaptation.
"""
import copy
import image_custody
from tools.ingestion_readiness_patch_execution import contract as c,private_file

def project(parent,parent_hash,audit,archive):
    c.require(c.digest(parent)==parent_hash and c.hashed(parent_hash)
        and parent.get('schema')=='ouf.ingestion-readiness-patch-native-inputs.v1'
        and parent.get('kind')=='PRIVATE_NATIVE_INPUTS_NOT_EXECUTABLE_AUTHORITY'
        and 'nativeArchiveAudit' not in parent and 'nativeArchivePreparation' not in parent
        and all(parent.get(k)is False for k in ('nativeRuntimeExecutorQualified','targetApplyAuthorized',
            'runtimeAuthorityIssued','automaticReplayAllowed','budgetReset','sourceActivationAllowed','releaseAcceptance')),
        'EXACT_COMPLETED_UNAUTHORIZED_PARENT_INPUTS_REQUIRED')
    private_file.validate(archive,maximum=image_custody.LIMIT)
    c.require(archive['metadata'][2:4]==[0,0] and audit.get('archiveSha256')==archive['sha256']
        and audit.get('archiveByteCustodyProven')is True and audit.get('targetApplyAuthorized')is False
        and audit.get('repositoryTags')==[] and audit.get('nativeIdentity')==image_custody.native_identity(audit),
        'EXACT_ROOT_CUSTODIED_AUDITED_TAGLESS_NATIVE_ARCHIVE_REQUIRED')
    candidate=parent['candidate'];source=candidate['Config']['Labels']['org.opencontainers.image.revision']
    c.require(audit['imageId']==candidate['Id'] and audit['sourceCommit']==source
        and parent['ingestionFrame']['requestTemplate']['Image']==candidate['Id'],
        'SAME_PARENT_CONFIGURATION_IMAGE_AND_SOURCE_REQUIRED')
    value=copy.deepcopy(parent);native=image_custody.runtime_image_id(audit)
    value['nativeArchiveAudit']=copy.deepcopy(audit)
    value['nativeArchivePreparation']={'schema':'ouf.ingestion-readiness-native-archive-preparation.v1',
        'parentNativeInputsHash':parent_hash,
        'originalArchiveBinding':copy.deepcopy(parent['candidateFileBindings']['image.tar.gz']),
        'originalStageIntentsHash':c.digest(parent['finiteIntentContract']['stages']),
        'configurationImageId':candidate['Id'],'nativeImageId':native,
        'imageRebuilt':False,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0}
    value['candidateFileBindings']['image.tar.gz']=copy.deepcopy(archive)
    value['imageImportProfile']['archive']=copy.deepcopy(archive)
    value['ingestionFrame']['requestTemplate']['Image']=native
    stages=value['finiteIntentContract']['stages']
    for original,stage in zip(parent['finiteIntentContract']['stages'],stages):
        if stage['name']=='IMPORT_INGESTION_IMAGE':
            c.require(original['intent'].get('nativeImageId')==candidate['Id'], 'ORIGINAL_CONFIGURATION_IMPORT_REQUIRED')
            stage['intent']={'nativeImageId':native,'archiveSha256':archive['sha256'],
                             'maximumArchiveBytes':archive['metadata'][6]}
        elif stage['name']=='ingestion.CREATE_REPLACEMENT':
            c.require(original['intent']['requestTemplate']['Image']==candidate['Id'], 'ORIGINAL_CONFIGURATION_CREATE_REQUIRED')
            stage['intent']['requestTemplate']['Image']=native
        stage['intentHash']=c.digest(stage['intent'])
    c.stages(value)
    c.require(value['finiteIntentContract']['logicalOperationRef']==parent['finiteIntentContract']['logicalOperationRef'],
              'MANIFEST_ADAPTATION_CANNOT_RESET_LOGICAL_OPERATION')
    return value
