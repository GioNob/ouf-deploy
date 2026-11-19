"""Reproducible installation-specific release from the retained public receipt.

Builds files only. Does not read target paths, inspect runtime, grant budget,
open login, or issue authority. All previous operations stay consumed.
"""
from pathlib import Path
from tools.ingestion_readiness_patch_execution import operator_delivery as d,release_delivery as release

ROOT='/etc/ouf/deploy-snapshots'
ARCHIVE=ROOT+'/ingestion-readiness-native-archive-86a63c83ae644484400e2e3531db57e5aa4869ca8c5f17bcbec908de889bb6c6'
PREVIOUS=ROOT+'/semantic-token-execution-usx0tsem/human-successor-control-c22c5d72643880ebeffa21f9d003cc96f71b222b6cabe612afc7a8fa2394d33a'


def build(root,evidence):
    root=Path(root);receipt=evidence['result'];_,manifest=d.core(root)
    if not(evidence['completedOperationMustNotBeReplayed']is True
        and receipt['status']=='NATIVE_ARCHIVE_INPUTS_PREPARED_NO_AUTHORITY'and receipt['complete']is True
        and receipt['bundleHash']=='f56d7989be393211665535a59cc4bf419c20665a912bf51aaf6f01671e2288dd'
        and receipt['contextPath']==ARCHIVE and receipt['plannedStages']==12):
        raise ValueError('EXACT_COMPLETED_TARGET_ARCHIVE_RECEIPT_REQUIRED')
    source='f5709378c1cff5847d4824d76bbb57ebaa451178'
    def ref(job):return {'repository':'GioNob/ouf-deploy','runId':39722859248,'jobId':job,'sourceCommit':source}
    qualification={'schema':'ouf.ingestion-readiness-patch-native-qualification.v1',
        'sourceCommit':manifest['sourceCommit'],'sourceHashes':manifest['sourceHashes'],
        'candidateNativeImageId':receipt['nativeImageId'],'candidateSourceCommit':'4165b9e149be467d5d7c6bed35e4e1af4e249db1',
        'results':dict.fromkeys(('rootCas','dockerTwoNetworks','apisix','jvmValidateOnly','postgres17','adversarial'),'PASS'),
        'runtimeAuthorityIssued':False,'notReleaseAcceptance':True,
        'evidenceRefs':{k:ref(119640067844 if k in ('rootCas','adversarial')else 119640067704)
            for k in ('rootCas','dockerTwoNetworks','apisix','jvmValidateOnly','postgres17','adversarial')}}
    runtime={'schema':'ouf.ingestion-readiness-patch-control-case.v1','snapshotRoot':ROOT,
        'nativeInputsPath':ARCHIVE+'/native-inputs.json','nativeInputsHash':receipt['bundleHash'],
        'nativeReceiptHash':d.sha(d.encoded(receipt)),'parentInputsHash':receipt['parentInputsHash'],
        'logicalOperationRef':receipt['logicalOperationRef'],'configurationImageId':receipt['configurationImageId'],
        'nativeImageId':receipt['nativeImageId'],'nativeArchiveSha256':receipt['nativeArchiveSha256'],
        'candidateSourceCommit':'4165b9e149be467d5d7c6bed35e4e1af4e249db1','plannedStages':12,
        'nativeDeclarationHash':d.sha(d.encoded(manifest)),'qualification':qualification,
        'requiredCumulativeOAuthAttempts':296,'maximumRuntimeSeconds':900,
        'controlSourceHash':d.sha((root/'tools/ingestion_readiness_patch_execution/operator_control.py').read_bytes())}
    case={'schema':'ouf.ingestion-readiness-patch-human-governance-case.v1',
        'purpose':'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT','runtimeCase':runtime,'nativeDeclaration':manifest,
        'predecessorControlPath':PREVIOUS,'predecessorReviewHash':'c22c5d72643880ebeffa21f9d003cc96f71b222b6cabe612afc7a8fa2394d33a',
        'humanOperatorTransportProfile':{'schema':'ouf.human-operator-platform-tls-direct.v1','platformSystemTrust':True,
            'httpsProxyAllowed':False,'environmentTrustOverridesAllowed':False},
        'governanceSourceHash':d.sha((root/'tools/ingestion_readiness_patch_execution/human_governance.py').read_bytes())}
    files,declarations=release.generate(root,case)
    names={'human.sh':'scripts/launch-ingestion-readiness-human-20261022.sh',
        'human.sh.operator.py':'scripts/ingestion-readiness-human-20261022.py',
        'runtime.sh':'scripts/launch-ingestion-readiness-runtime-20261022.sh',
        'runtime.sh.operator.py':'scripts/ingestion-readiness-runtime-20261022.py',
        'setup.sh':'scripts/prepare-ingestion-readiness-launchers-20261022.sh'}
    pins={'schema':'ouf.ingestion-readiness-patch-production-delivery-pins.v1','runtimeCaseHash':d.sha(d.encoded(runtime)),
        'humanCaseHash':d.sha(d.encoded(case)),'nativeInputsHash':receipt['bundleHash'],
        'files':{name:{'path':names[name],'sha256':d.sha(raw),'gitBlob':release.blob(raw),'bytes':len(raw)}for name,raw in files.items()},
        'declarationHashes':{k:d.sha(d.encoded(v))for k,v in declarations.items()},
        'targetCommandExecuted':False,'currentCumulativeOAuthAttempts':292,'maximumCumulativeOAuthAttempts':292,
        'newBudgetGranted':False,'runtimeAuthorityIssued':False,'targetPatchInstalled':False,
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    output={names[name]:raw for name,raw in files.items()}
    output['releases/ingestion-readiness-patch-human-case-20261022.json']=d.encoded(case)+b'\n'
    output['releases/ingestion-readiness-patch-runtime-case-20261022.json']=d.encoded(runtime)+b'\n'
    output['evidence/ingestion-readiness-production-delivery-pins-20261022.json']=d.encoded(pins)+b'\n'
    return output,pins
