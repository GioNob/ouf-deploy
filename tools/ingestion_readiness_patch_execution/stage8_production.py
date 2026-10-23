"""Build target-specific caches after completed whole-path qualification only.

No target access, budget/window, provider request, authority or effect at build.
"""
import copy,json
from pathlib import Path
from tools.ingestion_readiness_patch_execution import stage8_delivery as delivery
from tools.ingestion_readiness_patch_execution import stage8_continuation as control,stage8_human as human
from tools.ingestion_readiness_patch_execution import operator_delivery_v2 as old,release_delivery_v2 as release


def build(root,qualification):
    root=Path(root)
    if not(type(qualification)is dict and set(qualification)=={'sourceCommit','unitRun','pythonJobs','platformRun','platformJob'}
        and len(qualification['sourceCommit'])==40 and qualification['unitRun']>0 and qualification['platformRun']>0
        and len(qualification['pythonJobs'])==2 and {j['python']for j in qualification['pythonJobs']}=={'3.12','3.13.5'}
        and all(j['tests']>=129 and j['skipped']==0 and j['conclusion']=='success'and j['id']>0 for j in qualification['pythonJobs'])
        and qualification['platformJob']['tests']>=1 and qualification['platformJob']['skipped']==0
        and qualification['platformJob']['conclusion']=='success'and qualification['platformJob']['id']>0):
        raise ValueError('COMPLETE_FOUR_STAGE_HUMAN_RUNTIME_CI_REQUIRED_BEFORE_DELIVERY')
    receipt=json.loads((root/'evidence/ingestion-readiness-stage8-live-target-20261022.json').read_bytes())
    r=receipt['receipt']
    if not(receipt['replayAllowed']is False and r['status']=='STAGE8_LIVE_METADATA_MATCHED_NO_AUTHORITY'
        and r['complete']is True and r['privateCaptureHash']=='b9063de73e2d7699e3e7616a164f4b9a24346bc0a3fda1ed3762f4dc0dd95ef2'
        and r['appliedStageCount']==8 and r['remainingStages']==4 and r['priorOAuthAttempts']==300
        and r['predecessorJournalHash']=='b6b53f8740d6cbb02a3a7e4f7e0a16950475275896b4a433482e7701d4e5e17a'
        and r['prefixHash']=='2817613ea986a32046fad3066a954219b913189cae5918934a88c1764a439756'):
        raise ValueError('EXACT_MATCHED_STAGE8_TARGET_CAPTURE_REQUIRED')
    commit=qualification['sourceCommit'];_,prior=old.core(root)
    _,manifest=delivery.core(root,commit,{**prior['sourcePins'],'ouf-deploy':commit})
    original=json.loads((root/'releases/ingestion-readiness-successor-runtime-case-20261022.json').read_bytes())
    q=copy.deepcopy(original['qualification']);q.update(sourceCommit=commit,sourceHashes=manifest['sourceHashes'])
    def ref(kind):
        unit=kind in ('rootCas','adversarial')
        return {'repository':'GioNob/ouf-deploy','runId':qualification['unitRun'if unit else'platformRun'],
            'jobId':qualification['pythonJobs'][0]['id']if unit else qualification['platformJob']['id'],'sourceCommit':commit}
    q['evidenceRefs']={k:ref(k)for k in q['results']}
    case={'schema':control.SCHEMA,'capturePath':r['contextPath'],'captureHash':r['privateCaptureHash'],
        'expectedCaptureReceipt':r,'nativeDeclarationHash':old.sha(old.encoded(manifest)),
        'controlSourceHash':manifest['sourceHashes'][control.__name__], 'qualification':q,
        'requiredCumulativeOAuthAttempts':304,'maximumRuntimeSeconds':900}
    hc={'schema':human.SCHEMA,'purpose':'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT',
        'runtimeCase':case,'nativeDeclaration':manifest,
        'predecessorControlPath':'/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem/human-successor-control-4b61a8976c8ff8b508c8fdfe7a4e3e605cfdb69c2ace241966736c81734fc9f4',
        'predecessorReviewHash':'4b61a8976c8ff8b508c8fdfe7a4e3e605cfdb69c2ace241966736c81734fc9f4',
        'humanOperatorTransportProfile':{'schema':'ouf.human-operator-platform-tls-direct.v1','platformSystemTrust':True,
            'httpsProxyAllowed':False,'environmentTrustOverridesAllowed':False},
        'governanceSourceHash':old.sha((root/'tools/ingestion_readiness_patch_execution/stage8_human.py').read_bytes())}
    h,hd=delivery.human_generate(root,hc);r,rd=delivery.generate(root,case,manifest)
    files={'human.sh.operator.py':h,'runtime.sh.operator.py':r,'human.sh':release.launcher('human',h),
        'runtime.sh':delivery.launcher(r)};files['setup.sh']=release.setup(files)
    paths={name:'scripts/'+{'human.sh':'launch-ingestion-stage8-human-20261022.sh',
        'runtime.sh':'launch-ingestion-stage8-runtime-20261022.sh','setup.sh':'prepare-ingestion-stage8-continuation-20261022.sh',
        'human.sh.operator.py':'ingestion-stage8-human-20261022.py',
        'runtime.sh.operator.py':'ingestion-stage8-runtime-20261022.py'}[name]for name in files}
    pins={'schema':'ouf.ingestion-readiness-stage8-production-pins.v1','qualification':qualification,
        'runtimeCaseHash':old.sha(old.encoded(case)),'humanCaseHash':old.sha(old.encoded(hc)),
        'nativeDeclarationHash':old.sha(old.encoded(manifest)),'nativeSourceModules':manifest['moduleCount'],
        'humanDeclarationHash':old.sha(old.encoded(hd)),'runtimeDeclarationHash':old.sha(old.encoded(rd)),
        'files':{name:{'path':paths[name],'sha256':old.sha(raw),'gitBlob':release.blob(raw),'bytes':len(raw)}for name,raw in files.items()},
        'currentCumulativeOAuthAttempts':300,'maximumCumulativeOAuthAttempts':300,'proposedCumulativeCeiling':304,
        'newBudgetGranted':False,'newWindowOpened':False,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,
        'targetCommandExecuted':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    output={paths[name]:raw for name,raw in files.items()}
    output['releases/ingestion-readiness-stage8-runtime-case-20261022.json']=old.encoded(case)+b'\n'
    output['releases/ingestion-readiness-stage8-human-case-20261022.json']=old.encoded(hc)+b'\n'
    output['evidence/ingestion-readiness-stage8-production-pins-20261022.json']=old.encoded(pins)+b'\n'
    return output,pins
