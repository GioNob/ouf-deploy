"""Build only; exact reconciled predecessor and completed full successor CI.

No target path is accessed. No budget, authentication or runtime authority is
created by building a release. Old production files and claims are retained.
"""
import copy
import json
from pathlib import Path
from tools.ingestion_readiness_patch_execution import operator_delivery_v2 as d,release_delivery_v2 as release

PREVIOUS='/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem/human-successor-control-5f69412aa57b7301cb1917b858fc9ef8aa958266e430249286ef15db8f3421d0'


def build(root,qualification):
    root=Path(root)
    required={'sourceCommit','runId','pythonJobs','platformJob'}
    if not(type(qualification)is dict and set(qualification)==required
        and qualification['runId']>0 and len(qualification['sourceCommit'])==40
        and len(qualification['pythonJobs'])==2
        and {j['python']for j in qualification['pythonJobs']}=={'3.12','3.13.5'}
        and all(j['conclusion']=='success'and j['tests']>=105 and j['skipped']==0 and j['id']>0
            for j in qualification['pythonJobs'])
        and qualification['platformJob']['conclusion']=='success'
        and qualification['platformJob']['tests']>=5 and qualification['platformJob']['skipped']==0
        and qualification['platformJob']['id']>0):
        raise ValueError('COMPLETE_EXACT_SUCCESSOR_CI_REQUIRED_BEFORE_RELEASE')
    old=json.loads((root/'releases/ingestion-readiness-patch-runtime-case-20261022.json').read_bytes())
    rc=json.loads((root/'releases/ingestion-readiness-unissued-reconcile-case-20261022.json').read_bytes())
    receipt=json.loads((root/'evidence/ingestion-readiness-unissued-target-20261022.json').read_bytes())
    stopped=receipt['result']
    if not(receipt['completedOperationMustNotBeReplayed']is True and rc['runtimeCase']==old
        and d.sha(d.encoded(old))==stopped['runtimeCaseHash']=='9f3d63c728295180a431a9d84aa701e3265172d49340f75787f70b9f8edae6ac'
        and stopped['retainedControlJournalHash']=='af07734945f3b4ea93282f43808634501d4633261617d767b1bfa2f68942c910'
        and stopped['retainedDecisionHash']=='69a4a42c3776397d9d3e951843cca31092afd0b996941c2a2e9247aa5a10696c'
        and stopped['reviewHash']==rc['reviewHash'] and stopped['retainedState']=='ISSUING'
        and stopped['complete']is True and stopped['runtimeAuthorityIssued']is False):
        raise ValueError('EXACT_TARGET_STOPPED_UNISSUED_RECEIPT_REQUIRED')
    commit=qualification['sourceCommit'];_,previous=d.core(root)
    _,manifest=d.successor_core(root,commit,{**previous['sourcePins'],'ouf-deploy':commit})
    case=copy.deepcopy(old)
    def ref(job):return {'repository':'GioNob/ouf-deploy','runId':qualification['runId'],'jobId':job,'sourceCommit':commit}
    q=copy.deepcopy(old['qualification']);q.update(sourceCommit=commit,sourceHashes=manifest['sourceHashes'])
    q['evidenceRefs']={k:ref(qualification['pythonJobs'][0]['id']if k in ('rootCas','adversarial')else qualification['platformJob']['id'])for k in q['results']}
    case.update(schema='ouf.ingestion-readiness-patch-control-case.v2',qualification=q,
        nativeDeclarationHash=d.sha(d.encoded(manifest)),requiredCumulativeOAuthAttempts=300,
        controlSourceHash=d.sha((root/'tools/ingestion_readiness_patch_execution/operator_control_v2.py').read_bytes()),
        predecessorReconciliationCase=rc,predecessorResult=stopped)
    human={'schema':'ouf.ingestion-readiness-patch-human-governance-case.v2',
        'purpose':'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT','runtimeCase':case,'nativeDeclaration':manifest,
        'predecessorControlPath':PREVIOUS,'predecessorReviewHash':'5f69412aa57b7301cb1917b858fc9ef8aa958266e430249286ef15db8f3421d0',
        'humanOperatorTransportProfile':{'schema':'ouf.human-operator-platform-tls-direct.v1','platformSystemTrust':True,
            'httpsProxyAllowed':False,'environmentTrustOverridesAllowed':False},
        'governanceSourceHash':d.sha((root/'tools/ingestion_readiness_patch_execution/human_governance_v2.py').read_bytes())}
    files,declarations=release.generate(root,human)
    names={name:'scripts/'+{'human.sh':'launch-ingestion-readiness-successor-human-20261022.sh',
        'human.sh.operator.py':'ingestion-readiness-successor-human-20261022.py',
        'runtime.sh':'launch-ingestion-readiness-successor-runtime-20261022.sh',
        'runtime.sh.operator.py':'ingestion-readiness-successor-runtime-20261022.py',
        'setup.sh':'prepare-ingestion-readiness-successor-20261022.sh'}[name]for name in files}
    pins={'schema':'ouf.ingestion-readiness-successor-production-pins.v1',
        'runtimeCaseHash':d.sha(d.encoded(case)),'humanCaseHash':d.sha(d.encoded(human)),
        'predecessorRuntimeCaseHash':stopped['runtimeCaseHash'],'predecessorJournalHash':stopped['retainedControlJournalHash'],
        'qualification':qualification,'files':{name:{'path':names[name],'sha256':d.sha(raw),
            'gitBlob':release.blob(raw),'bytes':len(raw)}for name,raw in files.items()},
        'currentCumulativeOAuthAttempts':296,'maximumCumulativeOAuthAttempts':296,
        'proposedCumulativeOAuthCeiling':300,'newBudgetGranted':False,'newWindowOpened':False,
        'runtimeAuthorityIssued':False,'targetPatchInstalled':False,'targetCommandExecuted':False,
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    output={names[name]:raw for name,raw in files.items()}
    output['releases/ingestion-readiness-successor-runtime-case-20261022.json']=d.encoded(case)+b'\n'
    output['releases/ingestion-readiness-successor-human-case-20261022.json']=d.encoded(human)+b'\n'
    output['evidence/ingestion-readiness-successor-production-pins-20261022.json']=d.encoded(pins)+b'\n'
    return output,pins
