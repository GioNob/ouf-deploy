"""Explicit prepare/review/issue/resume/owner/continue for one successor scope."""
import json
from .core import require,digest
from . import resumption_prepare as p, resumption_install
from . import postboot_authority as a, postboot_controller as controller
from .postboot_entry import emit,review_binding
from .postboot_scopes import compile_scopes
from .resumption import KEY
from file_only_profile import FileOnlyProfile


def installed(root,prepared,authority,raw):
    from .postboot_prepare import Files
    files=Files()
    path=prepared['nativeContext']['executionRoot']+'/checkpoint-four-successor-installed.json'
    receipt,_=files.json(path,maximum=131072)
    require(receipt.get('schema')=='ouf.semantic-registry-checkpoint-successor-installation.v1'
            and receipt.get('scopeHash')==digest(json.loads(raw)[KEY])
            and receipt.get('authorityHash')==__import__('hashlib').sha256(raw).hexdigest(),
            'COMPLETE_SUCCESSOR_INSTALLATION_RECEIPT_REQUIRED_NO_PARTIAL_ADOPTION')


def execute(case,manifest,sources,argv):
    require(type(case) is dict and set(case)=={'schema','resumption'} and case['schema']=='ouf.semantic-registry-postboot-recovery-case.v1','CLOSED_SUCCESSOR_OPERATOR_CASE_REQUIRED')
    mode=argv[0];require(mode in ('prepare','review','issue','resume','owner','continue','status'),
                         'SUCCESSOR_CANNOT_REPLAY_INSTALL_OR_BOOTSTRAP')
    signed=mode in ('issue','resume','owner','continue')
    require(len(argv)==(2 if signed else 1),'EXACT_SUCCESSOR_MODE_ARGUMENTS_REQUIRED')
    selected=case['resumption'];root=p.root(selected,manifest)
    if mode=='prepare':
        return {'schema':'ouf.semantic-registry-resumption-preparation-result.v1',
                'status':'COMPLETE_CHECKPOINT_SUCCESSOR_INPUTS_PREPARED','complete':True,**p.prepare(selected,manifest,sources)}
    prepared=p.read(selected,manifest);context=prepared['nativeContext'];owner=prepared['ownerContext']
    if mode=='review':
        profile=FileOnlyProfile(prepared['registryInputs']['creationRequest'],prepared['registryInputs']['configtree'])
        scopes=compile_scopes(context,owner,prepared['registryInputs'],profile,owner['recovery']['bootId'])
        review=a.compile_review(context,owner,prepared['authorityInputs'],manifest,scopes)
        binding=a.publish_review(root,review)
        return {'schema':'ouf.semantic-registry-resumption-review-result.v1','status':'COMPLETE_CHECKPOINT_SUCCESSOR_REVIEW_PREPARED',
            'privateReviewPath':binding['path'],'reviewHash':binding['sha256'],'signedScopeCount':len(scopes),
            'sourceClosureHash':digest(manifest),'retainedNativeCheckpoint':4,'retainedControlledGrantAttempts':320,
            'proposedMaximumNewServiceGrantAttempts':1,'proposedMaximumSeconds':900,
            'prefixEffectReplayAllowed':False,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,
            'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    if mode=='status':
        return {'schema':'ouf.semantic-registry-resumption-status.v1','status':'PREPARATION_PRESENT_NO_LIVE_OBSERVATION',
                'runtimeEffectsDispatched':0,'runtimeAuthorityIssued':False,'serviceReadinessEstablished':False}
    _,binding=review_binding(root)
    require(argv[1]==binding['sha256'],'EXACT_PUBLISHED_SUCCESSOR_REVIEW_HASH_REQUIRED')
    if mode=='issue':return a.issue(root,binding,argv[1])
    authority,raw,verifier,signer=a.load_runtime(root,binding)
    if mode=='resume':return resumption_install.install(context,owner,authority,raw)
    installed(root,prepared,authority,raw)
    if mode=='owner':return controller.install_owner(context,owner,authority,raw)
    return controller.continue_recovery(context,owner,authority,raw,verifier,signer,emit)
