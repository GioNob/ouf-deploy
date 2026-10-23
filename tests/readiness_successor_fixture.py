"""Explicit synthetic stopped predecessor; never target admission evidence."""
import copy
import json
from pathlib import Path
from tools.ingestion_readiness_patch_execution import unissued_reconcile as inspect

def predecessor(root,case,old_manifest):
    old=copy.deepcopy(case)
    old.update(schema='ouf.ingestion-readiness-patch-control-case.v1',
        requiredCumulativeOAuthAttempts=296,nativeDeclarationHash=inspect.digest(old_manifest),
        controlSourceHash='b'*64)
    old.pop('predecessorReconciliationCase',None);old.pop('predecessorResult',None)
    h=inspect.digest(old);folder=Path(root)/('ingestion-readiness-execution-'+h)
    folder.mkdir(mode=0o700);control=folder/'operator-control';control.mkdir(mode=0o700)
    native=json.loads(Path(case['nativeInputsPath']).read_bytes())
    closure={'declaration':old_manifest};profile={'synthetic':'no credential access'}
    bind={'caseHash':h,'controlSourceHash':old['controlSourceHash'],
        'nativeInputsHash':case['nativeInputsHash'],'modeContract':'EXPLICIT_ONE_PATCH_STAGE_NO_REPLAY_V1'}
    def pad(value,size):
        value['syntheticPadding']='';n=size-len(inspect.encoded(value))
        if n<0:raise ValueError('SYNTHETIC_FIXTURE_TOO_LARGE')
        value['syntheticPadding']='x'*n;return value
    packet=pad({'nativeInputs':native},1320265)
    review=pad({'packetHash':inspect.digest(packet),'operatorControlBinding':bind,'sourceClosure':closure,
        'authorityDirectory':str(folder),'executionReview':{'executionContext':str(folder),
        'logicalOperationRef':old['logicalOperationRef'],'preparedInputsHash':old['nativeInputsHash'],
        'humanReadProfile':profile}},545058)
    material={'caseHash':h,'nativeInputsHash':old['nativeInputsHash'],'operatorControlBinding':bind,
        'sourceClosure':closure,'humanProfileHash':inspect.digest(profile)}
    row={'schema':inspect.ROW,'caseHash':h,'state':'ISSUING','complete':False,'budgetReset':False,
        'runtimeAuthorityIssued':False,'decisionHash':'d'*64,'reviewHash':inspect.digest(review),
        'packetHash':inspect.digest(packet),'materialHash':inspect.digest(material)}
    def write(p,value):p.write_bytes(inspect.encoded(value));p.chmod(0o600)
    for name,value in (('review.json',review),('packet.json',packet),('material.json',material),('human-profile.json',profile)):
        write(folder/name,value)
    write(control/'recovery.json',row)
    for name in ('recovery.lock','invocation.lock'):
        p=control/name;p.write_bytes(b'');p.chmod(0o600)
    write(Path(root)/('ingestion-readiness-review-'+old['logicalOperationRef']+'.claim.json'),
        {'schema':inspect.ROW,'caseHash':h,'logicalOperationRef':old['logicalOperationRef'],
        'contextPath':str(folder),'reviewHash':inspect.digest(review),'automaticReplayAllowed':False,'budgetReset':False})
    rc={'schema':'ouf.ingestion-readiness-unissued-reconcile-case.v1','runtimeCase':old,
        'reviewHash':inspect.digest(review),'reviewBytes':545058,'packetBytes':1320265}
    case['predecessorReconciliationCase']=rc;case['predecessorResult']=inspect.inspect(rc)
    return folder
