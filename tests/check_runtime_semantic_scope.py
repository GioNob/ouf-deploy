#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('runtime',sys.argv[1])
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
names=('semantic','postgres','keycloak','gateway-owner','apisix','caddy','udp')
roles,bound,retained,docs={},{},{},{}
for index,name in enumerate(names):
    cid=format(index+1,'064x')
    doc={'Id':cid,'Image':'sha256:'+name,'Config':{'Env':['TOKEN=TEST_SECRET'], 'StopTimeout':10},
         'HostConfig':{'RestartPolicy':{'Name':'no'},'OomKillDisable':False},'Mounts':[],
         'Path':'fixed','Args':['private-argument'],
         'State':{'Status':'running','Running':True,'StartedAt':'original'},
         'NetworkSettings':{'Networks':{'ouf-backend':{}}}}
    bound[name]=cid;retained[cid]=copy.deepcopy(doc);docs[cid]=copy.deepcopy(doc)
    roles[name]={'nativeImage':doc['Image'],'fingerprint':r.fingerprint(doc,'original')}
def snapshot():return roles,bound,retained,{},docs
with patch.object(r,'retained_snapshot',side_effect=snapshot):
    report={}
    assert r.retained_semantic(report)[0]['semantic']==bound['semantic']
    assert report['retainedConfigurationMismatches']==[]
    docs[bound['udp']]['Config']['StopTimeout']=60
    report={}
    assert r.retained_semantic(report)[0]['semantic']==bound['semantic']
    mismatch=report['retainedConfigurationMismatches'][0]
    assert mismatch['role']=='udp' and mismatch['changedConfigFields']==['StopTimeout']
    assert mismatch['safeScalarChanges']==[{'field':'Config.StopTimeout','before':10,'after':60}]
    try:r.retained_stack({});raise AssertionError('full-stack drift accepted')
    except ValueError as e:assert str(e)=='RETAINED_CONFIGURATION_CHANGED'
    docs[bound['semantic']]['Config']['Env']=['TOKEN=DIFFERENT_SECRET']
    report={}
    try:r.retained_semantic(report);raise AssertionError('semantic drift accepted')
    except ValueError as e:assert str(e)=='SEMANTIC_RETAINED_CONFIGURATION_CHANGED'
    assert report['semanticConfigurationCheck']['changedEnvironmentKeys']==['TOKEN']
    assert 'TEST_SECRET' not in json.dumps(report) and 'DIFFERENT_SECRET' not in json.dumps(report)
    assert 'private-argument' not in json.dumps(report)
    docs[bound['semantic']]=copy.deepcopy(retained[bound['semantic']])
    docs[bound['postgres']]['Image']='sha256:wrong'
    try:r.retained_semantic({});raise AssertionError('dependency image drift accepted')
    except ValueError as e:assert str(e)=='SEMANTIC_DEPENDENCY_NOT_READY_POSTGRES'
    docs[bound['postgres']]=copy.deepcopy(retained[bound['postgres']])
    docs[bound['apisix']]['State']['Running']=False
    try:r.retained_semantic({});raise AssertionError('stopped dependency accepted')
    except ValueError as e:assert str(e)=='SEMANTIC_DEPENDENCY_NOT_READY_APISIX'
    docs[bound['apisix']]=copy.deepcopy(retained[bound['apisix']])
    roles['semantic']['fingerprint']='not-the-baseline'
    report={}
    try:r.retained_semantic(report);raise AssertionError('mismatched plan baseline accepted')
    except ValueError:pass
    assert report['semanticConfigurationCheck']['capturedBaselineMatchesExpectedFingerprint'] is False
print('PASS: semantic-only scope, full-stack drift rejection, exact semantic fingerprint, dependency identity/state, baseline diagnosis and secret-free differences')

