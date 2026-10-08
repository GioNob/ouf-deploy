"""Real created-peer recheck through draft driver IO; full gate not proven."""
import copy
import importlib.util
from pathlib import Path
import sys
import types

BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE))
package=types.ModuleType('tools');package.__path__=[str(BASE/'cohort-draft'/'tools')];sys.modules['tools']=package
from tools.semantic_provider_deployment_authentication import VerificationBudget
from tools.semantic_provider_peer_bindings import digest,resolve
import test_semantic_provider_peer_bindings_native as fixture
spec=importlib.util.spec_from_file_location('cohort_driver',BASE/'cohort-draft'/'scripts'/'semantic_provider_preexec_hook.py')
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)

def probe(expected,snapshot,runtime_binding,runtime_root,io,read_bundle,generation):
    peer=expected['containerId'];current='f'*64;nic=expected['networkBindings'][0]
    flow={'purpose':'GATEWAY_ADAPTER','authorityRef':'ci-infrastructure','source':nic['ipv4'],
          'destination':'198.19.250.3','protocol':'tcp','port':9443,
          'peerIngress':{'kind':'CREATED_CANDIDATE','declaration':expected,'bindingRef':nic['bindingRef']}}
    policy={'networkBindings':[],'transport':[flow],'tableName':'ci_peer_recheck'}
    value={'profile':{'containerId':current,'policy':{'tableName':policy['tableName'],
                 'flows':resolve([flow],[expected],{peer:snapshot},current)}},
           'authorityScope':{'transportHash':digest(policy)},
           'runtimeBinding':{**runtime_binding,'root':runtime_root},
           'commands':{k:io[k]['path'] for k in io},
           'peerBinding':{'declaredPolicy':policy,'observations':{peer:snapshot},'commandBindings':io}}
    def verify(candidate):
        budget=VerificationBudget(15)
        return driver.verify_peers(candidate,budget,read_bundle,
            lambda binding,argv,limit:driver.bound_peer_run(binding,argv,limit,budget),generation)
    verify(value)
    changed=copy.deepcopy(value);changed['peerBinding']['observations'][peer]['generation']['startTicks']+=1
    try:verify(changed)
    except RuntimeError as error:
        if str(error)!='PEER_GENERATION_OR_LINK_CHANGED':raise
    else:raise RuntimeError('NATIVE_STALE_PEER_GENERATION_ACCEPTED')
    changed=copy.deepcopy(value);changed['profile']['policy']['flows'][0]['peerIngress']['ifindex']+=1
    try:verify(changed)
    except RuntimeError as error:
        if str(error)!='PEER_KERNEL_PROFILE_DRIFT':raise
    else:raise RuntimeError('NATIVE_PEER_PROFILE_DRIFT_ACCEPTED')
    print('COHORT_DRIVER_NATIVE=PASS REAL_CREATED_PEER=true HASH_BOUND_EXECUTABLES=true STALE_GENERATION_AND_PROFILE_REJECTED=true FIFO_RELEASED=false COMPLETE_ADMISSION_PROVEN=false TARGET_START_AUTHORIZED=false')

if __name__=='__main__':fixture.main(probe)
