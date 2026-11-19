import copy,importlib.util,json,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,BASE/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('owner_image_plan','tools/managed_file_owner_recovery/image_plan.py')
old=load('retained_plan_fixture','tests/test_managed_csv_control_image_plan.py');p=old.p;mac=old.mac

def fixture(root=Path('/fixture')):
    prior=old.fixture(root);observed=prior[0]['currentObservations'];proposal=prior[2]['nativePlan']['proposal']
    proposal['replacements']={'onboarding':proposal.pop('onboardingReplacement')}
    review={'schema':'ouf.ths-owner-request-update-review.v1','bootId':'fixture-boot','nativePlan':{'proposal':proposal}}
    previous={'complete':True,'nativeImageId':observed['onboarding']['Image'],'nativeBindingHash':m.digest(m.common_binding(observed['onboarding'])),
        'generation':copy.deepcopy(prior[0]['currentProcessPins']['onboarding']),'humanBudgetsGranted':0,'resumes':0}
    ownership=json.loads((BASE/'evidence/managed-file-ownership-read-target-20261028.json').read_text())['result']
    inputs={'schema':'ouf.managed-file-owner-recovery-current-inputs.v1','bootId':'fixture-boot','engineBinding':prior[0]['engineBinding'],
        'currentObservations':observed,'currentProcessPins':prior[0]['currentProcessPins'],'currentRootProcessPins':prior[0]['currentRootProcessPins'],
        'boundDatabaseProfile':proposal['boundDatabaseProfile'],'retainedSuccessfulReview':review,'retainedReviewHash':m.digest(review),'retainedSuccessfulResult':previous,
        'retainedOwnershipReadResult':ownership,'retainedOwnershipReadHash':m.digest(ownership),'targetRoles':['onboarding'],'unchangedPeers':12,
        **{k:False for k in('databaseSchemaObservedByThisCapture','currentJobOrBudgetStateObserved','runtimeAuthorityIssued','targetApplyAuthorized','nativePlanPrepared','automaticReplayAllowed','budgetReset')}}
    result=json.loads((BASE/'evidence/managed-file-owner-inputs-target-20261028.json').read_text())['result'];result.update(inputsHash=m.digest(inputs),contextPath=str(root/'capture'))
    receipt=json.loads((BASE/'releases/managed-file-owner-v38-image-custody-20261028.json').read_text())
    info={'ServerVersion':'29.8.1','DriverStatus':[['driver-type','io.containerd.snapshotter.v1']]}
    case={'captureResult':result,'captureHash':m.digest(inputs),'captureResultHash':m.digest(result),'captureRoot':str(root/'capture'),
        'retainedReviewHash':m.digest(review),'retainedApplyResultHash':m.digest(previous),'installedNativeImageId':observed['onboarding']['Image'],
        'ownershipReadHash':m.digest(ownership),'imageReceiptHash':m.digest(receipt),'candidateSourceCommit':receipt['sourceCommit'],
        'candidateNativeImageId':receipt['nativeImageId'],'additionalMigrations':receipt['additionalMigrations']}
    return inputs,result,info,receipt,{'path':str(root/'native.tar')},case

def reseal(values):
    inputs,result,info,receipt,archive,case=values
    case.update(retainedReviewHash=m.digest(inputs['retainedSuccessfulReview']),retainedApplyResultHash=m.digest(inputs['retainedSuccessfulResult']),imageReceiptHash=m.digest(receipt))
    inputs['retainedReviewHash']=case['retainedReviewHash'];case['captureHash']=result['inputsHash']=m.digest(inputs);case['captureResultHash']=m.digest(result)

class PlanTests(unittest.TestCase):
    def compile(self,v):return m.compile_plan(*v[:5],p,mac,v[5])
    def test_single_owner_36_to_38_plan_is_pure_conditional_and_preserves_12_peers(self):
        v=fixture();before=copy.deepcopy(v);out=self.compile(v);self.assertEqual(v,before)
        self.assertEqual(set(out['replacements']),{'onboarding'});self.assertEqual(len(out['unchangedApplications']),12)
        self.assertEqual(out['databaseMigration']['newMigrations'],2);self.assertEqual(out['databaseMigration']['from'],36);self.assertEqual(out['databaseMigration']['to'],38)
        for k in('runtimeAuthorityIssued','targetApplyAuthorized','executionEntryQualified','humanOwnershipOrBudgetOrResumeAuthorized','imageImportAuthorized'):self.assertFalse(out[k])
    def test_native_env_scope_request_mounts_ip_mac_port_and_memory_are_retained(self):
        v=fixture();out=self.compile(v);replacement=out['replacements']['onboarding'];actual=v[0]['currentObservations']['onboarding']
        self.assertEqual(replacement['request']['Env'],actual['Config']['Env']);self.assertEqual(replacement['request']['HostConfig']['Memory'],actual['HostConfig']['Memory'])
        self.assertEqual(replacement['request']['HostConfig']['PortBindings'],actual['NetworkSettings']['Ports'])
        endpoint=replacement['request']['NetworkingConfig']['EndpointsConfig']['ouf-ci'];self.assertEqual(endpoint['MacAddress'],actual['NetworkSettings']['Networks']['ouf-ci']['MacAddress'])
        self.assertEqual(endpoint['IPAMConfig']['IPv4Address'],actual['NetworkSettings']['Networks']['ouf-ci']['IPAddress'])
    def test_unknown_or_tampered_capture_is_not_adopted(self):
        for key,value in [('complete',False),('runtimeAuthorityIssued',True),('inputsHash','0'*64)]:
            v=fixture();v[1][key]=value
            with self.subTest(key=key),self.assertRaises(m.Stop):self.compile(v)
    def test_db_job_and_authority_claims_in_metadata_are_denied(self):
        for key in('databaseSchemaObservedByThisCapture','currentJobOrBudgetStateObserved','runtimeAuthorityIssued','targetApplyAuthorized'):
            v=fixture();v[0][key]=True;reseal(v)
            with self.subTest(key=key),self.assertRaises(m.Stop):self.compile(v)
    def test_unqualified_engine_or_storage_is_denied(self):
        for info in [{'ServerVersion':'29.8.0'},{'ServerVersion':'29.8.1','DriverStatus':[]}]:
            v=fixture();v[2].clear();v[2].update(info)
            with self.assertRaises(m.Stop):self.compile(v)
    def test_any_old_migration_new_migration_yaml_or_role_drift_is_denied(self):
        for kind in('old','new','yaml','role'):
            v=fixture();facts=v[3]['application']
            if kind=='old':facts['migrations'][0]['sha256']='0'*64
            elif kind=='new':facts['migrations'][37]['sha256']='0'*64
            elif kind=='yaml':facts['applicationYamlSha256']='0'*64
            else:facts['managedProfileRole']['roleId']='other'
            reseal(v)
            with self.subTest(kind=kind),self.assertRaises(m.Stop):self.compile(v)
    def test_changed_launch_or_added_env_defaults_are_denied(self):
        for kind in('entry','env','labels'):
            v=fixture();image=v[3]['imageAudit']['imageConfig']
            if kind=='entry':image['Entrypoint']=['other']
            elif kind=='env':image['Env'].append('NEW_UNREVIEWED=1')
            else:image.setdefault('Labels',{})['new.unreviewed']='1'
            reseal(v)
            with self.subTest(kind=kind),self.assertRaises(m.Stop):self.compile(v)
    def test_wrong_owner_generation_or_peer_set_is_denied(self):
        for kind in('generation','peer'):
            v=fixture()
            if kind=='generation':v[0]['currentProcessPins']['onboarding']['pid']+=1
            else:v[0]['currentObservations'].pop(next(k for k in v[0]['currentObservations']if k!='onboarding'))
            reseal(v)
            with self.subTest(kind=kind),self.assertRaises(m.Stop):self.compile(v)
    def test_capture_private_credential_values_are_never_in_plan_public_flags(self):
        v=fixture();v[0]['currentObservations']['onboarding']['Config']['Env'].append('PRIVATE_FIXTURE=secret-fixture')
        proposal=v[0]['retainedSuccessfulReview']['nativePlan']['proposal'];proposal['replacements']['onboarding']['request']['Env'].append('PRIVATE_FIXTURE=secret-fixture')
        v[0]['retainedSuccessfulResult']['nativeBindingHash']=m.digest(m.common_binding(v[0]['currentObservations']['onboarding']));reseal(v)
        plan=self.compile(v);self.assertIn('secret-fixture',json.dumps(plan));self.assertFalse(plan['runtimeAuthorityIssued'])
        # The entire plan is deliberately private; public output is separately projected by prepare.

if __name__=='__main__':unittest.main()
