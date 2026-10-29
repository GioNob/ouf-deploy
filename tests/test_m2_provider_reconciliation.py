"""Exact full-identity diagnosis; matches never grant execution authority."""
import copy,json,sys,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.m2_discovery_installation_profile import provider_reconciliation as m


def row():
    return {'Id':'a'*64,'Image':'sha256:'+'b'*64,'Config':{'Env':['SECRET=fixture-private-value']},
        'HostConfig':{'ReadonlyRootfs':False},'Mounts':[],
        'NetworkSettings':{'Networks':{'bridge':{'NetworkID':'c'*64,'GwPriority':0}}},
        'State':{'Pid':123,'StartedAt':'synthetic','Running':True,'Paused':False,'Restarting':False}}


def stop():
    return {'applicationE2EProven':False,'automaticReplayAllowed':False,'budgetReset':False,'complete':False,
        'counts':{'applicationMacKeyReads':0,'bytes':906004,'contextEngineGets':3,'credentialFileReads':0,
            'engineGets':27,'metadataReads':5,'nativeConfigurationReads':0,'preparedCopyReads':0,
            'privateCopiesPrepared':0,'publicCertificateCopiesPrepared':0,'publicCertificateReads':2,
            'publicTrustStoreReadbacks':1,'publicTrustStoresPrepared':1},
        'partialPublicStorePreserved':True,'rawCredentialOrKeyValuesPrinted':False,
        'reasonCode':'CURRENT_RETAINED_PROVIDER_IDENTITY_CHANGED','releaseAcceptance':False,
        'runtimeAuthorityIssued':False,'schema':'ouf.m2-discovery-trust-context-preparation-result.v1',
        'scope':str(m.STOP_SCOPE),'scopeConsumed':True,'status':'STOP_RECONCILE','targetApplyAuthorized':False}


class ProviderRepresentation(unittest.TestCase):
    def fixture(self):
        modern=row();legacy=copy.deepcopy(modern);del legacy['NetworkSettings']['Networks']['bridge']['GwPriority']
        return m.identity(modern),legacy,{'1.44':legacy,'1.54':modern},'1.54'

    def test_only_complete_historical_identity_matches_alternate_representation_no_admission(self):
        a=self.fixture();before=copy.deepcopy(a);report=m.analyze(*a)
        self.assertEqual(a,before);self.assertEqual(report['matchingCurrentApis'],['1.54'])
        self.assertFalse(report['identityChecks']['1.44']['completeIdentityMatches'])
        self.assertEqual(report['fieldsDroppedForMatching'],[])
        for k in ('providerAdmissionProven','resumeAllowed','runtimeAuthorityIssued','targetApplyAuthorized',
                  'nativeContextAcceptanceGranted','historicalAuthorityReused','automaticReplayAllowed','budgetReset'):
            self.assertFalse(report[k])

    def test_real_environment_drift_in_both_versions_never_matches(self):
        expected,captured,views,version=self.fixture();views=copy.deepcopy(views)
        for value in views.values():value['Config']['Env']=['SECRET=rotated-private-fixture']
        report=m.analyze(expected,captured,views,version)
        self.assertEqual(report['matchingCurrentApis'],[])
        self.assertFalse(report['capturedIdentityEqualsCurrentCaptureApi'])
        self.assertEqual(report['classification'],'HISTORICAL_PROVIDER_IDENTITY_HAS_NO_CURRENT_VIEW_MATCH')
        self.assertNotIn('rotated-private-fixture',json.dumps(report));self.assertNotIn('fixture-private-value',json.dumps(report))

    def test_image_change_is_reported_without_accepting_a_config_match(self):
        expected,captured,views,version=self.fixture();views=copy.deepcopy(views)
        for value in views.values():value['Image']='sha256:'+'f'*64
        report=m.analyze(expected,captured,views,version)
        self.assertFalse(report['identityChecks'][version]['imageId'])
        self.assertEqual(report['matchingCurrentApis'],[])

    def test_stopped_paused_and_restarting_provider_block_even_with_exact_identity(self):
        for state in ('Running','Paused','Restarting'):
            a=self.fixture();a[2][a[3]]=copy.deepcopy(a[2][a[3]])
            a[2][a[3]]['State'][state]=state!='Running'
            with self.subTest(state=state):
                report=m.analyze(*a)
                self.assertEqual(report['classification'],'CURRENT_PROVIDER_STATE_BLOCKS_NATIVE_CONTEXT')
                self.assertTrue(report['currentStateBlocksNativeContext']);self.assertFalse(report['resumeAllowed'])

    def test_wrong_container_response_and_untyped_state_are_refused(self):
        for change in ('id','state'):
            a=self.fixture();a[2][a[3]]=copy.deepcopy(a[2][a[3]])
            if change=='id':a[2][a[3]]['Id']='d'*64
            else:a[2][a[3]]['State']['Running']=1
            with self.subTest(change=change),self.assertRaises(ValueError):m.analyze(*a)

    def test_only_capture_and_exact_server_negotiated_api_views_are_allowed(self):
        a=self.fixture();a[2]['1.53']=copy.deepcopy(a[2]['1.54'])
        with self.assertRaises(ValueError):m.analyze(*a)
        for value in ('1.43','1.100','1.54/execute','https://outside.invalid','1.54?x=1',None):
            with self.subTest(value=value),self.assertRaises(ValueError):m.api_version(value)

    def test_same_capture_and_negotiated_version_needs_only_one_view(self):
        value=row();report=m.analyze(m.identity(value),value,{'1.44':value},'1.44')
        self.assertEqual(report['matchingCurrentApis'],['1.44']);self.assertFalse(report['resumeAllowed'])

    def test_exact_consumed_stop_and_canonical_hash_are_bound(self):
        value=stop();m.verify_stop(value)
        self.assertEqual(m.digest(value),m.STOP_HASH)
        for change in ('counts','reason','scope','authority'):
            v=copy.deepcopy(value)
            if change=='counts':v['counts']['nativeConfigurationReads']=1
            if change=='reason':v['reasonCode']='DIFFERENT_FAILURE'
            if change=='scope':v['scope']+='/other'
            if change=='authority':v['targetApplyAuthorized']=True
            with self.subTest(change=change),self.assertRaises(ValueError):m.verify_stop(v)

    def test_unknown_route_other_provider_early_api_or_repeated_version_dispatch_is_denied(self):
        c=types.SimpleNamespace(counts={'providerEngineGets':0},guarded=lambda:None)
        e=m.ProviderViewsEngine(c,{'socketPath':'/not-opened','socketBinding':[],'peerCredentials':[]},'a'*64)
        for selected in ('/v1.54/containers/'+'a'*64+'/json','/v1.44/containers/'+'b'*64+'/json','/execute','/containers/json'):
            with self.subTest(path=selected),self.assertRaises(ValueError):e.get(selected)
        e.negotiated='1.54'
        with self.assertRaises(ValueError):e.get('/version')
        self.assertEqual(c.counts['providerEngineGets'],0)

if __name__=='__main__':unittest.main()
