"""Real CA bytes, explicit synthetic bound owner/material records, no target IO."""
import copy,hashlib,ssl,sys,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_public_truststore as cert_fixture
from tools.m2_discovery_installation_profile import trust_inputs as m


class BoundTrustInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cert_fixture.PublicTruststore.setUpClass()
    @classmethod
    def tearDownClass(cls):cert_fixture.PublicTruststore.tearDownClass()

    def fixture(self):
        cert=cert_fixture.PublicTruststore.certificates;iam=cert['iam'];provider=cert['provider']
        issuer='https://iam.fixture.invalid/realms/ouf';endpoint=issuer+'/protocol/openid-connect/token'
        roles={r:'retained::'+r for r in ('semantic','mcp','apisix','gateway-owner')}
        current={alias:{'Id':format(i+1,'064x'),'Config':{'Env':[]}} for i,alias in enumerate(roles.values())}
        current[roles['semantic']]['Config']['Env']=['OUF_IAM_ISSUER='+issuer,'OUF_SCHEMA_GOV_TOKEN_ENDPOINT='+endpoint]
        current.update({'peer-'+str(i):{'Id':format(i+10,'064x')} for i in range(9)})
        ph=hashlib.sha256(provider).hexdigest()
        prepared={'schema':'ouf.m2-discovery-private-material-role-preparation.v1',
            'installationRoleMap':roles,'currentObservations':current,
            'selectedInstallationObservations':{r:current[a] for r,a in roles.items()},
            'preparedCopies':{'publicProviderCa':{'path':'/fixture/material/provider-public-ca.crt','sha256':ph,'uid':0,'gid':0,'mode':0o600}},
            'projectionPlan':{'publicTrustInput':{'sha256':ph}},
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'historicalAuthorityReused':False,
            'automaticReplayAllowed':False,'budgetReset':False}
        fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(iam.decode())).hexdigest()
        owner={'schema':'ouf.registry-operational-token-configuration.v1',
            'ownerInputs':{'iamProfile':{'issuer':issuer,'token_endpoint':endpoint},'tlsTrustHash':m.digest([fingerprint])},
            'tlsCa':{'path':'/fixture/owner/iam-ca.pem','sha256':hashlib.sha256(iam).hexdigest()}}
        return prepared,{'path':'/fixture/material/prepared-inputs.private.json','sha256':m.digest(prepared)},owner,{
            'path':'/fixture/owner/configuration.json','sha256':m.digest(owner)},iam,provider,time.time()

    def test_binds_both_exact_records_ca_files_issuer_and_native_owner_trust_digest(self):
        args=self.fixture();before=copy.deepcopy(args);raw,receipt=m.compile_trust(*args)
        self.assertEqual(args,before);self.assertEqual(receipt['sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(receipt['iamTrustDigest'],args[2]['ownerInputs']['tlsTrustHash'])
        self.assertEqual(receipt['certificateCount'],2);self.assertFalse(receipt['currentFileCustodyProvenHere'])
        self.assertFalse(receipt['currentOwnerAdmissionProvenHere']);self.assertFalse(receipt['runtimeAuthorityIssued'])

    def test_changed_unbound_record_or_file_is_denied(self):
        for case in ('material','owner','iam-file','provider-file'):
            a=list(self.fixture())
            if case=='material':a[0]['budgetReset']=True
            if case=='owner':a[2]['extra']='unbound'
            if case=='iam-file':a[4]+=b'\n'
            if case=='provider-file':a[5]+=b'\n'
            with self.subTest(case=case),self.assertRaises(ValueError):m.compile_trust(*a)

    def test_rehashed_unrelated_issuer_trust_set_or_projection_is_still_denied(self):
        for case in ('issuer','trust-digest','projection','role-view'):
            a=list(self.fixture())
            if case=='issuer':a[2]['ownerInputs']['iamProfile']['issuer']='https://other.fixture.invalid/realms/ouf'
            if case=='trust-digest':a[2]['ownerInputs']['tlsTrustHash']='e'*64
            if case=='projection':a[0]['projectionPlan']['publicTrustInput']['sha256']='e'*64
            if case=='role-view':a[0]['selectedInstallationObservations']['semantic']=copy.deepcopy(a[0]['selectedInstallationObservations']['mcp'])
            a[1]['sha256']=m.digest(a[0]);a[3]['sha256']=m.digest(a[2])
            with self.subTest(case=case),self.assertRaises(ValueError):m.compile_trust(*a)

if __name__=='__main__':unittest.main()
