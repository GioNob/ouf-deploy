"""Real public CA/PKCS12/OpenSSL and custody; profile/owner guard is modeled.

This independently tests the trust parser and binding format, not native TLS,
full selected-owner admission or target IAM/workload credentials.
"""
import copy,hashlib,os,shutil,ssl,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]+[str(ROOT/'tools'/p) for p in
    ('semantic_application_cutover','semantic_frame_compiler','semantic_database_cutover','semantic_policy_token_owner',
     'semantic_lease_recovery','semantic_transaction_profiles','semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_current_cohort as cohort
from tools.m2_discovery_installation_profile import current_tls as m,public_truststore as trust


def public_fixture(root):
    openssl=str(Path(shutil.which('openssl')).resolve());values={}
    for role in ('iam','provider'):
        key=root/(role+'.key');cert=root/(role+'.pem')
        subprocess.run([openssl,'req','-x509','-newkey','ed25519','-nodes','-days','2','-keyout',str(key),
            '-out',str(cert),'-subj','/CN=fixture-'+role+'-root','-addext','basicConstraints=critical,CA:TRUE'],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        key.chmod(0o600);cert.chmod(0o600);values[role]=cert.read_bytes()
    # This fixture already creates explicit CA certificates. Use the exact
    # deterministic public-store codec; its separate admission parser is not
    # substituted by this test (the local runtime preloads an ambient CA).
    ders=[ssl.PEM_cert_to_DER_cert(values[role].decode()) for role in ('iam','provider')]
    raw=trust._pkcs12(sorted(ders,key=lambda v:hashlib.sha256(v).hexdigest()))
    return openssl,values,raw,{'fixturePublicCertificateCount':2}


class TlsTrust(unittest.TestCase):
    def prepared(self):
        t=tempfile.TemporaryDirectory(dir=ROOT,prefix='current-tls-fixture-');self.addCleanup(t.cleanup)
        root=Path(t.name);root.chmod(0o700);openssl,values,raw,receipt=public_fixture(root)
        path=root/'public.p12';path.write_bytes(raw);path.chmod(0o440)
        f={'source':str(path),'uid':0,'gid':os.getegid(),'mode':0o440,'maxBytes':1048576,
            'sha256':hashlib.sha256(raw).hexdigest(),'metadataHash':m.digest(m.attributes(path.lstat()))}
        reader=object.__new__(m.CurrentTlsIdentities)
        reader.guard=lambda:SimpleNamespace(profile=SimpleNamespace(selection={'files':{'tlsTrustStore':f}}))
        inputs={k:v for k,v in cohort.fixture().items() if k in
            ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')}
        inputs.update(schema=m.SCHEMA,executionProfileHash='e'*64,trustStoreBindingHash=m.digest(f),
            caFiles={r:{'path':str(root/(r+'.pem')),'sha256':hashlib.sha256(v).hexdigest(),'maximumBytes':1048576} for r,v in values.items()},
            endpoints={r:{'peerRole':'caddy' if r=='iam' else 'provider','network':'ouf-backend',
                'port':443,'serverName':r+'.fixture.invalid'} for r in values})
        reader.inputs=inputs
        proposal={'configuration':{'verification':{'openssl':{'path':openssl,'sha256':hashlib.sha256(Path(openssl).read_bytes()).hexdigest()}}}}
        return reader,root,path,f,proposal,values

    def replace(self,path,f,raw):
        path.chmod(0o600);path.write_bytes(raw);path.chmod(0o440)
        f['sha256']=hashlib.sha256(raw).hexdigest();f['metadataHash']=m.digest(m.attributes(path.lstat()))

    def test_actual_java_public_store_matches_both_reviewed_ca_sets(self):
        reader,root,path,f,proposal,values=self.prepared();before=path.read_bytes()
        ca,pins=reader.trust(m.ObservationBudget(30),proposal)
        self.assertEqual(set(ca),{'iam','provider'});self.assertEqual(len(pins),3)
        self.assertEqual({k:len(v) for k,v in ca.items()},{'iam':1,'provider':1});self.assertEqual(path.read_bytes(),before)

    def test_trusted_store_missing_a_reviewed_anchor_is_denied(self):
        reader,_,path,f,proposal,values=self.prepared()
        self.replace(path,f,trust._pkcs12([ssl.PEM_cert_to_DER_cert(values['iam'].decode())]))
        with self.assertRaisesRegex(ValueError,'TRUST_ANCHORS_DIFFER'):reader.trust(m.ObservationBudget(30),proposal)

    def test_private_key_bag_is_not_accepted_as_a_public_truststore(self):
        reader,root,path,f,proposal,_=self.prepared();key_store=root/'key-store.p12'
        subprocess.run([proposal['configuration']['verification']['openssl']['path'],'pkcs12','-export',
            '-in',str(root/'iam.pem'),'-inkey',str(root/'iam.key'),'-certfile',str(root/'provider.pem'),
            '-out',str(key_store),'-passout','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        self.replace(path,f,key_store.read_bytes())
        with self.assertRaisesRegex(ValueError,'PUBLIC_CERTIFICATES_ONLY'):reader.trust(m.ObservationBudget(30),proposal)

    def test_ca_custody_drift_during_export_is_denied(self):
        reader,root,_,_,proposal,_=self.prepared();native=m.subprocess.run
        def drift(*a,**k):
            result=native(*a,**k);(root/'iam.pem').chmod(0o400);return result
        with patch.object(m.subprocess,'run',side_effect=drift),self.assertRaisesRegex(ValueError,'TRUST_MATERIAL_CHANGED'):
            reader.trust(m.ObservationBudget(30),proposal)

    def test_parent_binding_adds_exact_tls_hash_without_rebinding_old_inputs(self):
        reader,*_=self.prepared();initial=cohort.fixture();before=copy.deepcopy(initial)
        bound=m.bind_tls_inputs(initial,reader.inputs)
        self.assertEqual(initial,before);self.assertEqual(bound['additionalInputsHashes']['tlsIam'],m.validate(reader.inputs))
        changed=copy.deepcopy(reader.inputs);changed['endpoints']['iam']['port']=8443
        with self.assertRaisesRegex(ValueError,'CANNOT_BE_REPLACED'):m.bind_tls_inputs(bound,changed)
        changed=copy.deepcopy(reader.inputs);changed['endpoints']['iam']['peerRole']='udp'
        with self.assertRaises(ValueError):m.validate(changed)

    def test_only_public_certificates_enter_a_tls_context(self):
        reader,_,_,_,_,values=self.prepared()
        for raw in (values['iam']+b'PRIVATE KEY',b'',b'not a certificate'):
            with self.assertRaises(ValueError):m.certificates(raw,public_only=True)
        self.assertEqual(len(m.certificates(values['iam']+values['iam'],public_only=True)),1)

if __name__=='__main__':unittest.main()
