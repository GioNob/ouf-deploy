import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

s=importlib.util.spec_from_file_location('planner',Path(__file__).resolve().parents[1]/'scripts/compile-semantic-creation-plan-after-r12.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
ROOT=Path(__file__).resolve().parents[1]


class CurrentPlanner(unittest.TestCase):
    def sources(self):
        return {name:(ROOT/path).read_bytes() for name,path in {
            'prepare':'scripts/prepare-semantic-inputs-after-r12.py',
            'custody':'tools/semantic_target_review/prepare_application_runtime_inputs.py',
            'creation':'tools/semantic_application_cutover/creation_plan.py'}.items()}
    def test_complete_qualified_closure_loads_without_target_effects(self):
        sources=self.sources()
        for name,raw in sources.items():self.assertEqual(hashlib.sha256(raw).hexdigest(),m.SOURCE_HASHES[name])
        modules=m.load_sources(sources)
        self.assertEqual(set(modules),{'prepare','custody','creation'})
        self.assertEqual(modules['prepare'].UNIT,'ouf-semantic-provider-lease-resilient-r12.service')
    def test_all_module_tamper_positions_rejected_before_any_execution(self):
        for name in m.SOURCE_HASHES:
            sources=self.sources();sources[name]=b'raise AssertionError("MUST_NOT_EXECUTE")'
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'SEALED_PLANNER_MODULE_HASH_MISMATCH'):
                m.load_sources(sources)
        for value in (None,{},dict(self.sources(),unknown=b'extra')):
            with self.assertRaisesRegex(ValueError,'EXACT_SEALED_PLANNER_MODULE_SET_REQUIRED'):m.load_sources(value)
    def test_native_ttl_membership_quiescent_and_bool_values_denied(self):
        lease={'journalState':'LEASE_READY','leaseAuthorized':True,'nativeStructureVerified':True,
            'journalAndMembershipConsistent':True,'providerSetsEmpty':False,'flowCount':2,
            'flows':[{'inetAddressCount':1,'bridgeAddressCount':1,'approvedAddressCount':1,
                      'minRemainingTtlSeconds':16,'leaseSeconds':30} for _ in range(2)]}
        m.native_lease_ready(lease)
        for field,value in [('journalState','QUIESCED'),('leaseAuthorized',False),
                            ('providerSetsEmpty',True),('nativeStructureVerified',False)]:
            changed=copy.deepcopy(lease);changed[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):m.native_lease_ready(changed)
        for field,value in [('minRemainingTtlSeconds',0),('minRemainingTtlSeconds',True),
                            ('minRemainingTtlSeconds',31),('bridgeAddressCount',0),('inetAddressCount',True)]:
            changed=copy.deepcopy(lease);changed['flows'][1][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):m.native_lease_ready(changed)
    @unittest.skipUnless(os.geteuid()==0 and os.environ.get('OUF_POSIX_FIXTURE_ROOT'),
                         'actual role custody requires isolated hosted root fixture')
    def test_actual_four_file_custody_credential_binding_and_mode_denials(self):
        custody=m.load_sources(self.sources())['custody']
        with tempfile.TemporaryDirectory(dir=os.environ['OUF_POSIX_FIXTURE_ROOT']) as path:
            root=Path(path);root.chmod(0o700)
            mounts=[]
            for key in ('auth','discovery','trust'):
                file=root/key;value=('fixture-'+key).encode()
                custody.create(file,value,10001,10001,0o400)
                mounts.append({'source':str(file),'uid':10001,'gid':10001,'mode':0o400,
                               'readOnly':True,'sha256':hashlib.sha256(value).hexdigest()})
            secret=root/'database';secret.mkdir(mode=0o700);os.chown(secret,10001,10001);secret.chmod(0o500)
            value=b'fixture-password';file=secret/'OUF_SEM_DB_PASSWORD'
            custody.create(file,value,10001,10001,0o400)
            declaration={'roleOwnedReadOnlyMounts':mounts,'databaseSecretProjection':{
                'sourceDirectory':str(secret),'file':{'name':file.name,'uid':10001,'gid':10001,
                'mode':0o400,'sha256':hashlib.sha256(value).hexdigest()}}}
            current={'Config':{'Env':['OUF_SEM_DB_PASSWORD=fixture-password']}}
            m.verify_secret_custody(custody,declaration,current)
            current['Config']['Env']=['OUF_SEM_DB_PASSWORD=changed']
            with self.assertRaisesRegex(ValueError,'CURRENT_DATABASE_CREDENTIAL_BINDING_DRIFT'):
                m.verify_secret_custody(custody,declaration,current)
            current['Config']['Env']=['OUF_SEM_DB_PASSWORD=fixture-password']
            file.chmod(0o644)
            with self.assertRaises(ValueError):m.verify_secret_custody(custody,declaration,current)


if __name__=='__main__':unittest.main()
