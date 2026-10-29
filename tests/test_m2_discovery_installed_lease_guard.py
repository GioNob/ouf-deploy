"""Actual Ed25519 install/generation receipts; current native probe is synthetic."""
import copy,hashlib,json,os,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as signed
from tools.semantic_provider_deployment_authentication import signing_bytes
from tools.semantic_registry_operational_owner.core import Denied as OperationalDenied
from tools.m2_discovery_installation_profile import lease_worker
from tools.m2_discovery_installation_profile import installed_lease_guard as m

class Installed(unittest.TestCase):
    setUp=signed.SignedCutover.setUp
    native=signed.SignedCutover.native
    write=signed.SignedCutover.write
    binding=signed.SignedCutover.binding
    sign=signed.SignedCutover.sign

    def signed_receipt(self,value,role='CREATION_ATTESTATION'):
        raw=m.encoded(value);sha=signed.sha(raw)
        header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519',
            'keyRef':self.attestor['keyRef'],'role':role,'issuerRef':self.context['attestorRef'],
            'installationRef':self.context['installationRef'],'entityRef':self.context['entityRef'],'payloadHash':sha}
        frame=self.root/'receipt-frame';self.write(frame,signing_bytes(raw,header))
        signature=self.native('pkeyutl','-sign','-rawin','-inkey',str(self.key),'-in',str(frame))
        self.write(self.receipt_signatures/(sha+'.CREATION_ATTESTATION.json'),
            signed.encoded({**header,'signature':signature.hex()}))
        return raw

    def fixture(self):
        policy=json.loads(self.policy.read_bytes());self.attestor=policy['keys'][1]
        self.attestor['publicKey']=self.grant['publicKey'];self.write(self.policy,signed.encoded(policy))
        self.receipt_signatures=self.root/'receipt-signatures';self.receipt_signatures.mkdir(mode=0o700)
        unit=self.root/'worker.service';self.write(unit,b'[Service]\nExecStart=/usr/bin/python3 -I -B -S /synthetic/capsule.py\n')
        lock=self.root/'common.lock';self.write(lock,b'')
        boot=self.root/'boot-id';self.write(boot,b'12345678-1234-1234-1234-123456789abc\n')
        runtime=self.root/'source-bound-runtime';self.write(runtime,b'SYNTHETIC_BOUND_SOURCE')
        hashes={name:hashlib.sha256(Path(sys.modules[name].__file__).read_bytes()).hexdigest() for name in m.REQUIRED_MODULES}
        c={'schema':'ouf.discovery-operational-lease-configuration.v1','installationInputsHash':'a'*64,
            'desiredProfileHash':'b'*64,'sourceManifest':{'schema':'ouf.discovery-operational-lease-sources.v1',
                'sourceHashes':hashes,'dependencyClosureHash':'c'*64},
            'sources':[{'path':str(runtime),'sha256':signed.sha(runtime.read_bytes()),'maximumBytes':65536}],
            'verification':{'trustPolicy':self.binding(self.policy),
                'openssl':{**self.binding(self.openssl),'version':self.native('version').decode().split()[1]},
                'context':{k:self.context[k] for k in ('installationRef','entityRef','attestorRef')}},
            'serviceUnitPath':str(unit),'serviceUnitHash':signed.sha(unit.read_bytes()),
            'commonInvocationLock':str(lock),'commonLockIdentity':[getattr(lock.stat(),k) for k in
                ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink')],
            'generationReceiptPath':str(self.root/'current-generation.json'),'hostBootIdPath':str(boot),
            'ledgerRoot':str(self.root/'ledger'),'scopePolicyHash':'d'*64}
        path=self.root/'configuration.json';self.write(path,m.encoded(c));sha=m.digest(c)
        receipt={'schema':'ouf.discovery-operational-lease-installation-receipt.v1','complete':True,
            'configurationHash':sha,'installationInputsHash':c['installationInputsHash'],'desiredProfileHash':c['desiredProfileHash'],
            'sourceManifestHash':m.digest(c['sourceManifest']),'serviceUnitHash':c['serviceUnitHash'],
            'scopePolicyHash':c['scopePolicyHash'],'finiteApprovalAuthorizesInstallationOnly':True,
            'operationalLifetime':'UNTIL_DISABLE_CUSTODY_OR_INSTALLATION_TRUST_REVOCATION',
            'runtimeSigningKeyAccessAllowed':False,'containerLifecycleOperationsAllowed':False}
        self.write(self.root/'installed.json',self.signed_receipt(receipt))
        generation={'schema':'ouf.discovery-operational-lease-generation-receipt.v1','configurationHash':sha,
            'desiredProfileHash':c['desiredProfileHash'],'scopePolicyHash':c['scopePolicyHash'],
            'scopeHash':'e'*64,'generationRef':'f'*64,'bootId':boot.read_text().strip(),
            'nativeObservationHash':'1'*64,'nativeProfileHash':'2'*64,'ledgerRoot':c['ledgerRoot'],
            'state':'NATIVE_GENERATION_ADMITTED','containerStartAuthorized':False}
        self.write(Path(c['generationReceiptPath']),self.signed_receipt(generation))
        calls=[]
        def probe(value):
            calls.append(copy.deepcopy(value))
            return {k:value[k] for k in ('nativeObservationHash','nativeProfileHash','generationRef','bootId')}
        guard=m.InstalledLeaseGuard(path,sha,generation_probe=probe)
        return guard,c,generation,calls,receipt

    def test_installed_runtime_survives_expired_maintenance_mandate_without_private_signing_key(self):
        guard,c,generation,calls,_=self.fixture()
        self.write(self.mandate,b'SYNTHETIC_EXPIRED_MAINTENANCE_NO_LONGER_RUNTIME_AUTHORITY')
        self.key.rename(self.root/'unused-private-key')
        with guard.invocation():self.assertTrue(guard.current(generation['scopeHash'],generation['generationRef']))
        self.assertEqual(len(calls),1)

    def test_same_process_lifetime_fence_is_required(self):
        guard,c,g,calls,_=self.fixture()
        with self.assertRaisesRegex(ValueError,'LIFETIME_FENCE'):guard.current(g['scopeHash'],g['generationRef'])
        self.assertEqual(calls,[])

    def test_foreign_scope_or_generation_is_denied_before_probe(self):
        guard,c,g,calls,_=self.fixture()
        with guard.invocation():
            for scope,gen in (('0'*64,g['generationRef']),(g['scopeHash'],'0'*64)):
                with self.assertRaisesRegex(ValueError,'EXACT_CURRENT_OPERATIONAL'):guard.current(scope,gen)
        self.assertEqual(calls,[])

    def test_current_native_probe_must_match_signed_generation(self):
        guard,c,g,calls,_=self.fixture()
        guard.probe=lambda value:{'nativeObservationHash':'0'*64,'nativeProfileHash':value['nativeProfileHash'],
            'generationRef':value['generationRef'],'bootId':value['bootId']}
        with guard.invocation():
            with self.assertRaisesRegex(ValueError,'CURRENT_INDEPENDENT_NATIVE'):guard.current(g['scopeHash'],g['generationRef'])

    def test_missing_or_wrong_role_generation_signature_is_denied(self):
        guard,c,g,calls,_=self.fixture()
        signature=self.receipt_signatures/(signed.sha(m.encoded(g))+'.CREATION_ATTESTATION.json')
        with guard.invocation():
            signature.unlink()
            with self.assertRaises((signed.PreexecDenied,FileNotFoundError)):guard.current(g['scopeHash'],g['generationRef'])
            self.signed_receipt(g,role='FINAL_DEPLOYMENT_APPROVAL')
            with self.assertRaises(signed.PreexecDenied):guard.current(g['scopeHash'],g['generationRef'])
        self.assertEqual(calls,[])

    def test_wrong_boot_or_changed_unit_is_not_adopted(self):
        guard,c,g,calls,_=self.fixture()
        with guard.invocation():
            self.write(Path(c['hostBootIdPath']),b'87654321-1234-1234-1234-123456789abc\n')
            with self.assertRaisesRegex(ValueError,'CURRENT_BOOT'):guard.current(g['scopeHash'],g['generationRef'])
        self.assertEqual(calls,[])
        self.write(Path(c['serviceUnitPath']),b'UNREVIEWED_SERVICE')
        with self.assertRaisesRegex(OperationalDenied,'OPERATIONAL_INPUT_HASH_CHANGED'):guard.metadata_guard()

    def test_process_start_permission_cannot_be_smuggled_into_generation_receipt(self):
        guard,c,g,calls,_=self.fixture();bad={**g,'containerStartAuthorized':True}
        self.write(Path(c['generationReceiptPath']),self.signed_receipt(bad))
        with guard.invocation():
            with self.assertRaisesRegex(ValueError,'EXACT_CURRENT_OPERATIONAL'):guard.current(g['scopeHash'],g['generationRef'])
        self.assertEqual(calls,[])

    def test_lock_replacement_and_concurrent_invocation_are_denied(self):
        guard,c,g,calls,_=self.fixture()
        other=m.InstalledLeaseGuard(guard.path,guard.sha,generation_probe=guard.probe)
        with guard.invocation():
            with self.assertRaises(BlockingIOError):
                with other.invocation():pass
            path=Path(c['commonInvocationLock']);path.rename(path.with_suffix('.preserved'))
            self.write(path,b'')
            with self.assertRaisesRegex(ValueError,'LOCK_REPLACED'):guard.current(g['scopeHash'],g['generationRef'])

if __name__=='__main__':unittest.main()
