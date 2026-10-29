"""Real installed signature/custody composition; no native admission is inferred."""
import copy,dataclasses,hashlib,sys,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_installed_lease_guard as installed
from tools.m2_discovery_installation_profile import lease_service as m
from tools.m2_discovery_installation_profile.lease_worker import DiscoveryRecovery


class Service(unittest.TestCase):
    setUp=installed.Installed.setUp
    native=installed.Installed.native
    write=installed.Installed.write
    binding=installed.Installed.binding
    sign=installed.Installed.sign
    signed_receipt=installed.Installed.signed_receipt

    def fixture(self):
        guard,c,g,calls,receipt=installed.Installed.fixture(self)
        ledger=Path(c['ledgerRoot']);ledger.mkdir(mode=0o700)
        kernel={'tableName':'discovery_service_ci','guardedInterfaces':['leasebr'],'existingInterfaces':[],
            'staticFlows':[],'providerFlows':[{'endpointRef':'ci-'+str(i),'endpoint':'https://'+host+'/approved',
            'source':'10.77.0.'+str(i+2),'addresses':[],'leaseSeconds':30,'resolutionEvidenceRef':'synthetic-ci',
            'allowedPrivateAddresses':[]} for i,host in enumerate(('provider.example','identity.example'))]}
        dns={'resolvers':['127.0.0.1'],'resolverPort':15353,'timeoutSeconds':2,'maxLeaseSeconds':30,'applyBudgetSeconds':1}
        binding={'transactionId':'a'*64,'configurationHash':'b'*64,'leaseStructureHash':'c'*64}
        policy=m.Policy();policy_dict=dataclasses.asdict(policy);policy_dict['delays']=list(policy.delays)
        scope={'sourceClosureHash':c['sourceManifest']['dependencyClosureHash'],'installationInputsHash':c['installationInputsHash'],
            'contextRef':'a'*64,'generationRef':g['generationRef'],'policyHash':m.fingerprint(dataclasses.asdict(policy)),
            'coordinatorBindingHash':m.fingerprint(binding),'configurationHash':m.fingerprint(kernel),
            'dnsProfileHash':m.fingerprint(dns),'leaseStructureHash':binding['leaseStructureHash'],
            'pollSeconds':1,'heartbeatSeconds':1}
        program=Path('/usr/bin/true').resolve()  # Constructor must not execute it.
        lock=self.root/'lease-common.lock';self.write(lock,b'')
        recipe={'schema':'ouf.discovery-operational-lease-recipe.v1','kernel':kernel,'dns':dns,'binding':binding,
            'policy':policy_dict,'scope':scope,'nft':{'path':str(program),'sha256':hashlib.sha256(program.read_bytes()).hexdigest(),
            'maximumBytes':1048576},'coordinationJournal':str(ledger/'coordination.json'),'leaseCommonLock':str(lock),
            'leaseCommonLockIdentity':[getattr(lock.stat(),k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink')]}
        self.write(ledger/'coordination.json',m.encoded({'schema':'ouf.semantic-lease-coordination.v1',**binding,
            'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[],[]]}))
        journal=m.Journal(ledger);recovery=DiscoveryRecovery(journal,None,policy,scope['contextRef'],scope['generationRef'],
            lambda:(100.0,50.0),lambda:.5)
        journal.initialize({**recovery.initial(),'discoveryLeaseScopeHash':m.fingerprint(scope),
            'attempts':7,'publicationCount':4})
        for name in m.SERVICE_MODULES:
            c['sourceManifest']['sourceHashes'][name]=hashlib.sha256(Path(sys.modules[name].__file__).read_bytes()).hexdigest()
        c['scopePolicyHash']=scope['policyHash']
        self.c,self.g,self.receipt,self.path,self.recipe=c,g,receipt,guard.path,recipe
        self.reseal()
        return journal,calls

    def reseal(self):
        recipe_path=self.path.parent/'worker-recipe.json';self.write(recipe_path,m.encoded(self.recipe))
        self.c['sources']=[v for v in self.c['sources'] if v['path']!=str(recipe_path)]
        self.c['sources'].append({'path':str(recipe_path),'sha256':m.digest(self.recipe),'maximumBytes':1048576})
        self.write(self.path,m.encoded(self.c));sha=m.digest(self.c)
        self.receipt.update(configurationHash=sha,scopePolicyHash=self.c['scopePolicyHash'],
            sourceManifestHash=m.digest(self.c['sourceManifest']))
        self.write(self.root/'installed.json',self.signed_receipt(self.receipt))
        self.g.update(configurationHash=sha,scopePolicyHash=self.c['scopePolicyHash'],
            scopeHash=m.fingerprint(self.recipe['scope']))
        self.write(Path(self.c['generationReceiptPath']),self.signed_receipt(self.g))

    def test_build_uses_actual_native_classes_without_dns_kernel_calls_or_journal_changes(self):
        journal,calls=self.fixture();before=journal.record.read_bytes()
        with (mock.patch.object(m.DeadlineNftBackend,'run',side_effect=AssertionError('NO_NFT_DURING_BUILD')),
              mock.patch.object(m.dns,'exchange',side_effect=AssertionError('NO_DNS_DURING_BUILD'))):
            worker,guard,scope=m.build_installed(self.path,m.configuration_anchor(self.c))
        self.assertIs(type(worker.c),m.Coordinator);self.assertIs(type(worker.c.owner),m.LeaseOwner)
        self.assertIs(type(worker.c.owner.backend),m.DeadlineNftBackend)
        self.assertEqual(journal.record.read_bytes(),before);self.assertEqual(calls,[])
        self.assertEqual(worker.r.journal.read()['attempts'],7)
        self.assertEqual(worker.r.journal.read()['publicationCount'],4)

    def test_anchor_binds_every_configuration_field_except_separately_signed_unit_hash(self):
        self.fixture();anchor=m.configuration_anchor(self.c)
        changed=copy.deepcopy(self.c);changed['installationInputsHash']='0'*64
        self.write(self.path,m.encoded(changed))
        with self.assertRaisesRegex(ValueError,'ANCHOR_CHANGED'):m.build_installed(self.path,anchor)
        changed=copy.deepcopy(self.c);changed['serviceUnitHash']='0'*64
        self.assertEqual(m.configuration_anchor(changed),anchor)
        self.write(self.path,m.encoded(changed))
        with self.assertRaisesRegex(ValueError,'COMPLETED_DISTINCT_OPERATIONAL'):
            m.build_installed(self.path,anchor)

    def test_recipe_drift_and_unbound_program_are_denied(self):
        journal,_=self.fixture();worker,guard,scope=m.build_installed(self.path,m.configuration_anchor(self.c))
        self.write(self.path.parent/'worker-recipe.json',b'UNREVIEWED_RECIPE')
        with self.assertRaises(Exception):worker.r.adapter.sealed()
        self.assertEqual(journal.read()['attempts'],7)
        self.recipe['nft']['sha256']='0'*64;self.reseal()
        with self.assertRaises(Exception):m.build_installed(self.path,m.configuration_anchor(self.c))
        self.assertEqual(journal.read()['publicationCount'],4)

    def test_missing_recovery_record_is_not_initialized(self):
        journal,_=self.fixture();journal.record.unlink()
        with self.assertRaises(FileNotFoundError):m.build_installed(self.path,m.configuration_anchor(self.c))
        self.assertFalse(journal.record.exists());self.assertTrue(journal.lock.exists())

    def test_incomplete_executing_closure_and_old_coordination_path_are_denied(self):
        self.fixture();self.c['sourceManifest']['sourceHashes'].pop('deadline_backend');self.reseal()
        with self.assertRaisesRegex(ValueError,'COMPLETE_EXECUTING'):
            m.build_installed(self.path,m.configuration_anchor(self.c))
        self.c['sourceManifest']['sourceHashes']['deadline_backend']=hashlib.sha256(Path(sys.modules['deadline_backend'].__file__).read_bytes()).hexdigest()
        self.recipe['coordinationJournal']=str(self.root/'old-r12-journal.json');self.reseal()
        with self.assertRaisesRegex(ValueError,'DISTINCT_DISCOVERY_LEASE_LEDGER'):
            m.build_installed(self.path,m.configuration_anchor(self.c))

    def test_read_only_kernel_lock_is_shared_and_replacement_is_denied(self):
        self.fixture();path=Path(self.recipe['leaseCommonLock']);identity=self.recipe['leaseCommonLockIdentity']
        with m.existing_kernel_lock(path,identity):
            with self.assertRaises(BlockingIOError):
                with m.existing_kernel_lock(path,identity):self.fail('parallel kernel lock accepted')
        path.rename(path.with_suffix('.preserved'));self.write(path,b'')
        with self.assertRaisesRegex(ValueError,'CURRENT_DISCOVERY_KERNEL_LOCK_INODE'):
            with m.existing_kernel_lock(path,identity):self.fail('new inode adopted')

    def test_pinned_entry_reports_no_raw_exception_or_configuration(self):
        import contextlib,io
        output=io.StringIO()
        with (mock.patch.object(m,'run',side_effect=RuntimeError('PRIVATE_ENDPOINT_AND_SECRET')),
              contextlib.redirect_stdout(output)):
            result=m.execute(['--configuration','/synthetic/config.json','--configuration-anchor','a'*64])
        self.assertEqual(result,2);self.assertNotIn('PRIVATE_ENDPOINT_AND_SECRET',output.getvalue())
        self.assertIn('LOCAL_INSTALLED_DISCOVERY_LEASE_OUTCOME_UNPROVEN',output.getvalue())

if __name__=='__main__':unittest.main()
