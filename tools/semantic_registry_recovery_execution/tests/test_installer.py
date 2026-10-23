"""Real private ledgers/signatures and actual owner; synthetic factory context.

Factory context/retained-input validation is substituted ONLY in this focused
filesystem test. This is not whole native installer or target qualification.
"""
import copy,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_installed_observer as base
from tools.semantic_registry_recovery_execution import core as c,authorization as a,installer as i
from tools.semantic_registry_recovery_execution import read_budget as b

class Installer(base.InstalledObserver):
    # Reuse fixture, not the parent's test methods in discovery.
    def setUp(self):
        base.InstalledObserver.setUp(self)
        self.root=self.f.root/('semantic-registry-recovery-'+self.plan['logicalOperationRef'])
        self.context={'plan':self.plan,'executionRoot':str(self.root),
            'nodeRecipe':{'renewableToken':{'minimumRemainingSeconds':90}}}
        self.factory={'executionRoot':str(self.root),'fixtureOnly':True}
        scope=patch.object(i,'factory_scope',return_value=self.factory);scope.start();self.addCleanup(scope.stop)
        self.expected=i.installation_scope(self.context,self.reference)
        request={'disposableFixtureRequest':True}
        self.f.expected['creationRequestHash']=c.digest(request)
        self.f.approval.update(creationRequestHash=c.digest(request))
        raw=json.loads(self.f.authority);raw['creationRequestHash']=c.digest(request);self.f.authority=c.encoded(raw)
        self.resign({'semanticRegistryRecoveryInstallation':self.expected,
            'semanticRegistryRecoveryReads':b.read_scope(self.plan,self.root)})
        self.scoped=a.AuthorityScope(self.authority,self.f.authority,self.plan,request)
        scoped=patch.object(i,'current_scope',return_value=(self.factory,{},self.scoped))
        scoped.start();self.addCleanup(scoped.stop)

    def install(self):return i.install(self.context,self.reference,self.authority,self.f.authority)

    def test_create_once_preserves_both_ledgers_and_never_dispatches_runtime(self):
        calls=list(self.server.calls);before=self.owner.journal.read()
        receipt=self.install();store=c.Store(self.root,self.plan['logicalOperationRef'])
        self.assertEqual(store.read()['nextStage'],0);self.assertEqual(store.read()['effects'],[])
        self.assertEqual(receipt['runtimeEffectsDispatched'],0)
        reads=(self.root/'native-reads.json').read_bytes();journal=(self.root/'recovery.json').read_bytes()
        with self.assertRaises(FileExistsError):self.install()
        self.assertEqual((self.root/'native-reads.json').read_bytes(),reads)
        self.assertEqual((self.root/'recovery.json').read_bytes(),journal)
        self.assertEqual(self.owner.journal.read(),before);self.assertEqual(self.server.calls,calls)

    def test_partial_installation_remains_consumed_and_is_not_reinitialized(self):
        with patch.object(i.ReadBudget,'initialize',side_effect=OSError('fixture crash after first ledger')):
            with self.assertRaises(OSError):self.install()
        before=(self.root/'recovery.json').read_bytes()
        self.assertFalse((self.root/'native-reads.json').exists())
        with self.assertRaises(FileExistsError):self.install()
        self.assertEqual((self.root/'recovery.json').read_bytes(),before)
        self.assertFalse((self.root/'installation.json').exists())

    def test_revoked_owner_blocks_before_any_recovery_directory(self):
        self.owner.pause()
        with self.assertRaises(Exception):self.install()
        self.assertFalse(self.root.exists())

    def test_missing_signed_installation_scope_creates_nothing(self):
        self.resign({'semanticRegistryRecoveryInstallation':{}})
        with self.assertRaisesRegex(c.RecoveryDenied,'SIGNED_RECOVERY_INSTALLATION'):self.install()
        self.assertFalse(self.root.exists())

# Avoid repeating the superclass's six tests under this focused subclass.
for _name in list(base.InstalledObserver.__dict__):
    if _name.startswith('test_') and _name not in Installer.__dict__:setattr(Installer,_name,None)

if __name__=='__main__':unittest.main()
