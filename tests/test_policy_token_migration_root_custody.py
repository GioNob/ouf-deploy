"""Real directory custody, native signatures, fork crashes; no VPS effects."""
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tests')]
import test_policy_token_legacy_retirement as fixtures
import migration_root_custody as roots
binding=roots.binding

class RootCustodyTest(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.RetirementTest();self.f.setUp();self.addCleanup(self.f.doCleanups)
        p=patch.object(roots,'os',types.SimpleNamespace(**vars(os)));p.start();self.addCleanup(p.stop)
        base=self.f.f.root/'destinations';base.mkdir(mode=0o700)
        self.paths={role:str(base/role/'semantic')for role in roots.ROLES}
        p=patch.object(roots,'ROLES',self.paths);p.start();self.addCleanup(p.stop)
        proposed={}
        for role,path in self.paths.items():
            parts=Path(path).parts;ancestors=[]
            for depth in range(len(parts)-2):ancestors.append(roots.metadata(Path(*parts[:depth+1]).stat(),depth))
            proposed[role]={'path':path,'state':'ABSENT','firstMissingDepth':len(ancestors),
                'ancestors':ancestors,'custodyAccepted':False}
        self.f.host['proposedRootsMetadata']=proposed;self.f.raw=binding.encoded(self.f.host)
        digest=binding.sha(self.f.raw)
        p=patch.object(roots.legacy,'HOST_HASH',digest);p.start();self.addCleanup(p.stop)
        self.f.f.write(self.f.f.root/('policy-token-migration-host-inputs-'+digest+'.private.json'),self.f.raw)
        self.f.scope=self.f.action().scope;self.f.sign()
        action=self.action();self.scope=action.scope;self.sign()
    def action(self):
        retirement=self.f.action()
        return roots.RootCustody(retirement,retirement.authority,retirement.raw)
    def sign(self,alter=None):
        def change(a):
            a['policyTokenRootCustody']=self.scope
            if alter:alter(a)
        self.f.sign(change)
    def test_create_and_restart_preserve_directory_identities(self):
        action=self.action();row=action.run()
        self.assertEqual(row['state'],'ROOTS_CUSTODIED_NOT_RUNTIME_ACCEPTED')
        self.assertEqual(len(row['created']),6)
        for path in self.paths.values():
            info=Path(path).stat();self.assertEqual(info.st_uid,0);self.assertEqual(info.st_mode&0o777,0o700)
        with patch.object(roots.os,'mkdir',side_effect=AssertionError('must not recreate')):
            reread=self.action().run()
            self.assertEqual(reread['created'],row['created']);self.assertEqual(reread['version'],row['version'])
            self.assertEqual(reread['mkdirAttempts'],6)
    def test_existing_unknown_directory_never_adopted_or_modified(self):
        action=self.action();path=Path(action.steps[0]);path.mkdir(mode=0o755)
        before=path.stat()
        with self.assertRaisesRegex(binding.CandidateDenied,'NO_ADOPTION'):action.run()
        self.assertEqual(path.stat().st_ino,before.st_ino);self.assertEqual(path.stat().st_mode,before.st_mode)
    def test_missing_signed_scope_and_revocation_deny_creation(self):
        self.sign(lambda a:a.pop('policyTokenRootCustody'))
        with self.assertRaisesRegex(binding.CandidateDenied,'SIGNED_ROOT'):self.action().run()
        self.sign();self.f.f.approval['state']='REVOKED'
        self.f.f.write(self.f.f.mandate,binding.encoded(self.f.f.approval))
        with self.assertRaises(Exception):self.action().run()
        self.assertFalse(Path(self.scope['directories'][0]).exists())
    def test_crash_after_mkdir_blocks_unknown_inode_without_replay(self):
        action=self.action();mkdir=os.mkdir
        child=os.fork()
        if child==0:
            def crash(*args,**kwargs):mkdir(*args,**kwargs);os._exit(0)
            with patch.object(roots.os,'mkdir',side_effect=crash):
                try:action.run()
                except Exception:os._exit(91)
            os._exit(92)
        _,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),0)
        row=json.loads((self.f.f.root/action.name).read_bytes())
        self.assertEqual(row['pending'],action.steps[0]);self.assertEqual(row['created'],{})
        with patch.object(roots.os,'mkdir',side_effect=AssertionError('no retry')):
            with self.assertRaisesRegex(binding.CandidateDenied,'NO_ADOPTION'):self.action().run()
    def test_crash_before_mkdir_resumes_only_absent_pending_path(self):
        action=self.action();child=os.fork()
        if child==0:
            with patch.object(roots.os,'mkdir',side_effect=lambda *a,**kw:os._exit(0)):
                try:action.run()
                except Exception:os._exit(91)
            os._exit(92)
        _,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),0)
        self.assertFalse(Path(action.steps[0]).exists())
        self.assertEqual(self.action().run()['state'],'ROOTS_CUSTODIED_NOT_RUNTIME_ACCEPTED')
    def test_checkpointed_missing_or_replaced_directory_not_recreated(self):
        action=self.action();action.run();leaf=Path(self.paths['ownerCredential']);leaf.rmdir()
        with patch.object(roots.os,'mkdir',side_effect=AssertionError('no recreation')):
            with self.assertRaisesRegex(binding.CandidateDenied,'NO_RECREATE'):self.action().run()
    def test_parallel_fence_blocks_second_command(self):
        import fcntl
        action=self.action();fd=os.open(self.f.f.root/(action.name+'.lock'),os.O_CREAT|os.O_RDWR,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):action.run()
        finally:os.close(fd)
    def test_symlink_and_parent_permission_drift_block(self):
        action=self.action();Path(action.steps[0]).symlink_to(self.f.f.root,target_is_directory=True)
        with self.assertRaisesRegex(binding.CandidateDenied,'NO_ADOPTION'):action.run()
        Path(action.steps[0]).unlink()
        parent=Path(action.steps[0]).parent;parent.chmod(0o755)
        with self.assertRaisesRegex(binding.CandidateDenied,'ANCESTRY_CHANGED'):self.action().run()
    def test_durable_deadline_never_resets_on_restart(self):
        action=self.action();row=action.run()
        with patch.object(roots,'time',types.SimpleNamespace(monotonic=lambda:row['expiresMonotonic'])):
            with self.assertRaisesRegex(binding.CandidateDenied,'BUDGET_EXPIRED'):self.action().run()
        retained=json.loads((self.f.f.root/action.name).read_bytes())
        self.assertEqual(retained['expiresMonotonic'],row['expiresMonotonic'])
    def test_root_creation_needs_no_service_retirement_permission(self):
        self.sign(lambda a:a.pop('policyTokenLegacyRetirement'))
        with patch.object(roots.legacy,'read_units',side_effect=AssertionError('no service operation')):
            self.assertEqual(self.action().run()['state'],'ROOTS_CUSTODIED_NOT_RUNTIME_ACCEPTED')
    def test_exhausted_retained_attempt_count_cannot_reset(self):
        action=self.action()
        with patch.object(roots.os,'mkdir',side_effect=OSError('fixture failure before effect')):
            with self.assertRaises(OSError):action.run()
        path=self.f.f.root/action.name;row=json.loads(path.read_bytes())
        row['mkdirAttempts']=action.scope['maximumMkdirAttempts'];self.f.f.write(path,binding.encoded(row))
        with patch.object(roots.os,'mkdir',side_effect=AssertionError('no renewed budget')):
            with self.assertRaisesRegex(binding.CandidateDenied,'BUDGET_EXHAUSTED'):self.action().run()
        self.assertEqual(json.loads(path.read_bytes())['mkdirAttempts'],row['mkdirAttempts'])
    def test_revocation_after_mkdir_leaves_unproven_pending(self):
        action=self.action();mkdir=roots.os.mkdir
        def revoke(*args,**kwargs):
            mkdir(*args,**kwargs);self.f.f.approval['state']='REVOKED'
            self.f.f.write(self.f.f.mandate,binding.encoded(self.f.f.approval))
        with patch.object(roots.os,'mkdir',side_effect=revoke):
            with self.assertRaises(Exception):action.run()
        row=json.loads((self.f.f.root/action.name).read_bytes())
        self.assertEqual(row['created'],{});self.assertEqual(row['pending'],action.steps[0])
        self.assertEqual(row['mkdirAttempts'],1)

    def completed(self,row=None):
        if row is None:row=self.action().run()
        return roots.completed_roots(self.f.raw,binding.sha(binding.encoded(row)),self.scope['sourceClosureHash'])

    def test_completed_roots_bind_actual_inodes_without_renewing_expired_creation(self):
        action=self.action();row=action.run();before=(self.f.f.root/action.name).read_bytes()
        self.f.f.approval['state']='REVOKED'
        self.f.f.write(self.f.f.mandate,binding.encoded(self.f.f.approval))
        with patch.object(roots,'time',types.SimpleNamespace(monotonic=lambda:row['expiresMonotonic']+10000)),\
             patch.object(roots.os,'mkdir',side_effect=AssertionError('no creation replay')):
            with self.completed(row)as identities:
                for role,path in self.paths.items():
                    self.assertEqual(identities[role],{'path':path,'device':Path(path).stat().st_dev,'inode':Path(path).stat().st_ino})
        self.assertEqual((self.f.f.root/action.name).read_bytes(),before)

    def test_completed_roots_reject_altered_receipt_or_source_hash(self):
        action=self.action();row=action.run();digest=binding.sha(binding.encoded(row))
        for altered_hash,source in [('0'*64,action.scope['sourceClosureHash']),(digest,'0'*64)]:
            with self.assertRaises(binding.CandidateDenied):
                with roots.completed_roots(self.f.raw,altered_hash,source):self.fail('invalid custody accepted')

    def test_completed_roots_deny_partial_creation_even_with_matching_hash(self):
        action=self.action();row=action.run();row['state']='CREATING'
        self.f.f.write(self.f.f.root/action.name,binding.encoded(row))
        with self.assertRaisesRegex(binding.CandidateDenied,'SUCCESSFUL_ROOT_CREATION'):
            with self.completed(row):self.fail('partial custody accepted')

    def test_completed_root_permissions_or_inode_change_is_not_adopted(self):
        row=self.action().run();path=Path(self.paths['ownerCredential'])
        path.chmod(0o755)
        with self.assertRaisesRegex(binding.CandidateDenied,'CUSTODY_DRIFT'):
            with self.completed(row):self.fail('changed permissions accepted')
        path.chmod(0o700);path.rename(path.with_name('original'));path.mkdir(mode=0o700)
        with self.assertRaisesRegex(binding.CandidateDenied,'CUSTODY_DRIFT'):
            with self.completed(row):self.fail('replacement accepted')

    def test_completed_root_replacement_during_use_fails_and_restores_global_parent(self):
        row=self.action().run();parent=binding.PARENT;path=Path(self.paths['reviewedCode'])
        with self.assertRaises(binding.CandidateDenied):
            with self.completed(row):
                path.rename(path.with_name('original'));path.mkdir(mode=0o700)
        self.assertEqual(binding.PARENT,parent)

    def test_completed_root_ledger_change_during_use_is_denied(self):
        action=self.action();row=action.run()
        with self.assertRaisesRegex(binding.CandidateDenied,'LEDGER_CHANGED'):
            with self.completed(row):
                self.f.f.write(self.f.f.root/action.name,binding.encoded({**row,'version':row['version']+1}))

    def test_completed_root_identity_constructs_real_credential_scope_without_effects(self):
        from credential_transaction import CredentialTransaction
        action=self.action();row=action.run();retirement=self.f.action()
        registration={'id':'11111111-1111-1111-1111-111111111111','clientId':'fixture-client',
            'enabled':True,'serviceAccountsEnabled':True,'publicClient':False,'protocol':'openid-connect',
            'clientAuthenticatorType':'client-secret','protocolMappers':[],'defaultClientScopes':['fixture-read']}
        with self.completed(row)as identities:
            selected=identities['ownerCredential']
            transaction=CredentialTransaction(retirement,retirement.authority,retirement.raw,registration,
                selected['path'],{key:selected[key]for key in ('device','inode')})
            self.assertEqual(transaction.scope['directoryIdentity'],{key:selected[key]for key in ('device','inode')})
            self.assertFalse((Path(selected['path'])/transaction.MEMBER).exists())
        self.assertFalse((self.f.f.root/transaction.name).exists())

if __name__=='__main__':unittest.main()
