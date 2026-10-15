"""Native signatures/persistence with simulated systemctl; no VPS effects."""
import json
from pathlib import Path
import subprocess
import sys
import unittest
import types
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tests')]
import test_cutover_authority_native as fixtures
import legacy_retirement as retirement
binding=retirement.binding

class RetirementTest(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.SignedCutover();self.f.setUp();self.addCleanup(self.f.doCleanups)
        p=patch.object(retirement,'subprocess',types.SimpleNamespace(run=subprocess.run,DEVNULL=subprocess.DEVNULL));p.start();self.addCleanup(p.stop)
        self.before={u:{'Id':u,'LoadState':'loaded','ActiveState':'active' if u.endswith('.timer')else 'inactive',
            'SubState':'waiting' if u.endswith('.timer')else 'dead','Job':'',
            'UnitFileState':'enabled' if u.endswith('.timer')else 'static','MainPID':'0'}for u in retirement.UNITS}
        self.after={u:{**r,'LoadState':'masked','ActiveState':'inactive','SubState':'dead','UnitFileState':'masked'}for u,r in self.before.items()}
        self.host={'schema':'ouf.policy-token-migration-host-inputs.v1','logicalOwnerScopeHash':'f'*64,
            'legacyHistory':{'state':'UNKNOWN','cumulativeGrantAttemptCount':None,'reconciled':False,'gapRemainsOpen':True},
            'runtimeAuthorityIssued':False,'legacyUnitsMetadata':list(self.before.values()),'kernelBootId':'fixture-boot',
            'executables':{'systemctl':{'path':'/fixture/systemctl','sha256':'a'*64}}}
        self.raw=binding.encoded(self.host);digest=binding.sha(self.raw)
        self.f.write(self.f.root/('policy-token-migration-host-inputs-'+digest+'.private.json'),self.raw)
        for p in (patch.object(binding,'PARENT',self.f.root),patch.object(retirement,'HOST_HASH',digest),
            patch.object(retirement,'boot_identity',return_value='fixture-boot'),
            patch.object(retirement.governance,'executable',return_value=self.host['executables']['systemctl'])):
            p.start();self.addCleanup(p.stop)
        obj=self.action();self.scope=obj.scope;self.sign()
    def action(self):return retirement.LegacyRetirement(self.f.gate(),self.f.authority,self.raw)
    def sign(self,alter=None):
        a=json.loads(self.f.authority);a['policyTokenLegacyRetirement']=self.scope
        if alter:alter(a)
        self.f.authority=binding.encoded(a);self.f.approval['executionAuthorityHash']=binding.sha(self.f.authority)
        self.f.write(self.f.mandate,binding.encoded(self.f.approval));self.f.approved=binding.sha(self.f.mandate.read_bytes())
        for role in self.f.grant['roles']:self.f.sign(role)
    def test_reservation_precedes_effect_and_restart_only_reads(self):
        a=self.action()
        def command(argv,**kw):
            row=json.loads((self.f.root/a.name).read_bytes())
            self.assertTrue(row['commandAttemptConsumed']);self.assertEqual(row['state'],'COMMAND_RESERVED_OUTCOME_UNPROVEN')
            self.assertEqual(argv,['/usr/bin/systemctl','mask','--now',*retirement.UNITS])
            return subprocess.CompletedProcess(argv,0)
        with patch.object(retirement,'read_units',side_effect=[self.before,self.after]),patch.object(retirement.subprocess,'run',side_effect=command)as run:
            self.assertEqual(a.run()['state'],'QUIESCENCE_OBSERVED');self.assertEqual(run.call_count,1)
        with patch.object(retirement,'read_units',return_value=self.after),patch.object(retirement.subprocess,'run')as run:
            self.assertEqual(self.action().run()['state'],'QUIESCENCE_OBSERVED');run.assert_not_called()
    def test_timeout_and_new_approval_never_replay_but_masked_state_can_reconcile(self):
        with patch.object(retirement,'read_units',return_value=self.before),patch.object(retirement.subprocess,'run',side_effect=subprocess.TimeoutExpired('fixture',20)):
            with self.assertRaises(subprocess.TimeoutExpired):self.action().run()
        self.f.approval['approvalRef']='SECOND_SYNTHETIC_DECISION';self.sign()
        with patch.object(retirement,'read_units',return_value=self.before),patch.object(retirement.subprocess,'run')as run:
            with self.assertRaisesRegex(binding.CandidateDenied,'NO_COMMAND_REPLAY'):self.action().run()
            run.assert_not_called()
        with patch.object(retirement,'read_units',return_value=self.after),patch.object(retirement.subprocess,'run')as run:
            self.assertEqual(self.action().run()['state'],'QUIESCENCE_OBSERVED');run.assert_not_called()
    def test_design_approval_missing_scope_and_revoked_human_cannot_mutate(self):
        self.sign(lambda a:a.pop('policyTokenLegacyRetirement'))
        with patch.object(retirement.subprocess,'run')as run:
            with self.assertRaisesRegex(binding.CandidateDenied,'SIGNED_LEGACY'):self.action().run()
            run.assert_not_called()
        self.sign();self.f.approval['state']='REVOKED';self.f.write(self.f.mandate,binding.encoded(self.f.approval))
        with patch.object(retirement.subprocess,'run')as run:
            with self.assertRaises(Exception):self.action().run()
            run.assert_not_called()
    def test_baseline_drift_and_partial_mask_fail_closed(self):
        partial={u:dict(r)for u,r in self.before.items()};partial[retirement.UNITS[0]]=self.after[retirement.UNITS[0]]
        self.assertFalse(retirement.quiescent(partial))
        with patch.object(retirement,'read_units',return_value=partial),patch.object(retirement.subprocess,'run')as run:
            with self.assertRaisesRegex(binding.CandidateDenied,'BASELINE_CHANGED'):self.action().run()
            run.assert_not_called()
        self.assertFalse((self.f.root/self.action().name).exists())
    def test_revocation_after_command_keeps_reservation_and_no_success(self):
        action=self.action()
        def command(*args,**kw):
            self.f.approval['state']='REVOKED';self.f.write(self.f.mandate,binding.encoded(self.f.approval))
            return subprocess.CompletedProcess(args,0)
        with patch.object(retirement,'read_units',side_effect=[self.before,self.after]),patch.object(retirement.subprocess,'run',side_effect=command):
            with self.assertRaises(Exception):action.run()
        row=json.loads((self.f.root/action.name).read_bytes())
        self.assertTrue(row['commandAttemptConsumed']);self.assertEqual(row['state'],'COMMAND_RESERVED_OUTCOME_UNPROVEN')
    def test_process_crash_after_reservation_does_not_replay(self):
        import os
        child=os.fork()
        if child==0:
            with patch.object(retirement,'read_units',return_value=self.before),patch.object(retirement.subprocess,'run',side_effect=lambda *a,**k:os._exit(0)):
                try:self.action().run()
                except Exception:os._exit(91)
            os._exit(92)
        _,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),0)
        with patch.object(retirement,'read_units',return_value=self.before),patch.object(retirement.subprocess,'run')as run:
            with self.assertRaisesRegex(binding.CandidateDenied,'NO_COMMAND_REPLAY'):self.action().run()
            run.assert_not_called()
    def test_metadata_reader_rejects_duplicate_units(self):
        def command(argv,**kw):
            self.assertEqual(argv[1],'show')
            row='Id='+retirement.UNITS[0]+'\nLoadState=masked\nActiveState=inactive\nSubState=dead\nJob=\nUnitFileState=masked\n'
            kw['stdout'].write((row+'\n'+row).encode())
            return subprocess.CompletedProcess(argv,0)
        with patch.object(retirement.subprocess,'run',side_effect=command):
            with self.assertRaisesRegex(binding.CandidateDenied,'EXACT_LEGACY_UNITS'):retirement.read_units()
    def test_parallel_invocation_and_boot_change_deny(self):
        import fcntl,os
        a=self.action();fd=os.open(self.f.root/(a.name+'.lock'),os.O_CREAT|os.O_RDWR,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):a.run()
        finally:os.close(fd)
        with patch.object(retirement,'boot_identity',return_value='different-boot'):
            with self.assertRaisesRegex(binding.CandidateDenied,'BOOT_CHANGED'):self.action().run()

if __name__=='__main__':unittest.main()

