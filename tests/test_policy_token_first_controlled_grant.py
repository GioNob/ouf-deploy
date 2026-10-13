"""Actual TLS, role crypto and persistence; synthetic issuer and HUMAN only."""
import json
import os
from pathlib import Path
import sys
import time
import subprocess
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tests')]
import test_policy_token_credential_transaction as fixtures
import tools
tools.__path__.append(str(ROOT/'tools'))
from test_iam_token_admission import Fixture
import first_controlled_grant as grant
import accounting_gap_session as sessions
import legacy_retirement as legacy
binding=grant.evidence

class FirstGrantTest(unittest.TestCase):
    def setUp(self):
        self.c=fixtures.CredentialTransactionTest();self.c.setUp();self.addCleanup(self.c.doCleanups)
        self.f=self.c.f.f;self.root=self.f.root
        with patch.object(fixtures.transaction.SecretAdmin,'call',side_effect=self.c.admin):self.c.make().run()
        self.server=Fixture(self.root);self.addCleanup(self.server.close)
        self.output=self.root/'output';self.output.mkdir(mode=0o750);os.chown(self.output,0,10001)
        info=self.output.stat();self.output_identity={'device':info.st_dev,'inode':info.st_ino}
        self.clock=lambda:(time.time(),time.monotonic())
        self.transport=grant.PinnedIamOpener(self.server.profile,self.clock,self.server.context())
        self.binding=grant.Binding(self.server.profile.token_endpoint,'fixture-client','authorization.bundle.read',str(self.output),'token.jwt',10001)
        raw=binding.encoded({'schema':'ouf.policy-token-accounting-source-observation.v1','auditConfiguration':{'eventsEnabled':False},
            'historicalGrantAttemptCount':None,'historicalAccountingReconciled':False});gap=binding.sha(raw)
        self.f.write(self.root/('policy-token-owner-accounting-observation-'+gap+'.private.json'),raw)
        p=patch.object(sessions,'GAP_HASH',gap);p.start();self.addCleanup(p.stop)
        p=patch.object(sessions,'boot_identity',return_value='11111111-1111-1111-1111-111111111111');p.start();self.addCleanup(p.stop)
        provisional=self.make()
        a=json.loads(self.f.authority);a['policyTokenAccountingGapMigration']=provisional.session.scope;a['policyTokenFirstControlledGrant']=provisional.scope
        self.f.authority=binding.encoded(a);self.f.approval['executionAuthorityHash']=binding.sha(self.f.authority)
        self.f.write(self.f.mandate,binding.encoded(self.f.approval));self.f.approved=binding.sha(self.f.mandate.read_bytes())
        for role in self.f.grant['roles']:self.f.sign(role)
    def make(self):
        authority=self.f.gate();retirement=legacy.LegacyRetirement(authority,self.f.authority,self.c.f.raw)
        credential=fixtures.transaction.CredentialTransaction(retirement,authority,self.f.authority,self.c.registration,str(self.c.destination),self.c.identity)
        session=sessions.FirstGapSession(authority,self.f.authority,'f'*64,self.f.expected['sourceClosureHash'],self.f.clock)
        return grant.FirstControlledGrant(session,credential,self.binding,self.server.profile,self.transport,self.output_identity,self.clock)
    def test_single_grant_actual_online_admission_publication_and_restart_no_replay(self):
        row=self.make().run();self.assertEqual(row['attemptSlotsConsumed'],1)
        self.assertIsNone(row['legacyHistoricalGrantAttempts']);self.assertTrue(row['gapRemainsOpen'])
        self.assertFalse(row['runtimeAuthorityIssued']);self.assertEqual((self.output/'token.jwt').read_text(),'FIXTURE_TOKEN')
        self.assertEqual(sum(p.endswith('/token')for p,_ in self.server.calls),1)
        before=len(self.server.calls)
        with self.assertRaisesRegex(binding.CandidateDenied,'CONSUMED_NO_REPLAY'):self.make().run()
        self.assertEqual(len(self.server.calls),before)
    def test_inactive_token_after_grant_prevents_publication_and_consumes_slot(self):
        original=self.server.active;self.server.active=lambda:{**original(),'active':False}
        with self.assertRaises(Exception):self.make().run()
        self.assertFalse((self.output/'token.jwt').exists())
        self.assertEqual(sum(p.endswith('/token')for p,_ in self.server.calls),1)
        with self.assertRaisesRegex(binding.CandidateDenied,'CONSUMED_NO_REPLAY'):self.make().run()
    def test_revocation_during_grant_prevents_introspection_and_publication(self):
        def revoke():
            if self.server.calls[-1][0].endswith('/token'):
                self.f.approval['state']='REVOKED';self.f.write(self.f.mandate,binding.encoded(self.f.approval))
        self.server.after=revoke;operation=self.make()
        with self.assertRaises(Exception):operation.run()
        self.assertFalse((self.output/'token.jwt').exists())
        self.assertEqual(sum(p.endswith('/token')for p,_ in self.server.calls),1)
        self.assertEqual(sum(p.endswith('/introspect')for p,_ in self.server.calls),0)
        row=json.loads((self.root/operation.session.name).read_bytes());self.assertEqual(row['attemptSlotsConsumed'],1)
    def test_existing_output_denied_without_grant_or_consumption(self):
        target=self.output/'token.jwt';target.write_text('PREEXISTING');target.chmod(0o440);os.chown(target,0,10001)
        operation=self.make()
        with self.assertRaisesRegex(binding.CandidateDenied,'MUST_BE_EMPTY'):operation.run()
        self.assertEqual(self.server.calls,[])
        self.assertEqual(json.loads((self.root/operation.session.name).read_bytes())['attemptSlotsConsumed'],0)
    def test_composed_retirement_credential_and_grant_once_without_new_journal(self):
        operation=self.make();transaction=operation.transaction;retirement=transaction.retirement
        self.c.retirement=retirement;self.c.gate=transaction.authority
        (self.root/transaction.name).unlink();(self.c.destination/'client-secret').unlink()
        (self.root/retirement.name).unlink();self.c.calls.clear()
        state=dict(self.c.f.before);commands=[]
        def command(argv,**kwargs):
            commands.append(argv);state.clear();state.update(self.c.f.after)
            return subprocess.CompletedProcess(argv,0)
        with patch.object(legacy,'read_units',side_effect=lambda:dict(state)),patch.object(legacy.subprocess,'run',side_effect=command),\
            patch.object(fixtures.transaction.SecretAdmin,'call',side_effect=self.c.admin):
            receipt=operation.migrate()
            self.assertEqual(receipt['state'],'TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED')
            self.assertEqual(len(commands),1);self.assertEqual(self.c.calls.count(('create','/client-secret')),1)
            before=(len(commands),len(self.c.calls),len(self.server.calls))
            with self.assertRaisesRegex(binding.CandidateDenied,'CONSUMED_NO_REPLAY'):self.make().migrate()
            self.assertEqual(before,(len(commands),len(self.c.calls),len(self.server.calls)))
    def test_composed_ambiguous_credential_stops_before_service_or_issuer(self):
        operation=self.make();path=self.root/operation.transaction.name
        row=json.loads(path.read_bytes());row.update(state='ROTATION_RESERVED_OUTCOME_UNPROVEN',credentialPublished=False)
        self.f.write(path,binding.encoded(row))
        with patch.object(legacy,'read_units',side_effect=AssertionError('no service reads')),\
            patch.object(fixtures.transaction.SecretAdmin,'call',side_effect=AssertionError('no IAM calls')):
            with self.assertRaisesRegex(binding.CandidateDenied,'CREDENTIAL_RECONCILIATION')as caught:operation.migrate()
        self.assertEqual(caught.exception.safe_diagnostics['phase'],'MIGRATION_SCOPE_PREFLIGHT')
        self.assertEqual(self.server.calls,[])
    def test_composed_successful_credential_resumes_without_regeneration(self):
        operation=self.make();retirement=operation.transaction.retirement
        self.f.write(self.root/retirement.name,binding.encoded({'schema':'ouf.policy-token-legacy-retirement.v1',
            'operation':retirement.operation,'scope':retirement.scope,'commandAttemptConsumed':True,
            'state':'QUIESCENCE_OBSERVED','version':1}))
        with patch.object(fixtures.transaction.SecretAdmin,'call',side_effect=AssertionError('no IAM replay')):
            receipt=operation.migrate()
        self.assertEqual(receipt['attemptSlotsConsumed'],1)
        self.assertEqual(sum(p.endswith('/token')for p,_ in self.server.calls),1)

if __name__=='__main__':unittest.main()
