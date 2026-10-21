"""Disposable root journals, four explicit provider steps and signed prefix import."""
import base64
import copy
import hashlib
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests'), str(ROOT / 'tools/semantic_policy_token_owner'),
    str(ROOT / 'tools/semantic_application_cutover'), str(ROOT / 'tools/semantic_cohort_admission/cohort-draft')]
spec = importlib.util.spec_from_file_location('ouf_stopped_snapshot', ROOT / 'scripts/read-ingestion-rollout-stopped-20261021.py')
snapshot = importlib.util.module_from_spec(spec); sys.modules[spec.name] = snapshot; spec.loader.exec_module(snapshot)
from tools.ingestion_rollout_preparation import continuation_common as common, oauth_budget_extension as budget, stage18_control as runtime
from tools.ingestion_rollout_execution import contract as c, private_file
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.governed_human_successor import stage18 as auth, operator, window
from tools.governed_human_successor.session import ExplicitFreshSession
from tools.chatbot_file_cohort import human_session as human
from tools.ingestion_rollout_execution.runner import Runner, Ports
import test_ingestion_continuation_inputs as input_fixture
import test_cutover_authority_native as crypto
from iam_owner_action import publish


def seal(path):
    ancestors = []
    for p in reversed(path.parents):
        s = p.stat(); ancestors.append({'path': str(p), 'identity': [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode]})
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'metadata': private_file.metadata(path.stat()), 'ancestors': ancestors}


class Fixture(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0: self.skipTest('actual root custody required; mandatory in CI')
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT', str(ROOT)))
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.previous = self.root / 'previous-human'; self.previous.mkdir(mode=0o700)
        self.context = self.root / 'previous-runtime'; self.context.mkdir(mode=0o700)
        if not Path('/proc/sys/kernel/random/boot_id').exists():
            self.assertNotEqual(os.environ.get('GITHUB_ACTIONS'), 'true', 'CI requires real boot evidence')
            for obj, name in ((window, 'boot_id'), (runtime, 'boot_id'), (human.HumanSession, '_boot')):
                self.addPatch(patch.object(obj, name, return_value='synthetic-local-boot'))
        self.now = int(time.time()); self.boot = window.boot_id()
        self.selection = {'issuer': 'https://fixture.invalid/realm', 'subject': 'fixture-human', 'tenant': 'fixture-tenant'}
        binding = {'sessionId': 'old-session', **self.selection, 'selectionHash': c.digest(self.selection),
            'clientId': human.CLIENT, 'scopes': list(human.SCOPES), 'sessionDirectory': str(self.previous),
            'tokenPath': str(self.previous / 'human-access.jwt'), 'createdAt': self.now - 14400,
            'expiresAt': self.now - 7200, 'retryProfile': {**copy.deepcopy(human.PROFILE), 'id': 'fixture-completed288', 'maximumAttempts': 288}}
        prior_review = {'maximumCumulativeOAuthAttempts': 288, 'priorOAuthAttempts': 284,
            'requestedScopes': binding['scopes'], 'budgetReset': False, 'automaticRenewalAllowed': False,
            'oldCredentialsReusable': False, 'freshIssuerAuthenticationRequired': True}
        old_human = {'schema': 'ouf.chatbot-human-session.private.v1', 'binding': binding, 'attempts': 288,
            'state': 'READY', 'budgetReset': False, 'bootId': self.boot, 'monotonicDeadline': time.monotonic() - 60,
            'lastObservedAt': self.now - 7200, 'accessExpiresAt': self.now - 7300,
            'governedWindowRenewal': {'review': prior_review, 'decision': {'reviewHash': c.digest(prior_review),
                'approvedAt': binding['createdAt'], 'expiresAt': binding['expiresAt']}},
            'accessToken': 'PRIVATE_OLD_ACCESS_NEVER_REUSE', 'refreshToken': 'PRIVATE_OLD_REFRESH_NEVER_REUSE'}
        Journal(self.previous).initialize(old_human); self.old_human_bytes = (self.previous / 'recovery.json').read_bytes()
        self.profile = {'schema': 'ouf.ingestion-rollout-existing-human-read-only.v1', 'selection': self.selection,
            'expectedBinding': binding, 'journal': seal(self.previous / 'recovery.json'),
            'minimumCumulativeAttempts': 288, 'maximumCumulativeAttempts': 288, 'expectedBootId': self.boot,
            'expectedMonotonicDeadline': old_human['monotonicDeadline'],
            'governedWindowReceiptHash': c.digest(old_human['governedWindowRenewal']),
            'readOnly': True, 'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False, 'budgetReset': False}
        native, packet, row, _, _ = input_fixture.fixture()
        native.update(executionContext=str(self.context), humanBinding=binding, humanReadProfile=self.profile,
            retainedOwnerHistory={'ownerPlanHash': '1'*64, 'completedResultHash': '2'*64,
                'minimumRetainedOAuthAttempts': 278, 'maximumCumulativeOAuthAttempts': 288,
                'completedOwnerActionReplayed': False, 'completedPublicationReplayed': False, 'retainedClaimsHash': '3'*64})
        self.old_review = {'executionReview': native}
        self.row = {'schema': 'ouf.ingestion-rollout-finite-journal.v1', **row, 'scopeHash': c.digest(c.scope(native)),
            'authorityHash': 'f'*64, 'bootId': self.boot, 'version': 2005, 'createdAt': self.now - 8000,
            'expiresAt': self.now - 60, 'expiresMonotonic': time.monotonic() - 60,
            'lastWall': self.now - 120, 'lastMonotonic': time.monotonic() - 120,
            'readAttempts': 18, 'stageReadAttempts': 0, 'readState': 'IDLE', 'nextReadAt': self.now - 120,
            'nextReadMonotonic': time.monotonic() - 120, 'budgetReset': False, 'incidentState': 'OPEN', 'acceptanceGranted': False,
            'nativeDirectEngineGets': 700, 'nativeDirectEnginePosts': 13, 'nativeOwnerGetAttempts': 120,
            'nativeGatewayGetAttempts': 200, 'nativeDatabaseReadSessions': 42, 'nativeUnknownFutureCounter': 23}
        for e in self.row['effects']: e['evidence'] = {'fixtureRetained': e['stage']}
        self.write(self.context / 'review.json', self.old_review); self.write(self.context / 'recovery.json', self.row)
        receipt = {'status': 'RETAINED_STAGE18_LIVE_INPUTS_MATCHED_NO_AUTHORITY', 'complete': True, 'readOnly': True,
            'predecessorJournalHash': c.digest(self.row), 'predecessorReviewHash': c.digest(self.old_review),
            'logicalOperationRef': native['logicalOperationRef'], 'priorOAuthAttempts': 288,
            'additionalOAuthBudgetGranted': False, 'oauthRequests': 0, 'runtimeEffectsDispatched': 0,
            'replacementGenerations': {name: self.row['effects'][next(i for i,s in enumerate(native['stages'])
                if s['name'] == name + '.START_REPLACEMENT')]['nativeResource'] for name in ('ingestion','gateway')}}
        bc = {'schema': 'ouf.technical-oauth-budget-extension-case.v1', 'purpose': 'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT',
            'journalHash': c.digest(self.row), 'reviewHash': c.digest(self.old_review), 'logicalOperationRef': native['logicalOperationRef'],
            'liveInputReceipt': receipt, 'maximumAdditionalOAuthAttempts': 4, 'proposedCumulativeCeiling': 292, 'grantIsRuntimeAuthority': False}
        self.observation = {'contextPath': str(self.context), 'journalHash': bc['journalHash'], 'reviewHash': bc['reviewHash'],
            'logicalOperationRef': bc['logicalOperationRef'], 'sameBoot': True, 'wallClockConsistent': True,
            'pendingStageClaim': False, 'nextStage': 18, 'recordedSecondsRemaining': 0, 'recordedMonotonicSecondsRemaining': 0}
        self.snapshot = {**vars(snapshot), 'inspect': lambda _: copy.deepcopy(self.observation)}
        granted = budget.grant(bc, self.snapshot, confirm=lambda p,h: True)
        self.case = {'schema': 'ouf.ingestion-rollout-stage18-successor-case.v1',
            'purpose': 'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT', 'budgetCase': bc, 'budgetReceipt': granted,
            'nativeDeclarationHash': '4'*64, 'runtimeControllerHash': '5'*64, 'commonHash': '6'*64,
            'authControllerHash': '7'*64, 'humanOperatorTransportProfile': dict(operator.TRANSPORT)}
        self.p = budget.proposal(bc, self.snapshot)
        # Synthetic fixture replaces only offline inspection/expensive retained
        # executable preflight; grant/profile/private custody are real.
        self.addPatch(patch.object(snapshot, 'inspect', self.snapshot['inspect']))
        self.addPatch(patch.object(runtime, 'preflight', return_value=(self.p,self.old_review,self.row)))
        clean = {k:v for k,v in os.environ.items() if k.lower() not in
            ('ssl_cert_file','ssl_cert_dir','https_proxy','http_proxy','all_proxy')}
        self.addPatch(patch.dict(os.environ, clean, clear=True))
        self.addPatch(patch.object(operator, 'terminal_notice'))
        self.closure = 'a'*64

    def addPatch(self, p): result=p.start(); self.addCleanup(p.stop); return result
    def write(self, p, value): p.write_bytes(c.encoded(value)); p.chmod(0o600)
    def open(self):
        with patch.object(operator, 'terminal_confirm', return_value=True):
            result=auth.execute('open-window',None,self.case,{},self.closure)
        self.control=result['controlPath']; return result
    def fresh(self):
        self.open(); config,binding=auth.load(self.control,self.case,self.closure)
        return ExplicitFreshSession(config['selection'],binding,config['review'],config['decision'])
    def token(self, **changes):
        claims={'iss':self.selection['issuer'],'sub':self.selection['subject'],'tenant_id':self.selection['tenant'],
            'ouf_actor_type':'HUMAN','azp':human.CLIENT,'acr':'fixture','aud':'ouf-api-gateway',
            'scope':' '.join(human.SCOPES),'exp':int(time.time())+1200,**changes}
        return 'fixture.'+base64.urlsafe_b64encode(c.encoded(claims)).decode().rstrip('=')+'.fixture'
    def provider_flow(self, token_changes=None):
        session=self.fresh(); issuer=self.selection['issuer']; replies=[
            (200,{'issuer':issuer,**{k:issuer+'/protocol/openid-connect/'+k for k in ('device_authorization_endpoint','token_endpoint','userinfo_endpoint')}},0),
            (200,{'verification_uri':issuer+'/device','user_code':'FIXTURE-CODE','device_code':'PRIVATE-DEVICE','expires_in':600,'interval':5},0)]
        http=Mock(side_effect=replies); session._http=http
        session.step(); session.step(); row=session.journal.read()
        session.journal.compare_and_save(row,{**row,'nextPollAt':time.time()-1})
        challenge=session.step()['challenge']; http.side_effect=[
            (200,{'access_token':self.token(**(token_changes or {})),'refresh_token':'PRIVATE-FRESH-REFRESH','token_type':'Bearer'},0),
            (200,{'sub':self.selection['subject']},0)]
        session.step({'challengeHash':c.digest(challenge),'confirmedAt':time.time()}); session.step()
        return session,http


class HumanFlow(Fixture):
    def test_prepare_reads_grant_without_window_or_requests(self):
        before=sorted(self.root.rglob('*'))
        with patch.object(operator,'terminal_confirm') as tty, patch.object(ExplicitFreshSession,'_http') as http:
            value=auth.execute('prepare',None,self.case,{},self.closure)
        self.assertTrue(value['complete']); self.assertEqual(value['attempts'],288)
        tty.assert_not_called();http.assert_not_called();self.assertEqual(before,sorted(self.root.rglob('*')))

    def test_one_new_window_starts_at288_and_never_copies_old_credentials(self):
        self.open();cfg,b=auth.load(self.control,self.case,self.closure); row=Journal(b['sessionDirectory']).read()
        self.assertEqual(row['attempts'],288);self.assertEqual(b['retryProfile']['maximumAttempts'],292)
        self.assertNotIn('accessToken',row);self.assertNotIn('refreshToken',row)
        self.assertEqual(self.old_human_bytes,(self.previous/'recovery.json').read_bytes())
        with patch.object(operator,'terminal_confirm') as tty, self.assertRaises(Exception): self.open()
        tty.assert_not_called()

    def test_full_four_request_provider_flow_and_current_read_only292_profile(self):
        session,http=self.provider_flow();row=session.journal.read()
        self.assertEqual(row['state'],'READY');self.assertEqual(row['attempts'],292);self.assertEqual(http.call_count,4)
        path=operator.publish_private_reader(self.control,session,row); profile=snapshot.decode(snapshot.private_read(path))
        read=auth.entry.authority.human_reader.open_existing(profile);self.assertEqual(read.current(),row['binding'])
        self.assertEqual(profile['minimumCumulativeAttempts'],292)
        self.assertEqual((self.previous/'recovery.json').read_bytes(),self.old_human_bytes)
        with self.assertRaises(Exception): read.refresh_if_due()

    def test_foreign_provider_principal_blocks_before_ready(self):
        with self.assertRaisesRegex(Exception, 'EXACT_CURRENT_HUMAN_CONTEXT_REQUIRED'): self.provider_flow({'sub':'FOREIGN'})
        cfg,b=auth.load(self.control,self.case,self.closure)
        self.assertEqual(Journal(b['sessionDirectory']).read()['state'],'BLOCKED')
        self.assertEqual(Journal(b['sessionDirectory']).read()['attempts'],291)
        self.assertFalse((Path(self.control)/'human-read-profile.json').exists())

    def test_denied_window_writes_nothing(self):
        before=sorted(self.root.rglob('*'))
        with patch.object(operator,'terminal_confirm',return_value=False),self.assertRaises(Exception):
            auth.execute('open-window',None,self.case,{},self.closure)
        self.assertEqual(before,sorted(self.root.rglob('*')))

    def test_partial_window_after_grant_claim_cannot_reopen(self):
        with patch.object(operator,'terminal_confirm',return_value=True),patch.object(operator,'write_new',side_effect=OSError('synthetic crash')):
            with self.assertRaises(OSError):auth.execute('open-window',None,self.case,{},self.closure)
        self.assertTrue((common.root(self.case)/'stage18-human-window.claim.json').exists())
        with patch.object(operator,'terminal_confirm')as tty,self.assertRaises(Exception):self.open()
        tty.assert_not_called()

    def test_changed_grant_or_old_journal_blocks_before_consent(self):
        old=self.case['budgetReceipt']['decisionHash'];self.case['budgetReceipt']['decisionHash']='f'*64
        with patch.object(operator,'terminal_confirm')as tty,self.assertRaises(Exception):self.open()
        tty.assert_not_called();self.case['budgetReceipt']['decisionHash']=old
        self.write(self.context/'recovery.json',{**self.row,'readAttempts':0})
        with patch.object(operator,'terminal_confirm')as tty,self.assertRaises(Exception):self.open()
        tty.assert_not_called()

    def test_two_processes_cannot_open_two_windows(self):
        ctx=multiprocessing.get_context('fork');barrier=ctx.Barrier(2);queue=ctx.Queue()
        def worker():
            def consent(*_):barrier.wait(timeout=5);return True
            try:
                with patch.object(operator,'terminal_confirm',side_effect=consent):auth.open_window(self.case,self.closure)
                queue.put('opened')
            except Exception:queue.put('blocked')
        ps=[ctx.Process(target=worker)for _ in range(2)]
        for p in ps:p.start()
        for p in ps:p.join(10);self.assertFalse(p.is_alive())
        self.assertEqual(sorted(queue.get(timeout=2)for _ in ps),['blocked','opened'])

    def test_pending_poll_consumes_291_and_userinfo_reserve_prevents_another_poll(self):
        session=self.fresh(); issuer=self.selection['issuer']
        http=Mock(side_effect=[(200,{'issuer':issuer,**{k:issuer+'/protocol/openid-connect/'+k for k in
            ('device_authorization_endpoint','token_endpoint','userinfo_endpoint')}},0),
            (200,{'verification_uri':issuer+'/device','user_code':'FIXTURE','device_code':'PRIVATE','expires_in':600,'interval':5},0)])
        session._http=http;session.step();session.step();row=session.journal.read()
        session.journal.compare_and_save(row,{**row,'nextPollAt':time.time()-1})
        challenge=session.step()['challenge'];http.side_effect=[(400,{'error':'authorization_pending'},0)]
        session.step({'challengeHash':c.digest(challenge),'confirmedAt':time.time()})
        self.assertEqual(session.journal.read()['attempts'],291);self.assertEqual(http.call_count,3)
        row=session.journal.read();session.journal.compare_and_save(row,{**row,'nextPollAt':time.time()-1})
        challenge=session.step()['challenge']
        with self.assertRaisesRegex(Exception,'VERIFICATION_BUDGET_RESERVED'):
            session.step({'challengeHash':c.digest(challenge),'confirmedAt':time.time()})
        self.assertEqual(http.call_count,3)

    def test_lost_device_response_keeps_consumed_attempt_and_blocks_replay(self):
        session=self.fresh();issuer=self.selection['issuer'];session._http=Mock(return_value=(200,
            {'issuer':issuer,**{k:issuer+'/protocol/openid-connect/'+k for k in
                ('device_authorization_endpoint','token_endpoint','userinfo_endpoint')}},0))
        session.step();session._http.side_effect=OSError('synthetic lost reply')
        with self.assertRaises(Exception):session.step()
        self.assertEqual(session.journal.read()['attempts'],290)
        calls=session._http.call_count
        with self.assertRaises(Exception):session.step()
        self.assertEqual(session._http.call_count,calls)


class Prefix(Fixture):
    def new_review(self):
        profile=copy.deepcopy(self.profile); b=profile['expectedBinding']
        b.update(sessionId='new',sessionDirectory=str(self.root/'new-human'),tokenPath=str(self.root/'new-human/human-access.jwt'),
            createdAt=self.now,expiresAt=self.now+7200)
        b['retryProfile'].update(maximumAttempts=292,id='fixture-292')
        profile.update(minimumCumulativeAttempts=292,maximumCumulativeAttempts=292)
        return common.successor_native(self.case,self.p,self.old_review,self.row,profile)

    def test_pure_review_preserves_all_intents_and_old_history(self):
        original=copy.deepcopy(self.old_review);new=self.new_review()
        self.assertEqual(new['stages'],original['executionReview']['stages'])
        self.assertEqual(new['logicalOperationRef'],original['executionReview']['logicalOperationRef'])
        self.assertEqual(new['predecessorRetainedOwnerHistory'],original['executionReview']['retainedOwnerHistory'])
        self.assertEqual(new['retainedOwnerHistory']['maximumCumulativeOAuthAttempts'],292)
        self.assertEqual(self.old_review,original)

    def test_import_preserves_every_resource_counter_and_original_created_at(self):
        following=common.imported_record(self.case,self.p,self.row,'a'*64,'b'*64,self.now+800,
            wall=self.now,mono=time.monotonic(),boot=self.boot)
        for k in self.row:
            if k not in ('scopeHash','authorityHash','version','expiresAt','expiresMonotonic','lastWall','lastMonotonic','nextReadAt','nextReadMonotonic'):
                self.assertEqual(following[k],self.row[k],k)
        self.assertEqual(following['nextStage'],18);self.assertEqual(following['readAttempts'],18)
        self.assertEqual(following['version'],2006)
        common.verify_imported_prefix(self.case,self.p,self.row,following)
        for k,v in [('readAttempts',0),('nativeUnknownFutureCounter',0),('createdAt',self.now),('nextStage',0)]:
            bad=copy.deepcopy(following);bad[k]=v
            with self.assertRaises(ValueError):common.verify_imported_prefix(self.case,self.p,self.row,bad)
        bad=copy.deepcopy(following);bad['effects'][1]['nativeResource']={'foreign':True}
        with self.assertRaises(ValueError):common.verify_imported_prefix(self.case,self.p,self.row,bad)

    def test_new_native_review_validates_against_original_full_native_contract(self):
        import test_ingestion_rollout_native_review as fixture
        f=fixture.NativeReview();f.setUp();self.addCleanup(f.doCleanups)
        native=f.compile();native.update(humanBinding=self.profile['expectedBinding'],humanReadProfile=self.profile)
        old={'executionReview':native};session,_=self.provider_flow()
        path=operator.publish_private_reader(self.control,session,session.journal.read())
        new_profile=snapshot.decode(snapshot.private_read(path))
        new=common.successor_native(self.case,self.p,old,self.row,new_profile)
        fixture.n.validate_review(new,f.packet)
        self.assertEqual(new['stages'],native['stages'])
        self.assertEqual(native['retainedOwnerHistory']['maximumCumulativeOAuthAttempts'],288)

    def test_live_parent_boot_or_authority_window_drift_blocks_import(self):
        for boot,wall,mono,expiry in [('other',self.now,time.monotonic(),self.now+800),
            (self.boot,self.now,time.monotonic(),self.now+901),(self.boot,self.now,time.monotonic(),self.now-1),
            (self.boot,self.now-9000,time.monotonic(),self.now+800)]:
            with self.assertRaises(ValueError):common.imported_record(self.case,self.p,self.row,'a'*64,'b'*64,expiry,wall=wall,mono=mono,boot=boot)

    def test_original_selection_and_no_lowered_counter_are_mandatory(self):
        new=self.new_review()
        for key,value in [('minimumCumulativeAttempts',288),('maximumCumulativeAttempts',296)]:
            profile=copy.deepcopy(new['humanReadProfile']);profile[key]=value
            with self.assertRaises(ValueError):common.successor_native(self.case,self.p,self.old_review,self.row,profile)
        profile=copy.deepcopy(new['humanReadProfile']);profile['expectedBinding']['subject']='foreign'
        with self.assertRaises(ValueError):common.successor_native(self.case,self.p,self.old_review,self.row,profile)

    def signed(self):
        q=crypto.SignedCutover()
        with patch.object(crypto,'ROOT',self.root):q.setUp()
        self.addCleanup(q.doCleanups)
        new=self.new_review(); scope=c.scope(new)
        value=json.loads(q.authority);value[c.AUTHORITY_KEY]=scope;value['expiresAt']=q.now+480
        q.authority=c.encoded(value);q.approval.update(expiresAt=q.now+540,executionAuthorityHash=c.digest(value))
        q.write(q.mandate,c.encoded(q.approval));q.approved=crypto.sha(q.mandate.read_bytes())
        for role in q.grant['roles']:q.sign(role)
        action=AggregateAction(q.gate(),q.authority,q.expected['sourceClosureHash'])
        target=common.context(self.case);target.mkdir(mode=0o700);ctl=target/'operator-control';ctl.mkdir(mode=0o700)
        journal=Journal(ctl);journal.initialize({'state':'ISSUED'})
        review={'executionReview':new,'authenticatedHuman':new['humanBinding']}
        loaded=(target,journal,journal.read(),review,types.SimpleNamespace(current=lambda:new['humanBinding']),self.p,self.row)
        entry=types.SimpleNamespace(c=c,Journal=Journal,authority=types.SimpleNamespace(protected_directory=protected_directory,publish=publish))
        return q,new,action,loaded,entry

    def test_actual_dual_signed_import_then_only_residual_stages_can_apply(self):
        q,new,action,loaded,entry=self.signed()
        result=runtime.import_prefix(entry,self.case,self.snapshot,vars(budget),common,loaded,action)
        self.assertEqual(result['nextStage'],18);self.assertEqual(result['runtimeEffectsDispatched'],0)
        class FixturePorts(Ports):
            def __init__(self):self.effects=[]
            def boot(self):return self_boot
            def guard_current(self,stage):action.guard(c.AUTHORITY_KEY,c.scope(new))
            def apply(self,stage):self.effects.append(stage['name'])
            def observe(self,stage):return 'APPLIED',{'fixtureObserved':stage['name']}
        self_boot=self.boot;ports=FixturePorts();runner=Runner(action,Journal(loaded[0]),new,ports)
        for _ in range(10):runner.step()
        self.assertTrue(runner.step()['complete'])
        self.assertEqual(ports.effects,[s['name']for s in new['stages'][18:]if s['kind']=='EFFECT'])
        final=runner.record();self.assertEqual(final['effects'][:18],self.row['effects'])
        self.assertEqual(final['readAttempts'],28);self.assertEqual(final['nativeUnknownFutureCounter'],23)
        with self.assertRaises(Exception):runtime.import_prefix(entry,self.case,self.snapshot,vars(budget),common,loaded,action)

    def test_partial_import_before_or_after_journal_keeps_fence(self):
        q,new,action,loaded,entry=self.signed()
        def crash(phase):raise RuntimeError('synthetic import interruption')
        with self.assertRaises(RuntimeError):runtime.import_prefix(entry,self.case,self.snapshot,vars(budget),common,loaded,action,fault=crash)
        self.assertFalse((loaded[0]/'recovery.json').exists())
        with self.assertRaises(Exception):runtime.import_prefix(entry,self.case,self.snapshot,vars(budget),common,loaded,action)

    def test_partial_import_after_complete_journal_preserves_prefix_but_cannot_reimport(self):
        q,new,action,loaded,entry=self.signed()
        def crash(phase):
            if phase=='AFTER_IMPORTED_JOURNAL':raise RuntimeError('synthetic crash after durable prefix')
        with self.assertRaises(RuntimeError):runtime.import_prefix(entry,self.case,self.snapshot,vars(budget),common,loaded,action,fault=crash)
        row=Journal(loaded[0]).read();self.assertEqual(row['effects'],self.row['effects'])
        self.assertEqual(row['readAttempts'],18)
        with self.assertRaises(Exception):runtime.import_prefix(entry,self.case,self.snapshot,vars(budget),common,loaded,action)

    def test_expired_signed_authority_blocks_before_import_fence(self):
        q,new,action,loaded,entry=self.signed();q.now+=481
        with self.assertRaises(Exception):runtime.import_prefix(entry,self.case,self.snapshot,vars(budget),common,loaded,action)
        self.assertFalse(list(self.root.glob('ingestion-rollout-continuation-*.claim.json')))

    def test_two_signed_import_processes_share_one_global_fence(self):
        q,new,action,loaded,entry=self.signed();ctx=multiprocessing.get_context('fork');queue=ctx.Queue()
        def worker():
            try:runtime.import_prefix(entry,self.case,self.snapshot,vars(budget),common,loaded,action);queue.put('imported')
            except Exception:queue.put('blocked')
        ps=[ctx.Process(target=worker)for _ in range(2)]
        for p in ps:p.start()
        for p in ps:p.join(10);self.assertFalse(p.is_alive())
        self.assertEqual(sorted(queue.get(timeout=2)for _ in ps),['blocked','imported'])

    def test_revoked_signature_blocks_before_import_claim(self):
        q,new,action,loaded,entry=self.signed()
        value=json.loads(q.policy.read_bytes());value['keys'][0]['state']='REVOKED';q.write(q.policy,c.encoded(value))
        with self.assertRaises(Exception):runtime.import_prefix(entry,self.case,self.snapshot,vars(budget),common,loaded,action)
        self.assertFalse(list(self.root.glob('ingestion-rollout-continuation-*.claim.json')))


if __name__=='__main__':unittest.main()
