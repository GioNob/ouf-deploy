"""Synthetic owner/IAM/approval fixtures only; main/public endpoints never run."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import urllib.error
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('descriptor_publication', ROOT/'scripts/publish-managed-profile-descriptor-20261028.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class Reply:
    def __init__(self, url, status, value, headers=None):
        self.url, self.code = url, status
        self.raw = json.dumps(value).encode() if value is not None else b''
        self.headers = headers or {}
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def geturl(self): return self.url
    def read(self, maximum): return self.raw[:maximum]


class SyntheticOwner:
    def __init__(self):
        run = m.registration(m.EXISTING[0])['descriptor']
        self.current = {'policyRef': m.BASE_REF, 'contentHash': m.BASE_HASH, 'activatedAt': '2026-10-25T05:00:00Z',
                        'policy': {'bundleId': 'ouf-lab-authorization', 'version': 56, 'publishedAt': '2026-10-25T05:00:00Z',
                                   'capabilities': [m.registration(m.EXISTING[1])['descriptor'],run, {'capabilityId':'unrelated.service.read', 'operation':'READ', 'requiredScope':'unrelated.service.read', 'allowedActors':['SERVICE']}],
                                   'grants': [
                                       {'grantId':'ouf-role:retained', 'capabilityId':'ingestion.run.read', 'tenantId':'ouf-lab', 'subjectId':'retained', 'validFrom':'2020-01-01T00:00:00Z', 'validUntil':'2036-01-01T00:00:00Z', 'constraints':{'effect':'ALLOW','resourceAttributes':{'sourceRef':'PRIVATE_GRANT_CANARY'}}},
                                       {'grantId':'other-tenant-deny', 'capabilityId':'unrelated.service.read', 'tenantId':'other', 'servicePrincipalId':'retained-service', 'validFrom':'2020-01-01T00:00:00Z', 'validUntil':'2021-01-01T00:00:00Z', 'constraints':{'effect':'DENY','allowedDataLabels':['SENSITIVE']}}]}}
        self.catalogue = {cap:m.registration(cap) for cap in m.EXISTING}
        self.catalogue['unrelated.service.read'] = {'ownerRef':'other','descriptor':self.current['policy']['capabilities'][-1]}
        self.calls, self.draft = [], None
        self.before = lambda *_: None
        self.after = lambda *_: None
        self.preview_change = lambda value: value
        self.grants_at_publish = None

    def open(self, request, **kwargs):
        path = request.full_url.removeprefix(m.ADMIN)
        method = request.get_method()
        body = json.loads(request.data) if request.data is not None else None
        self.calls.append((method, path, copy.deepcopy(body)))
        self.before(method, path, body)
        assert request.get_header('Authorization') == 'Bearer SYNTHETIC_TOKEN_CANARY'
        status, headers, value = 200, {}, None
        if method == 'GET' and path == '/policies/active':
            value = self.current
        elif method == 'GET' and path.startswith('/capabilities?'):
            value = [{'capability_id':cap, 'owner_ref':row['ownerRef'], 'descriptor':row['descriptor']} for cap,row in self.catalogue.items()]
        elif method == 'POST' and path == '/capabilities':
            self.catalogue[body['descriptor']['capabilityId']] = copy.deepcopy(body)
            status = 201
        elif method == 'POST' and path == '/policies':
            self.draft = {'id':str(uuid.uuid4()), 'revision':0, 'state':'DRAFT', 'baseActiveRef':m.BASE_REF, 'policy':copy.deepcopy(body)}
            value, headers = self.draft, {'ETag':'"0"'}
        elif method == 'GET' and self.draft and path == '/policies/'+self.draft['id']:
            value = self.draft
        elif method == 'POST' and path.endswith(':preview'):
            assert request.get_header('If-match') == '"0"'
            value = {'draftId':self.draft['id'], 'revision':0, 'baseActiveRef':m.BASE_REF, 'activeHash':'sha256:'+m.BASE_HASH,
                     'draftHash':'sha256:'+m.digest(self.draft['policy']), 'addedCapabilities':[m.registration(cap)['descriptor'] for cap in m.MISSING],
                     'removedCapabilities':[], 'grantChanges':[], 'authoritative':False}
            value = self.preview_change(value)
        elif method == 'POST' and path.endswith(':publish'):
            assert request.get_header('If-match') == '"0"'
            self.draft.update(state='PUBLISHED', revision=1)
            policy = copy.deepcopy(self.draft['policy'])
            policy['publishedAt'] = '2026-10-25T19:00:00Z'  # server publication time differs from the preview
            if self.grants_at_publish is not None: policy['grants'] = self.grants_at_publish
            self.current = {'policyRef':'ouf-lab-authorization:57', 'contentHash':'sha256:'+m.digest(policy), 'policy':policy}
            value, headers = self.draft, {'ETag':'"1"'}
        else:
            raise AssertionError('unexpected native API request')
        self.after(method, path, body)
        return Reply(request.full_url, status, copy.deepcopy(value), headers)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.context = m.Journal(Path(self.tmp.name)/'fixed-operation')
        self.owner = SyntheticOwner()
        self.old_response = m.BASE_RESPONSE
        self.old_catalogue = m.BASE_CATALOGUE
        m.BASE_CATALOGUE = m.digest(self.owner.catalogue)
        m.BASE_RESPONSE = m.digest(self.owner.current)
        self.t = m.Transport('SYNTHETIC_TOKEN_CANARY', self.context)
        self.t.opener = self.owner
        self.plan = m.prepare(copy.deepcopy(self.owner.current), self.owner.catalogue, time.time()+800)
    def tearDown(self):
        m.BASE_RESPONSE = self.old_response
        m.BASE_CATALOGUE = self.old_catalogue
        self.tmp.cleanup()
    def synthetic_tty_approval(self, suffix=''):
        master, slave = os.openpty()
        emitted = []
        try:
            os.write(master, ('APPROVO '+m.digest(self.plan)+suffix+'\n').encode())
            m.approve(self.plan, self.context, self.t, fd=slave, emit=emitted.append)
        finally:
            os.close(master)
            os.close(slave)
        return emitted
    def execute(self):
        return m.execute(self.plan, copy.deepcopy(self.owner.catalogue), self.context, self.t)

    def test_exact_real_pty_parser_then_full_additive_native_api_sequence(self):
        before = copy.deepcopy(self.owner.current['policy'])
        prompts = self.synthetic_tty_approval()
        self.assertIn('APPROVO '+m.digest(self.plan), prompts)
        result = self.execute()
        self.assertEqual(result['status'], 'MANAGED_PROFILE_DESCRIPTOR_PUBLISHED_GRANTS_UNCHANGED')
        self.assertEqual(self.owner.current['policy']['grants'], before['grants'])
        self.assertEqual(self.owner.current['policy']['capabilities'][:len(before['capabilities'])], before['capabilities'])
        self.assertEqual(self.t.counts['administrativeWrites'], 3)
        self.assertEqual(self.t.counts['previewPosts'], 2)
        self.assertEqual(result['newGrantsGranted'], 0)
        self.assertFalse(result['mcpOAuthScopesVerified'])
        self.assertNotIn('PRIVATE_GRANT_CANARY', json.dumps(result))
        self.assertNotIn('SYNTHETIC_TOKEN_CANARY', json.dumps(result))

    def test_wrong_line_then_correct_line_in_same_native_pty_is_not_authority_or_new_window(self):
        master,slave = os.openpty(); emitted=[]
        expected='APPROVO '+m.digest(self.plan)
        def emit(line):
            emitted.append(line)
            if line=='Conferma:':os.write(master,(expected+' explanation\n').encode())
            if 'Riga non valida:' in line:
                self.assertFalse(self.context.row.get('humanReviewApproved'))
                self.assertEqual(self.owner.calls,[])
                os.write(master,(expected+'\n').encode())
        deadline=self.t.deadline
        try:m.approve(self.plan,self.context,self.t,fd=slave,emit=emit)
        finally:os.close(master);os.close(slave)
        self.assertTrue(self.context.row['humanReviewApproved'])
        self.assertEqual(self.context.row['ttyInput']['rejectedLines'],1)
        self.assertEqual(self.t.deadline,deadline)

    def test_no_tty_cannot_authorize(self):
        read_fd, write_fd = os.pipe()
        try:
            with self.assertRaisesRegex(m.Stop, 'REAL_REVIEW_TTY_REQUIRED'):
                m.approve(self.plan, self.context, self.t, fd=read_fd)
        finally:
            os.close(read_fd); os.close(write_fd)
        self.assertFalse(self.context.row.get('humanReviewApproved'))

    def test_mutation_without_human_review_never_reaches_owner(self):
        with self.assertRaisesRegex(m.Stop, 'APPROVED_ADMIN_POST_REQUIRED'):
            self.t.request('/capabilities', method='POST', body=m.registration(m.MISSING[0]))
        self.assertEqual(self.owner.calls, [])

    def test_wrong_scope_or_actor_conflict_is_not_silently_replaced(self):
        bad = copy.deepcopy(self.owner.catalogue)
        bad[m.MISSING[0]] = m.registration(m.MISSING[0])
        bad[m.MISSING[0]]['descriptor']['requiredScope'] = 'mcp.connect'
        with self.assertRaisesRegex(m.Stop, 'REGISTERED_DESCRIPTOR_SEMANTICS_CONFLICT'):
            m.prepare(self.owner.current, bad, time.time()+100)

    def test_unreviewed_registered_catalogue_drift_stops_before_writes(self):
        self.owner.catalogue[m.MISSING[0]]=m.registration(m.MISSING[0])
        with self.assertRaisesRegex(m.Stop,'EXACT_OBSERVED_REGISTERED_CATALOGUE_REQUIRED'):
            m.prepare(self.owner.current,self.owner.catalogue,time.time()+800)
        self.assertEqual(self.owner.calls,[])

    def test_lost_registration_reply_leaves_claimed_and_never_reposts(self):
        self.synthetic_tty_approval()
        def lose(method, path, body):
            if method == 'POST' and path == '/capabilities':
                raise urllib.error.URLError(TimeoutError('synthetic lost response'))
        self.owner.after = lose
        with self.assertRaisesRegex(m.Stop, 'ADMIN_TRANSPORT_OUTCOME_REQUIRES_RECONCILIATION'):
            self.execute()
        key = 'REGISTER:'+m.MISSING[0]
        self.assertEqual(self.context.row['effects'][key]['state'], 'CLAIMED')
        self.assertIn(m.MISSING[0], self.owner.catalogue)
        self.assertEqual(len([x for x in self.owner.calls if x[0] == 'POST']), 1)

    def test_lost_publish_response_retains_activated_effect_as_claimed(self):
        self.synthetic_tty_approval()
        def lose(method, path, body):
            if path.endswith(':publish'):
                raise urllib.error.URLError(TimeoutError('synthetic lost publication response'))
        self.owner.after = lose
        with self.assertRaisesRegex(m.Stop, 'ADMIN_TRANSPORT_OUTCOME_REQUIRES_RECONCILIATION'):
            self.execute()
        self.assertEqual(self.owner.current['policyRef'], 'ouf-lab-authorization:57')
        self.assertEqual(self.context.row['effects']['PUBLISH_DRAFT']['state'], 'CLAIMED')
        self.assertEqual(len([x for x in self.owner.calls if x[1].endswith(':publish')]), 1)

    def test_changed_preview_blocks_publication(self):
        self.synthetic_tty_approval()
        self.owner.preview_change = lambda p: {**p, 'grantChanges':[{'grantId':'unexpected'}]}
        with self.assertRaisesRegex(m.Stop, 'OWNER_PREVIEW_DELTA_MISMATCH'):
            self.execute()
        self.assertFalse(any(x[1].endswith(':publish') for x in self.owner.calls))

    def test_different_active_base_blocks_before_any_mutation(self):
        self.synthetic_tty_approval()
        self.owner.current['policyRef'] = 'ouf-lab-authorization:57'
        with self.assertRaisesRegex(m.Stop, 'EXACT_OBSERVED_ACTIVE_BASE_REQUIRED'):
            self.execute()
        self.assertFalse(any(x[0] == 'POST' for x in self.owner.calls))

    def test_grant_change_after_publication_cannot_produce_success(self):
        self.synthetic_tty_approval()
        self.owner.grants_at_publish = []
        with self.assertRaisesRegex(m.Stop, 'PUBLISHED_ACTIVE_PRESERVATION_NOT_PROVEN'):
            self.execute()
        self.assertEqual(self.context.row['effects']['PUBLISH_DRAFT']['state'], 'CLAIMED')

    def test_owner_denial_is_not_retried(self):
        def denied(method, path, body):
            raise urllib.error.HTTPError(m.ADMIN+path, 403, 'synthetic', {}, io.BytesIO(b'PRIVATE_CANARY'))
        self.owner.before = denied
        with self.assertRaisesRegex(m.Stop, 'ADMIN_HTTP_403_NO_AUTOMATIC_REPLAY'):
            self.t.get('one-denial', '/policies/active')
        self.assertEqual(len(self.owner.calls), 1)

    def test_transient_get_retry_retains_cumulative_attempts(self):
        clock = [0]
        self.t.clock = lambda: clock[0]
        self.t.sleep = lambda seconds: clock.__setitem__(0, clock[0]+seconds)
        self.t.deadline = 100
        def first_failure(method, path, body):
            if len(self.owner.calls) == 1:
                raise urllib.error.HTTPError(m.ADMIN+path, 503, 'synthetic', {'Retry-After':'1'}, io.BytesIO(b''))
        self.owner.before = first_failure
        self.t.get('transient-read', '/policies/active')
        self.assertEqual(self.t.counts['ownerGets'], 2)
        self.assertEqual(self.context.row['reads']['transient-read']['attempts'], 2)
        self.assertGreater(clock[0], 5)

    def test_unknown_endpoints_and_role_grant_or_iam_edits_are_rejected(self):
        self.synthetic_tty_approval()
        for path in ('/roles', '/policies/arbitrary/grants/old', '/capabilities?limit=999', '/iam/clients'):
            with self.assertRaises(m.Stop):
                self.t.request(path, method='POST', body={})
        self.assertEqual(self.owner.calls, [])

    def test_expiry_does_not_extend_token_or_reset_counts(self):
        self.synthetic_tty_approval()
        self.t.deadline = self.t.clock()-1
        with self.assertRaisesRegex(m.Stop, 'FINITE_HUMAN_WINDOW_EXPIRED'):
            self.execute()
        self.assertEqual(self.owner.calls, [])
        self.assertFalse(self.context.row['budgetReset'])

    def test_completed_scope_cannot_be_reopened_or_reexecuted(self):
        self.synthetic_tty_approval()
        self.execute()
        count = len(self.owner.calls)
        with self.assertRaisesRegex(m.Stop, 'READ_STAGE_ALREADY_CONSUMED'):
            self.execute()
        self.assertEqual(len(self.owner.calls), count)
        with self.assertRaisesRegex(m.Stop, 'PUBLICATION_SCOPE_EXISTS_RECONCILE_NO_REPLAY'):
            m.Journal(self.context.path)

    def test_changed_private_review_blocks_dispatch_after_approval(self):
        self.synthetic_tty_approval()
        private = self.context.path/'review.json'
        review = json.loads(private.read_text())
        review['newGrants'] = 1
        private.write_text(json.dumps(review))
        with self.assertRaisesRegex(m.Stop, 'PRIVATE_REVIEW_CHANGED'):
            self.execute()
        self.assertEqual(self.owner.calls, [])

    def test_changed_in_memory_plan_cannot_widen_candidate_after_approval(self):
        self.synthetic_tty_approval()
        self.plan['candidatePolicy']['grants'] = []
        with self.assertRaisesRegex(m.Stop, 'HUMAN_APPROVAL_REQUIRED'):
            self.execute()
        self.assertEqual(self.owner.calls, [])

    def test_zero_revision_matches_owner_migration_and_negative_revision_is_rejected(self):
        value = {'id':str(uuid.uuid4()), 'revision':0, 'state':'DRAFT', 'baseActiveRef':m.BASE_REF, 'policy':self.plan['candidatePolicy']}
        m.validate_draft(value, self.plan)
        value['revision'] = -1
        with self.assertRaisesRegex(m.Stop, 'EXACT_OWNER_DRAFT_REQUIRED'):
            m.validate_draft(value, self.plan)

    def test_response_receipt_persisted_before_a_later_validation_failure(self):
        self.synthetic_tty_approval()
        original = self.owner.open
        def malformed(request, **kwargs):
            reply = original(request, **kwargs)
            if request.get_method() == 'POST' and request.full_url == m.ADMIN+'/policies':
                body = json.loads(reply.raw)
                body['state'] = 'UNEXPECTED'
                reply.raw = json.dumps(body).encode()
            return reply
        self.t.opener = type('Opener', (), {'open':staticmethod(malformed)})()
        with self.assertRaisesRegex(m.Stop, 'EXACT_OWNER_DRAFT_REQUIRED'):
            self.execute()
        retained = json.loads((self.context.path/'owner-create-response.json').read_text())
        self.assertEqual(retained['status'], 200)
        self.assertEqual(retained['etag'], '"0"')
        self.assertEqual(json.loads(retained['bodyUtf8'])['id'], self.owner.draft['id'])
        self.assertEqual(self.context.row['effects']['CREATE_DRAFT']['state'], 'CLAIMED')

    def test_real_tty_gate_precedes_login_and_private_scope(self):
        with patch.object(m.sys, 'argv', ['controller']), patch.object(m.sys.stdin, 'isatty', return_value=False), patch.object(m.sys,'flags',type('Flags',(),{'isolated':1,'no_site':1})()), patch.object(m.sys,'dont_write_bytecode',True), patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'getegid',return_value=0),patch.object(m,'login') as login, patch.object(m, 'Journal') as journal:
            with self.assertRaisesRegex(m.Stop, 'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED'):m.main()
        login.assert_not_called();journal.assert_not_called()

    def test_bad_json_create_retains_raw_receipt_with_uuid_and_no_second_create(self):
        self.synthetic_tty_approval();original=self.owner.open
        def malformed(request,**kwargs):
            reply=original(request,**kwargs)
            if request.get_method()=='POST' and request.full_url==m.ADMIN+'/policies':reply.raw=b'{bad json UUID_PRIVATE_CANARY'
            return reply
        self.t.opener=type('Opener',(),{'open':staticmethod(malformed)})()
        with self.assertRaisesRegex(m.Stop,'INVALID_ADMIN_RESPONSE'):self.execute()
        self.assertIn('UUID_PRIVATE_CANARY',(self.context.path/'owner-create-response.json').read_text())
        self.assertEqual(self.context.row['effects']['CREATE_DRAFT']['state'],'CLAIMED')
        self.assertEqual(len([c for c in self.owner.calls if c[:2]==('POST','/policies')]),1)

    def test_http_error_response_is_private_before_permanent_status_guard(self):
        def denied(method,path,body):raise urllib.error.HTTPError(m.ADMIN+path,403,'private',{'ETag':'"0"'},io.BytesIO(b'PRIVATE_HTTP_ERROR_CANARY'))
        self.owner.before=denied
        with self.assertRaisesRegex(m.Stop,'ADMIN_HTTP_403_NO_AUTOMATIC_REPLAY'):self.t.get('one','/policies/active')
        receipt=json.loads((self.context.path/'response-00001.json').read_text())
        self.assertEqual(receipt['status'],403)
        self.assertEqual(receipt['bodyUtf8'],'PRIVATE_HTTP_ERROR_CANARY')
        self.assertEqual(self.t.counts['ownerGets'],1)

    def test_registration_catalogue_change_after_review_blocks_all_writes(self):
        self.synthetic_tty_approval()
        self.owner.catalogue['unexpected']={'ownerRef':'other','descriptor':{'capabilityId':'unexpected'}}
        with self.assertRaisesRegex(m.Stop,'REGISTERED_CATALOGUE_CHANGED_AFTER_REVIEW'):self.execute()
        self.assertFalse(any(c[0]=='POST' for c in self.owner.calls))

    def test_exact_durable_mutation_claim_required_even_with_approved_plan(self):
        self.synthetic_tty_approval()
        with self.assertRaisesRegex(m.Stop,'EXACT_DURABLE_MUTATION_CLAIM_REQUIRED'):
            self.t.request('/capabilities',method='POST',body=m.registration(m.MISSING[0]))
        self.assertEqual(self.owner.calls,[])

    def test_descriptor_operation_scope_and_actor_are_exact(self):
        self.assertEqual(m.registration(m.MISSING[0]),{'ownerRef':'onboarding','descriptor':{'capabilityId':m.MISSING[0],'operation':'COMMAND','requiredScope':m.MISSING[0],'allowedActors':['HUMAN']}})
        for cap in m.EXISTING:self.assertEqual(self.plan['candidatePolicy']['capabilities'][:len(self.owner.current['policy']['capabilities'])],self.owner.current['policy']['capabilities'])

if __name__=='__main__':unittest.main()
