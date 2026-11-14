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
SPEC = importlib.util.spec_from_file_location('operational_grants_publication', ROOT/'scripts/publish-ouf-admin-operational-grants-20261111.py')
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
        caps = [m.registration(cap)['descriptor'] for cap in m.EXISTING]
        caps += [{'capabilityId':'retained-'+str(i), 'operation':'READ',
                  'requiredScope':'retained.read', 'allowedActors':['HUMAN']} for i in range(52)]
        grants = [{'grantId':'retained-'+str(i), 'capabilityId':'retained-0',
                   'tenantId':'other' if i == 162 else 'ouf-lab',
                   'subjectId':'retained', 'servicePrincipalId':None, 'organizationId':None,
                   'validFrom':'2020-01-01T00:00:00Z', 'validUntil':'2036-01-01T00:00:00Z',
                   'constraints':{'effect':'DENY', 'allowedDataLabels':['SENSITIVE'],
                                  'resourceAttributes':{'sourceRef':'PRIVATE_GRANT_CANARY'}}} for i in range(163)]
        self.current = {'policyRef':m.BASE_REF, 'contentHash':m.BASE_HASH,
                        'activatedAt':'2026-11-10T05:00:00Z',
                        'policy':{'bundleId':'ouf-lab-authorization', 'version':69,
                                  'publishedAt':'2026-11-10T05:00:00Z', 'capabilities':caps, 'grants':grants}}
        self.catalogue = {cap:m.registration(cap) for cap in m.EXISTING}
        self.catalogue.update({d['capabilityId']:{'ownerRef':'retained','descriptor':copy.deepcopy(d)} for d in caps[4:]})
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
                     'removedCapabilities':[], 'grantChanges':[{'grantId':g['grantId'],'before':None,'after':g} for g in m.additions()], 'authoritative':False}
            value = self.preview_change(value)
        elif method == 'POST' and path.endswith(':publish'):
            assert request.get_header('If-match') == '"0"'
            self.draft.update(state='PUBLISHED', revision=1)
            policy = copy.deepcopy(self.draft['policy'])
            policy['publishedAt'] = '2026-10-25T19:00:00Z'  # server publication time differs from the preview
            if self.grants_at_publish is not None: policy['grants'] = self.grants_at_publish
            self.current = {'policyRef':'ouf-lab-authorization:70', 'contentHash':'sha256:'+m.digest(policy), 'policy':policy}
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
        self.t = m.Transport('SYNTHETIC_TOKEN_CANARY', self.context)
        self.t.opener = self.owner
        self.plan = m.prepare(copy.deepcopy(self.owner.current), self.owner.catalogue, time.time()+800)
        self.catalogue_at_review = copy.deepcopy(self.owner.catalogue)
        self.network_guard = patch('urllib.request.OpenerDirector.open',side_effect=AssertionError('EXTERNAL_NETWORK_FORBIDDEN'))
        self.network_guard.start()
    def tearDown(self):
        self.network_guard.stop()
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
        return m.execute(self.plan, self.catalogue_at_review, self.context, self.t)

    def test_exact_real_pty_parser_then_full_additive_native_api_sequence(self):
        before = copy.deepcopy(self.owner.current['policy'])
        prompts = self.synthetic_tty_approval()
        self.assertIn('APPROVO '+m.digest(self.plan), prompts)
        result = self.execute()
        self.assertEqual(result['status'], 'OUF_ADMIN_OPERATIONAL_GRANTS_POLICY70_PUBLISHED')
        self.assertEqual(self.owner.current['policy']['grants'][:163], before['grants'])
        self.assertEqual(self.owner.current['policy']['capabilities'][:len(before['capabilities'])], before['capabilities'])
        self.assertEqual(self.t.counts['administrativeWrites'], 6)
        self.assertEqual(self.t.counts['previewPosts'], 2)
        self.assertEqual(result['newGrantsGranted'], 16)
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
        with self.assertRaisesRegex(m.Stop, 'NEW_REGISTRATION_ALREADY_PRESENT'):
            m.prepare(self.owner.current, bad, time.time()+100)

    def test_unreviewed_registered_catalogue_drift_stops_before_writes(self):
        self.owner.catalogue[m.MISSING[0]]=m.registration(m.MISSING[0])
        with self.assertRaisesRegex(m.Stop,'NEW_REGISTRATION_ALREADY_PRESENT'):
            m.prepare(self.owner.current,self.owner.catalogue,time.time()+800)
        self.assertEqual(self.owner.calls,[])

    def test_exact_delta_independent_expected_values_and_deep_preservation(self):
        before = copy.deepcopy(self.owner.current)
        policy = before['policy']
        candidate = self.plan['candidatePolicy']
        ids = ('operations.status.read', 'ouf.operations.summary',
               'ouf.gateway.operations.summary', 'ouf.ingestion.operations.summary',
               'operations.incident.read', 'ouf.operations.incidents',
               'ouf.gateway.operations.incidents', 'ouf.ingestion.operations.incidents')
        descriptors = [{'ownerRef':owner, 'descriptor':{
            'capabilityId':cap, 'operation':'READ', 'allowedActors':['HUMAN'],
            'requiredScope':'operations.incident.read'}}
            for cap, owner in zip(ids[4:], ('ingestion','mcp','gateway','ingestion'))]
        self.assertEqual(self.plan['registrationAdditions'], descriptors)
        self.assertEqual(candidate['capabilities'][:56], policy['capabilities'])
        self.assertEqual(candidate['grants'][:163], policy['grants'])
        for name, count in [('capabilities',56),('grants',163)]:
            self.assertEqual(json.dumps(candidate[name][:count],separators=(',',':')),
                             json.dumps(policy[name],separators=(',',':')))
        self.assertEqual(candidate['capabilities'][56:], [d['descriptor'] for d in descriptors])
        self.assertEqual(len(candidate['capabilities']), 60)
        self.assertEqual(len(candidate['grants']), 179)
        self.assertEqual(candidate['version'], 70)
        self.assertEqual(candidate['bundleId'], policy['bundleId'])
        constraints = {'effect':'ALLOW','resourceId':None,'requiredAcr':None,
            'requiredAmr':[],'resourceType':None,'externalRoleRef':None,
            'allowedDataLabels':[], 'allowedDetailLevels':['PUBLIC_OPERATIONAL',
            'RESTRICTED_OPERATIONAL','SECURITY_SENSITIVE','TENANT_OPERATIONAL'],
            'resourceAttributes':{},'maxAuthenticationAgeSeconds':None}
        expected = []
        for cap in ids:
            for kind in ('base', 'detail'):
                grant = {'grantId':'grant-ouf-admin-ops-'+cap.replace('.', '-')+'-'+kind+'-20261111',
                    'capabilityId':cap, 'tenantId':'ouf-lab',
                    'subjectId':'b93d8cf6-cd14-4ee6-91d7-84cd76c4f500',
                    'servicePrincipalId':None,'organizationId':None,
                    'validFrom':'2026-11-11T00:00:00Z',
                    'validUntil':'2036-09-15T07:13:50.968730Z'}
                if kind == 'detail':grant['constraints'] = copy.deepcopy(constraints)
                expected.append(grant)
        self.assertEqual(self.plan['grantAdditions'], expected)
        self.assertEqual(candidate['grants'][163:], expected)
        self.assertEqual(self.owner.current, before)
        self.assertEqual(self.plan['baseResponseHash'], m.digest(before))
        self.assertEqual(self.plan['baseCatalogueHash'], m.digest(self.owner.catalogue))
        candidate['grants'][0]['constraints']['effect'] = 'ALLOW'
        self.assertEqual(self.owner.current, before)

    def test_baseline_stop_codes_before_any_post(self):
        cases = [
            (lambda a,c:a.update(policyRef='ouf-lab-authorization:68'), 'EXACT_OBSERVED_ACTIVE_BASE_REQUIRED'),
            (lambda a,c:a.update(contentHash='0'*64), 'EXACT_OBSERVED_ACTIVE_BASE_REQUIRED'),
            (lambda a,c:a['policy'].update(version=68), 'EXACT_POLICY_SHAPE_REQUIRED'),
            (lambda a,c:a['policy']['capabilities'].pop(), 'EXACT_ACTIVE_COUNTS_REQUIRED'),
            (lambda a,c:a['policy']['grants'].pop(), 'EXACT_ACTIVE_COUNTS_REQUIRED'),
            (lambda a,c:a['policy']['grants'].append(m.additions()[0]), 'NEW_GRANT_ALREADY_ACTIVE'),
            (lambda a,c:a['policy']['capabilities'].append(m.registration(m.MISSING[0])['descriptor']), 'NEW_DESCRIPTOR_ALREADY_ACTIVE'),
            (lambda a,c:c.update({m.MISSING[0]:m.registration(m.MISSING[0])}), 'NEW_REGISTRATION_ALREADY_PRESENT'),
            (lambda a,c:c.pop(m.EXISTING[0]), 'EXACT_CATALOGUE_COUNT_REQUIRED'),
            (lambda a,c:a['policy']['capabilities'][0].update(operation='COMMAND'), 'EXISTING_SUMMARY_DESCRIPTOR_MISMATCH'),
            (lambda a,c:c[m.EXISTING[0]].update(ownerRef='mcp'), 'REGISTERED_SUMMARY_DESCRIPTOR_MISMATCH')]
        for mutate, code in cases:
            with self.subTest(code=code):
                active, catalogue = copy.deepcopy(self.owner.current), copy.deepcopy(self.owner.catalogue)
                mutate(active, catalogue)
                with self.assertRaisesRegex(m.Stop, code):m.prepare(active, catalogue, time.time()+100)
        self.assertEqual(self.owner.calls, [])

    def test_all_summary_descriptors_owners_scopes_actors_and_duplicate_ids(self):
        for cap in m.EXISTING:
            for key, value in [('operation','COMMAND'),('requiredScope',cap),('allowedActors',['SERVICE'])]:
                if key == 'requiredScope' and value == 'operations.status.read':value = 'wrong'
                active = copy.deepcopy(self.owner.current)
                next(d for d in active['policy']['capabilities'] if d['capabilityId'] == cap)[key] = value
                with self.assertRaisesRegex(m.Stop,'EXISTING_SUMMARY_DESCRIPTOR_MISMATCH'):
                    m.prepare(active,self.owner.catalogue,time.time()+100)
                catalogue = copy.deepcopy(self.owner.catalogue)
                catalogue[cap]['descriptor'][key] = value
                with self.assertRaisesRegex(m.Stop,'REGISTERED_SUMMARY_DESCRIPTOR_MISMATCH'):
                    m.prepare(self.owner.current,catalogue,time.time()+100)
        for collection in ('capabilities','grants'):
            active = copy.deepcopy(self.owner.current)
            active['policy'][collection][-1] = active['policy'][collection][0]
            with self.assertRaisesRegex(m.Stop,'UNIQUE_ACTIVE_ENTRIES_REQUIRED'):m.baseline(active)

    def test_review_displays_every_registration_grant_level_expiry_and_observed_digest(self):
        text = '\n'.join(self.synthetic_tty_approval())
        for row in self.plan['registrationAdditions']:self.assertIn(row['descriptor']['capabilityId'], text)
        for row in self.plan['grantAdditions']:
            self.assertIn(row['grantId'], text)
            self.assertIn(row['capabilityId'], text)
            self.assertIn(row['validUntil'], text)
        for level in m.DETAIL_LEVELS:self.assertIn(level, text)
        for key in ('baseResponseHash','baseCatalogueHash'):self.assertIn(self.plan[key], text)
        self.assertIn('56 -> 60', text)
        self.assertIn('163 -> 179', text)

    def test_response_drift_with_same_declared_hash_stops_before_first_write(self):
        self.synthetic_tty_approval()
        self.owner.current['policy']['grants'][0]['constraints']['effect'] = 'ALLOW'
        with self.assertRaisesRegex(m.Stop,'ACTIVE_RESPONSE_CHANGED_AFTER_REVIEW'):self.execute()
        self.assertFalse(any(c[0] == 'POST' for c in self.owner.calls))

    def test_post_dispatch_reservation_prevents_reusing_claim_even_on_lost_reply(self):
        self.synthetic_tty_approval()
        row = self.plan['registrationAdditions'][0]
        key = 'REGISTER:'+row['descriptor']['capabilityId']
        self.context.effect(key,row)
        def lose(*_):raise urllib.error.URLError(TimeoutError())
        self.owner.after = lose
        with self.assertRaises(m.Stop):self.t.request('/capabilities',method='POST',body=row)
        self.assertTrue(self.context.row['effects'][key]['dispatched'])
        with self.assertRaisesRegex(m.Stop,'EXACT_DURABLE_MUTATION_CLAIM_REQUIRED'):
            self.t.request('/capabilities',method='POST',body=row)
        self.assertEqual(len(self.owner.calls),1)

    def test_all_posts_have_claims_and_preview_grants_must_be_exact(self):
        self.synthetic_tty_approval()
        self.execute()
        self.assertEqual(len(self.context.row['effects']),8)
        self.assertTrue(all(v['state']=='APPLIED' and v['dispatched'] for v in self.context.row['effects'].values()))
        self.assertEqual(self.t.counts['administrativeWrites'],6)
        self.assertEqual(self.t.counts['previewPosts'],2)

    def test_catalogue_drift_between_registrations_stops_before_next_post(self):
        self.synthetic_tty_approval()
        def drift(method,path,body):
            if method == 'POST' and path == '/capabilities':
                self.owner.catalogue[m.EXISTING[0]]['ownerRef'] = 'unexpected'
        self.owner.after = drift
        with self.assertRaisesRegex(m.Stop,'REGISTRATION_READBACK_MISMATCH'):self.execute()
        self.assertEqual(len([c for c in self.owner.calls if c[0]=='POST']),1)

    def test_sha256_prefix_is_accepted_and_write_budgets_are_finite(self):
        active = copy.deepcopy(self.owner.current)
        active['contentHash'] = 'sha256:'+m.BASE_HASH
        m.prepare(active,self.owner.catalogue,time.time()+100)
        self.assertEqual(m.LIMITS['administrativeWrites'],6)
        self.assertEqual(m.LIMITS['previewPosts'],2)

    def test_each_of_the_sixteen_grants_and_four_registrations_is_absent(self):
        for grant in m.additions():
            active = copy.deepcopy(self.owner.current)
            active['policy']['grants'][-1] = grant
            with self.assertRaisesRegex(m.Stop,'NEW_GRANT_ALREADY_ACTIVE'):m.baseline(active)
        for cap in m.MISSING:
            active = copy.deepcopy(self.owner.current)
            active['policy']['capabilities'][-1] = m.registration(cap)['descriptor']
            with self.assertRaisesRegex(m.Stop,'NEW_DESCRIPTOR_ALREADY_ACTIVE'):m.baseline(active)
            catalogue = copy.deepcopy(self.owner.catalogue)
            catalogue.pop(next(k for k in catalogue if k not in m.EXISTING))
            catalogue[cap] = m.registration(cap)
            with self.assertRaisesRegex(m.Stop,'NEW_REGISTRATION_ALREADY_PRESENT'):
                m.prepare(self.owner.current,catalogue,time.time()+100)


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
        self.assertEqual(self.owner.current['policyRef'], 'ouf-lab-authorization:70')
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
        self.owner.current['policyRef'] = 'ouf-lab-authorization:70'
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
        review['newGrants'] = 17
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

    def test_detail_label_constraint_in_preview_cannot_reintroduce_the_403(self):
        self.synthetic_tty_approval()
        def change(value):
            value['grantChanges'][1]['after']['constraints']['allowedDataLabels'] = ['PUBLIC']
            return value
        self.owner.preview_change = change
        with self.assertRaisesRegex(m.Stop,'OWNER_PREVIEW_DELTA_MISMATCH'):self.execute()
        self.assertFalse(any(c[1].endswith(':publish') for c in self.owner.calls))

    def test_base_grant_constraints_key_must_remain_absent_in_preview(self):
        self.synthetic_tty_approval()
        def change(value):
            value['grantChanges'][0]['after']['constraints'] = None
            return value
        self.owner.preview_change = change
        with self.assertRaisesRegex(m.Stop,'OWNER_PREVIEW_DELTA_MISMATCH'):self.execute()
        self.assertFalse(any(c[1].endswith(':publish') for c in self.owner.calls))

    def test_write_budget_exhaustion_precedes_dispatch(self):
        self.synthetic_tty_approval()
        row = self.plan['registrationAdditions'][0]
        key = 'REGISTER:'+row['descriptor']['capabilityId']
        self.context.effect(key,row)
        self.t.counts['administrativeWrites'] = 6
        with self.assertRaisesRegex(m.Stop,'ADMIN_REQUEST_BUDGET_EXHAUSTED'):
            self.t.request('/capabilities',method='POST',body=row)
        self.assertEqual(self.owner.calls,[])
        self.assertNotIn('dispatched',self.context.row['effects'][key])

    def test_device_flow_uses_exact_public_client_and_checks_the_admin_subject(self):
        class IamFixture:
            deadline = 600
            def __init__(self,subject):self.subject=subject;self.calls=[]
            def clock(self):return 0
            def request(self,url,**kw):
                self.calls.append((url,kw))
                device=m.ISSUER+'/protocol/openid-connect/auth/device'
                endpoint=m.ISSUER+'/protocol/openid-connect/token'
                if url.endswith('/.well-known/openid-configuration'):
                    return 200,{'issuer':m.ISSUER,'device_authorization_endpoint':device,'token_endpoint':endpoint}
                if url == device:
                    assert kw['form']=={'client_id':'ouf-human-admin','scope':'openid authorization.policy.admin'}
                    return 200,{'verification_uri':m.ISSUER+'/device','user_code':'CI-ONLY',
                                'device_code':'SYNTHETIC_DEVICE','expires_in':100,'interval':5}
                assert url == endpoint and kw['form']['client_id']=='ouf-human-admin'
                claims={'iss':m.ISSUER,'sub':self.subject,'tenant_id':'ouf-lab','ouf_actor_type':'HUMAN',
                        'exp':100,'scope':'openid authorization.policy.admin'}
                payload=m.base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
                return 200,{'access_token':'CI.'+payload+'.NOT_A_SIGNATURE'}
        fixture=IamFixture(m.SUBJECT)
        self.assertTrue(m.login(fixture,sleep=lambda _:None,emit=lambda _:None,wall=lambda:0))
        self.assertEqual(len(fixture.calls),3)
        with self.assertRaisesRegex(m.Stop,'EXACT_OUF_ADMIN_CONTEXT_REQUIRED'):
            m.login(IamFixture('another-subject'),sleep=lambda _:None,emit=lambda _:None,wall=lambda:0)


def owner_driver(fixture_path, mode):
    """CI loopback bridge to pinned Java owner; never used by the publisher main."""
    fixture = json.loads(Path(fixture_path).read_text())
    assert fixture['origin'].startswith('http://127.0.0.1:')
    m.ADMIN = fixture['origin']
    # Java seed has the same shape/counts, but cannot have the live v69 hash.
    m.BASE_HASH = fixture['active']['contentHash'].removeprefix('sha256:')
    with tempfile.TemporaryDirectory() as tmp:
        j = m.Journal(Path(tmp)/'ci-only-publication')
        t = m.Transport('CI_SYNTHETIC_PRINCIPAL_NOT_IAM',j)
        active = t.get('initial-active','/policies/active')
        catalogue = m.registered(t,'initial-catalogue')
        plan = m.prepare(active,catalogue,time.time()+180)
        master, slave = os.openpty()
        def emit(line):
            if line == 'Conferma:':os.write(master,('APPROVO '+m.digest(plan)+(' extra' if mode=='decline' else '')+'\n').encode())
            if mode == 'decline' and 'Riga non valida:' in line:t.deadline=t.clock()-1
        try:
            try:
                m.approve(plan,j,t,fd=slave,emit=emit)
                result = m.execute(plan,catalogue,j,t)
            except m.Stop as error:
                assert mode in ('decline','lost'), str(error)
                if mode == 'decline':assert str(error)=='FINITE_HUMAN_WINDOW_EXPIRED', str(error)
                else:assert str(error)=='ADMIN_TRANSPORT_OUTCOME_REQUIRES_RECONCILIATION', str(error)
            else:
                assert mode == 'success'
                assert result['counts']['administrativeWrites']==6 and result['counts']['previewPosts']==2
                assert result['preexistingGrantsPreserved'] and result['newGrantsGranted']==16
            if mode == 'decline':assert t.counts['administrativeWrites']==0 and not j.row.get('humanReviewApproved')
            elif mode == 'lost':
                assert j.row['effects']['PUBLISH_DRAFT']['state']=='CLAIMED'
                try:m.execute(plan,catalogue,j,t)
                except m.Stop:pass
                else:raise AssertionError('publication replayed')
            else:
                for filename, etag, revision in [('owner-create-response.json','"0"',0),('owner-publish-response.json','"1"',1)]:
                    response=json.loads((j.path/filename).read_text())
                    assert response['etag']==etag and json.loads(response['bodyUtf8'])['revision']==revision
            print('ACTUAL_OWNER_OUF_ADMIN_OPERATIONAL_GRANTS_'+mode.upper()+'_PASS',flush=True)
        finally:os.close(master);os.close(slave)


if __name__ == '__main__':
    import sys
    if len(sys.argv)==4 and sys.argv[1]=='--owner-driver':owner_driver(sys.argv[2],sys.argv[3])
    else:unittest.main()
