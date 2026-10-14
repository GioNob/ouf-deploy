"""Actual signed AggregateAction + owner helper bytes; explicit HTTP/IAM fixture.

The fixture models owner HTTP state transitions, not production authentication.
No target requests, credentials, database writes or session revocations occur.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
OWNER = Path(os.environ.get('OUF_CHATBOT_DEPLOY_ROOT',str(ROOT)))
ONBOARDING = Path(os.environ['OUF_CHATBOT_ONBOARDING_ROOT'])
sys.path[:0] = [str(ROOT),str(OWNER),str(OWNER/'tests'),str(OWNER/'tools/semantic_policy_token_owner'),
               str(OWNER/'tools/semantic_application_cutover'),str(OWNER/'tools/semantic_cohort_admission/cohort-draft')]
from tools.chatbot_file_cohort.authorization import (
    ADMIN, NEW, CHAT, BROWSER, OwnerPrimitives, OwnerTransport, AuthorizationDelta,
    AuthorizationPaused, compile_plan, authorization_scope, expected_role_grant_additions,
)
from tools.chatbot_file_cohort.plan import digest, encoded
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
import test_cutover_authority_native as signed


def helpers():
    names = ('scripts/r4a_authorization_lifecycle.py','scripts/r4a_keycloak_client_scope_catalogue.py',
             'catalogue/chatbot-source-review-capabilities.json')
    bindings = {name:hashlib.sha256((ONBOARDING/name).read_bytes()).hexdigest() for name in names}
    return OwnerPrimitives(ONBOARDING,bindings)


def fixture():
    selection = {'origin':'https://gateway.fixture.invalid','issuer':'https://auth.fixture.invalid/realms/fixture',
        'tenant':'tenant-fixture','subject':'human-fixture','docker':{'path':'/usr/bin/docker','sha256':'a'*64},
        'keycloakContainer':'b'*64,'realm':'fixture',
        'clients':{p:{'clientId':'fixture-'+p,'requestedScopes':[]} for p in ('chatgpt','ths')}}
    roles = {'issuer':selection['issuer'],'roles':[{'roleId':'admin','displayName':'Existing administrator','permissions':[]}],
        'assignments':[{'assignmentId':'existing-admin','roleId':'admin','subjectId':selection['subject'],'externalRoleRef':None,
                        'validFrom':'2020-01-01T00:00:00Z','validUntil':'2036-01-01T00:00:00Z'}]}
    cap = {'capabilityId':'ingestion.operations.read','operation':'READ','requiredScope':'ingestion.operations.read','allowedActors':['HUMAN']}
    direct = {'grantId':'existing-consultation','capabilityId':'ouf.semantic.consultation.read','tenantId':selection['tenant'],
        'subjectId':selection['subject'],'servicePrincipalId':None,'organizationId':None,
        'validFrom':'2020-01-01T00:00:00Z','validUntil':'2036-01-01T00:00:00Z','constraints':None}
    consultation={'capabilityId':'ouf.semantic.consultation.read','operation':'READ','requiredScope':'ouf.semantic.read','allowedActors':['HUMAN']}
    policy = {'bundleId':'fixture-policy','version':38,'publishedAt':'2026-01-01T00:00:00Z','capabilities':[cap,consultation],
              'grants':[direct,dict(direct,grantId='other-tenant',tenantId='retained-other-tenant')]}
    active = {'policyRef':'fixture-policy:38','contentHash':digest(policy),'activatedAt':'2026-01-01T00:00:00Z','policy':policy}
    scopes = {}
    for n in sorted(set(CHAT+BROWSER)-set(NEW)):
        scopes[n] = {'id':'scope-'+str(len(scopes)), 'name':n,'protocol':'openid-connect',
                     'attributes':{'include.in.token.scope':'true','display.on.consent.screen':'false'}}
    clients = {}
    for purpose,names in [('chatgpt',CHAT),('ths',BROWSER)]:
        clients[purpose] = {'id':'id-'+purpose,'clientId':selection['clients'][purpose]['clientId'],'requestedScopes':[],
            'default':[{'id':scopes[n]['id'],'name':n} for n in names if n in scopes],'optional':[]}
    obs = {'active':active,'roles':roles,'registrations':{cap['capabilityId']:{'ownerRef':'ingestion','descriptor':cap}},
           'oauth':{'scopes':scopes,'clients':clients}}
    return selection,obs


class OwnerFixture:
    def __init__(self, observed, plan):
        self.current,self.plan = copy.deepcopy(observed),plan
        self.drafts,self.proposals,self.calls = {},{},[]
        self.lost = None
        self.proposal_failure = None

    def observe(self): return copy.deepcopy(self.current)
    def active(self): return copy.deepcopy(self.current['active'])
    def roles(self): return copy.deepcopy(self.current['roles'])
    def registrations(self): return copy.deepcopy(self.current['registrations'])
    def oauth(self): return copy.deepcopy(self.current['oauth'])

    def request(self,path,method='GET',body=None,etag=None,**_kwargs):
        self.calls.append((method,path))
        if path == ADMIN+'/capabilities' and method == 'POST':
            self.current['registrations'][body['descriptor']['capabilityId']] = copy.deepcopy(body)
            reply = (201,None,{})
        elif path == ADMIN+'/policies' and method == 'POST':
            ident = '11111111-1111-4111-8111-'+str(len(self.drafts)+1).zfill(12)
            draft = {'id':ident,'revision':0,'state':'DRAFT','baseActiveRef':self.current['active']['policyRef'],'policy':copy.deepcopy(body)}
            self.drafts[ident] = draft; reply = (200,copy.deepcopy(draft),{'ETag':'"0"'})
        elif path.startswith(ADMIN+'/policies/'):
            operation = path.removeprefix(ADMIN+'/policies/'); ident = operation.split(':')[0]
            draft = self.drafts[ident]
            if operation.endswith(':preview'):
                reply = (200,{'addedCapabilities':self.plan['addedDescriptors'],'removedCapabilities':[],'grantChanges':[]},{})
            elif operation.endswith(':publish'):
                assert draft['revision'] == etag and draft['state'] == 'DRAFT'
                draft['state'] = 'PUBLISHED'; draft['revision'] += 1
                policy = copy.deepcopy(draft['policy']);policy['publishedAt'] = '2026-10-14T09:00:00Z'
                self.current['active'] = {'policyRef':policy['bundleId']+':'+str(policy['version']),
                    'policy':policy,'contentHash':digest(policy),'activatedAt':policy['publishedAt']}
                reply = (200,copy.deepcopy(draft),{})
            else: reply = (200,copy.deepcopy(draft),{})
        else: raise AssertionError('Unexpected owner request '+method+' '+path)
        if self.lost == (method,path):
            self.lost = None
            raise AuthorizationPaused('FIXTURE_LOST_RESPONSE_AFTER_EFFECT')
        return reply

    def kc(self,verb,path,*_args,body=None):
        self.calls.append(('KC:'+verb,path))
        if verb == 'create' and path == 'client-scopes':
            value = copy.deepcopy(body);value['id']='new-scope-'+str(len(self.current['oauth']['scopes']))
            self.current['oauth']['scopes'][body['name']] = value
        elif verb == 'update':
            _,cid,kind,sid = path.split('/')
            assert kind == 'default-client-scopes'
            client = next(c for c in self.current['oauth']['clients'].values() if c['id'] == cid)
            scope = next(s for s in self.current['oauth']['scopes'].values() if s['id'] == sid)
            client['default'].append({'id':sid,'name':scope['name']})
        else: raise AssertionError('Unreviewed IAM operation')

    def tool(self,name,arguments,key):
        self.calls.append((name,key))
        if name == 'authorization.permissions.propose':
            if key not in self.proposals:
                self.proposals[key] = {'proposalId':'22222222-2222-4222-8222-222222222222','revision':0,'state':'PENDING',
                    'expiresAt':'2026-10-14T09:15:00Z','approvalPath':'https://ths.fixture.invalid/trusted-human/authorization/?proposal=fixture',
                    'finalPolicyRef':None}
            if self.proposal_failure:
                failure,self.proposal_failure=self.proposal_failure,None
                raise AuthorizationPaused(failure)
            return copy.deepcopy(self.proposals[key])
        if name == 'authorization.proposal.read':
            return copy.deepcopy(next(p for p in self.proposals.values() if p['proposalId'] == arguments['proposalId']))
        raise AssertionError('Unreviewed permission tool')

    def human_confirms(self):
        # Explicit fixture HUMAN owner transition; production code has no such adapter.
        self.current['roles'] = copy.deepcopy(self.plan['targetRoles'])
        policy = self.current['active']['policy']
        policy['grants'] += list(expected_role_grant_additions(self.plan).values())
        policy['version'] += 1
        self.current['active'].update(policyRef=policy['bundleId']+':'+str(policy['version']),contentHash=digest(policy))
        for proposal in self.proposals.values():
            proposal.update(state='PUBLISHED',revision=1,finalPolicyRef=self.current['active']['policyRef'])


class CompilerTest(unittest.TestCase):
    def setUp(self): self.primitives=helpers();self.selection,self.obs=fixture()
    def compile(self): return compile_plan(self.obs,self.primitives,self.selection,now='2026-10-14T09:00:00Z')
    def test_real_owner_helper_preserves_grants_assignments_and_adds_exact_scopes(self):
        plan=self.compile()
        self.assertEqual(plan['candidatePolicy']['grants'],self.obs['active']['policy']['grants'])
        self.assertEqual(plan['targetRoles']['assignments'],self.obs['roles']['assignments'])
        self.assertEqual({p['capabilityId'] for p in plan['addedPermissions']},set(NEW)|{'ingestion.operations.read'})
        self.assertEqual(set(plan['scopeCreations']),set(NEW)|{'ingestion.operations.read'})
        self.assertEqual({b['purpose'] for b in plan['scopeBindings']},{'chatgpt'})
        self.assertFalse(plan['revokeSessions']);self.assertFalse(plan['issueTokens'])
    def test_conflicting_registration_and_missing_status_contract_fail_before_any_transport(self):
        cap=next(iter(NEW));self.obs['registrations'][cap]={'ownerRef':'wrong','descriptor':{}}
        with self.assertRaisesRegex(ValueError,'REGISTRATION_CONFLICT'):self.compile()
        del self.obs['registrations'][cap];del self.obs['registrations']['ingestion.operations.read']
        with self.assertRaisesRegex(ValueError,'STATUS_DESCRIPTOR_UNPROVEN'):self.compile()
    def test_existing_optional_scope_is_preserved_and_must_be_requested(self):
        scope=self.obs['oauth']['scopes']['ouf.semantic.read'];client=self.obs['oauth']['clients']['chatgpt']
        row=next(v for v in client['default'] if v['id']==scope['id']);client['default'].remove(row);client['optional'].append(row)
        with self.assertRaisesRegex(ValueError,'OPTIONAL_SCOPE_NOT_REQUESTED'):self.compile()
        client['requestedScopes']=['ouf.semantic.read'];self.compile()
    def test_memory_loader_factory_checks_source_identity_and_never_uses_files(self):
        modules=[]
        for name,path in [('qualified_owner_authorization_lifecycle','scripts/r4a_authorization_lifecycle.py'),
                          ('qualified_owner_scope_catalogue','scripts/r4a_keycloak_client_scope_catalogue.py')]:
            m=types.ModuleType(name);m.__qualified_source_sha256__=self.primitives.bindings[path]
            exec(compile((ONBOARDING/path).read_bytes(),path,'exec'),m.__dict__);modules.append(m)
        raw=(ONBOARDING/'catalogue/chatbot-source-review-capabilities.json').read_bytes()
        with patch.object(Path,'read_bytes',side_effect=AssertionError('No source fallback')):
            loaded=OwnerPrimitives.from_qualified_modules(*modules,raw,self.primitives.bindings)
            self.assertEqual(loaded.descriptors,self.primitives.descriptors)
        modules[0].__qualified_source_sha256__='0'*64
        with self.assertRaisesRegex(ValueError,'CLOSURE_MISMATCH'):OwnerPrimitives.from_qualified_modules(*modules,raw,self.primitives.bindings)
    def test_existing_mcp_transport_supplies_current_sdk_metadata_without_forged_identity_headers(self):
        transport=OwnerTransport(self.selection,Path('/unused/admin'),Path('/unused/mcp'))
        reply={'jsonrpc':'2.0','result':{'content':[{'type':'text','text':json.dumps(self.obs['roles'])}]}}
        with patch.object(transport,'request',return_value=(200,reply,{})) as request:
            self.assertEqual(transport.tool('authorization.permissions.read',{'view':'ROLES'},'read'),self.obs['roles'])
        payload=request.call_args.args[2]
        self.assertEqual(payload['params']['_meta']['io.modelcontextprotocol/protocolVersion'],'2026-07-28')
        self.assertEqual(payload['params']['_meta']['io.modelcontextprotocol/clientCapabilities'],{})
        self.assertEqual(payload['params']['name'],'authorization.permissions.read')
    def test_actual_mcp_read_keys_are_fresh_and_pacing_does_not_change_command_identity(self):
        now=[100.0];delays=[]
        def wait(delay):delays.append(delay);now[0]+=delay
        transport=OwnerTransport(self.selection,Path('/unused/admin'),Path('/unused/mcp'),wait=wait)
        reply={'jsonrpc':'2.0','result':{'content':[{'type':'text','text':'{}'}]}}
        import tools.chatbot_file_cohort.authorization as module
        with patch.object(module.time,'monotonic',side_effect=lambda:now[0]),patch.object(transport,'request',return_value=(200,reply,{})) as req:
            for _ in range(2):transport.tool('authorization.permissions.read',{'view':'ROLES'},'same-read')
            for _ in range(2):transport.tool('authorization.permissions.propose',{'operation':'REPLACE_ROLES'},'same-command')
        keys=[c.kwargs['key'] for c in req.call_args_list]
        self.assertNotEqual(keys[0],keys[1]);self.assertEqual(keys[2:],['same-command','same-command'])
        self.assertEqual(delays,[31,31,31])
    def test_role_cache_requires_same_fresh_owner_policy_and_invalidates_on_publication(self):
        transport=OwnerTransport(self.selection,Path('/unused/admin'),Path('/unused/mcp'))
        active=copy.deepcopy(self.obs['active']);roles=copy.deepcopy(self.obs['roles'])
        with patch.object(transport,'active',side_effect=lambda:copy.deepcopy(active)),patch.object(transport,'tool',side_effect=lambda *_:copy.deepcopy(roles)) as tool:
            self.assertEqual(transport.roles(),roles);self.assertEqual(transport.roles(),roles)
            self.assertEqual(tool.call_count,1)
            active['contentHash']='different-published-hash';active['policyRef']='fixture-policy:39'
            roles['roles'][0]['displayName']='Changed by owner'
            self.assertEqual(transport.roles(),roles);self.assertEqual(tool.call_count,2)
        with patch.object(transport,'active',side_effect=[active,dict(active,contentHash='drift')]),patch.object(transport,'tool',return_value=roles):
            transport._role_cache=None
            with self.assertRaisesRegex(ValueError,'ROLE_POLICY_CHANGED_DURING_READ'):transport.roles()


class ComposedAuthorizationTest(unittest.TestCase):
    def setUp(self):
        self.crypto=signed.SignedCutover();self.crypto.setUp();self.addCleanup(self.crypto.doCleanups)
        self.primitives=helpers();selection,observed=fixture()
        self.plan=compile_plan(observed,self.primitives,selection,now='2026-10-14T09:00:00Z')
        f=self.crypto;authority=json.loads(f.authority);authority['chatbotFileAuthorization']=authorization_scope(self.plan)
        f.authority=encoded(authority);f.approval['executionAuthorityHash']=signed.sha(f.authority)
        f.write(f.mandate,encoded(f.approval));f.approved=signed.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        action=AggregateAction(f.gate(),f.authority,f.expected['sourceClosureHash'])
        directory=f.root/'authorization';directory.mkdir(mode=0o700);journal=Journal(directory)
        transport=OwnerTransport(selection,f.root/'unused-admin.jwt',f.root/'unused-mcp.jwt')
        self.owner=OwnerFixture(observed,self.plan)
        for method in ('observe','active','roles','registrations','oauth','request','kc','tool'):
            p=patch.object(transport,method,side_effect=getattr(self.owner,method));p.start();self.addCleanup(p.stop)
        self.delta=AuthorizationDelta(action,self.plan,journal,transport,self.primitives);self.delta.initialize()
    def prepare(self):
        with self.assertRaisesRegex(AuthorizationPaused,'HUMAN_OWNER_ROLE_CONFIRMATION_REQUIRED') as error:self.delta.apply()
        self.assertTrue(error.exception.detail['approvalPath'].startswith('https://ths.fixture.invalid/'))
    def test_complete_real_signed_action_preserves_prior_data_waits_for_human_and_resumes_without_replay(self):
        self.prepare()
        self.assertEqual(self.owner.roles(),self.plan['baseline']['roles'])
        self.assertEqual(self.owner.active()['policy']['grants'],self.plan['baseline']['active']['policy']['grants'])
        count=len(self.owner.calls);self.prepare()
        self.assertEqual(len(self.owner.drafts),1);self.assertEqual(len(self.owner.proposals),1)
        self.owner.human_confirms();receipt=self.delta.apply()
        self.assertEqual(receipt['status'],'OWNER_POLICY_ROLES_SCOPES_RECONCILED')
        self.assertFalse(receipt['freshClientTokenScopesProven']);self.assertFalse(receipt['runtimeAuthorityIssued'])
        mutations=[c for c in self.owner.calls if c[0] in ('POST','KC:create','KC:update','authorization.permissions.propose')]
        self.delta.apply()
        self.assertEqual(mutations,[c for c in self.owner.calls if c[0] in ('POST','KC:create','KC:update','authorization.permissions.propose')])
    def test_lost_registration_response_reconciles_and_does_not_register_twice(self):
        self.owner.lost=('POST',ADMIN+'/capabilities')
        with self.assertRaisesRegex(AuthorizationPaused,'LOST_RESPONSE'):self.delta.apply()
        self.prepare()
        self.assertEqual(self.owner.calls.count(('POST',ADMIN+'/capabilities')),3)
    def test_ambiguous_non_idempotent_draft_is_not_recreated_and_exact_owner_id_can_reconcile(self):
        self.owner.lost=('POST',ADMIN+'/policies')
        with self.assertRaisesRegex(AuthorizationPaused,'LOST_RESPONSE'):self.delta.apply()
        with self.assertRaisesRegex(AuthorizationPaused,'EFFECT_RECONCILIATION_REQUIRED'):self.delta.apply()
        self.assertEqual(len(self.owner.drafts),1)
        self.delta.reconcile_draft(next(iter(self.owner.drafts)));self.prepare()
        self.assertEqual(len(self.owner.drafts),1)
    def test_publish_response_loss_reads_active_without_second_publish(self):
        path=ADMIN+'/policies/11111111-1111-4111-8111-000000000001:publish';self.owner.lost=('POST',path)
        with self.assertRaisesRegex(AuthorizationPaused,'LOST_RESPONSE'):self.delta.apply()
        self.prepare();self.assertEqual(self.owner.calls.count(('POST',path)),1)
    def test_revoked_human_mandate_blocks_all_mutations(self):
        self.crypto.approval['state']='REVOKED';self.crypto.write(self.crypto.mandate,encoded(self.crypto.approval))
        with self.assertRaises(Exception):self.delta.apply()
        self.assertFalse(self.owner.calls)
    def test_idempotent_proposal_lost_reply_keeps_key_budget_and_backoff_across_resume(self):
        self.owner.proposal_failure='AUTHORIZATION_TRANSPORT_OUTCOME_UNPROVEN'
        with self.assertRaisesRegex(AuthorizationPaused,'OUTCOME_UNPROVEN'):self.delta.apply()
        record=self.delta.record();effect=record['effects']['role-proposal'];self.assertEqual(effect['attempts'],1)
        with self.assertRaisesRegex(AuthorizationPaused,'RETRY_NOT_DUE'):self.delta.apply()
        import tools.chatbot_file_cohort.authorization as module
        with patch.object(module.time,'time',return_value=effect['nextAttemptAt']+1):self.prepare()
        self.assertEqual(len(self.owner.proposals),1)
        self.assertEqual(self.delta.record()['effects']['role-proposal']['attempts'],2)
    def test_permanent_proposal_error_never_uses_idempotency_to_auto_retry(self):
        self.owner.proposal_failure='AUTHORIZATION_HTTP_403'
        with self.assertRaisesRegex(AuthorizationPaused,'HTTP_403'):self.delta.apply()
        with self.assertRaisesRegex(AuthorizationPaused,'PERMANENT_EFFECT_REQUIRES_RECONCILIATION'):self.delta.apply()
        self.assertEqual(sum(c[0]=='authorization.permissions.propose' for c in self.owner.calls),1)
    def test_retry_status_requires_exact_retained_effect_and_remaining_budget(self):
        self.owner.proposal_failure='AUTHORIZATION_HTTP_503'
        with self.assertRaises(AuthorizationPaused) as failed:self.delta.apply()
        before=self.delta.record();status=self.delta.retry_status(failed.exception)
        self.assertEqual(status['effect'],'role-proposal');self.assertEqual(status['remainingAttempts'],127)
        self.assertEqual(before,self.delta.record())
        self.assertIsNone(self.delta.retry_status(AuthorizationPaused('AUTHORIZATION_HTTP_503')))
        self.assertIsNone(self.delta.retry_status(AuthorizationPaused('AUTHORIZATION_HTTP_403',effect='role-proposal')))
        self.assertIsNone(self.delta.retry_status(AuthorizationPaused('AUTHORIZATION_RETRY_NOT_DUE',effect='role-proposal',nextAttemptAt=0)))
        with self.assertRaises(AuthorizationPaused) as pending:self.delta.apply()
        self.assertEqual(self.delta.retry_status(pending.exception),status)
        import tools.chatbot_file_cohort.authorization as module
        with patch.object(module.time,'time',return_value=status['deadline']):
            self.assertIsNone(self.delta.retry_status(failed.exception))
    def test_release_reverify_rejects_direct_grant_removal_unreviewed_addition_and_scope_drift(self):
        self.prepare();self.owner.human_confirms();self.delta.verify()
        grants=self.owner.current['active']['policy']['grants'];saved=copy.deepcopy(grants)
        grants.pop(0)
        with self.assertRaisesRegex(ValueError,'GRANT_CHANGED_OR_REMOVED'):self.delta.verify()
        grants[:]=saved+[dict(saved[0],grantId='unreviewed-extra')]
        with self.assertRaisesRegex(ValueError,'UNREVIEWED_GRANT_ADDITION'):self.delta.verify()
        grants[:]=saved
        self.owner.current['oauth']['scopes']['ouf.semantic.read']['attributes']['include.in.token.scope']='false'
        with self.assertRaisesRegex(ValueError,'SCOPE_DEFINITION_DRIFT'):self.delta.verify()


if __name__=='__main__':unittest.main()
