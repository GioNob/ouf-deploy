"""Current owner APIs and additive OAuth scopes under one signed cohort action.

Registration is distinct from ACTIVE policy and from role publication. Role
confirmation remains the existing browser THS operation; this CLI prepares its
idempotent proposal and resumes by reading the owner. No DB bootstrap, token
issuance, session revocation, implicit authority or automatic rollback exists.
"""
import copy
import base64
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import time
import types
import secrets
import urllib.error
import urllib.parse
import urllib.request
import uuid

from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.plan import digest, encoded, require

PROFILE = 'ouf.chatbot-file-authorization.v1'
RETRY = {'maximumAttempts':128,'maximumElapsedSeconds':86400,'backoffSeconds':[5,15,60,300,900],'maximumJitterPercent':20}
ADMIN = '/api/trusted-human/v1/authorization'
NEW = {
    'ouf.managed-source.onboarding.review.prepare': ('onboarding', 'COMMAND', 'source'),
    'ouf.managed-source.onboarding.read': ('onboarding', 'READ', 'source'),
    'ouf.semantic.proposal.read': ('semantic', 'READ', 'semantic.proposalcommand'),
}
CHAT = ['ouf.managed-source.file.upload','ouf.managed-source.file.profile','ouf.managed-source.preview',
        'ouf.managed-source.onboarding.create','ouf.semantic.propose','ouf.semantic.review.prepare',
        'ouf.semantic.approval.request','ouf.semantic.search','ouf.semantic.read','urban.object.search',*NEW]
BROWSER = ['ouf.managed-source.file.upload','ouf.onboarding.configuration.write','ouf.semantic.review',
           'ouf.semantic.approve','ouf.semantic.publish','urban.identity.preflight',
           'resolution.issue.read','resolution.match.approve']


class AuthorizationPaused(RuntimeError):
    def __init__(self, reason, **detail):
        self.reason, self.detail = reason, detail
        super().__init__(reason)


class OwnerPrimitives:
    """Reuse the qualified Onboarding helpers; source bindings join the plan."""
    def __init__(self, directory, bindings):
        self.root, self.bindings = Path(directory), copy.deepcopy(bindings)
        required = {'scripts/r4a_authorization_lifecycle.py', 'scripts/r4a_keycloak_client_scope_catalogue.py',
                    'catalogue/chatbot-source-review-capabilities.json'}
        require(set(bindings) == required, 'EXACT_EXISTING_OWNER_HELPER_BINDINGS_REQUIRED')
        self.modules = {}
        for name in sorted(bindings):
            path = self.root/name
            require(path.is_file() and not path.is_symlink(), 'QUALIFIED_OWNER_SOURCE_REQUIRED')
            raw = path.read_bytes()
            require(len(raw) <= 131072 and hashlib.sha256(raw).hexdigest() == bindings[name],
                    'OWNER_HELPER_SOURCE_HASH_MISMATCH')
            if name.endswith('.py'):
                module = types.ModuleType('qualified_'+Path(name).stem)
                exec(compile(raw, name, 'exec'), module.__dict__)
                self.modules[Path(name).stem] = module
            else:
                self.descriptors = json.loads(raw)
        self.lifecycle = self.modules['r4a_authorization_lifecycle']
        self.scopes = self.modules['r4a_keycloak_client_scope_catalogue']
        self.validate_descriptors()

    @classmethod
    def from_qualified_modules(cls, lifecycle, scopes, catalogue, bindings):
        expected = {'scripts/r4a_authorization_lifecycle.py','scripts/r4a_keycloak_client_scope_catalogue.py',
                    'catalogue/chatbot-source-review-capabilities.json'}
        require(set(bindings) == expected and type(catalogue) is bytes
                and hashlib.sha256(catalogue).hexdigest() == bindings['catalogue/chatbot-source-review-capabilities.json'],
                'EXACT_MEMORY_LOADED_OWNER_BINDINGS_REQUIRED')
        for module, name, path in ((lifecycle,'qualified_owner_authorization_lifecycle','scripts/r4a_authorization_lifecycle.py'),
                                   (scopes,'qualified_owner_scope_catalogue','scripts/r4a_keycloak_client_scope_catalogue.py')):
            require(type(module) is types.ModuleType and module.__name__ == name
                    and getattr(module,'__qualified_source_sha256__',None) == bindings[path],
                    'QUALIFIED_OWNER_MODULE_CLOSURE_MISMATCH')
        result = cls.__new__(cls)
        result.bindings = copy.deepcopy(bindings)
        result.lifecycle,result.scopes,result.descriptors = lifecycle,scopes,json.loads(catalogue)
        result.validate_descriptors()
        return result

    def validate_descriptors(self):
        require(len(self.descriptors) == len(NEW) and {r['descriptor']['capabilityId'] for r in self.descriptors} == set(NEW),
                'EXACT_THREE_CHATBOT_DESCRIPTORS_REQUIRED')
        for row in self.descriptors:
            cap = row['descriptor']['capabilityId']; owner, operation, _ = NEW[cap]
            require(row == {'ownerRef': owner, 'descriptor': {'capabilityId':cap,'operation':operation,
                    'requiredScope':cap,'allowedActors':['HUMAN']}}, 'OWNER_DESCRIPTOR_SEMANTICS_CHANGED')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuthorizationPaused('AUTHORIZATION_REDIRECT_DENIED')


class OwnerTransport:
    """Selected HTTPS owner + existing HUMAN credentials and kcadm session.

    Credential bytes stay in memory. No browser cookies are read or fabricated.
    The server independently verifies both HUMAN credentials and write proof.
    """
    def __init__(self, selection, admin_token_file, mcp_token_file, *, wait=None):
        self.selection = copy.deepcopy(selection)
        require(set(selection) == {'origin','issuer','tenant','subject','docker','keycloakContainer','realm','clients'},
                'EXACT_AUTHORIZATION_TRANSPORT_SELECTION_REQUIRED')
        origin = urllib.parse.urlsplit(selection['origin'])
        require(origin.scheme == 'https' and origin.hostname and not origin.username and not origin.password
                and not origin.query and not origin.fragment and origin.path in ('','/'), 'SELECTED_HTTPS_OWNER_REQUIRED')
        require(re.fullmatch('[a-f0-9]{64}',selection['keycloakContainer']) is not None
                and re.fullmatch('[A-Za-z0-9._:-]{1,128}',selection['realm']) is not None,
                'EXACT_EXISTING_KEYCLOAK_SELECTION_REQUIRED')
        require(set(selection['docker']) == {'path','sha256'}, 'EXACT_DOCKER_EXECUTABLE_BINDING_REQUIRED')
        require(set(selection['clients']) == {'chatgpt','ths'} and all(set(c) == {'clientId','requestedScopes'}
                and re.fullmatch('[A-Za-z0-9._:-]{1,128}',c['clientId']) is not None
                and type(c['requestedScopes']) is list for c in selection['clients'].values()),
                'SELECTED_CHATGPT_AND_THS_CLIENTS_REQUIRED')
        self.tokens = {'admin':Path(admin_token_file), 'mcp':Path(mcp_token_file)}
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
        require(wait is None or callable(wait), 'AUTHORIZATION_WAIT_FUNCTION_REQUIRED')
        self.wait = time.sleep if wait is None else wait
        self._last_mcp_at, self._role_cache = None, None

    def token(self, kind):
        path = self.tokens[kind]
        require(path.is_absolute() and path.resolve() == path, 'EXACT_PRIVATE_HUMAN_CREDENTIAL_PATH_REQUIRED')
        fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 16384,
                    'PRIVATE_EXISTING_HUMAN_CREDENTIAL_REQUIRED')
            raw = os.read(fd,16385)
            after = os.fstat(fd)
            require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) ==
                    (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) and len(raw) == before.st_size,
                    'HUMAN_CREDENTIAL_CHANGED_DURING_READ')
            value = raw.decode('ascii').strip()
            require(value and not any(c.isspace() for c in value), 'INVALID_EXISTING_HUMAN_CREDENTIAL')
            # This is a local context check only. The HTTPS owner independently
            # validates the signature, issuer, audience and trusted write proof.
            parts = value.split('.')
            require(len(parts) == 3, 'EXISTING_HUMAN_JWT_REQUIRED')
            try: claims = json.loads(base64.urlsafe_b64decode(parts[1]+'='*(-len(parts[1])%4)))
            except Exception: raise AuthorizationPaused('HUMAN_CREDENTIAL_CONTEXT_UNREADABLE') from None
            required = {'authorization.policy.admin'} if kind == 'admin' else {
                'mcp.connect','authorization.permissions.read','authorization.permissions.propose','authorization.proposal.read'}
            require(claims.get('iss') == self.selection['issuer'] and claims.get('sub') == self.selection['subject']
                    and claims.get('tenant_id') == self.selection['tenant'] and claims.get('ouf_actor_type') == 'HUMAN'
                    and type(claims.get('exp')) in (int,float) and claims['exp'] > time.time()
                    and required <= set(str(claims.get('scope','')).split()), 'EXACT_CURRENT_HUMAN_SESSION_REQUIRED')
            return value
        finally:
            os.close(fd)

    def request(self, path, method='GET', body=None, etag=None, kind='admin', key=None):
        require(path.startswith(ADMIN+'/') or path == '/mcp', 'FIXED_AUTHORIZATION_OWNER_PATH_REQUIRED')
        raw = None if body is None else encoded(body)
        require(raw is None or len(raw) <= 5*1024*1024, 'BOUNDED_AUTHORIZATION_REQUEST_REQUIRED')
        headers = {'Authorization':'Bearer '+self.token(kind),'Accept':'application/json','Content-Type':'application/json'}
        if etag is not None: headers['If-Match'] = '"'+str(etag)+'"'
        if path == '/mcp':
            headers.update({'Mcp-Protocol-Version':'2026-07-28','Mcp-Method':'tools/call',
                            'Mcp-Name':body['params']['name'],
                            'Accept':'application/json, text/event-stream','Idempotency-Key':key})
        req = urllib.request.Request(self.selection['origin'].rstrip('/')+path,data=raw,method=method,headers=headers)
        try:
            with self.opener.open(req,timeout=30) as reply:
                data = reply.read(8_000_001)
                require(len(data) <= 8_000_000, 'BOUNDED_AUTHORIZATION_RESPONSE_REQUIRED')
                if reply.headers.get('Content-Type','').startswith('text/event-stream'):
                    events = [v[6:] for v in data.decode().splitlines() if v.startswith('data: ')]
                    require(len(events) == 1, 'EXACT_MCP_RESPONSE_REQUIRED'); data = events[0].encode()
                return reply.status, json.loads(data) if data else None, dict(reply.headers)
        except urllib.error.HTTPError as e:
            retry = e.headers.get('Retry-After','') if e.headers else ''
            delay = None
            try:
                delay = float(retry) if retry.isdigit() else max(0,parsedate_to_datetime(retry).timestamp()-time.time())
            except (ValueError,TypeError,OverflowError): pass
            raise AuthorizationPaused('AUTHORIZATION_HTTP_'+str(e.code),retryAfterSeconds=delay) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise AuthorizationPaused('AUTHORIZATION_TRANSPORT_OUTCOME_UNPROVEN') from None

    def tool(self, name, arguments, key):
        require(name in ('authorization.permissions.read','authorization.permissions.propose','authorization.proposal.read'),
                'EXACT_EXISTING_PERMISSION_TOOL_REQUIRED')
        # Actual MCP retains read admission claims but does not replay payloads.
        # A fresh read key does not reset its principal/tenant budget or query guard.
        if name != 'authorization.permissions.propose':
            key = key+':'+str(uuid.uuid4())
        # Existing admission permits three calls/minute, and at most two equivalent
        # queries. Pace the client; never change server budgets to make delivery pass.
        if self._last_mcp_at is not None:
            delay = self._last_mcp_at + 31 - time.monotonic()
            if delay > 0: self.wait(delay)
        self._last_mcp_at = time.monotonic()
        status, reply, _ = self.request('/mcp','POST',{'jsonrpc':'2.0','id':key,'method':'tools/call',
            'params':{'name':name,'arguments':arguments,'_meta':{
                'io.modelcontextprotocol/protocolVersion':'2026-07-28',
                'io.modelcontextprotocol/clientCapabilities':{},
                'io.modelcontextprotocol/clientInfo':{'name':'ouf-cohort-authorization','version':'1'}}}},kind='mcp',key=key)
        require(status == 200 and type(reply) is dict and 'error' not in reply, 'OWNER_PERMISSION_TOOL_UNAVAILABLE')
        result = reply.get('result',{})
        require(result.get('isError') is not True, 'OWNER_PERMISSION_TOOL_DENIED')
        if 'structuredContent' in result: return result['structuredContent']
        texts = [r['text'] for r in result.get('content',[]) if r.get('type') == 'text']
        require(len(texts) == 1, 'EXACT_PERMISSION_OWNER_RESULT_REQUIRED')
        return json.loads(texts[0])

    def kc(self, verb, path, *query, body=None):
        binary = Path(self.selection['docker']['path']); info = binary.lstat()
        require(binary.is_absolute() and stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode&0o022
                and hashlib.sha256(binary.read_bytes()).hexdigest() == self.selection['docker']['sha256'],
                'AUTHORIZATION_DOCKER_EXECUTABLE_DRIFT')
        require(verb in ('get','create','update') and re.fullmatch(r'[A-Za-z0-9_./:-]+',path), 'BOUNDED_KCADM_OPERATION_REQUIRED')
        args = [str(binary),'exec','-i',self.selection['keycloakContainer'],'/opt/keycloak/bin/kcadm.sh',verb,path,
                '-r',self.selection['realm'],*query]
        if body is not None: args += ['-f','-']
        try:
            result = subprocess.run(args,input=None if body is None else encoded(body),stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,timeout=25,check=False)
        except (OSError,TimeoutError,subprocess.TimeoutExpired):
            raise AuthorizationPaused('IAM_ADMIN_OUTCOME_UNPROVEN') from None
        require(len(result.stdout) <= 8_000_000 and len(result.stderr) <= 262144, 'BOUNDED_EXISTING_IAM_REPLY_REQUIRED')
        if result.returncode:
            reason = 'EXISTING_IAM_SESSION_EXPIRED' if b'Session has expired' in result.stderr+result.stdout else 'EXISTING_IAM_ADMIN_UNAVAILABLE'
            raise AuthorizationPaused(reason)
        # kcadm write acknowledgements are informational text, not owner JSON.
        # Every mutation is accepted only after a separate metadata read-back.
        return json.loads(result.stdout) if verb == 'get' and result.stdout.strip() else None

    def active(self): return self.request(ADMIN+'/policies/active')[1]

    def roles(self, active=None):
        # The owner changes its role catalogue only inside the same locked policy
        # publication transaction (OufRoleCatalogueStore.stage / decide). Validate
        # that owner policy afresh; cached roles never survive a version/hash change.
        current = self.active() if active is None else active
        if self._role_cache is not None and self._role_cache[0] == current:
            return copy.deepcopy(self._role_cache[1])
        roles = self.tool('authorization.permissions.read',{'view':'ROLES'},'cohort:roles:read')
        require(self.active() == current, 'ROLE_POLICY_CHANGED_DURING_READ')
        self._role_cache = (copy.deepcopy(current),copy.deepcopy(roles))
        return roles

    def registrations(self):
        rows = []
        for offset in range(0,10001,200):
            page = self.request(ADMIN+'/capabilities?limit=200&offset='+str(offset))[1]
            require(type(page) is list and len(page) <= 200, 'BOUNDED_OWNER_CATALOGUE_PAGE_REQUIRED')
            rows += page
            if len(page) < 200: break
        else: raise AuthorizationPaused('OWNER_CATALOGUE_BOUND_EXCEEDED')
        result = {}
        for row in rows:
            d = row['descriptor']
            if type(d) is dict and d.get('type') == 'jsonb': d = d['value']
            if type(d) is str: d = json.loads(d)
            cap = row['capability_id']; require(cap not in result, 'OWNER_CATALOGUE_DUPLICATE_OR_CHANGED')
            result[cap] = {'ownerRef':row['owner_ref'],'descriptor':d}
        return result

    def oauth(self):
        catalogue = self.kc('get','client-scopes')
        require(type(catalogue) is list and len(catalogue) <= 10000, 'BOUNDED_OIDC_SCOPE_CATALOGUE_REQUIRED')
        scopes = {}
        for row in catalogue:
            require(row['name'] not in scopes, 'DUPLICATE_OIDC_SCOPE_NAME')
            scopes[row['name']] = row
        clients = {}
        for purpose, selection in self.selection['clients'].items():
            found = self.kc('get','clients','-q','clientId='+selection['clientId'], '--fields','id,clientId,enabled,protocol')
            require(type(found) is list and len(found) == 1 and found[0]['clientId'] == selection['clientId']
                    and found[0].get('enabled') is True and found[0].get('protocol') == 'openid-connect',
                    'EXACT_ENABLED_OAUTH_CLIENT_REQUIRED')
            client = found[0]
            row = {'id':client['id'],'clientId':client['clientId'],'requestedScopes':selection['requestedScopes']}
            for kind in ('default','optional'):
                values = self.kc('get','clients/'+client['id']+'/'+kind+'-client-scopes','--fields','id,name')
                require(type(values) is list and len(values) <= 1000, 'BOUNDED_OAUTH_BINDINGS_REQUIRED')
                row[kind] = sorted(values,key=lambda x:x['id'])
            require(not ({x['id'] for x in row['default']} & {x['id'] for x in row['optional']}),
                    'CONFLICTING_OAUTH_BINDINGS')
            clients[purpose] = row
        return {'scopes':scopes,'clients':clients}

    def observe(self):
        # Complete preflight before any mutation, including both HUMAN sessions.
        active = self.active(); roles = self.roles(active); registrations = self.registrations(); oauth = self.oauth()
        require(self.active() == active, 'AUTHORIZATION_BASELINE_CHANGED_DURING_READ')
        return {'active':active,'roles':roles,'registrations':registrations,'oauth':oauth}


def compile_plan(observed, primitives, selection, *, role_id='admin', include_ingestion_status=True, now=None):
    require(type(primitives) is OwnerPrimitives, 'QUALIFIED_EXISTING_OWNER_PRIMITIVES_REQUIRED')
    active, roles = observed['active'], observed['roles']
    require(set(roles) == {'issuer','roles','assignments'} and roles['issuer'] == selection['issuer'],
            'COMPLETE_CURRENT_ROLE_CATALOGUE_REQUIRED')
    matches = [r for r in roles['roles'] if r['roleId'] == role_id]
    when = datetime.fromisoformat(now.replace('Z','+00:00')) if now else datetime.now(timezone.utc)
    require(len(matches) == 1 and any(a['roleId'] == role_id and a.get('subjectId') == selection['subject']
            and datetime.fromisoformat(a['validFrom'].replace('Z','+00:00')) <= when < datetime.fromisoformat(a['validUntil'].replace('Z','+00:00'))
            for a in roles['assignments']), 'EXISTING_NOMINAL_ADMIN_ASSIGNMENT_REQUIRED')
    desired = [primitives.lifecycle.normalize_descriptor(r['descriptor']) for r in primitives.descriptors]
    missing_registration = []
    for row in primitives.descriptors:
        retained = observed['registrations'].get(row['descriptor']['capabilityId'])
        if retained is None: missing_registration.append(row)
        else: require(retained == row, 'EXISTING_DESCRIPTOR_REGISTRATION_CONFLICT')
    caps = {c['capabilityId']:c for c in active['policy']['capabilities']}
    additions = []
    for cap, (_, _, resource) in NEW.items():
        additions.append({'capabilityId':cap,'constraints':{'effect':'ALLOW','resourceType':resource,
            'resourceAttributes':{'module':'SEMANTIC'} if resource == 'semantic.proposalcommand' else {}}})
    if include_ingestion_status:
        cap = 'ingestion.operations.read'; registered = observed['registrations'].get(cap)
        require(registered is not None and registered['descriptor'] == caps.get(cap)
                and caps[cap]['operation'] == 'READ' and caps[cap]['requiredScope'] == cap
                and 'HUMAN' in caps[cap]['allowedActors'], 'EXISTING_INGESTION_STATUS_DESCRIPTOR_UNPROVEN')
        additions.append({'capabilityId':cap,'constraints':{'effect':'ALLOW','resourceType':'operational',
            'resourceAttributes':{'module':'INGESTION'},'allowedDetailLevels':['TENANT_OPERATIONAL']}})
    target_roles = copy.deepcopy(roles)
    target = next(r for r in target_roles['roles'] if r['roleId'] == role_id)
    existing = {p['capabilityId']:p for p in target['permissions']}
    new_permissions = []
    for permission in additions:
        if permission['capabilityId'] in existing:
            # Do not replace established constraints merely because a role exists.
            constraint = existing[permission['capabilityId']].get('constraints')
            require(constraint is None or normalized_grant({'constraints':constraint}) == normalized_grant({'constraints':permission['constraints']}),
                    'EXISTING_ROLE_PERMISSION_CONSTRAINT_REVIEW_REQUIRED')
            continue
        target['permissions'].append(permission); new_permissions.append(permission)
    require(len(encoded(target_roles)) <= 45000, 'OWNER_ROLE_PROPOSAL_SIZE_LIMIT')
    candidate, missing = primitives.lifecycle.build_candidate(active,desired,now=now)
    scope_creations = {}; scope_bindings = []
    required = {'chatgpt':CHAT+(['ingestion.operations.read'] if include_ingestion_status else []),'ths':BROWSER}
    for purpose, names in required.items():
        client = observed['oauth']['clients'][purpose]
        require(client['clientId'] == selection['clients'][purpose]['clientId'], 'OAUTH_CLIENT_SELECTION_DRIFT')
        defaults = {x['name'] for x in client['default']}; optional = {x['name'] for x in client['optional']}
        for name in names:
            scope = observed['oauth']['scopes'].get(name)
            if scope is None:
                require(name in NEW or name == 'ingestion.operations.read', 'PREEXISTING_REQUIRED_OAUTH_SCOPE_MISSING:'+name)
                scope_creations[name] = primitives.scopes.desired(name)
            else:
                require(scope.get('protocol') == 'openid-connect'
                        and str((scope.get('attributes') or {}).get('include.in.token.scope')).lower() == 'true',
                        'EXISTING_OAUTH_SCOPE_CONTRACT_DRIFT:'+name)
                if name in NEW:
                    require(not scope.get('protocolMappers'), 'NEW_AUTHORIZATION_SCOPE_MAPPER_REQUIRES_REVIEW')
            if name in defaults: continue
            if name in optional:
                require(name in client['requestedScopes'], 'OPTIONAL_SCOPE_NOT_REQUESTED:'+purpose+':'+name)
                continue
            scope_bindings.append({'purpose':purpose,'clientId':client['id'],'scopeName':name,'kind':'default'})
    plan = {'schema':'ouf.chatbot-file-authorization-plan.v1','profile':PROFILE,'selection':copy.deepcopy(selection),
            'helperBindings':copy.deepcopy(primitives.bindings),'baseline':copy.deepcopy(observed),
            'registrationAdditions':missing_registration,'candidatePolicy':candidate,'addedDescriptors':missing,
            'targetRoles':target_roles,'addedPermissions':new_permissions,'roleId':role_id,
            'scopeCreations':scope_creations,'scopeBindings':scope_bindings,'requiredScopes':required,
            'roleProposal':{'operation':'REPLACE_ROLES','reason':'Complete the reviewed CSV chatbot workflow and its bounded status reads.',
                            'roleCatalogue':target_roles} if new_permissions else None,
            'preserveExistingGrants':True,'preserveRoleAssignments':True,'revokeSessions':False,
            'issueTokens':False,'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}
    return plan


def authorization_scope(plan):
    return {'profile':PROFILE,'planHash':digest(plan),'basePolicyRef':plan['baseline']['active']['policyRef'],
            'basePolicyHash':plan['baseline']['active']['contentHash'],
            'descriptorDeltaHash':digest({'registrations':plan['registrationAdditions'],'descriptors':plan['addedDescriptors']}),
            'roleDeltaHash':digest(plan['roleProposal']),
            'oauthDeltaHash':digest({'create':plan['scopeCreations'],'bind':plan['scopeBindings']}),
            'preserveExistingGrants':True,'preserveRoleAssignments':True,'sessionRevocationAuthorized':False,
            'tokenIssuanceAuthorized':False,'roleConfirmationRequiresOwnerHumanSession':True,'retryPolicy':RETRY}


class AuthorizationDelta:
    def __init__(self, action, plan, journal, transport, primitives):
        require(type(action) is AggregateAction and type(journal) is Journal and type(transport) is OwnerTransport
                and type(primitives) is OwnerPrimitives, 'REAL_AGGREGATE_AUTHORIZATION_COMPONENTS_REQUIRED')
        self.action,self.plan,self.journal,self.transport,self.primitives = action,copy.deepcopy(plan),journal,transport,primitives
        require(plan.get('schema') == 'ouf.chatbot-file-authorization-plan.v1' and plan['selection'] == transport.selection
                and plan['helperBindings'] == primitives.bindings, 'EXACT_AUTHORIZATION_PLAN_SELECTION_REQUIRED')
        self.hash,self.scope = digest(plan),authorization_scope(plan)

    def guard(self):
        require(digest(self.plan) == self.hash and authorization_scope(self.plan) == self.scope, 'AUTHORIZATION_PLAN_DRIFT')
        self.action.guard('chatbotFileAuthorization',self.scope)

    def initialize(self):
        self.guard()
        self.journal.initialize({'schema':'ouf.chatbot-file-authorization-journal.v1','planHash':self.hash,
            'authorityHash':self.action.authority_hash,'version':1,'effects':{},'budgetReset':False})

    def record(self):
        row = self.journal.read()
        require(row.get('schema') == 'ouf.chatbot-file-authorization-journal.v1' and row.get('planHash') == self.hash
                and row.get('authorityHash') == self.action.authority_hash and row.get('budgetReset') is False,
                'AUTHORIZATION_JOURNAL_SCOPE_DRIFT')
        for effect in row['effects'].values():
            require(effect.get('state') in ('CLAIMED','DISPATCHED','APPLIED')
                    and type(effect.get('attempts')) is int and 1 <= effect['attempts'] <= RETRY['maximumAttempts']
                    and type(effect.get('startedAt')) in (int,float)
                    and type(effect.get('nextAttemptAt')) in (int,float), 'AUTHORIZATION_EFFECT_HISTORY_DRIFT')
        return row

    def save_effect(self, name, value):
        before = self.record(); following = copy.deepcopy(before)
        following['effects'][name] = value; following['version'] += 1
        self.journal.compare_and_save(before,following)

    def retry_status(self, error):
        """Read the exact retained retry claim; never grant retry from error text alone."""
        self.guard()
        if type(error) is not AuthorizationPaused:
            return None
        effect_name = error.detail.get('effect')
        if type(effect_name) is not str:
            return None
        effect = self.record()['effects'].get(effect_name)
        if (effect is None or effect['state'] != 'CLAIMED' or effect.get('retryAllowed') is not True
                or (error.reason != effect.get('failureReason') and error.reason != 'AUTHORIZATION_RETRY_NOT_DUE')):
            return None
        now = time.time(); deadline = effect['startedAt'] + RETRY['maximumElapsedSeconds']
        if (effect['attempts'] >= RETRY['maximumAttempts'] or now >= deadline
                or effect['nextAttemptAt'] >= deadline):
            return None
        if (error.reason == 'AUTHORIZATION_RETRY_NOT_DUE'
                and error.detail.get('nextAttemptAt') != effect['nextAttemptAt']):
            return None
        return {'effect':effect_name,'failureReason':effect['failureReason'],
                'nextAttemptAt':effect['nextAttemptAt'],'attempts':effect['attempts'],
                'remainingAttempts':RETRY['maximumAttempts']-effect['attempts'],
                'deadline':deadline,'planHash':self.hash,'budgetReset':False}

    def reconcile_draft(self, draft_id):
        """Recover a lost create acknowledgement from an owner-observed draft ID.

        There is no draft listing endpoint. This explicit read never creates a
        replacement draft or guesses an ID, and only accepts exact planned bytes.
        """
        self.guard(); require(str(uuid.UUID(draft_id)) == draft_id, 'EXACT_OBSERVED_DRAFT_ID_REQUIRED')
        with self.journal.invocation():
            prior = self.record()['effects'].get('descriptor-policy-draft')
            require(prior is not None and prior['state'] == 'CLAIMED', 'ONLY_AMBIGUOUS_DRAFT_CREATE_CAN_BE_RECONCILED')
            draft = self.transport.request(ADMIN+'/policies/'+draft_id)[1]
            require(draft['state'] == 'DRAFT' and draft['baseActiveRef'] == self.plan['baseline']['active']['policyRef']
                    and draft['policy'] == self.plan['candidatePolicy'], 'EXACT_OWNER_DRAFT_RECONCILIATION_REQUIRED')
            self.guard()
            self.save_effect('descriptor-policy-draft',{**prior,'state':'APPLIED','evidence':{'id':draft_id,'revision':draft['revision']}})

    def effect(self, name, mutate, reconcile, *, retry_idempotent=False):
        """Claim before dispatch. A retained claim only reads back unless dedup is proven."""
        self.guard(); row = self.record(); prior = row['effects'].get(name)
        if prior:
            found = reconcile(prior)
            if found is not None:
                if prior.get('state') != 'APPLIED' or prior.get('evidence') != found:
                    self.save_effect(name,{**prior,'state':'APPLIED','evidence':found})
                return found
            if not retry_idempotent: raise AuthorizationPaused('AUTHORIZATION_EFFECT_RECONCILIATION_REQUIRED',effect=name)
            if prior.get('retryAllowed') is not True:
                raise AuthorizationPaused('AUTHORIZATION_UNKNOWN_OR_PERMANENT_EFFECT_REQUIRES_RECONCILIATION',effect=name)
            require(prior['attempts'] < RETRY['maximumAttempts'] and time.time()-prior['startedAt'] < RETRY['maximumElapsedSeconds'],
                    'AUTHORIZATION_DURABLE_RETRY_BUDGET_EXHAUSTED')
            if time.time() < prior['nextAttemptAt']:
                raise AuthorizationPaused('AUTHORIZATION_RETRY_NOT_DUE',effect=name,nextAttemptAt=prior['nextAttemptAt'])
            claim = {**prior,'state':'CLAIMED','attempts':prior['attempts']+1}
        else:
            claim = {'state':'CLAIMED','attempts':1,'startedAt':time.time()}
        claim['retryAllowed'] = False
        delay = RETRY['backoffSeconds'][min(claim['attempts']-1,len(RETRY['backoffSeconds'])-1)]
        claim['nextAttemptAt'] = time.time()+delay*(1+secrets.randbelow(201)/1000)
        self.save_effect(name,claim)
        self.guard()
        try:
            reply = mutate()
        except AuthorizationPaused as failure:
            retryable = failure.reason in ('AUTHORIZATION_TRANSPORT_OUTCOME_UNPROVEN','AUTHORIZATION_HTTP_408',
                'AUTHORIZATION_HTTP_429','AUTHORIZATION_HTTP_502','AUTHORIZATION_HTTP_503','AUTHORIZATION_HTTP_504')
            retry_after = failure.detail.get('retryAfterSeconds')
            if type(retry_after) in (int,float) and retry_after >= 0:
                claim['nextAttemptAt'] = max(claim['nextAttemptAt'],time.time()+retry_after)
            self.save_effect(name,{**claim,'retryAllowed':bool(retry_idempotent and retryable),'failureReason':failure.reason})
            raise AuthorizationPaused(failure.reason,**{**failure.detail,'effect':name}) from failure
        self.save_effect(name,{**claim,'state':'DISPATCHED','reply':reply})
        self.guard(); found = reconcile({'reply':reply})
        if found is None: raise AuthorizationPaused('AUTHORIZATION_EFFECT_NOT_YET_RECONCILED',effect=name)
        self.save_effect(name,{**claim,'state':'APPLIED','evidence':found}); return found

    def policy_matches(self, current, expected):
        policy = current['policy']
        return all(policy.get(k) == expected.get(k) for k in ('bundleId','version','capabilities','grants'))

    def apply(self):
        self.guard()
        with self.journal.invocation():
            self.record()
            # No mutation if either HUMAN authentication or existing IAM session is unavailable.
            observed = self.transport.observe()
            baseline = self.plan['baseline']
            require(observed['roles'] in (baseline['roles'],self.plan['targetRoles']), 'ROLE_BASELINE_DRIFT')
            if (self.plan['roleProposal'] is not None and observed['roles'] == self.plan['targetRoles']
                    and 'role-proposal' in self.record()['effects']):
                return self.verify()
            if not self.record()['effects']:
                require(observed == baseline, 'COMPLETE_AUTHORIZATION_PREFLIGHT_DRIFT')
            for registration in self.plan['registrationAdditions']:
                cap = registration['descriptor']['capabilityId']
                def read_registration(_prior, cap=cap, registration=registration):
                    row = self.transport.registrations().get(cap)
                    require(row is None or row == registration, 'REGISTRATION_RECONCILIATION_CONFLICT')
                    return {'capabilityId':cap,'descriptorHash':digest(row)} if row else None
                self.effect('register:'+cap,lambda r=registration:self.transport.request(ADMIN+'/capabilities','POST',r)[0],read_registration)
            if self.plan['addedDescriptors']:
                def read_draft(prior):
                    saved = prior.get('reply') or prior.get('evidence')
                    if not saved: return None
                    draft_id = saved['id']
                    draft = self.transport.request(ADMIN+'/policies/'+draft_id)[1]
                    require(draft['policy'] == self.plan['candidatePolicy'] and draft['baseActiveRef'] == baseline['active']['policyRef'],
                            'AUTHORIZATION_DRAFT_CONTENT_DRIFT')
                    return {'id':draft_id,'revision':saved['revision']}
                def create_draft():
                    require(self.transport.active() == baseline['active'], 'ACTIVE_POLICY_CHANGED_BEFORE_DRAFT')
                    status,draft,_ = self.transport.request(ADMIN+'/policies','POST',self.plan['candidatePolicy'])
                    require(status == 200 and draft['state'] == 'DRAFT', 'OWNER_DRAFT_CREATE_UNPROVEN')
                    return {'id':draft['id'],'revision':draft['revision']}
                draft = self.effect('descriptor-policy-draft',create_draft,read_draft)
                def read_published(_prior):
                    current = self.transport.active()
                    if self.policy_matches(current,self.plan['candidatePolicy']):
                        return {'policyRef':current['policyRef'],'contentHash':current['contentHash']}
                    require(current == baseline['active'], 'ACTIVE_POLICY_DRIFT_DURING_PUBLICATION')
                    return None
                def publish():
                    preview = self.transport.request(ADMIN+'/policies/'+draft['id']+':preview','POST',etag=draft['revision'])[1]
                    self.primitives.lifecycle.validate_preview(preview,self.plan['addedDescriptors'])
                    require(self.transport.active() == baseline['active'], 'ACTIVE_POLICY_CHANGED_BEFORE_PUBLISH')
                    return self.transport.request(ADMIN+'/policies/'+draft['id']+':publish','POST',etag=draft['revision'])[0]
                self.effect('descriptor-policy-publish',publish,read_published)
            for name, definition in self.plan['scopeCreations'].items():
                def read_scope(_prior,name=name,definition=definition):
                    scope = self.transport.oauth()['scopes'].get(name)
                    if scope is None: return None
                    require(all(scope.get(k) == v for k,v in definition.items()) and not scope.get('protocolMappers'),
                            'CREATED_OAUTH_SCOPE_DRIFT')
                    return {'id':scope['id'],'name':name,'definitionHash':digest(definition)}
                self.effect('scope:'+name,lambda d=definition:self.transport.kc('create','client-scopes',body=d),read_scope)
            for binding in self.plan['scopeBindings']:
                name, purpose = binding['scopeName'],binding['purpose']
                def read_binding(_prior,binding=binding):
                    current = self.transport.oauth(); client = current['clients'][binding['purpose']]
                    require(client['id'] == binding['clientId'], 'OAUTH_CLIENT_REPLACED')
                    expected = current['scopes'][binding['scopeName']]['id']
                    return {'clientId':client['id'],'scopeId':expected,'kind':'default'} if any(r['id'] == expected for r in client['default']) else None
                def bind(binding=binding):
                    current = self.transport.oauth(); client = current['clients'][binding['purpose']]
                    require(client['id'] == binding['clientId'], 'OAUTH_CLIENT_REPLACED')
                    scope_id = current['scopes'][binding['scopeName']]['id']
                    require(not any(r['id'] == scope_id for r in client['optional']), 'OAUTH_BINDING_DRIFT')
                    return self.transport.kc('update','clients/'+client['id']+'/default-client-scopes/'+scope_id)
                self.effect('bind:'+purpose+':'+name,bind,read_binding)
            if self.plan['roleProposal'] is not None:
                key = 'cohort-roles:'+self.hash
                def read_proposal(prior):
                    saved = prior.get('reply') or prior.get('evidence')
                    if not saved: return None
                    return self.transport.tool('authorization.proposal.read',{'proposalId':saved['proposalId']},'cohort:proposal:read')
                def propose_roles():
                    current = self.transport.active()
                    expected = self.plan['candidatePolicy'] if self.plan['addedDescriptors'] else baseline['active']['policy']
                    require(self.policy_matches(current,expected) and self.transport.roles() == baseline['roles'],
                            'ROLE_PROPOSAL_BASELINE_DRIFT')
                    return self.transport.tool('authorization.permissions.propose',self.plan['roleProposal'],key)
                receipt = self.effect('role-proposal',propose_roles,
                                      read_proposal,retry_idempotent=True)
                if receipt['state'] != 'PUBLISHED':
                    raise AuthorizationPaused('HUMAN_OWNER_ROLE_CONFIRMATION_REQUIRED',proposalId=receipt['proposalId'],
                        approvalPath=receipt['approvalPath'],expiresAt=receipt['expiresAt'],state=receipt['state'])
            return self.verify()

    def verify(self):
        self.guard(); current = self.transport.observe(); baseline = self.plan['baseline']
        require(current['roles'] == self.plan['targetRoles'], 'REVIEWED_ROLE_PUBLICATION_NOT_RECONCILED')
        expected_caps = self.plan['candidatePolicy']['capabilities'] if self.plan['addedDescriptors'] else baseline['active']['policy']['capabilities']
        require(current['active']['policy']['capabilities'] == expected_caps, 'ACTIVE_CAPABILITY_SET_DRIFT')
        # The owner recompiles managed role grants atomically. Existing direct grants
        # and every preexisting role grant must remain byte-semantically unchanged.
        before = {g['grantId']:g for g in baseline['active']['policy']['grants']}
        after = {g['grantId']:g for g in current['active']['policy']['grants']}
        require(all(after.get(k) == v for k,v in before.items()), 'PREEXISTING_GRANT_CHANGED_OR_REMOVED')
        expected = expected_role_grant_additions(self.plan)
        extra = {k:v for k,v in after.items() if k not in before}
        require(set(extra) == set(expected) and all(normalized_grant(extra[k]) == normalized_grant(v) for k,v in expected.items()),
                'UNREVIEWED_GRANT_ADDITION_OR_ROLE_COMPILATION_DRIFT')
        version = baseline['active']['policy']['version'] + bool(self.plan['addedDescriptors']) + bool(self.plan['roleProposal'])
        require(current['active']['policy']['version'] == version and current['active']['policy']['bundleId'] == baseline['active']['policy']['bundleId'],
                'EXACT_AUTHORIZATION_PUBLICATION_LINEAGE_REQUIRED')
        for cap in NEW:
            require(current['registrations'].get(cap) == next(r for r in self.primitives.descriptors if r['descriptor']['capabilityId'] == cap),
                    'REGISTERED_DESCRIPTOR_DRIFT')
        for purpose,names in self.plan['requiredScopes'].items():
            client = current['oauth']['clients'][purpose]; original = baseline['oauth']['clients'][purpose]
            require(client['id'] == original['id'] and all(x in client[k] for k in ('default','optional') for x in original[k]),
                    'EXISTING_OAUTH_BINDING_CHANGED')
            available = {s['name'] for s in client['default']} | ({s['name'] for s in client['optional']} & set(client['requestedScopes']))
            require(set(names) <= available, 'REQUIRED_OAUTH_SCOPE_BINDING_NOT_RECONCILED')
            for name in names:
                actual = current['oauth']['scopes'].get(name)
                require(actual is not None and actual.get('protocol') == 'openid-connect'
                        and str((actual.get('attributes') or {}).get('include.in.token.scope')).lower() == 'true',
                        'REQUIRED_OAUTH_SCOPE_DEFINITION_DRIFT')
                retained = baseline['oauth']['scopes'].get(name)
                if retained is not None:
                    require(actual == retained, 'PREEXISTING_OAUTH_SCOPE_CHANGED')
        return {'schema':'ouf.chatbot-file-authorization-receipt.v1','status':'OWNER_POLICY_ROLES_SCOPES_RECONCILED',
            'planHash':self.hash,'policyRef':current['active']['policyRef'],'policyHash':current['active']['contentHash'],
            'roleCatalogueHash':digest(current['roles']),'oauthBindingsHash':digest(current['oauth']['clients']),
            'existingGrantsPreserved':True,'existingRoleAssignmentsPreserved':True,'sessionsRevoked':False,
            'tokenGrantRequests':0,'freshClientTokenScopesProven':False,'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}


def normalized_grant(grant):
    result = {k:grant.get(k) for k in ('grantId','capabilityId','tenantId','subjectId','servicePrincipalId',
                                     'organizationId','validFrom','validUntil')}
    c = grant.get('constraints') or {}
    result['constraints'] = {k:c.get(k) for k in ('effect','externalRoleRef','resourceType','resourceId','requiredAcr','maxAuthenticationAgeSeconds')}
    result['constraints']['effect'] = c.get('effect','ALLOW')
    result['constraints']['resourceAttributes'] = c.get('resourceAttributes') or {}
    for key in ('allowedDataLabels','allowedDetailLevels','requiredAmr'):
        result['constraints'][key] = sorted(c.get(key) or [])
    return result


def expected_role_grant_additions(plan):
    """Exact IDs/selectors from existing OufRoleCatalogue.compile; no publication."""
    result = {}; tenant = plan['selection']['tenant']
    prefix = 'ouf-role:'+hashlib.sha256(tenant.encode()).hexdigest()[:16]+':'
    for assignment in plan['targetRoles']['assignments']:
        if assignment['roleId'] != plan['roleId']: continue
        for permission in plan['addedPermissions']:
            cap = permission['capabilityId']
            grant_id = prefix+hashlib.sha256((assignment['assignmentId']+'\n'+cap).encode()).hexdigest()
            constraints = copy.deepcopy(permission['constraints'])
            constraints['externalRoleRef'] = assignment.get('externalRoleRef')
            result[grant_id] = {'grantId':grant_id,'capabilityId':cap,'tenantId':tenant,'subjectId':assignment.get('subjectId'),
                'servicePrincipalId':None,'organizationId':None,'validFrom':assignment['validFrom'],
                'validUntil':assignment['validUntil'],'constraints':constraints}
    return result
