"""One operator-consented admin password grant, identity lookup and policy read.

No refresh, retry, unattended login, policy write or runtime authority. The old
seven-request read stays unchanged. A fenced administrative successor records
its own finite allowance and carries the previous cumulative OAuth count.
"""
import base64
import http.client
import ipaddress
import os
from pathlib import Path, PurePosixPath
import re
import select
import stat
import subprocess
import termios
import time

CHECKPOINT = {'phase': 'NOT_STARTED', 'contextPath': None}
SCHEMA = 'ouf.iam-explicit-api-successor.v1'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def terminal(summary, phrase=None):
    """Controlling tty only; password echo restored even on timeout/interrupt."""
    fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_NOFOLLOW)
    old = None
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode) and os.isatty(fd), 'CONTROLLING_ADMIN_TERMINAL_REQUIRED')
        termios.tcflush(fd, termios.TCIFLUSH)
        if phrase is None:
            old = termios.tcgetattr(fd)
            hidden = termios.tcgetattr(fd)
            hidden[3] &= ~(termios.ECHO | termios.ECHONL)
            termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
            os.write(fd, ('\n' + summary + '\n> ').encode())
        else:
            os.write(fd, ('\n' + summary + '\nScrivi esattamente: ' + phrase + '\n> ').encode())
        require(bool(select.select([fd], [], [], 90)[0]), 'ADMIN_TERMINAL_INPUT_TIMEOUT_NO_REPLAY')
        raw = os.read(fd, 4097)
        require(0 < len(raw) <= 4096 and raw.endswith(b'\n') and b'\x00' not in raw,
            'BOUNDED_ADMIN_TERMINAL_LINE_REQUIRED')
        value = raw[:-1].decode('utf-8')
        if phrase is not None:
            require(value == phrase, 'EXACT_ADMIN_API_TERMINAL_CONSENT_REQUIRED')
            return True
        require(value and not any(c in value for c in '\r\n'), 'NONEMPTY_SINGLE_ADMIN_PASSWORD_REQUIRED')
        return value
    finally:
        if old is not None:
            termios.tcsetattr(fd, termios.TCSANOW, old)
            os.write(fd, b'\n')
        os.close(fd)


CHILD = r'''import http.client,ipaddress,json,os,re,signal,sys,urllib.parse
signal.alarm(8)
try:
 v=json.loads(sys.stdin.buffer.read(32769))
 if set(v)!={'host','port','adminRealm','clientId','expectedUser','targetRealm','targetClient','operation','credential','subject','clientUuid'}:raise ValueError()
 if not ipaddress.ip_address(v['host']).is_loopback or type(v['port'])is not int or not 1<=v['port']<=65535:raise ValueError()
 for k in ('adminRealm','clientId','expectedUser','targetRealm','targetClient'):
  if type(v[k])is not str or not re.fullmatch('[A-Za-z0-9._-]{1,128}',v[k]):raise ValueError()
 op=v['operation'];cred=v['credential']
 if type(cred)is not str or not 0<len(cred)<=16384 or any(c in cred for c in '\r\n\x00'):raise ValueError()
 headers={'Accept':'application/json','Connection':'close'};body=None;method='GET'
 if op=='PASSWORD_GRANT':
  path='/realms/'+v['adminRealm']+'/protocol/openid-connect/token';method='POST'
  headers['Content-Type']='application/x-www-form-urlencoded'
  body=urllib.parse.urlencode({'client_id':v['clientId'],'grant_type':'password','username':v['expectedUser'],'password':cred,'scope':'openid'})
 else:
  headers['Authorization']='Bearer '+cred
  base='/admin/realms/'+v['targetRealm']
  if op=='IDENTITY':
   if not re.fullmatch('[A-Za-z0-9_-]{1,128}',v['subject']):raise ValueError()
   path='/admin/realms/'+v['adminRealm']+'/users/'+v['subject']
  elif op=='REALM':path=base
  elif op=='CLIENT_LIST':path=base+'/clients?'+urllib.parse.urlencode({'clientId':v['targetClient'],'exact':'true','first':0,'max':2})
  elif op=='CLIENT':
   if not re.fullmatch('[A-Za-z0-9_-]{1,128}',v['clientUuid']):raise ValueError()
   path=base+'/clients/'+v['clientUuid']
  else:raise ValueError()
 fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
 c=http.client.HTTPConnection(v['host'],v['port'],timeout=6)
 c.request(method,path,body=body,headers=headers);r=c.getresponse();raw=r.read(524289)
 if len(raw)>524288:raise ValueError()
 result={'status':r.status,'body':json.loads(raw)if r.status==200 else None}
 out=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
 if len(out)>1048576:raise ValueError()
 sys.stdout.buffer.write(out);sys.stdout.buffer.flush();c.close()
except BaseException:os._exit(2)
os._exit(0)
'''


def dispatch(api, program, ns, payload):
    result = subprocess.run([api.executable(program), '-I', '-B', '-S', '-c', CHILD, str(ns)],
        input=api.encoded(payload), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=10, pass_fds=(ns,), env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'})
    require(result.returncode == 0 and 0 < len(result.stdout) <= 1048576,
        'ADMIN_API_OUTCOME_UNPROVEN_NO_RETRY')
    value = api.decode(result.stdout)
    require(type(value) is dict and value.get('status') == 200 and type(value.get('body')) in (dict, list),
        'ADMIN_API_DENIED_OR_RESPONSE_UNPROVEN_NO_RETRY')
    return value['body']


def access(api, response, endpoint, issuer, requested_at):
    require(type(response) is dict and response.get('token_type', '').lower() == 'bearer'
        and type(response.get('expires_in')) is int and 0 < response['expires_in'] <= 3600,
        'EXACT_FRESH_ADMIN_TOKEN_RESPONSE_REQUIRED')
    token = response.get('access_token')
    require(type(token) is str and len(token) <= 16384 and len(token.split('.')) == 3,
        'BOUNDED_FRESH_ADMIN_ACCESS_TOKEN_REQUIRED')
    part = token.split('.')[1]
    require(re.fullmatch('[A-Za-z0-9_-]+', part) is not None, 'FRESH_ADMIN_JWT_PAYLOAD_REQUIRED')
    claims = api.decode(base64.b64decode(part + '=' * (-len(part) % 4), altchars=b'-_', validate=True))
    allowed = {issuer.rsplit('/realms/', 1)[0] + '/realms/' + endpoint['adminRealm'],
        endpoint['storedServerUrl'] + '/realms/' + endpoint['adminRealm']}
    require(type(claims) is dict and claims.get('iss') in allowed,
        'FRESH_ADMIN_ACCESS_ISSUER_MUST_MATCH_SELECTED_PROVIDER')
    require(claims.get('azp') == endpoint['adminClientId'], 'FRESH_ADMIN_ACCESS_CLIENT_MUST_MATCH')
    require(type(claims.get('exp')) is type(claims.get('iat')) is int
        and requested_at - 10 <= claims['iat'] <= time.time() + 5,
        'FRESH_ADMIN_ACCESS_TIMESTAMPS_REQUIRED')
    # A lightweight access token can omit BOTH preferred_username and sub.
    # Resolve the routing subject from the ID token returned in this same
    # fresh, directly received password-grant response (scope=openid). This is
    # provider-channel provenance, not independent JWT signature validation.
    # A protected Admin user lookup must then prove username/id/enabled state.
    id_token = response.get('id_token')
    require(type(id_token) is str and len(id_token) <= 16384 and len(id_token.split('.')) == 3,
        'FRESH_ADMIN_OIDC_ID_TOKEN_REQUIRED_FOR_SUBJECT')
    part = id_token.split('.')[1]
    require(re.fullmatch('[A-Za-z0-9_-]+', part) is not None, 'BOUNDED_ADMIN_ID_TOKEN_PAYLOAD_REQUIRED')
    identity = api.decode(base64.b64decode(part + '=' * (-len(part) % 4), altchars=b'-_', validate=True))
    require(type(identity) is dict and identity.get('iss') == claims['iss'], 'SAME_PROVIDER_ADMIN_ID_TOKEN_ISSUER_REQUIRED')
    audience = identity.get('aud')
    require(audience == endpoint['adminClientId'] or type(audience) is list
        and endpoint['adminClientId'] in audience and all(type(v) is str for v in audience),
        'ADMIN_ID_TOKEN_AUDIENCE_MUST_INCLUDE_SELECTED_CLIENT')
    require(identity.get('azp', endpoint['adminClientId']) == endpoint['adminClientId'],
        'ADMIN_ID_TOKEN_AUTHORIZED_PARTY_MUST_MATCH')
    require(type(identity.get('exp')) is type(identity.get('iat')) is int
        and requested_at - 10 <= identity['iat'] <= time.time() + 5 and identity['exp'] > time.time(),
        'FRESH_ADMIN_ID_TOKEN_TIMESTAMPS_REQUIRED')
    require(re.fullmatch('[A-Za-z0-9_-]{1,128}', identity.get('sub', '')),
        'BOUNDED_ADMIN_ID_TOKEN_SUBJECT_REQUIRED')
    require(claims.get('sub') is None or claims['sub'] == identity['sub'],
        'ADMIN_ACCESS_AND_ID_TOKEN_SUBJECTS_MUST_AGREE_WHEN_PRESENT')
    expiry = min(claims['exp'], requested_at + response['expires_in'])
    require(expiry > time.time() + 45, 'FRESH_ADMIN_TOKEN_TOO_SHORT_FOR_FOUR_BOUNDED_GETS')
    # This is routing metadata, never independent JWT signature verification.
    # The provider's protected user endpoint must establish subject identity.
    return token, expiry, identity['sub']


def base(case, api, files):
    old = case['reconciledCase']['originalReadCase']
    context = Path(case['reconciledCase']['retainedContextPath'])
    require(case['schema'] == 'ouf.iam-explicit-api-case.v1'
        and case['maximumNewOAuthRequests'] == 1 and case['maximumNewEngineGets'] == 2
        and case['maximumNewAdminGets'] == 4 and case['expectedAttempts'] == 282
        and case['maximumCumulativeOAuthAttempts'] == 288,
        'EXACT_FINITE_ADMIN_SUCCESSOR_CASE_REQUIRED')
    seals = []
    def read(path, expected=None):
        value, seal = files.selected(str(path), expected)
        seals.append(seal)
        return value
    row = read(context / 'recovery.json')
    claim = read(context.parent / ('iam-policy-read-' + api.digest(old) + '.claim.json'))
    reconciliation = read(context / 'admin-session-context-reconcile.claim.json')
    require(claim == {'schema': api.PROFILE, 'caseHash': api.digest(old), 'contextPath': str(context)}
        and row['schema'] == api.PROFILE and row['caseHash'] == api.digest(old)
        and row['state'] == 'STOP_RECONCILE' and row['complete'] is False
        and row['engineRequestsReserved'] == 7 and row['adminGetsReserved'] == 0
        and row['reconciliationState'] == 'COMPLETE_METADATA_ONLY'
        and api.digest(row['reconciliationResult']) == case['retainedReconciliationResultHash']
        and reconciliation['caseHash'] == api.digest(case['reconciledCase'])
        and reconciliation['sourceHash'] == case['reconciledSourceHash'],
        'EXACT_COMPLETED_METADATA_RECONCILIATION_AND_UNCHANGED_OLD_STOP_REQUIRED')
    owner = read(old['ownerPlanBinding']['path'])
    control = Path(old['humanControlPath'])
    config = read(control / 'control.json')
    binding = read(control / 'binding.json')
    profile = read(control / 'human-read-profile.json')
    selection = config['selection']
    require(api.digest(owner) == old['ownerPlanBinding']['sha256']
        and config['schema'] == 'ouf.human-explicit-successor-control.v1'
        and config['sourceClosureHash'] == old['humanSourceClosureHash']
        and api.digest(selection) == owner['humanBinding']['selectionHash'] == binding['selectionHash']
        and binding['clientId'] == old['humanClientId']
        and profile['expectedBinding'] == binding and profile['selection'] == selection
        and profile['minimumCumulativeAttempts'] == case['expectedAttempts']
        and profile['maximumCumulativeAttempts'] == case['maximumCumulativeOAuthAttempts'],
        'SAME_FULL_OWNER_BOUND_HUMAN_AND_ADMIN_SELECTION_REQUIRED')
    session = Path(binding['sessionDirectory'])
    require(str(session) == str(control.parent / ('human-successor-' + api.digest(config['review'])))
        and profile['journal']['path'] == str(session / 'recovery.json'), 'EXACT_RETAINED_HUMAN_SESSION_REQUIRED')
    human = read(session / 'recovery.json', profile['journal'])
    require(human['schema'] == 'ouf.chatbot-human-session.private.v1' and human['state'] == 'READY'
        and human['binding'] == binding and human['attempts'] == case['expectedAttempts']
        and human['budgetReset'] is False and binding['expiresAt'] < time.time(),
        'EXACT_EXPIRED_READY_HISTORY_WITH_RETAINED_CUMULATIVE_BUDGET_REQUIRED')
    prepared = read(Path(old['productionContextPath']) / 'preparation.json')
    require(prepared['controlSourceHash'] == old['productionControlSourceHash']
        and prepared['caseHash'] == old['productionCaseHash'], 'EXACT_RETAINED_ADMIN_PROGRAM_BINDING_REQUIRED')
    endpoint = old['adminReadProfile']
    require(ipaddress.ip_address(endpoint['connectHost']).is_loopback
        and endpoint['storedHost'] in ('localhost', endpoint['connectHost'])
        and endpoint['storedServerUrl'] == 'http://' + endpoint['storedHost'] + ':' + str(endpoint['connectPort'])
        and type(endpoint['connectPort']) is int and 1 <= endpoint['connectPort'] <= 65535,
        'EXPLICIT_SELECTED_ADMIN_NAMESPACE_LOOPBACK_TRANSPORT_REQUIRED')
    for key in ('realm',):
        require(re.fullmatch('[A-Za-z0-9._-]{1,128}', selection[key]), 'BOUNDED_SELECTED_ADMIN_TARGET_REQUIRED')
    for key in ('adminRealm', 'adminClientId', 'expectedAdminUser'):
        require(re.fullmatch('[A-Za-z0-9._-]{1,128}', endpoint[key]), 'BOUNDED_EXPLICIT_ADMIN_PROFILE_REQUIRED')
    require(re.fullmatch('[A-Za-z0-9._-]{1,128}', old['humanClientId']), 'BOUNDED_HUMAN_CLIENT_REQUIRED')
    return old, context, session, selection, owner, prepared, endpoint, seals


def run(case, api, files, process_adapter, Journal):
    CHECKPOINT.update(phase='VALIDATE_RETAINED_METADATA_AND_BUDGET', contextPath=None)
    old, context, session, selection, owner, prepared, endpoint, seals = base(case, api, files)
    destination = context / 'explicit-admin-api-successor'
    CHECKPOINT['contextPath'] = str(destination)
    budget_claim = session / 'successor-window.claim.json'
    require(not os.path.lexists(budget_claim) and not os.path.lexists(destination),
        'ADMIN_SUCCESSOR_ALREADY_CLAIMED_STATUS_ONLY_NO_REPLAY')
    review = {'schema': SCHEMA, 'caseHash': api.digest(case), 'retainedContextPath': str(context),
        'priorOAuthAttempts': case['expectedAttempts'], 'maximumCumulativeOAuthAttempts': 288,
        'maximumNewOAuthRequests': 1, 'maximumNewEngineGets': 2, 'maximumNewAdminGets': 4,
        'originalEngineCeilingRetained': 7, 'newCumulativeEngineCeiling': 9,
        'newHumanWindow': False, 'policyWritesAllowed': False, 'runtimeAuthorityIssued': False}
    CHECKPOINT['phase'] = 'EXPLICIT_ADMIN_API_TERMINAL_CONSENT'
    terminal('Autorizzi UNA autenticazione API admin con password e QUATTRO letture: identita e policy.\n'
        'Conteggio OAuth cumulativo282/288 -> al massimo283/288; nessun reset.\n'
        'Nuova operazione finita:2 GET Engine; vecchio contatore7/7 immutato, cumulativo massimo9.\n'
        'Nessun refresh, console, modifica IAM, finestra HUMAN o autorita runtime.\n'
        'Serve la password IAM dell\'account admin configurato, NON la password sudo.\n'
        'La password resta nascosta e non viene conservata. Nessuna ripetizione automatica.',
        'AUTORIZZO LETTURA IAM API ' + api.digest(review))
    for seal in seals:
        files.recheck(seal)
    grant = {**review, 'reviewHash': api.digest(review), 'approvedAt': int(time.time()),
        'expiresAt': int(time.time()) + 240, 'destination': str(destination),
        'automaticReplayAllowed': False, 'budgetReset': False,
        'futureHumanSuccessorMustIncludeThisLedger': True}
    # Fence legacy window-openers and concurrent administrative successors.
    # No predecessor journal/counter or existing claim is overwritten.
    with Journal(session).invocation():
        for seal in seals:
            files.recheck(seal)
        Journal(session).create(budget_claim, api.encoded(grant))
        Journal(session).sync()
    os.mkdir(destination, 0o700)
    journal = Journal(destination)
    journal.initialize({'schema': SCHEMA, 'caseHash': api.digest(case), 'grant': grant,
        'state': 'CONSENTED', 'attempts': case['expectedAttempts'], 'maximumCumulativeOAuthAttempts': 288,
        'oauthRequestsReserved': 0, 'engineRequestsReserved': 0, 'adminGetsReserved': 0,
        'runtimeAuthorityIssued': False, 'budgetReset': False, 'automaticReplayAllowed': False})
    process, ns, password = None, None, None
    try:
        CHECKPOINT['phase'] = 'PRIVATE_ADMIN_PASSWORD_TERMINAL_INPUT'
        password = terminal('Password IAM per ' + endpoint['expectedAdminUser'] + ' (input nascosto):')
        engine = api.EngineRead(owner['engine'], journal, selection['keycloakContainer'])
        container = engine.request('GET')
        before = api.generation(container, selection['keycloakContainer'])
        process = process_adapter.ProcessFiles(before['Pid'])
        ns_path = '/proc/' + str(before['Pid']) + '/ns/net'
        ns = os.open(ns_path, os.O_RDONLY | os.O_CLOEXEC)
        ns_identity = (os.fstat(ns).st_dev, os.fstat(ns).st_ino)
        program = prepared['sourceClosure']['executables']['python']
        def request(operation, credential, subject='', uuid='', expiry=None):
            CHECKPOINT['phase'] = operation
            for seal in seals:
                files.recheck(seal)
            process.check()
            require((os.stat(ns_path).st_dev, os.stat(ns_path).st_ino) == ns_identity
                and time.time() < grant['expiresAt'], 'CURRENT_ADMIN_NAMESPACE_AND_EXPLICIT_GRANT_REQUIRED')
            row = journal.read()
            if operation == 'PASSWORD_GRANT':
                require(row['oauthRequestsReserved'] == 0 and row['attempts'] == case['expectedAttempts'],
                    'ONE_EXPLICIT_ADMIN_AUTHENTICATION_ONLY_NO_REPLAY')
                api.save(journal, state='AUTHENTICATING', oauthRequestsReserved=1, attempts=row['attempts'] + 1)
            else:
                require(row['adminGetsReserved'] < 4 and expiry is not None and expiry > time.time() + 8,
                    'CURRENT_ADMIN_TOKEN_AND_FOUR_GET_CEILING_REQUIRED')
                api.save(journal, state='READING', adminGetsReserved=row['adminGetsReserved'] + 1)
            payload = {'host': endpoint['connectHost'], 'port': endpoint['connectPort'],
                'adminRealm': endpoint['adminRealm'], 'clientId': endpoint['adminClientId'],
                'expectedUser': endpoint['expectedAdminUser'], 'targetRealm': selection['realm'],
                'targetClient': old['humanClientId'], 'operation': operation, 'credential': credential,
                'subject': subject, 'clientUuid': uuid}
            value = dispatch(api, program, ns, payload)
            process.check()
            return value
        requested = time.time()
        response = request('PASSWORD_GRANT', password)
        password = None
        token, expiry, subject = access(api, response, endpoint, selection['issuer'], requested)
        del response  # In particular, discard any returned refresh token.
        identity = request('IDENTITY', token, subject=subject, expiry=expiry)
        require(type(identity) is dict and identity.get('id') == subject
            and identity.get('username') == endpoint['expectedAdminUser'] and identity.get('enabled') is True,
            'PROVIDER_ADMIN_SUBJECT_USERNAME_AND_ENABLED_LOOKUP_REQUIRED')
        realm = request('REALM', token, expiry=expiry)
        listing = request('CLIENT_LIST', token, expiry=expiry)
        require(type(listing) is list and len(listing) == 1 and type(listing[0]) is dict
            and listing[0].get('clientId') == old['humanClientId']
            and re.fullmatch('[A-Za-z0-9_-]{1,128}', listing[0].get('id', '')),
            'UNIQUE_EXACT_HUMAN_CLIENT_BEFORE_DETAIL_REQUIRED')
        client = request('CLIENT', token, uuid=listing[0]['id'], expiry=expiry)
        del token, identity
        result = api.policy(realm, listing, client, selection['realm'], old['humanClientId'])
        require(journal.read()['engineRequestsReserved'] == 1, 'TWO_NEW_ENGINE_GET_CEILING_REQUIRED')
        require(api.generation(engine.request('GET'), selection['keycloakContainer']) == before,
            'ADMIN_CONTAINER_GENERATION_CHANGED_DURING_READ')
        process.check()
        for seal in seals:
            files.recheck(seal)
        counters = journal.read()
        result.update(schema='ouf.iam-explicit-api-result.v1', status='CURRENT_ADMIN_IDENTITY_AND_IAM_POLICY_READ_NO_AUTHORITY',
            contextPath=str(destination), complete=True, readOnly=False, policyReadOnly=True,
            authenticationStateChanged=True, currentProviderPolicyProven=True, adminIdentityApiVerified=True,
            adminSubjectFromSameFreshProviderIdToken=True, jwtSignatureIndependentlyVerified=False,
            preferredUsernameClaimRequired=False, attempts=counters['attempts'], remainingAttempts=288-counters['attempts'],
            maximumCumulativeOAuthAttempts=288, oauthRequestsReserved=1, engineRequestsThisOperation=2,
            originalEngineRequestsRetained=7, cumulativeDiagnosticEngineRequests=9,
            adminGetsReserved=4, credentialFilesRead=0, humanCredentialJournalsRead=1,
            humanBearerFilesOpened=0, newLoginPerformed=True, refreshPerformed=False,
            iamMutations=0, policyMutations=0, containerLifecycleOperations=0,
            oldContextsAndClaimsRetained=True, oldPolicyReadStillStopped=True,
            priorHumanJournalUnchanged=True, futureHumanMustConsumeSupplementaryLedger=True,
            secretValuesPersisted=False, credentialValuesPrinted=False, credentialHashesPrinted=False,
            identityValuesPrinted=False, runtimeAuthorityIssued=False, budgetReset=False,
            automaticReplayAllowed=False, windowExtended=False, completedTechnicalPhases=8,
            functionalMilestonesProven=4, notReleaseAcceptance=True, observedAtUnix=time.time())
        api.save(journal, state='COMPLETE', complete=True, result=result)
        return result
    except BaseException:
        api.save(journal, state='STOP_RECONCILE', complete=False)
        raise
    finally:
        password = None
        if ns is not None:
            os.close(ns)
        if process is not None:
            process.close()


def status(case, api, files, Journal):
    context = Path(case['reconciledCase']['retainedContextPath']) / 'explicit-admin-api-successor'
    row, _ = files.selected(str(context / 'recovery.json'))
    require(row['schema'] == SCHEMA and row['caseHash'] == api.digest(case), 'EXACT_ADMIN_SUCCESSOR_STATUS_REQUIRED')
    return {'schema': 'ouf.iam-explicit-api-result.v1', 'status': 'RETAINED_ADMIN_SUCCESSOR_METADATA_ONLY',
        'contextPath': str(context), 'state': row['state'], 'complete': row.get('complete', False),
        'attempts': row['attempts'], 'maximumCumulativeOAuthAttempts': 288,
        'remainingAttempts': 288-row['attempts'], 'oauthRequestsReserved': row['oauthRequestsReserved'],
        'engineRequestsReserved': row['engineRequestsReserved'], 'adminGetsReserved': row['adminGetsReserved'],
        'oauthRequestsThisInvocation': 0, 'engineRequestsThisInvocation': 0, 'adminGetsThisInvocation': 0,
        'credentialFilesRead': 0, 'humanCredentialJournalsRead': 0, 'readOnly': True,
        'newLoginPerformed': False, 'refreshPerformed': False, 'runtimeAuthorityIssued': False,
        'automaticReplayAllowed': False, 'budgetReset': False}
