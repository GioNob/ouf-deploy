"""Finite real HUMAN device login and refresh for the single cohort command.

Reuses the existing ouf-human-admin device flow. OAuth tokens remain only in a
private journal and bearer file; the signed plan contains the public binding.
An ambiguous refresh is not replayed: rotating refresh tokens have no safe
client-side idempotency key. JWT parsing is a context check, not signature proof;
the issuer's HTTPS userinfo endpoint verifies each new bearer before publication,
and application owners independently validate every authenticated request.
"""
import base64
import copy
from email.utils import parsedate_to_datetime
import json
import os
from pathlib import Path
import secrets
import ssl
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from tools.chatbot_file_cohort.plan import digest, require
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.owner_installation import AggregateAction

CLIENT = 'ouf-human-admin'
SCOPES = ['openid', 'authorization.policy.admin', 'mcp.connect',
          'authorization.permissions.read', 'authorization.permissions.propose',
          'authorization.proposal.read']
PROFILE = {'id':'ouf.chatbot-human-session.finite.v1', 'maximumAttempts':128,
           'maximumElapsedSeconds':7200, 'backoffSeconds':[5,15,60,300,900],
           'maximumJitterPercent':20, 'automaticBudgetRenewalAllowed':False}


class HumanSessionPaused(RuntimeError):
    def __init__(self, reason, *, retry_at=None):
        super().__init__(reason)
        self.reason, self.retry_at = reason, retry_at


class HumanBrowserConfirmationRequired(HumanSessionPaused):
    """A durable pending challenge, never proof of browser authentication."""
    def __init__(self, row):
        super().__init__('HUMAN_BROWSER_CONFIRMATION_REQUIRED', retry_at=row['nextPollAt'])
        self.row_hash = digest(row)
        self.challenge = {key: row[key] for key in
                          ('verificationUri', 'userCode', 'deviceDeadline', 'attempts')}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HumanSessionPaused('HUMAN_OAUTH_REDIRECT_DENIED')


class HumanSession:
    def __init__(self, selection, directory, token_path, expires_at, action=None):
        self.selection = copy.deepcopy(selection)
        for key in ('issuer','subject','tenant'):
            require(type(selection.get(key)) is str and selection[key], 'PINNED_HUMAN_SELECTION_REQUIRED')
        issuer = urllib.parse.urlsplit(selection['issuer'])
        require(issuer.scheme == 'https' and issuer.hostname and not issuer.username and not issuer.password
                and not issuer.query and not issuer.fragment and not issuer.path.endswith('/'),
                'PINNED_HTTPS_HUMAN_ISSUER_REQUIRED')
        self.directory, self.token_path = Path(directory), Path(token_path)
        require(self.directory.is_absolute() and self.directory.resolve() == self.directory
                and self.token_path.parent == self.directory and self.token_path.name == 'human-access.jwt',
                'EXACT_PRIVATE_HUMAN_SESSION_PATH_REQUIRED')
        for path in (self.directory, *self.directory.parents):
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
                    'HUMAN_SESSION_ANCESTOR_CUSTODY_REQUIRED')
        self.journal = Journal(self.directory)
        require(type(expires_at) is int, 'FINITE_HUMAN_SESSION_EXPIRY_REQUIRED')
        self.expires_at, self.action = expires_at, action
        require(action is None or type(action) is AggregateAction, 'REAL_AGGREGATE_HUMAN_SESSION_ACTION_REQUIRED')
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
        self.failure = None
        self.thread = None
        self._journal_mutex = threading.RLock()

    def _read(self):
        with self._journal_mutex:
            return self.journal.read()

    def _boot(self):
        return Path('/proc/sys/kernel/random/boot_id').read_text().strip()

    def binding(self):
        return self.current()

    def _check_identity_and_budget(self, row):
        binding = row.get('binding', {})
        require(row.get('schema') == 'ouf.chatbot-human-session.private.v1'
                and binding.get('selectionHash') == digest(self.selection)
                and binding.get('issuer') == self.selection['issuer']
                and binding.get('subject') == self.selection['subject']
                and binding.get('tenant') == self.selection['tenant']
                and binding.get('clientId') == CLIENT and binding.get('scopes') == SCOPES
                and binding.get('tokenPath') == str(self.token_path)
                and binding.get('sessionDirectory') == str(self.directory)
                and binding.get('expiresAt') == self.expires_at
                and binding.get('retryProfile') == PROFILE
                and row.get('budgetReset') is False and row.get('bootId') == self._boot(),
                'HUMAN_SESSION_BINDING_OR_HISTORY_DRIFT')
        require(type(row.get('attempts')) is int and 0 <= row['attempts'] <= PROFILE['maximumAttempts'],
                'HUMAN_SESSION_BUDGET_DRIFT')
        if 'governedWindowRenewal' in row:
            receipt=row['governedWindowRenewal'];review=receipt['review'];decision=receipt['decision']
            require(review['maximumCumulativeOAuthAttempts']==PROFILE['maximumAttempts']
                and row['attempts']>=review['priorOAuthAttempts']
                and decision['reviewHash']==digest(review)
                and binding['createdAt']==decision['approvedAt']
                and binding['expiresAt']==decision['expiresAt']
                and decision['expiresAt']-decision['approvedAt']==PROFILE['maximumElapsedSeconds'],
                'RENEWED_HUMAN_WINDOW_CUMULATIVE_HISTORY_REQUIRED')

    def _check(self, row):
        self._check_identity_and_budget(row)
        now = time.time()
        require(now + 2 >= row['lastObservedAt'] and now < self.expires_at
                and time.monotonic() < row['monotonicDeadline'], 'HUMAN_SESSION_WINDOW_EXPIRED_OR_CLOCK_DRIFT')
        if self.action is not None:
            scope = json.loads(self.action.raw).get('chatbotFileAuthorization', {})
            require(scope.get('sessionBinding') == row['binding'], 'EXACT_SIGNED_HUMAN_SESSION_BINDING_REQUIRED')
            self.action.guard('chatbotFileAuthorization', scope)
        if self.failure is not None:
            raise self.failure

    def expired_window_review(self, operation_binding):
        """Read-only qualification; no renewed time window or request is issued."""
        require(self.action is None, 'PRE_AUTHORITY_EXPIRED_LOGIN_ONLY')
        row=self._read();self._check_identity_and_budget(row);now=time.time()
        require('governedWindowRenewal' not in row
            and now>=self.expires_at and time.monotonic()>=row['monotonicDeadline']
            and now+2>=row['lastObservedAt'], 'ORIGINAL_EXPIRED_HUMAN_WINDOW_REQUIRED')
        require(row['state']=='DEVICE_POLL' and type(row.get('deviceDeadline'))in(int,float)
            and 0<row['deviceDeadline']<=self.expires_at
            and type(row.get('deviceCode'))is str and bool(row['deviceCode'])
            and not any(row.get(k)for k in ('accessToken','refreshToken','publishedAccessToken'))
            and not os.path.lexists(self.token_path), 'EXPIRED_PRE_TOKEN_POLL_ONLY_NO_AMBIGUOUS_REQUEST')
        require(row['attempts']<PROFILE['maximumAttempts'], 'HUMAN_CUMULATIVE_OAUTH_BUDGET_EXHAUSTED')
        require(type(operation_binding)is dict and operation_binding
            and all(type(k)is str and type(v)is str and len(v)==64
                and all(c in '0123456789abcdef'for c in v)for k,v in operation_binding.items()),
                'EXACT_LOGIN_RENEWAL_OPERATION_BINDING_REQUIRED')
        return {'schema':'ouf.human-expired-login-window-review.v1',
            'predecessorDirectory':str(self.directory),'predecessorRowHash':digest(row),
            'predecessorBindingHash':digest(row['binding']),'predecessorExpiredAt':self.expires_at,
            'selectionHash':digest(self.selection),'bootId':row['bootId'],
            'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':PROFILE['maximumAttempts'],
            'maximumRemainingOAuthAttempts':PROFILE['maximumAttempts']-row['attempts'],
            'newWindowSeconds':PROFILE['maximumElapsedSeconds'],'operationBinding':copy.deepcopy(operation_binding),
            'automaticRenewalAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False}

    def start_approved_window(self, review, decision, destination):
        """New private journal after exact operator consent; old journal unchanged.

        This terminal consent only opens the login window. Authenticated HUMAN
        verification and the existing dual-role infrastructure decision follow.
        """
        from tools.semantic_policy_token_owner.producer import protected_directory
        require(review==self.expired_window_review(review['operationBinding']),
                'EXPIRED_HUMAN_PREDECESSOR_CHANGED')
        now=time.time()
        require(set(decision)=={'schema','reviewHash','decision','approvedAt','expiresAt'}
            and decision['schema']=='ouf.human-login-window-terminal-consent.v1'
            and decision['reviewHash']==digest(review)
            and decision['decision']=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
            and type(decision['approvedAt'])is int and type(decision['expiresAt'])is int
            and decision['approvedAt']<=now<decision['approvedAt']+60
            and decision['expiresAt']-decision['approvedAt']==PROFILE['maximumElapsedSeconds'],
            'EXACT_CURRENT_LOGIN_WINDOW_CONSENT_REQUIRED')
        destination=Path(destination)
        require(destination==self.directory.parent/'human-session-window2',
                'EXACT_SINGLE_RENEWED_HUMAN_DIRECTORY_REQUIRED')
        with protected_directory(destination.parent)as directory:
            os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
        following=HumanSession(self.selection,destination,destination/'human-access.jwt',decision['expiresAt'])
        binding={'sessionId':str(uuid.uuid4()),'selectionHash':digest(self.selection),
            **{k:self.selection[k]for k in ('subject','issuer','tenant')},
            'clientId':CLIENT,'scopes':SCOPES,'tokenPath':str(following.token_path),
            'sessionDirectory':str(destination),'createdAt':decision['approvedAt'],
            'expiresAt':decision['expiresAt'],'retryProfile':PROFILE}
        following.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':binding,
            'bootId':self._boot(),'monotonicDeadline':time.monotonic()+decision['expiresAt']-now,
            'lastObservedAt':now,'attempts':review['priorOAuthAttempts'],'state':'NEW','budgetReset':False,
            'governedWindowRenewal':{'review':copy.deepcopy(review),'decision':copy.deepcopy(decision)}})
        following._check(following._read())
        return following

    def _save(self, row, **updates):
        self._check(row)
        following = copy.deepcopy(row)
        following.update(updates, lastObservedAt=time.time())
        with self._journal_mutex:
            self.journal.compare_and_save(row, following)
        return following

    def _endpoint(self, value):
        require(type(value) is str and value.startswith(self.selection['issuer']+'/protocol/openid-connect/'),
                'HUMAN_OAUTH_ENDPOINT_DRIFT')
        parsed = urllib.parse.urlsplit(value)
        require(not parsed.query and not parsed.fragment and not parsed.username and not parsed.password,
                'HUMAN_OAUTH_ENDPOINT_DRIFT')
        return value

    def prepare_interrupted_login(self, emit=print):
        """Continue the SAME login budget; replace only a proven expired challenge.

        A pending mutating/rotating request is never replayed. No deadline,
        attempt counter, authenticated identity or throttle state is reset.
        """
        require(self.action is None, 'PRE_AUTHORITY_LOGIN_CONTINUATION_ONLY')
        with self.journal.invocation():
            row=self._read();self._check(row)
            state=row.get('state')
            require(state in {'NEW','DEVICE_START','DEVICE_POLL','REQUESTING','RETRY_WAIT','VERIFYING','READY','BLOCKED'},
                    'KNOWN_INTERRUPTED_HUMAN_STATE_REQUIRED')
            if state=='BLOCKED':raise HumanSessionPaused('HUMAN_LOGIN_ALREADY_BLOCKED_RECONCILIATION_REQUIRED')
            if state=='REQUESTING' and row.get('operation') not in ('DISCOVERY','USERINFO'):
                self._save(row,state='BLOCKED',reason='HUMAN_OAUTH_INTERRUPTED_OUTCOME_UNPROVEN')
                raise HumanSessionPaused('HUMAN_OAUTH_INTERRUPTED_OUTCOME_UNPROVEN')
            effective=row.get('resumeState') if state=='RETRY_WAIT' else state
            if effective!='DEVICE_POLL':
                return {'state':state,'attempts':row['attempts'],'expiresAt':self.expires_at,'budgetReset':False}
            if state=='RETRY_WAIT' and time.time()<row['nextAttemptAt']:
                raise HumanSessionPaused('HUMAN_OAUTH_TEMPORARILY_UNAVAILABLE',retry_at=row['nextAttemptAt'])
            deadline=row.get('deviceDeadline')
            require(type(deadline)in (int,float) and 0<deadline<=self.expires_at,
                    'RETAINED_DEVICE_CHALLENGE_DEADLINE_REQUIRED')
            if time.time()<deadline:
                uri,code=row.get('verificationUri'),row.get('userCode')
                if uri is None or code is None:
                    # Old code did not retain display metadata. Do not create
                    # a second outstanding challenge or bypass its deadline.
                    raise HumanSessionPaused('HUMAN_DEVICE_PROMPT_NOT_RETAINED_WAIT_EXPIRY',retry_at=deadline)
                require(type(uri)is str and uri.startswith(self.selection['issuer']+'/')
                    and not any(c.isspace()for c in uri) and type(code)is str and 1<=len(code)<=64
                    and all(c.isalnum()or c=='-'for c in code),'EXACT_RETAINED_DEVICE_PROMPT_REQUIRED')
                emit('OPEN_IN_BROWSER='+uri);emit('ENTER_DEVICE_CODE='+code)
                return {'state':state,'attempts':row['attempts'],'expiresAt':self.expires_at,'budgetReset':False}
            require(not any(row.get(k)for k in ('accessToken','refreshToken','publishedAccessToken'))
                and type(row.get('deviceCode'))is str and row['deviceCode']
                and row['attempts']<PROFILE['maximumAttempts'], 'EXPIRED_PRE_TOKEN_CHALLENGE_ONLY')
            history=copy.deepcopy(row.get('expiredDeviceChallengeHistory',[]))
            require(type(history)is list and len(history)<PROFILE['maximumAttempts'],
                    'BOUNDED_DEVICE_CHALLENGE_HISTORY_REQUIRED')
            receipt={'schema':'ouf.human-expired-device-challenge.v1','previousRowHash':digest(row),
                'attemptsBefore':row['attempts'],'expiredAt':deadline,'continuedAt':time.time(),
                'reason':'INTERRUPTED_PRE_AUTHORITY_LOGIN_PROMPT_CONTINUATION',
                'originalSessionExpiry':self.expires_at,'budgetReset':False}
            history.append(receipt)
            following=self._save(row,state='DEVICE_START',resumeState='DEVICE_START',
                expiredDeviceChallengeHistory=history,deviceCode=None,verificationUri=None,userCode=None)
            require(following['attempts']==row['attempts'] and following['binding']==row['binding']
                and following['monotonicDeadline']==row['monotonicDeadline'], 'HUMAN_LOGIN_BUDGET_MUST_BE_PRESERVED')
            return {'state':'DEVICE_START','attempts':row['attempts'],'expiresAt':self.expires_at,
                'expiredChallengeReceiptHash':digest(receipt),'budgetReset':False}

    def _http(self, url, values=None, bearer=None):
        headers = {'Accept':'application/json'}
        raw = None
        if values is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            raw = urllib.parse.urlencode(values).encode('ascii')
        if bearer is not None:
            headers['Authorization'] = 'Bearer '+bearer
        request = urllib.request.Request(url, data=raw, headers=headers)
        try:
            try:
                reply = self.opener.open(request, timeout=20)
            except urllib.error.HTTPError as error:
                reply = error
            with reply:
                raw = reply.read(65537)
                require(len(raw) <= 65536, 'BOUNDED_HUMAN_OAUTH_RESPONSE_REQUIRED')
                try:
                    value = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise HumanSessionPaused('HUMAN_OAUTH_RESPONSE_UNKNOWN') from None
                require(type(value) is dict, 'HUMAN_OAUTH_RESPONSE_SHAPE_UNKNOWN')
                retry = reply.headers.get('Retry-After', '')
                try:
                    delay = int(retry) if retry.isdigit() else max(0,parsedate_to_datetime(retry).timestamp()-time.time())
                except (ValueError,TypeError,OverflowError):
                    delay = 0
                return reply.status, value, delay
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLError):
                raise HumanSessionPaused('HUMAN_OAUTH_TLS_FAILED') from None
            raise HumanSessionPaused('HUMAN_OAUTH_TRANSPORT_OUTCOME_UNPROVEN') from None
        except (TimeoutError, OSError):
            raise HumanSessionPaused('HUMAN_OAUTH_TRANSPORT_OUTCOME_UNPROVEN') from None

    def _request(self, row, operation, url, values=None, bearer=None):
        require(row['attempts'] < PROFILE['maximumAttempts'], 'HUMAN_SESSION_BUDGET_EXHAUSTED')
        # Do not acquire a new credential with no remaining request to verify it.
        # A browser acknowledgement can be premature; it must never consume this reserve.
        reserve = {'DISCOVERY':4, 'DEVICE_START':3, 'DEVICE_POLL':2, 'REFRESH':2}.get(operation, 1)
        require(PROFILE['maximumAttempts']-row['attempts'] >= reserve,
                'HUMAN_VERIFICATION_BUDGET_RESERVED')
        row = self._save(row, state='REQUESTING', operation=operation,
                         attempts=row['attempts']+1, resumeState=row['state'])
        try:
            status, result, retry = self._http(url, values, bearer)
        except Exception as error:
            if operation in ('DISCOVERY','USERINFO') and isinstance(error,HumanSessionPaused) \
                    and error.reason == 'HUMAN_OAUTH_TRANSPORT_OUTCOME_UNPROVEN':
                self._transient(row,503,{'error':'temporarily_unavailable'},0,row['resumeState'])
            # Request may have consumed a rotating credential. No automatic replay.
            self._save(row, state='BLOCKED', reason='HUMAN_OAUTH_OUTCOME_UNPROVEN')
            raise HumanSessionPaused('HUMAN_OAUTH_OUTCOME_UNPROVEN') from None
        self._check(row)
        return row, status, result, retry

    def _transient(self, row, status, result, retry, resume):
        if status == 429 or (status in (400,503) and result.get('error') == 'temporarily_unavailable'):
            index = min(row.get('consecutiveFailures', 0), 4)
            delay = PROFILE['backoffSeconds'][index] * (0.8 + secrets.randbelow(401)/1000)
            when = time.time()+max(delay, retry)
            self._save(row, state='RETRY_WAIT', resumeState=resume, nextAttemptAt=when,
                       consecutiveFailures=row.get('consecutiveFailures', 0)+1)
            raise HumanSessionPaused('HUMAN_OAUTH_TEMPORARILY_UNAVAILABLE', retry_at=when)
        self._save(row, state='BLOCKED', reason='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN')
        raise HumanSessionPaused('HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN')

    def _claims(self, token):
        require(type(token) is str and 0 < len(token) <= 16384 and not any(c.isspace() for c in token),
                'BOUNDED_HUMAN_ACCESS_TOKEN_REQUIRED')
        try:
            parts = token.split('.')
            require(len(parts) == 3, 'HUMAN_JWT_CONTEXT_REQUIRED')
            claims = json.loads(base64.urlsafe_b64decode(parts[1]+'='*(-len(parts[1]) % 4)))
        except (ValueError, UnicodeError):
            raise HumanSessionPaused('HUMAN_JWT_CONTEXT_UNREADABLE') from None
        audience = claims.get('aud')
        require(claims.get('iss') == self.selection['issuer'] and claims.get('sub') == self.selection['subject']
                and claims.get('tenant_id') == self.selection['tenant'] and claims.get('ouf_actor_type') == 'HUMAN'
                and claims.get('azp') == CLIENT and claims.get('acr')
                and (audience == 'ouf-api-gateway' or type(audience) is list and 'ouf-api-gateway' in audience)
                and set(SCOPES) <= set(str(claims.get('scope','')).split())
                and type(claims.get('exp')) in (int,float) and claims['exp'] > time.time()+5,
                'EXACT_CURRENT_HUMAN_CONTEXT_REQUIRED')
        return claims

    def _retain_tokens(self, row, result):
        access, refresh = result.get('access_token'), result.get('refresh_token')
        self._claims(access)
        require(str(result.get('token_type','')).lower() == 'bearer'
                and type(refresh) is str and 0 < len(refresh) <= 16384 and not any(c.isspace() for c in refresh),
                'ROTATING_HUMAN_REFRESH_CREDENTIAL_REQUIRED')
        # Save the received rotation before any further network request. A crash
        # here resumes userinfo verification; it never reuses the previous token.
        return self._save(row, state='VERIFYING', accessToken=access, refreshToken=refresh,
                          deviceCode=None, consecutiveFailures=0)

    def _publish(self, row):
        self._check(row)
        self._claims(row['accessToken'])
        if os.path.lexists(self.token_path):
            info = self.token_path.lstat()
            self.journal.check_file(info)
            fd = os.open(self.token_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                opened = os.fstat(fd); self.journal.check_file(opened)
                require((opened.st_dev,opened.st_ino) == (info.st_dev,info.st_ino), 'HUMAN_BEARER_CHANGED_DURING_READ')
                if os.read(fd,16385) == row['accessToken'].encode('ascii'):
                    return
            finally:
                os.close(fd)
        temporary = self.directory/('.human-token-'+uuid.uuid4().hex)
        self.journal.create(temporary, row['accessToken'].encode('ascii'))
        try:
            self._check(row)
            os.replace(temporary, self.token_path)
            self.journal.sync()
        finally:
            if temporary.exists():
                temporary.unlink()

    def _verify_and_publish(self, row):
        # A positively received rotation is durable, unlike a lost refresh
        # response. If its bearer expired during a read-only outage, use that
        # newly received refresh credential, never replay its predecessor.
        part = row['accessToken'].split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(part+'='*(-len(part) % 4)))
        if claims['exp'] <= time.time()+5:
            row = self._renew(row)
        row, status, info, retry = self._request(row, 'USERINFO', row['endpoints']['userinfo_endpoint'],
                                                bearer=row['accessToken'])
        if status != 200:
            self._transient(row, status, info, retry, 'VERIFYING')
        require(info.get('sub') == self.selection['subject'], 'HUMAN_PROVIDER_PRINCIPAL_CHANGED')
        claims = self._claims(row['accessToken'])
        # Publish before advertising READY. A crash leaves VERIFYING, which can
        # safely repeat only userinfo; readers never see a new verified journal
        # generation while the actual bearer file is still the expired one.
        self._publish(row)
        row = self._save(row, state='READY', accessExpiresAt=claims['exp'],
                         publishedAccessToken=row['accessToken'], resumeState='READY',
                         refreshAt=claims['exp']-min(60,max(10,(claims['exp']-time.time())/4)),
                         consecutiveFailures=0)
        return copy.deepcopy(row['binding'])

    def login(self, emit=print, stop=None, confirm_browser=None):
        """At most one token poll per browser confirmation; wait outside invocation locks.

        The callback receives only URL/code/deadline/count and must return True.
        A missing callback pauses before the first poll. Pending provider replies
        require another confirmation of the SAME durable challenge, not a new login.
        """
        stopper = stop or threading.Event()
        confirmed = None
        while not stopper.is_set():
            try:
                return self._login_locked(emit, stopper, confirmed)
            except HumanBrowserConfirmationRequired as error:
                confirmed = None
                if confirm_browser is None:
                    raise
                while time.time() < error.retry_at and not stopper.is_set():
                    self._check(self._read())
                    stopper.wait(min(5, error.retry_at-time.time()))
                if stopper.is_set():
                    break
                self._check(self._read())
                require(time.time() < error.challenge['deviceDeadline'], 'HUMAN_DEVICE_LOGIN_EXPIRED')
                # Always redisplay the URL and code at the point of acknowledgement.
                emit('OPEN_IN_BROWSER='+error.challenge['verificationUri'])
                emit('ENTER_DEVICE_CODE='+error.challenge['userCode'])
                require(confirm_browser(copy.deepcopy(error.challenge)) is True,
                        'HUMAN_BROWSER_CONFIRMATION_NOT_GIVEN')
                confirmed = error.row_hash
            except HumanSessionPaused as error:
                confirmed = None
                if error.retry_at is None:
                    raise
                emit('HUMAN_SESSION_PAUSED='+error.reason)
                while time.time() < error.retry_at and not stopper.is_set():
                    self._check(self._read())
                    stopper.wait(min(5, error.retry_at-time.time()))
        raise HumanSessionPaused('HUMAN_SESSION_CANCELLED')

    def _login_locked(self, emit, stopper, confirmed):
        """Print only the provider's verification URL and HUMAN entry code."""
        require(self.action is None, 'INITIAL_DEVICE_LOGIN_PRECEDES_AGGREGATE_ACTION')
        if not os.path.lexists(self.journal.record):
            now = int(time.time())
            require(0 < self.expires_at-now <= PROFILE['maximumElapsedSeconds'], 'FINITE_LOGIN_WINDOW_REQUIRED')
            binding = {'sessionId':str(uuid.uuid4()), 'selectionHash':digest(self.selection),
                'subject':self.selection['subject'], 'issuer':self.selection['issuer'], 'tenant':self.selection['tenant'],
                'clientId':CLIENT, 'scopes':SCOPES, 'tokenPath':str(self.token_path),
                'sessionDirectory':str(self.directory), 'createdAt':now, 'expiresAt':self.expires_at,
                'retryProfile':PROFILE}
            self.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1', 'binding':binding,
                'bootId':self._boot(), 'monotonicDeadline':time.monotonic()+self.expires_at-now,
                'lastObservedAt':time.time(), 'attempts':0, 'state':'NEW', 'budgetReset':False})
        with self.journal.invocation():
            while not stopper.is_set():
                row = self._read(); self._check(row)
                if row['state'] == 'REQUESTING':
                    if row['operation'] in ('USERINFO','DISCOVERY'):
                        row = self._save(row, state=row['resumeState'])
                    else:
                        row = self._save(row, state='BLOCKED', reason='HUMAN_OAUTH_INTERRUPTED_OUTCOME_UNPROVEN')
                if row['state'] == 'BLOCKED':
                    raise HumanSessionPaused(row['reason'])
                try:
                    if row['state'] == 'RETRY_WAIT':
                        if time.time() < row['nextAttemptAt']:
                            raise HumanSessionPaused('HUMAN_OAUTH_TEMPORARILY_UNAVAILABLE', retry_at=row['nextAttemptAt'])
                        row = self._save(row, state=row['resumeState'])
                    if row['state'] == 'READY':
                        return self._refresh_ready(row)
                    if row['state'] == 'NEW':
                        row, status, metadata, retry = self._request(row, 'DISCOVERY',
                            self.selection['issuer']+'/.well-known/openid-configuration')
                        if status != 200: self._transient(row, status, metadata, retry, 'NEW')
                        require(metadata.get('issuer') == self.selection['issuer'], 'HUMAN_DISCOVERY_ISSUER_DRIFT')
                        endpoints = {k:self._endpoint(metadata.get(k)) for k in
                                     ('device_authorization_endpoint','token_endpoint','userinfo_endpoint')}
                        row = self._save(row, state='DEVICE_START', endpoints=endpoints)
                    if row['state'] == 'DEVICE_START':
                        row, status, result, retry = self._request(row, 'DEVICE_START', row['endpoints']['device_authorization_endpoint'],
                            {'client_id':CLIENT, 'scope':' '.join(SCOPES)})
                        if status != 200: self._transient(row, status, result, retry, 'DEVICE_START')
                        uri, code = result.get('verification_uri'), result.get('user_code')
                        require(type(uri) is str and uri.startswith(self.selection['issuer']+'/')
                                and not any(c.isspace() for c in uri) and type(code) is str and 1 <= len(code) <= 64
                                and all(c.isalnum() or c == '-' for c in code)
                                and type(result.get('device_code')) is str and 0 < len(result['device_code']) <= 16384
                                and type(result.get('expires_in')) is int and result['expires_in'] > 0,
                                'EXACT_PROVIDER_DEVICE_CHALLENGE_REQUIRED')
                        supplied_interval = result.get('interval',5)
                        require(type(supplied_interval) is int and 1 <= supplied_interval <= 600,
                                'BOUNDED_PROVIDER_POLL_INTERVAL_REQUIRED')
                        interval = max(5,supplied_interval)
                        row = self._save(row, state='DEVICE_POLL', deviceCode=result['device_code'],
                            verificationUri=uri,userCode=code,
                            deviceDeadline=min(self.expires_at,time.time()+min(600,result['expires_in'])),
                            interval=interval, nextPollAt=time.time()+interval)
                        emit('OPEN_IN_BROWSER='+uri); emit('ENTER_DEVICE_CODE='+code)
                    if row['state'] == 'DEVICE_POLL':
                        require(time.time() < row['deviceDeadline'], 'HUMAN_DEVICE_LOGIN_EXPIRED')
                        require(PROFILE['maximumAttempts']-row['attempts'] >= 2,
                                'HUMAN_VERIFICATION_BUDGET_RESERVED')
                        if confirmed != digest(row):
                            raise HumanBrowserConfirmationRequired(row)
                        if time.time() < row['nextPollAt']:
                            raise HumanBrowserConfirmationRequired(row)
                        confirmed = None
                        row, status, result, retry = self._request(row, 'DEVICE_POLL', row['endpoints']['token_endpoint'],
                            {'client_id':CLIENT, 'grant_type':'urn:ietf:params:oauth:grant-type:device_code',
                             'device_code':row['deviceCode']})
                        if status == 200:
                            row = self._retain_tokens(row, result)
                        elif status == 400 and result.get('error') in ('authorization_pending','slow_down'):
                            interval = min(600,row['interval']+(5 if result['error'] == 'slow_down' else 0))
                            self._save(row, state='DEVICE_POLL', interval=interval, nextPollAt=time.time()+interval)
                            continue
                        else: self._transient(row,status,result,retry,'DEVICE_POLL')
                    if row['state'] == 'VERIFYING':
                        return self._verify_and_publish(row)
                except HumanSessionPaused as error:
                    raise
            raise HumanSessionPaused('HUMAN_SESSION_CANCELLED')

    def current(self):
        row = self._read(); self._check(row)
        if row['state'] == 'BLOCKED': raise HumanSessionPaused(row['reason'])
        # A concurrent refresh never hides the previously verified, still valid
        # bearer. New credentials are published only after issuer verification.
        if row.get('accessExpiresAt',0) <= time.time()+5:
            raise HumanSessionPaused('CURRENT_HUMAN_SESSION_REFRESH_PENDING',
                                     retry_at=row.get('nextAttemptAt') or time.time()+5)
        self._claims(row['publishedAccessToken'])
        return copy.deepcopy(row['binding'])

    def refresh_if_due(self):
        with self.journal.invocation():
            row = self._read(); self._check(row)
            if row['state'] == 'REQUESTING':
                if row['operation'] == 'USERINFO':
                    row = self._save(row, state='VERIFYING')
                else:
                    self._save(row, state='BLOCKED', reason='HUMAN_REFRESH_INTERRUPTED_OUTCOME_UNPROVEN')
                    raise HumanSessionPaused('HUMAN_REFRESH_INTERRUPTED_OUTCOME_UNPROVEN')
            if row['state'] == 'BLOCKED': raise HumanSessionPaused(row['reason'])
            if row['state'] == 'RETRY_WAIT':
                if time.time() < row['nextAttemptAt']:
                    raise HumanSessionPaused('HUMAN_OAUTH_TEMPORARILY_UNAVAILABLE', retry_at=row['nextAttemptAt'])
                row = self._save(row, state=row['resumeState'])
            if row['state'] == 'VERIFYING': return self._verify_and_publish(row)
            return self._refresh_ready(row)

    def _refresh_ready(self, row):
        require(row['state'] == 'READY', 'HUMAN_LOGIN_NOT_COMPLETE')
        if time.time() < row['refreshAt']:
            self._publish(row)
            return copy.deepcopy(row['binding'])
        return self._verify_and_publish(self._renew(row))

    def _renew(self, row):
        resume = row['state']
        row, status, result, retry = self._request(row, 'REFRESH', row['endpoints']['token_endpoint'],
            {'client_id':CLIENT, 'grant_type':'refresh_token', 'refresh_token':row['refreshToken']})
        if status != 200: self._transient(row,status,result,retry,resume)
        return self._retain_tokens(row,result)

    def start_refresh(self, stop, emit=print):
        require(type(stop) is threading.Event and self.thread is None, 'ONE_STOPPABLE_HUMAN_REFRESH_WORKER_REQUIRED')
        def serve():
            while not stop.is_set():
                try:
                    self.refresh_if_due()
                except HumanSessionPaused as error:
                    if error.retry_at is not None:
                        emit('HUMAN_SESSION_PAUSED='+error.reason)
                    else:
                        self.failure = error; emit('HUMAN_SESSION_BLOCKED='+error.reason); return
                except Exception:
                    self.failure = HumanSessionPaused('HUMAN_SESSION_GUARD_OR_IDENTITY_FAILED')
                    emit('HUMAN_SESSION_BLOCKED='+self.failure.reason); return
                stop.wait(5)
        self.thread = threading.Thread(target=serve, name='ouf-finite-human-session', daemon=True)
        self.thread.start()
        return self.thread
