class HumanBrowserConfirmationRequired(HumanSessionPaused):
    """A durable pending challenge, never proof of browser authentication."""

    def __init__(self, row):
        super().__init__('HUMAN_BROWSER_CONFIRMATION_REQUIRED', retry_at=row['nextPollAt'])
        self.row_hash = digest(row)
        self.challenge = {key: row[key] for key in ('verificationUri', 'userCode', 'deviceDeadline', 'attempts')}

def _recovery288_request(self, row, operation, url, values=None, bearer=None):
    require(row.get('binding', {}).get('retryProfile') == PROFILE, 'PREDECESSOR272_OAUTH_DISPATCH_FORBIDDEN')
    self._check(row)
    require(row['attempts'] < PROFILE['maximumAttempts'], 'HUMAN_SESSION_BUDGET_EXHAUSTED')
    reserve = {'DISCOVERY': 4, 'DEVICE_START': 3, 'DEVICE_POLL': 2, 'REFRESH': 2}.get(operation, 1)
    require(PROFILE['maximumAttempts'] - row['attempts'] >= reserve, 'HUMAN_VERIFICATION_BUDGET_RESERVED')
    row = self._save(row, state='REQUESTING', operation=operation, attempts=row['attempts'] + 1, resumeState=row['state'])
    try:
        status, result, retry = self._http(url, values, bearer)
    except Exception as error:
        if operation in ('DISCOVERY', 'USERINFO') and isinstance(error, HumanSessionPaused) and (error.reason == 'HUMAN_OAUTH_TRANSPORT_OUTCOME_UNPROVEN'):
            self._transient(row, 503, {'error': 'temporarily_unavailable'}, 0, row['resumeState'])
        self._save(row, state='BLOCKED', reason='HUMAN_OAUTH_OUTCOME_UNPROVEN')
        raise HumanSessionPaused('HUMAN_OAUTH_OUTCOME_UNPROVEN') from None
    self._check(row)
    return (row, status, result, retry)

HumanSession._request=_recovery288_request

def _recovery288login(self, emit=print, stop=None, confirm_browser=None):
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
            while time.time() < error.retry_at and (not stopper.is_set()):
                self._check(self._read())
                stopper.wait(min(5, error.retry_at - time.time()))
            if stopper.is_set():
                break
            self._check(self._read())
            require(time.time() < error.challenge['deviceDeadline'], 'HUMAN_DEVICE_LOGIN_EXPIRED')
            emit('OPEN_IN_BROWSER=' + error.challenge['verificationUri'])
            emit('ENTER_DEVICE_CODE=' + error.challenge['userCode'])
            require(confirm_browser(copy.deepcopy(error.challenge)) is True, 'HUMAN_BROWSER_CONFIRMATION_NOT_GIVEN')
            confirmed = error.row_hash
        except HumanSessionPaused as error:
            confirmed = None
            if error.retry_at is None:
                raise
            emit('HUMAN_SESSION_PAUSED=' + error.reason)
            while time.time() < error.retry_at and (not stopper.is_set()):
                self._check(self._read())
                stopper.wait(min(5, error.retry_at - time.time()))
    raise HumanSessionPaused('HUMAN_SESSION_CANCELLED')

HumanSession.login=_recovery288login

def _recovery288_login_locked(self, emit, stopper, confirmed):
    """Print only the provider's verification URL and HUMAN entry code."""
    require(self.action is None, 'INITIAL_DEVICE_LOGIN_PRECEDES_AGGREGATE_ACTION')
    if not os.path.lexists(self.journal.record):
        now = int(time.time())
        require(0 < self.expires_at - now <= PROFILE['maximumElapsedSeconds'], 'FINITE_LOGIN_WINDOW_REQUIRED')
        binding = {'sessionId': str(uuid.uuid4()), 'selectionHash': digest(self.selection), 'subject': self.selection['subject'], 'issuer': self.selection['issuer'], 'tenant': self.selection['tenant'], 'clientId': CLIENT, 'scopes': SCOPES, 'tokenPath': str(self.token_path), 'sessionDirectory': str(self.directory), 'createdAt': now, 'expiresAt': self.expires_at, 'retryProfile': PROFILE}
        self.journal.initialize({'schema': 'ouf.chatbot-human-session.private.v1', 'binding': binding, 'bootId': self._boot(), 'monotonicDeadline': time.monotonic() + self.expires_at - now, 'lastObservedAt': time.time(), 'attempts': 0, 'state': 'NEW', 'budgetReset': False})
    with self.journal.invocation():
        while not stopper.is_set():
            row = self._read()
            self._check(row)
            if row['state'] == 'REQUESTING':
                if row['operation'] in ('USERINFO', 'DISCOVERY'):
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
                    row, status, metadata, retry = self._request(row, 'DISCOVERY', self.selection['issuer'] + '/.well-known/openid-configuration')
                    if status != 200:
                        self._transient(row, status, metadata, retry, 'NEW')
                    require(metadata.get('issuer') == self.selection['issuer'], 'HUMAN_DISCOVERY_ISSUER_DRIFT')
                    endpoints = {k: self._endpoint(metadata.get(k)) for k in ('device_authorization_endpoint', 'token_endpoint', 'userinfo_endpoint')}
                    row = self._save(row, state='DEVICE_START', endpoints=endpoints)
                if row['state'] == 'DEVICE_START':
                    row, status, result, retry = self._request(row, 'DEVICE_START', row['endpoints']['device_authorization_endpoint'], {'client_id': CLIENT, 'scope': ' '.join(SCOPES)})
                    if status != 200:
                        self._transient(row, status, result, retry, 'DEVICE_START')
                    uri, code = (result.get('verification_uri'), result.get('user_code'))
                    require(type(uri) is str and uri.startswith(self.selection['issuer'] + '/') and (not any((c.isspace() for c in uri))) and (type(code) is str) and (1 <= len(code) <= 64) and all((c.isalnum() or c == '-' for c in code)) and (type(result.get('device_code')) is str) and (0 < len(result['device_code']) <= 16384) and (type(result.get('expires_in')) is int) and (result['expires_in'] > 0), 'EXACT_PROVIDER_DEVICE_CHALLENGE_REQUIRED')
                    supplied_interval = result.get('interval', 5)
                    require(type(supplied_interval) is int and 1 <= supplied_interval <= 600, 'BOUNDED_PROVIDER_POLL_INTERVAL_REQUIRED')
                    interval = max(5, supplied_interval)
                    row = self._save(row, state='DEVICE_POLL', deviceCode=result['device_code'], verificationUri=uri, userCode=code, deviceDeadline=min(self.expires_at, time.time() + min(600, result['expires_in'])), interval=interval, nextPollAt=time.time() + interval)
                    emit('OPEN_IN_BROWSER=' + uri)
                    emit('ENTER_DEVICE_CODE=' + code)
                if row['state'] == 'DEVICE_POLL':
                    require(time.time() < row['deviceDeadline'], 'HUMAN_DEVICE_LOGIN_EXPIRED')
                    require(PROFILE['maximumAttempts'] - row['attempts'] >= 2, 'HUMAN_VERIFICATION_BUDGET_RESERVED')
                    if confirmed != digest(row):
                        raise HumanBrowserConfirmationRequired(row)
                    if time.time() < row['nextPollAt']:
                        raise HumanBrowserConfirmationRequired(row)
                    confirmed = None
                    row, status, result, retry = self._request(row, 'DEVICE_POLL', row['endpoints']['token_endpoint'], {'client_id': CLIENT, 'grant_type': 'urn:ietf:params:oauth:grant-type:device_code', 'device_code': row['deviceCode']})
                    if status == 200:
                        row = self._retain_tokens(row, result)
                    elif status == 400 and result.get('error') in ('authorization_pending', 'slow_down'):
                        interval = min(600, row['interval'] + (5 if result['error'] == 'slow_down' else 0))
                        self._save(row, state='DEVICE_POLL', interval=interval, nextPollAt=time.time() + interval)
                        continue
                    else:
                        self._transient(row, status, result, retry, 'DEVICE_POLL')
                if row['state'] == 'VERIFYING':
                    return self._verify_and_publish(row)
            except HumanSessionPaused as error:
                raise
        raise HumanSessionPaused('HUMAN_SESSION_CANCELLED')

HumanSession._login_locked=_recovery288_login_locked
