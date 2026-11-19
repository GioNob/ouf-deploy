"""One explicit OAuth request per step after a separately approved window.

Reuse the existing bounded TLS/provider verification and private token writer.
No background work, wait loop, refresh, automatic login, or window creation.
The resulting READY journal can be consumed by the existing read-only reader.
"""
import copy
import time
from tools.chatbot_file_cohort.human_session import HumanSession,HumanSessionPaused,CLIENT,PROFILE
from tools.ingestion_rollout_execution.contract import require,digest
from tools.governed_human_successor.contract import validate_review

def validate_consent(review,decision,now):
    validate_review(review)
    require(type(decision)is dict and set(decision)=={'schema','reviewHash','decision','approvedAt','expiresAt'}
        and decision['schema']=='ouf.human-login-window-terminal-consent.v1'
        and decision['reviewHash']==digest(review)
        and decision['decision']=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
        and type(decision['approvedAt'])is type(decision['expiresAt'])is int
        and decision['approvedAt']<=now<decision['expiresAt']
        and decision['expiresAt']-decision['approvedAt']==review['newWindowSeconds']==7200,
        'EXACT_CURRENT_SUCCESSOR_WINDOW_CONSENT_REQUIRED')

class ExplicitFreshSession(HumanSession):
    def __init__(self,selection,binding,review,decision):
        validate_consent(review,decision,time.time())
        self.successor_review=copy.deepcopy(review);self.successor_decision=copy.deepcopy(decision)
        self.expected_binding=copy.deepcopy(binding)
        self.successor_hash=digest({'review':review,'decision':decision,'binding':binding})
        self.scopes=copy.deepcopy(review['requestedScopes'])
        self.maximum=review['maximumCumulativeOAuthAttempts'];self.minimum=review['priorOAuthAttempts']
        super().__init__(selection,binding['sessionDirectory'],binding['tokenPath'],binding['expiresAt'])
        # A missing prepared journal must never fall back to the legacy zero counter.
        require(self.journal.record.exists(),'PREPARED_SUCCESSOR_JOURNAL_REQUIRED_NO_ZERO_INITIALIZATION')
        self._check(self._read())

    def _check_identity_and_budget(self,row):
        review,decision,b=self.successor_review,self.successor_decision,self.expected_binding
        validate_consent(review,decision,time.time())
        require(digest({'review':review,'decision':decision,'binding':b})==self.successor_hash,
                'APPROVED_SUCCESSOR_CONFIGURATION_CHANGED')
        require(row.get('schema')=='ouf.chatbot-human-session.private.v1'
            and row.get('binding')==b and row.get('bootId')==self._boot()
            and row.get('budgetReset')is False and type(row.get('attempts'))is int
            and self.minimum<=row['attempts']<=self.maximum
            and b.get('selectionHash')==digest(self.selection)
            and all(b.get(k)==self.selection[k]for k in('issuer','subject','tenant'))
            and b.get('clientId')==CLIENT and b.get('scopes')==self.scopes
            and b.get('sessionDirectory')==str(self.directory)and b.get('tokenPath')==str(self.token_path)
            and b.get('createdAt')==decision['approvedAt']and b.get('expiresAt')==decision['expiresAt']
            and b.get('retryProfile',{}).get('maximumAttempts')==self.maximum
            and row.get('governedWindowRenewal')=={'review':review,'decision':decision},
            'EXACT_SUCCESSOR_IDENTITY_CLOCK_CONSENT_AND_CUMULATIVE_HISTORY_REQUIRED')
        require(all(b['retryProfile'].get(k)==v for k,v in PROFILE.items()if k not in('id','maximumAttempts')),
                'UNCHANGED_FINITE_RETRY_POLICY_REQUIRED')

    def _save(self,row,**updates):
        require(updates.get('binding',row['binding'])==row['binding']
            and updates.get('monotonicDeadline',row['monotonicDeadline'])==row['monotonicDeadline']
            and updates.get('budgetReset',False)is False,'SUCCESSOR_BINDING_OR_WINDOW_RESET_FORBIDDEN')
        count=updates.get('attempts',row['attempts'])
        require(type(count)is int and count in(row['attempts'],row['attempts']+1)
            and count<=self.maximum,'SUCCESSOR_COUNTER_RESET_OR_JUMP_FORBIDDEN')
        if count!=row['attempts']:
            require(updates.get('state')=='REQUESTING'and updates.get('operation')in
                    ('DISCOVERY','DEVICE_START','DEVICE_POLL','USERINFO'),'OAUTH_RESERVATION_BEFORE_DISPATCH_REQUIRED')
        return super()._save(row,**updates)

    def _claims(self,token):
        claims=super()._claims(token)
        require(set(self.scopes)<=set(str(claims.get('scope','')).split()),'ALL_APPROVED_RETAINED_SCOPES_REQUIRED')
        return claims

    def _request(self,row,operation,url,values=None,bearer=None):
        require(operation in('DISCOVERY','DEVICE_START','DEVICE_POLL','USERINFO'),
                'FRESH_AUTHENTICATION_ONLY_NO_REFRESH')
        reserve={'DISCOVERY':4,'DEVICE_START':3,'DEVICE_POLL':2,'USERINFO':1}[operation]
        require(self.maximum-row['attempts']>=reserve,'HUMAN_VERIFICATION_BUDGET_RESERVED')
        row=self._save(row,state='REQUESTING',operation=operation,attempts=row['attempts']+1,resumeState=row['state'])
        try:status,result,retry=self._http(url,values,bearer)
        except Exception as error:
            if operation in('DISCOVERY','USERINFO')and isinstance(error,HumanSessionPaused)and error.reason=='HUMAN_OAUTH_TRANSPORT_OUTCOME_UNPROVEN':
                self._transient(row,503,{'error':'temporarily_unavailable'},0,row['resumeState'])
            self._save(row,state='BLOCKED',reason='HUMAN_OAUTH_OUTCOME_UNPROVEN')
            raise HumanSessionPaused('HUMAN_OAUTH_OUTCOME_UNPROVEN')from None
        self._check(row);return row,status,result,retry

    def public_status(self,row):
        return {'state':row['state'],'attempts':row['attempts'],'maximumCumulativeOAuthAttempts':self.maximum,
            'remainingAttempts':self.maximum-row['attempts'],'expiresAt':self.expires_at,
            'budgetReset':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False}

    def browser_challenge(self,row):
        return {'sessionBindingHash':digest(row['binding']),'attempts':row['attempts'],
            **{k:row[k]for k in('verificationUri','userCode','deviceDeadline','nextPollAt')}}

    def step(self,browser_confirmation=None):
        """One foreground invocation, at most one network request; never sleeps."""
        with self.journal.invocation():
            initial=self._read()
            try:return self._step_locked(browser_confirmation)
            except Exception:
                current=self._read()
                # Transport failures already retain RETRY_WAIT or BLOCKED.
                # A received but invalid reply must not become a replayable read.
                if current.get('state')=='REQUESTING' and current.get('attempts',0)>initial.get('attempts',0):
                    self._save(current,state='BLOCKED',reason='HUMAN_RECEIVED_RESPONSE_IDENTITY_OR_SHAPE_UNPROVEN')
                raise

    def _step_locked(self,browser_confirmation):
        row=self._read();self._check(row);state=row['state']
        require(state not in('REQUESTING','BLOCKED'),'STOP_RECONCILE_NO_AMBIGUOUS_AUTHENTICATION_REPLAY')
        if state=='RETRY_WAIT':
            require(time.time()>=row['nextAttemptAt'],'EXPLICIT_FINITE_RETRY_PAUSE_STILL_ACTIVE')
            row=self._save(row,state=row['resumeState']);state=row['state']
        if state=='NEW':
            row,status,metadata,retry=self._request(row,'DISCOVERY',self.selection['issuer']+'/.well-known/openid-configuration')
            if status!=200:self._transient(row,status,metadata,retry,'NEW')
            require(metadata.get('issuer')==self.selection['issuer'],'HUMAN_DISCOVERY_ISSUER_DRIFT')
            endpoints={k:self._endpoint(metadata.get(k))for k in('device_authorization_endpoint','token_endpoint','userinfo_endpoint')}
            row=self._save(row,state='DEVICE_START',endpoints=endpoints)
        elif state=='DEVICE_START':
            row,status,result,retry=self._request(row,'DEVICE_START',row['endpoints']['device_authorization_endpoint'],
                {'client_id':CLIENT,'scope':' '.join(self.scopes)})
            if status!=200:self._transient(row,status,result,retry,'DEVICE_START')
            uri,code=result.get('verification_uri'),result.get('user_code')
            require(type(uri)is str and uri.startswith(self.selection['issuer']+'/')and not any(c.isspace()for c in uri)
                and type(code)is str and 1<=len(code)<=64 and all(c.isalnum()or c=='-'for c in code)
                and type(result.get('device_code'))is str and 0<len(result['device_code'])<=16384
                and type(result.get('expires_in'))is int and result['expires_in']>0,
                'EXACT_PROVIDER_DEVICE_CHALLENGE_REQUIRED')
            interval=result.get('interval',5)
            require(type(interval)is int and 1<=interval<=600,'BOUNDED_PROVIDER_POLL_INTERVAL_REQUIRED')
            row=self._save(row,state='DEVICE_POLL',deviceCode=result['device_code'],verificationUri=uri,userCode=code,
                deviceDeadline=min(self.expires_at,time.time()+min(600,result['expires_in'])),
                interval=max(5,interval),nextPollAt=time.time()+max(5,interval))
        elif state=='DEVICE_POLL':
            challenge=self.browser_challenge(row)
            if browser_confirmation is None:return {**self.public_status(row),'browserConfirmationRequired':True,'challenge':challenge}
            require(type(browser_confirmation)is dict and set(browser_confirmation)=={'challengeHash','confirmedAt'}
                and browser_confirmation['challengeHash']==digest(challenge)
                and type(browser_confirmation['confirmedAt'])in(int,float)
                and browser_confirmation['confirmedAt']<=time.time()<browser_confirmation['confirmedAt']+60
                and row['nextPollAt']<=time.time()<row['deviceDeadline'],
                'EXACT_CURRENT_BROWSER_CONFIRMATION_FOR_ONE_POLL_REQUIRED')
            row,status,result,retry=self._request(row,'DEVICE_POLL',row['endpoints']['token_endpoint'],
                {'client_id':CLIENT,'grant_type':'urn:ietf:params:oauth:grant-type:device_code','device_code':row['deviceCode']})
            if status==200:row=self._retain_tokens(row,result)
            elif status==400 and result.get('error')in('authorization_pending','slow_down'):
                interval=min(600,row['interval']+(5 if result['error']=='slow_down'else 0))
                row=self._save(row,state='DEVICE_POLL',interval=interval,nextPollAt=time.time()+interval)
            else:self._transient(row,status,result,retry,'DEVICE_POLL')
        elif state=='VERIFYING':
            self._verify_and_publish(row);row=self._read()
        elif state=='READY':self.current()
        else:require(False,'KNOWN_EXPLICIT_FRESH_AUTHENTICATION_STATE_REQUIRED')
        return self.public_status(row)

    def reconcile_read(self):
        """Only a lost read can be selected for an explicit later step."""
        with self.journal.invocation():
            row=self._read();self._check(row)
            require(row['state']=='REQUESTING'and row.get('operation')in('DISCOVERY','USERINFO'),
                    'LOST_MUTATING_AUTHENTICATION_OUTCOME_REQUIRES_EXTERNAL_RECONCILIATION')
            row=self._save(row,state=row['resumeState'])
            return self.public_status(row)

    def _forbidden(self,*args,**kwargs):
        raise HumanSessionPaused('EXPLICIT_FRESH_STEP_ONLY_NO_REFRESH_RENEWAL_LOOP_OR_BACKGROUND_WORK')
    login=_forbidden
    _login_locked=_forbidden
    _renew=_forbidden
    _refresh_ready=_forbidden
    refresh_if_due=_forbidden
    start_refresh=_forbidden
    expired_window_review=_forbidden
    start_approved_window=_forbidden
    prepare_interrupted_login=_forbidden
