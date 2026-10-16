"""Finite owner-operation scheduler; no automatic episode/session creation.

Every grant attempt, including scheduled successes, consumes the SAME finite
operation budget. This conservative profile does not claim unbounded healthy
renewal or implement HUMAN budget renewal. Installer supplies current history.
"""
from tools.semantic_lease_recovery.bounded_recovery import Recovery,Permanent,require,number
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import TokenRenewalAdapter,protected_directory

class ScheduledRecovery(Recovery):
    PROFILE='ouf.policy-token-finite-owner-operation.v1'
    def __init__(self,*args,interval_seconds=60,**kwargs):
        require(type(interval_seconds) is int and 1<=interval_seconds<=3600,
                'FINITE_RENEWAL_INTERVAL_REQUIRED')
        super().__init__(*args,**kwargs)
        require(type(self.journal) is Journal and type(self.adapter) is TokenRenewalAdapter,
                'EXISTING_TOKEN_ADAPTER_AND_JOURNAL_REQUIRED')
        self.interval=interval_seconds
    def initial(self):
        # Test/governed installer ONLY. Worker never invokes this method.
        return {**super().initial(),'renewalProfile':self.PROFILE,
                'intervalSeconds':self.interval,'publicationCount':0,
                'nextRenewalWall':None,'nextRenewalMonotonic':None,
                'tokenExpiresWall':None,'tokenExpiresMonotonic':None}
    def validate(self,row):
        if 'workerSessionHash' in row:
            prior=row.get('controlledPredecessorGrantAttempts')
            governed=row.get('controlledHistoryProfile')=='ouf.policy-token-governed-worker-continuation.v1'
            require(type(row.get('attempts'))is int and 0<=row['attempts']<=self.policy.max_attempts
                and type(prior)is int and (governed and 1<=prior<=1000000 or prior==1 and 'controlledHistoryProfile'not in row or prior in(2,3,4,5,6,8,9,10)
                and row.get('controlledHistoryProfile')=='ouf.policy-token-cancelled-worker-continuation.v1'
                and all(type(row.get(k))is str and len(row[k])==64 and all(c in '0123456789abcdef'for c in row[k])
                    for k in('predecessorCancelledWorkerHash','predecessorWorkerSessionHash')))
                and row.get('controlledCumulativeGrantAttempts')==prior+row.get('attempts',-1),
                'CONTROLLED_SESSION_HISTORY_DRIFT')
        require(row.get('renewalProfile')==self.PROFILE and row.get('intervalSeconds')==self.interval
                and type(row.get('publicationCount')) is int and row['publicationCount']>=0,
                'INSTALLED_SCHEDULE_OR_HISTORY_DRIFT')
        if row['state']=='ACTIVE':
            require(all(number(row.get(k)) for k in ('nextRenewalWall','nextRenewalMonotonic',
                    'tokenExpiresWall','tokenExpiresMonotonic'))
                    and row['lastWall']<=row['nextRenewalWall']<row['tokenExpiresWall']
                    and row['lastMonotonic']<=row['nextRenewalMonotonic']<row['tokenExpiresMonotonic'],
                    'DURABLE_RENEWAL_WINDOW_REQUIRED')
    def _step(self,*,cancelled=False):
        self.validate(self.journal.read())
        return super()._step(cancelled=cancelled)
    def save(self,previous,state,reason,**values):
        self.validate(previous)
        if state=='ACTIVE' and reason=='RECOVERED':
            window=self.adapter.publication_window
            require(type(window) is tuple and len(window)==3 and all(number(v) for v in window),
                    'FRESH_PUBLICATION_WINDOW_REQUIRED')
            wall,mono=self.now();published_wall,published_mono,expires=window
            require(wall>=published_wall and mono>=published_mono
                    and expires-mono>=self.adapter.binding.minimum_remaining,
                    'PUBLICATION_WINDOW_EXPIRED_OR_CLOCK_REGRESSED')
            delay=min(self.interval,(expires-mono)/2)
            require(delay>=1,'BOUNDED_RENEWAL_WINDOW_REQUIRED')
            values.update(publicationCount=previous['publicationCount']+1,
                nextRenewalWall=wall+delay,nextRenewalMonotonic=mono+delay,
                tokenExpiresWall=wall+expires-mono,tokenExpiresMonotonic=expires)
        if 'workerSessionHash' in previous:
            values['controlledCumulativeGrantAttempts']=previous['controlledPredecessorGrantAttempts']+values.get('attempts',previous['attempts'])
        return super().save(previous,state,reason,**values)

class RenewalWorker:
    def __init__(self,recovery,*,heartbeat=5):
        require(type(recovery) is ScheduledRecovery and type(heartbeat) is int and 1<=heartbeat<=30,
                'SEALED_SCHEDULED_RECOVERY_AND_HEARTBEAT_REQUIRED')
        self.r,self.heartbeat=recovery,heartbeat
        self.active_here=False
    def _tick(self):
        r=self.r;row=r.journal.read()
        try:r.adapter.guard()
        except Permanent as error:return r.pause(row,'BLOCKED',error.code)
        except Exception:return r.pause(row,'BLOCKED','LOCAL_AUTHORITY_UNPROVEN')
        # Validate context, clocks, generation and profile even while ACTIVE.
        preceding_state=row['state']
        row=r.step()
        if row['state']!='ACTIVE':
            self.active_here=False
            return row
        if preceding_state!='ACTIVE':
            self.active_here=True
            return row
        if not self.active_here:
            # Only a just-completed attempt in THIS invocation can be scheduled.
            # Recovered ACTIVE requires source/credential/authority reconciliation.
            return r.pause(row,'RECONCILE_REQUIRED','WORKER_INVOCATION_RECONCILIATION_REQUIRED')
        wall,mono=r.now()
        if wall>=row['tokenExpiresWall'] or mono>=row['tokenExpiresMonotonic']:
            self.active_here=False
            return r.pause(row,'RECONCILE_REQUIRED','TOKEN_VALIDITY_WINDOW_EXPIRED')
        if r.remaining(row)<=0 or row['attempts']>=r.policy.max_attempts:
            self.active_here=False
            return r.pause(row,'PAUSED_EXHAUSTED','FINITE_OWNER_OPERATION_EXHAUSTED')
        if wall<row['nextRenewalWall'] or mono<row['nextRenewalMonotonic']:
            return row
        # Persist next intent in SAME record; never replace counters/start times.
        self.active_here=False
        row=r.save(row,'NEW','SCHEDULED_RENEWAL_DUE')
        return self._attempt()
    def _attempt(self):
        row=self.r.step()
        if row['state']=='ACTIVE':self.active_here=True
        return row
    def _advance(self):
        return self._tick()
    def tick(self):
        # Bounded single-step driver for owner-controlled tests/integration.
        with protected_directory(self.r.journal.root),self.r.journal.invocation():
            try:return self._advance()
            except Exception:
                self.active_here=False
                try:self.r.adapter.pause()
                except Exception:raise RuntimeError('TOKEN_WORKER_SAFE_PAUSE_UNPROVEN') from None
                raise RuntimeError('TOKEN_WORKER_STATE_UNPROVEN') from None
    def wait_seconds(self,row):
        if row['state']!='ACTIVE':return self.r.wait_seconds(row,self.heartbeat)
        wall,mono=self.r.now()
        return max(0,min(self.heartbeat,max(row['nextRenewalWall']-wall,
                                         row['nextRenewalMonotonic']-mono)))
    def status(self,row):
        return {'state':row['state'],'reason':row['reason'],'attempts':row['attempts'],
            'publications':row['publicationCount'],'live':True,'applicationReady':False,
            'runtimeAuthorityIssued':False}
    def serve(self,stop,observe):
        # Lifetime process fence, not journal transaction/shared lease lock.
        with protected_directory(self.r.journal.root),self.r.journal.invocation():
            self.active_here=False
            try:
                while not stop.is_set():
                    row=self._advance();observe(self.status(row))
                    if stop.wait(self.wait_seconds(row)):break
                return self.r.step(cancelled=True)
            finally:
                self.active_here=False
                self.r.adapter.pause()
