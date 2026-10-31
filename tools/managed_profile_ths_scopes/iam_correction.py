"""Reviewed additive IAM correction; pure plan and journaled one-dispatch effects.

One absent definition and three explicit-request-only links. No client overwrite,
realm default, mapper/role mutation, application grant or deployment authority.
"""
import copy,re,time,uuid
from urllib.parse import urlsplit
from tools.managed_csv_recovery.retained_inputs import Stop,require,digest,Capture,stable_binding
from tools.managed_profile_ths_scopes.contract import REQUIRED
from tools.managed_profile_ths_scopes.iam_read import ReadLedger

MARKER='ouf.provisioning.operation-ref'

def compile_correction(observation,expected,*,installation_ref,parent_result_hash,realm):
    require(observation==expected and observation.get('schema')=='ouf.ths-oidc-client-binding-observation.v1'
            and observation['bindingAndUnrestrictedEligibilityProven']is False and observation['iamMutations']==0
            and observation['blockedScopes']==list(REQUIRED),'EXACT_RETAINED_BINDING_BASELINE_REQUIRED')
    rows=observation['requiredScopes']
    require([r['name']for r in rows]==list(REQUIRED)and all(r['binding']=='NONE'for r in rows),'THREE_ABSENT_LINKS_REQUIRED')
    require(all(r['defined']is True and r['includeInTokenScope']is True and r['unrestrictedByScopeRoleMappings']is True
                and re.fullmatch('[A-Za-z0-9_-]{1,128}',r['id'])for r in rows[:2])
            and rows[2]['defined']is False and rows[2]['id']is None,'EXACT_TWO_DEFINITIONS_AND_ONE_ABSENT_REQUIRED')
    require(re.fullmatch('[a-f0-9]{64}',parent_result_hash)and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',installation_ref)
            and re.fullmatch('[A-Za-z0-9_.-]{1,128}',realm),'EXPLICIT_INSTALLATION_LINEAGE_REQUIRED')
    operation=digest({'schema':'ouf.ths-iam-correction-intent.v1','installationRef':installation_ref,'realm':realm,
                      'parentResultHash':parent_result_hash,'bindingSnapshotHash':observation['bindingSnapshotHash'],
                      'clientUuid':observation['clientUuid'],'scopes':list(REQUIRED)})
    new_id=str(uuid.uuid5(uuid.NAMESPACE_URL,'ouf:ths-iam-correction:'+operation+':'+REQUIRED[2]))
    definition={'id':new_id,'name':REQUIRED[2],'protocol':'openid-connect',
                'attributes':{'include.in.token.scope':'true',MARKER:operation},'protocolMappers':[]}
    assignments=[{'name':r['name'],'id':r['id']if r['defined']else new_id,'type':'OPTIONAL'}for r in rows]
    return {'schema':'ouf.ths-additive-iam-correction-plan.v1','installationRef':installation_ref,'realm':realm,
            'parentResultHash':parent_result_hash,'operationRef':operation,'clientId':observation['clientId'],
            'clientUuid':observation['clientUuid'],'baselineBindingHash':observation['bindingSnapshotHash'],
            'definitionToCreate':definition,'assignmentsToAdd':assignments,
            'preservedDefaultScopeCount':observation['defaultScopeCount'],'preservedOptionalScopeCount':observation['optionalScopeCount'],
            'previousDefinitionCount':observation['definitionCount'],'newDefinitionCount':observation['definitionCount']+1,
            'newOptionalScopeCount':observation['optionalScopeCount']+3,'maximumDefinitionCreates':1,'maximumOptionalAssignments':3,
            'realmDefaultMutationAuthorized':False,'clientSettingsMutationAuthorized':False,'existingDefinitionMutationAuthorized':False,
            'roleOrMapperMutationAuthorized':False,'newApplicationGrantsAuthorized':False,'humanProfilingBudgetAuthorized':False,
            'resumeAuthorized':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'automaticReplayAllowed':False,'budgetReset':False}

def link_map(rows):
    require(type(rows)is list and len(rows)<=1024,'BOUNDED_BINDING_LIST_REQUIRED');result={}
    for row in rows:
        require(type(row)is dict and re.fullmatch('[A-Za-z0-9_-]{1,128}',row.get('id',''))
                and type(row.get('name'))is str and row['id']not in result,'UNIQUE_BINDING_ID_REQUIRED')
        result[row['id']]=row['name']
    require(len(set(result.values()))==len(result),'UNIQUE_BINDING_NAME_REQUIRED');return result

def validate_created_scope(detail,plan):
    wanted=plan['definitionToCreate']
    require(type(detail)is dict and all(detail.get(k)==wanted[k]for k in ('id','name','protocol','attributes'))
            and detail.get('protocolMappers',[])==[] and detail.get('otherAttributeCount',0)==0,'EXACT_CREATED_DEFINITION_ID_MARKER_AND_EMPTY_MAPPERS_REQUIRED')
    return wanted['id']

def validate_location(location,plan,endpoint,issuer):
    require(type(location)is str and 0<len(location)<=2048 and all(32<=ord(c)<127 for c in location),'BOUNDED_CREATE_LOCATION_REQUIRED')
    u=urlsplit(location);expected='/admin/realms/'+plan['realm']+'/client-scopes/'+plan['definitionToCreate']['id']
    require(u.path==expected and not u.query and not u.fragment and not u.username and not u.password,'EXACT_PREAPPROVED_SCOPE_LOCATION_REQUIRED')
    if u.scheme or u.netloc:
        origin=u.scheme+'://'+u.netloc
        allowed={issuer.rsplit('/realms/',1)[0],endpoint['storedServerUrl'],
                 'http://'+endpoint['connectHost']+':'+str(endpoint['connectPort'])}
        require(origin in allowed,'SELECTED_PROVIDER_CREATE_LOCATION_REQUIRED')

def verify_postcondition(before,after,plan):
    require(after['report']['bindingAndUnrestrictedEligibilityProven']is True
            and after['report']['clientUuid']==plan['clientUuid']and after['report']['clientId']==plan['clientId'],
            'CORRECTED_CLIENT_BINDING_ELIGIBILITY_REQUIRED')
    require(link_map(before['defaults'])==link_map(after['defaults']),'ALL_PREEXISTING_DEFAULT_BINDINGS_MUST_REMAIN_EXACT')
    wanted={**link_map(before['optionals']),**{r['id']:r['name']for r in plan['assignmentsToAdd']}}
    require(link_map(after['optionals'])==wanted,'ONLY_THREE_REVIEWED_OPTIONAL_LINKS_MAY_BE_ADDED')
    require(before['clientIntegrity']==after['clientIntegrity'],'UNRELATED_CLIENT_CONFIGURATION_CHANGED')
    require(before['realmDefaults']==after['realmDefaults'],'REALM_DEFAULT_SCOPE_ASSIGNMENTS_CHANGED')
    old,new=before['definitionIntegrity'],after['definitionIntegrity'];scope=plan['definitionToCreate']
    require(len(old)==plan['previousDefinitionCount']and len(new)==len(old)+1 and scope['id']not in old
            and set(new)==set(old)|{scope['id']}and all(new[k]==v for k,v in old.items()),'ONLY_ONE_REVIEWED_DEFINITION_MAY_BE_CREATED')
    return True

class CorrectionCapture(Capture):
    def put(self,name,value):
        if name=='claim.json':self.maximums.update(privateMetadataReads=3,engineGets=7)
        if re.fullmatch('engine-get-[0-9]+-response.json',name):
            value={'schema':'ouf.ths-iam-engine-observation.v1','rawEnvironmentPersisted':False,'binding':stable_binding(value)}if 'Id'in value else{'schema':'ouf.ths-iam-engine-info.v1','serverVersion':value.get('ServerVersion')}
        return super().put(name,value)

class CorrectionLedger(ReadLedger):
    def __init__(self,capture,*,clock=time.time,sleep=time.sleep):
        super().__init__(capture,clock=clock,sleep=sleep)
        require('iamWritesReserved'not in self.c.counts,'CORRECTION_LEDGER_CANNOT_RESET_COUNTERS')
        self.c.counts.update(iamWritesReserved=0,iamWritesObserved=0);self.approvedReviewHash=None
        self.claimedWrites=set();self.claimedStages=set();self.observedStages=set()
    def request(self,stage,operation,payload,send,guard,*,expiry=None):
        require(operation in ('PASSWORD_GRANT','IDENTITY','CLIENT_LIST','CLIENT','DEFAULTS','OPTIONALS','DEFINITIONS','SCOPE_ROLES','SCOPE_DETAIL','CLIENT_INTEGRITY','DEFINITIONS_INTEGRITY','REALM_DEFAULTS','REALM_OPTIONALS')
                and payload.get('operation')==operation,'EXACT_COUNTED_CORRECTION_READ_REQUIRED')
        # Reuse the established read-only state machine with this operation's
        # explicit40GET profile. Authentication remains exactly one dispatch.
        for attempt in range(3):
            guard();require(self.approvedReviewHash is not None and self.deadline is not None and self.clock()<self.deadline,'CURRENT_CORRECTION_REVIEW_AND_WINDOW_REQUIRED')
            if operation=='PASSWORD_GRANT':
                require(attempt==0 and self.c.counts['oauthRequestsReserved']==0,'ONE_CORRECTION_AUTHENTICATION_NO_REPLAY');self.c.counts['oauthRequestsReserved']=1
            else:
                require(self.authenticated and expiry is not None and expiry>self.clock()+8 and self.c.counts['adminGetsReserved']<40,'FINITE_CURRENT_CORRECTION_GET_PROFILE_REQUIRED')
                require(operation=='IDENTITY'or self.identityVerified,'PROTECTED_IDENTITY_REQUIRED_BEFORE_IAM_CORRECTION_READ')
                if attempt:require(self.c.counts['adminGetRetryReservations']<4,'CORRECTION_GET_RETRY_BUDGET_EXHAUSTED');self.c.counts['adminGetRetryReservations']+=1
                self.c.counts['adminGetsReserved']+=1
            self.event(stage,operation=operation,attempt=attempt+1,dispatchReserved=True)
            value=send(payload);self.c.counts['bytes']+=value['bytes'];require(self.c.counts['bytes']<=25165824,'CORRECTION_BYTE_LIMIT')
            self.event(stage,operation=operation,status=value['status'],responseReceived=True);guard()
            if value['status']==200:return value['body']
            require(operation!='PASSWORD_GRANT','CORRECTION_AUTHENTICATION_AMBIGUOUS_OR_DENIED_NO_RETRY')
            require(value['status']in(0,429,502,503,504)and attempt<2,'CORRECTION_GET_DENIED_OR_UNKNOWN_NO_RETRY')
            import random
            delay=(5,15)[attempt]*random.SystemRandom().uniform(.8,1.2);header=value.get('retryAfter','')
            if header:
                if header.isdigit():retry=float(header)
                else:
                    from email.utils import parsedate_to_datetime
                    try:retry=parsedate_to_datetime(header).timestamp()-self.clock()
                    except (ValueError,TypeError,OverflowError):raise Stop('INVALID_CORRECTION_RETRY_AFTER')from None
                delay=max(delay,max(0,retry))
            require(delay<=20 and self.clock()+delay+8<min(expiry,self.deadline),'CORRECTION_RETRY_CANNOT_EXTEND_CURRENT_WINDOW')
            until=self.clock()+delay;self.event(stage,transient=True,nextAttemptAt=until)
            while self.clock()<until:guard();self.sleep(min(1,until-self.clock()))
        raise Stop('FINITE_CORRECTION_GET_STAGE_EXHAUSTED')
    def write(self,stage,operation,payload,send,guard,*,expiry):
        require(operation in ('CREATE_SCOPE','ASSIGN_OPTIONAL')and payload.get('operation')==operation,'CLOSED_CORRECTION_WRITE_REQUIRED')
        signature=(operation,payload['clientUuid'],payload['scopeUuid'])
        require(signature not in self.claimedWrites and stage not in self.claimedStages,'CORRECTION_EFFECT_ALREADY_CLAIMED_NO_REPLAY')
        guard();require(self.approvedReviewHash is not None and self.authenticated and self.identityVerified and expiry>self.clock()+8
                        and self.clock()<self.deadline and self.c.counts['iamWritesReserved']<4,'LIVE_REVIEW_IDENTITY_AND_FOUR_WRITE_LIMIT_REQUIRED')
        self.claimedWrites.add(signature);self.claimedStages.add(stage)
        self.c.counts['iamWritesReserved']+=1
        self.event(stage,operation=operation,dispatchReserved=True,reviewHash=self.approvedReviewHash,
                   scopeId=payload['scopeUuid'],scopeName=payload['scopeName'],clientUuid=payload['clientUuid'])
        try:value=send(payload)
        except BaseException:
            self.event(stage,operation=operation,responseNotObserved=True,reconciliationRequired=True)
            raise
        self.c.counts['bytes']+=value['bytes']
        # Persist the whitelisted HTTP receipt BEFORE any parser, process,
        # expiry or state guard. A subsequent STOP cannot erase this evidence.
        self.event(stage,operation=operation,status=value['status'],location=value.get('location',''),responseReceived=True)
        guard();require(self.c.counts['bytes']<=25165824,'CORRECTION_BYTE_LIMIT')
        require(value['status']in(0,200,201,204,429,500,502,503,504),'CORRECTION_WRITE_DENIED_OR_UNKNOWN_PRESERVED_NO_REPLAY')
        return value
    def observed(self,stage,*,ambiguous):
        require(stage in self.claimedStages and stage not in self.observedStages
                and self.c.counts['iamWritesObserved']<self.c.counts['iamWritesReserved'],'ONE_PROOF_PER_CLAIMED_CORRECTION_EFFECT_REQUIRED')
        self.observedStages.add(stage)
        self.c.counts['iamWritesObserved']+=1
        self.event(stage,effectStateObserved=True,httpOutcomeAmbiguous=ambiguous,writeWillNotBeRepeated=True)
