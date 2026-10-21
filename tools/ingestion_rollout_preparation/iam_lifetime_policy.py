"""One reviewed client-only lifetime PUT after fresh manual admin consent.

Preserve device/password/standard flows and every unrelated client/realm field.
Retain the283 attempt ledger and append one bounded administrative successor.
No HUMAN login/window, refresh, runtime grant, rollback or automatic replay.
"""
import copy
import os
from pathlib import Path
import re
import subprocess
import time

CHECKPOINT = {'phase': 'NOT_STARTED', 'contextPath': None}
SCHEMA = 'ouf.iam-client-lifetime-successor.v1'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def profile(case, receipt, api):
    p = case['installationDurationProfile']
    require(case['schema'] == 'ouf.iam-client-lifetime-case.v1'
        and p['schema'] == 'ouf.iam-client-lifetime-installation-profile.v1'
        and type(p['proposedAccessTokenSeconds']) is int
        and p['runtimeMaximumSeconds'] == 900 and p['clockSafetyMarginSeconds'] == 30
        and p['reviewAndApprovalAllowanceSeconds'] == 120
        and p['proposedAccessTokenSeconds'] > 900+30+120
        and p['proposedAccessTokenSeconds'] <= 1800
        and p['acceptedNormalTokenFreshnessBoundSeconds'] == p['proposedAccessTokenSeconds']
        and p['administrativeWriterIsolation'] == 'EXCLUSIVE_OPERATOR_MAINTENANCE_WINDOW'
        and p['clientUuid'] == receipt['clientUuid'] and p['clientId'] == receipt['clientId']
        and p['realm'] == receipt['realm'] and case['expectedAttempts'] == receipt['attempts']
        and type(case['expectedAttempts']) is int and 0 <= case['expectedAttempts'] <= 283
        and receipt['maximumCumulativeOAuthAttempts'] == case['maximumCumulativeOAuthAttempts'] == 288
        and case['maximumNewOAuthRequests'] == 1 and case['maximumNewEngineGets'] == 2
        and case['maximumNewAdminGets'] == 5 and case['maximumClientPuts'] == 1,
        'EXACT_FINITE_CLIENT_DURATION_AND_SUPPLEMENTARY_BUDGET_PROFILE_REQUIRED')
    require(receipt['schema'] == 'ouf.iam-explicit-api-result.v1' and receipt['complete'] is True
        and receipt['status'] == 'CURRENT_ADMIN_IDENTITY_AND_IAM_POLICY_READ_NO_AUTHORITY'
        and receipt['adminIdentityApiVerified'] is receipt['currentProviderTimeoutMetadataRead'] is True
        and receipt['runtimeAuthorityIssued'] is receipt['budgetReset'] is False,
        'EXACT_COMPLETED_ADMIN_API_READ_REQUIRED')
    require(all(type(p[k]) is str and re.fullmatch('[A-Za-z0-9._-]{1,128}',p[k])
        for k in ('realm','clientId','clientUuid')), 'EXACT_BOUNDED_CLIENT_DURATION_TARGET_REQUIRED')
    realm = receipt['realmTimeouts']
    require(type(realm['ssoSessionIdleTimeout']) is type(realm['ssoSessionMaxLifespan']) is int
        and p['proposedAccessTokenSeconds'] < min(realm['ssoSessionIdleTimeout'], realm['ssoSessionMaxLifespan']),
        'PROPOSED_DURATION_MUST_FIT_RETAINED_SSO_SESSION_CEILINGS')
    return {'schema': 'ouf.iam-client-lifetime-review.v1', 'caseHash': api.digest(case),
        'target': {k:p[k] for k in ('realm','clientId','clientUuid')},
        'previousClientLifetimeAttribute': receipt['clientTimeoutAttributes']['access.token.lifespan'],
        'previousRealmLifetimeSeconds': realm['accessTokenLifespan'],
        'proposedAccessTokenSeconds': p['proposedAccessTokenSeconds'],
        'normalTokenFreshnessBoundAcceptedSeconds': p['acceptedNormalTokenFreshnessBoundSeconds'],
        'priorAttempts': case['expectedAttempts'], 'maximumCumulativeAttempts': 288,
        'projectedAttemptsAfterAdminAuthentication': case['expectedAttempts']+1,
        'nominalLaterHumanProviderRequests': 4,
        'projectedAttemptsAfterAdminAndNominalHuman': case['expectedAttempts']+5,
        'maximumNewEngineGets':2,'maximumNewAdminGets':5,'maximumClientPuts':1,
        'flowChangesAllowed':False,'roleChangesAllowed':False,'realmChangesAllowed':False,
        'automaticExpiryOfClientOverride':False,'automaticRollbackAllowed':False,
        'exclusiveAdministrativeWriterRequired':True,'providerAtomicCasProven':False,
        'humanWindowOpeningAllowed':False,'runtimeAuthorityIssued':False,'budgetReset':False}


def selected_state(realm, client, api):
    attrs = client.get('attributes') or {}
    require(type(attrs) is dict and len(attrs) <= 256
        and all(type(k) is str and 0<len(k)<=256 and type(v) is str and len(v)<=8192 for k,v in attrs.items()),
        'BOUNDED_STRING_CLIENT_ATTRIBUTES_REQUIRED')
    return {'realmTimeouts': {k:realm.get(k) for k in ('accessTokenLifespan','ssoSessionIdleTimeout',
        'ssoSessionMaxLifespan','clientSessionIdleTimeout','clientSessionMaxLifespan')},
        'clientTimeoutAttributes': {k:attrs.get(k) for k in ('access.token.lifespan',
        'client.session.idle.timeout','client.session.max.lifespan')},
        'clientFlowFlags': {k:client.get(k) for k in ('directAccessGrantsEnabled','standardFlowEnabled',
        'serviceAccountsEnabled','publicClient')},
        'deviceGrantEnabledAttribute':attrs.get('oauth2.device.authorization.grant.enabled'),
        'revocationMetadata':{'realmNotBefore':realm.get('notBefore'),'clientNotBefore':client.get('notBefore'),
        'revokeRefreshToken':realm.get('revokeRefreshToken'),'refreshTokenMaxReuse':realm.get('refreshTokenMaxReuse')}}


def canonical_client(client,api):
    value=copy.deepcopy(client)
    # These are sets/maps in Keycloak's ClientModel, exposed as JSON arrays.
    # Preserve every element and every mapper field; only ordering is ignored.
    for name in ('redirectUris','webOrigins','defaultClientScopes','optionalClientScopes','protocolMappers'):
        if name in value:
            require(type(value[name])is list,'TYPED_CLIENT_SET_REPRESENTATION_REQUIRED')
            value[name]=sorted(value[name],key=api.encoded)
    return value


def comparison(before,after,api):
    first,second=canonical_client(before,api),canonical_client(after,api)
    names=('id','clientId','enabled','publicClient','directAccessGrantsEnabled','standardFlowEnabled',
        'serviceAccountsEnabled','attributes','protocolMappers','defaultClientScopes','optionalClientScopes',
        'redirectUris','webOrigins','secret','clientAuthenticatorType','authenticationFlowBindingOverrides',
        'fullScopeAllowed','access','registeredNodes','authorizationServicesEnabled')
    same={k:first.get(k)==second.get(k) and (k in first)==(k in second)for k in names}
    same['allOtherFields']=({k:v for k,v in first.items()if k not in names}=={k:v for k,v in second.items()if k not in names})
    return same


PUT_CHILD = r'''import http.client,ipaddress,json,os,re,signal,sys
signal.alarm(8)
try:
 v=json.loads(sys.stdin.buffer.read(131073))
 if set(v)!={'host','port','realm','clientUuid','token','attributes','lifespan'}:raise ValueError()
 if not ipaddress.ip_address(v['host']).is_loopback or type(v['port'])is not int or not 1<=v['port']<=65535:raise ValueError()
 if not all(type(v[k])is str and re.fullmatch('[A-Za-z0-9._-]{1,128}',v[k])for k in ('realm','clientUuid')):raise ValueError()
 if type(v['token'])is not str or not 0<len(v['token'])<=16384 or any(c.isspace()for c in v['token']):raise ValueError()
 if type(v['lifespan'])is not int or not 1050<v['lifespan']<=1800:raise ValueError()
 attrs=v['attributes']
 if type(attrs)is not dict or len(attrs)>256 or attrs.get('access.token.lifespan')!=str(v['lifespan']):raise ValueError()
 if not all(type(k)is str and 0<len(k)<=256 and type(x)is str and len(x)<=8192 for k,x in attrs.items()):raise ValueError()
 raw=json.dumps({'attributes':attrs},sort_keys=True,separators=(',',':'),allow_nan=False).encode()
 if len(raw)>65536:raise ValueError()
 fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
 c=http.client.HTTPConnection(v['host'],v['port'],timeout=6)
 c.request('PUT','/admin/realms/'+v['realm']+'/clients/'+v['clientUuid'],body=raw,headers={'Authorization':'Bearer '+v['token'],'Content-Type':'application/json','Connection':'close'})
 r=c.getresponse();body=r.read(1025)
 if r.status!=204 or body:raise ValueError()
 sys.stdout.buffer.write(b'{"status":204}');sys.stdout.buffer.flush();c.close()
except BaseException:os._exit(2)
os._exit(0)
'''


def put(api, program, ns, payload):
    run = subprocess.run([api.executable(program),'-I','-B','-S','-c',PUT_CHILD,str(ns)],
        input=api.encoded(payload),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,
        pass_fds=(ns,),env={'LC_ALL':'C','PATH':'/usr/bin:/bin'})
    require(run.returncode==0 and run.stdout==b'{"status":204}',
        'CLIENT_PUT_OUTCOME_UNPROVEN_RECONCILE_NO_REPLAY')


def retained(case, api, auth, files):
    prior = case['originalApiCase']
    values = auth.base(prior,api,files)
    old, context, session, selection, owner, prepared, endpoint, seals = values
    parent = context/'explicit-admin-api-successor'
    row,seal = files.selected(str(parent/'recovery.json'));seals.append(seal)
    claim,cseal=files.selected(str(session/'successor-window.claim.json'));seals.append(cseal)
    require(row['schema']==auth.SCHEMA and row['caseHash']==api.digest(prior)
        and row['state']=='COMPLETE' and row['complete'] is True
        and row['attempts']==case['expectedAttempts'] and row['oauthRequestsReserved']==1
        and row['engineRequestsReserved']==2 and row['adminGetsReserved']==4
        and row['grant']==claim and claim['destination']==str(parent)
        and api.digest(row['result'])==case['retainedApiResultHash'],
        'EXACT_COMPLETED_ADMIN_LEDGER_AND_RESULT_REQUIRED')
    review=profile(case,row['result'],api)
    return values,parent,row['result'],review


def run(case,api,auth,files,process_adapter,Journal):
    CHECKPOINT.update(phase='RETAINED_ADMIN_LEDGER_AND_SCOPED_REVIEW',contextPath=None)
    values,parent,receipt,review=retained(case,api,auth,files)
    old,context,session,selection,owner,prepared,endpoint,seals=values
    destination=parent/'lifetime-policy-successor'
    CHECKPOINT['contextPath']=str(destination)
    claim=parent/'provider-budget-successor.claim.json'
    require(not os.path.lexists(claim) and not os.path.lexists(destination),
        'CLIENT_LIFETIME_SUCCESSOR_CONSUMED_STATUS_ONLY_NO_REPLAY')
    seconds=review['proposedAccessTokenSeconds']
    CHECKPOINT['phase']='EXPLICIT_IAM_LIFETIME_AND_FRESHNESS_CONSENT'
    auth.terminal('Approvi UN override access.token.lifespan='+str(seconds)+' sul solo client '+receipt['clientId']+'.\n'
        'Il realm resta a'+str(receipt['realmTimeouts']['accessTokenLifespan'])+'secondi; flussi, ruoli e altri campi invariati.\n'
        'Tutti i futuri token di QUESTO client potranno durare'+str(seconds)+'secondi ('+str(seconds//60)+'minuti).\n'
        'Accetti questo limite normale di freshness delle autorizzazioni; revoca urgente non provata da questa operazione.\n'
        'Override persistente fino a modifica esplicita: NON scade e NON si ripristina da solo.\n'
        'Confermi nessun altro writer amministrativo sul client durante questo passaggio (API senza CAS/ETag).\n'
        'Budget cumulativo'+str(case['expectedAttempts'])+'/288 -> massimo'+str(case['expectedAttempts']+1)+'/288.\n'
        'UNA autenticazione admin,5GET Admin,1PUT client,2GET Engine aggiuntivi; nessun reset o replay.\n'
        'Nessun login/finestra HUMAN, nessuna autorita runtime o approvazione THS. Serve password IAM, non sudo.',
        'APPROVO TOKEN '+str(seconds)+' FRESHNESS '+str(seconds)+' '+api.digest(review))
    for seal in seals:files.recheck(seal)
    now=int(time.time())
    grant={'schema':SCHEMA,'caseHash':api.digest(case),'review':review,'reviewHash':api.digest(review),
        'approvedAt':now,'expiresAt':now+240,'destination':str(destination),
        'priorAttempts':case['expectedAttempts'],'maximumCumulativeOAuthAttempts':288,
        'futureHumanSuccessorMustIncludeThisLedger':True,'runtimeAuthorityIssued':False,'budgetReset':False}
    with Journal(parent).invocation():
        for seal in seals:files.recheck(seal)
        Journal(parent).create(claim,api.encoded(grant));Journal(parent).sync()
    os.mkdir(destination,0o700)
    journal=Journal(destination)
    journal.initialize({'schema':SCHEMA,'caseHash':api.digest(case),'grant':grant,'state':'CONSENTED',
        'attempts':case['expectedAttempts'],'oauthRequestsReserved':0,'engineRequestsReserved':0,
        'adminGetsReserved':0,'clientPutsReserved':0,'budgetReset':False,'runtimeAuthorityIssued':False})
    process,ns,password=None,None,None
    try:
        CHECKPOINT['phase']='PRIVATE_ADMIN_PASSWORD_TERMINAL_INPUT'
        password=auth.terminal('Password IAM per '+endpoint['expectedAdminUser']+' (input nascosto):')
        engine=api.EngineRead(owner['engine'],journal,selection['keycloakContainer'])
        before=api.generation(engine.request('GET'),selection['keycloakContainer'])
        process=process_adapter.ProcessFiles(before['Pid'])
        ns_path='/proc/'+str(before['Pid'])+'/ns/net'
        ns=os.open(ns_path,os.O_RDONLY|os.O_CLOEXEC)
        namespace=(os.fstat(ns).st_dev,os.fstat(ns).st_ino)
        program=prepared['sourceClosure']['executables']['python']
        def check():
            for seal in seals:files.recheck(seal)
            process.check()
            require(time.time()<grant['expiresAt'] and (os.stat(ns_path).st_dev,os.stat(ns_path).st_ino)==namespace,
                'CURRENT_FINITE_LIFETIME_GRANT_AND_NAMESPACE_REQUIRED')
        def get(op,credential,subject='',expiry=None):
            CHECKPOINT['phase']=op;check();row=journal.read()
            if op=='PASSWORD_GRANT':
                require(row['oauthRequestsReserved']==0 and row['attempts']==case['expectedAttempts'],
                    'ONE_NEW_ADMIN_AUTHENTICATION_ONLY')
                api.save(journal,state='AUTHENTICATING',oauthRequestsReserved=1,attempts=row['attempts']+1)
            else:
                require(row['adminGetsReserved']<5 and expiry is not None and expiry>time.time()+12,
                    'FIVE_GET_CEILING_AND_CURRENT_ADMIN_TOKEN_REQUIRED')
                api.save(journal,state='READING',adminGetsReserved=row['adminGetsReserved']+1)
            value=auth.dispatch(api,program,ns,{'host':endpoint['connectHost'],'port':endpoint['connectPort'],
                'adminRealm':endpoint['adminRealm'],'clientId':endpoint['adminClientId'],
                'expectedUser':endpoint['expectedAdminUser'],'targetRealm':selection['realm'],
                'targetClient':old['humanClientId'],'operation':op,'credential':credential,
                'subject':subject,'clientUuid':receipt['clientUuid'] if op=='CLIENT' else ''})
            check();return value
        requested=time.time();response=get('PASSWORD_GRANT',password);password=None
        token,expiry,subject=auth.access(api,response,endpoint,selection['issuer'],requested);del response
        identity=get('IDENTITY',token,subject=subject,expiry=expiry)
        require(type(identity)is dict and identity.get('id')==subject
            and identity.get('username')==endpoint['expectedAdminUser'] and identity.get('enabled')is True,
            'EXACT_FRESH_ADMIN_API_IDENTITY_REQUIRED')
        del identity
        realm=get('REALM',token,expiry=expiry);client=get('CLIENT',token,expiry=expiry)
        api.policy(realm,[client],client,selection['realm'],old['humanClientId'])
        current=selected_state(realm,client,api)
        expected={k:receipt[k]for k in current}
        require(client.get('id')==receipt['clientUuid'] and current==expected,
            'RETAINED_CLIENT_OR_REALM_POLICY_DRIFT_NO_PUT_ALLOWED')
        attrs=copy.deepcopy(client.get('attributes')or{})
        attrs['access.token.lifespan']=str(seconds)
        proposed=copy.deepcopy(client);proposed['attributes']=attrs
        require(len(api.encoded({'attributes':attrs}))<=65536,'BOUNDED_ONE_FIELD_CLIENT_UPDATE_REQUIRED')
        CHECKPOINT['phase']='DISPATCH_ONE_REVIEWED_CLIENT_LIFETIME_PUT';check()
        require(expiry>time.time()+12 and journal.read()['clientPutsReserved']==0,
            'CURRENT_ADMIN_TOKEN_AND_UNCONSUMED_SINGLE_PUT_REQUIRED')
        # Persist hashes privately for ambiguous-outcome reconciliation, never
        # full responses/attributes/secrets. No provider CAS/ETag is claimed.
        api.save(journal,state='DISPATCHING_PUT',clientPutsReserved=1,
            originalClientDigest=api.digest(canonical_client(client,api)),expectedClientDigest=api.digest(canonical_client(proposed,api)),
            expectedRealmDigest=api.digest(realm),previousLifetimeAttribute=receipt['clientTimeoutAttributes']['access.token.lifespan'])
        put(api,program,ns,{'host':endpoint['connectHost'],'port':endpoint['connectPort'],
            'realm':selection['realm'],'clientUuid':receipt['clientUuid'],'token':token,
            'attributes':attrs,'lifespan':seconds})
        check()
        after=get('CLIENT',token,expiry=expiry)
        unchanged=comparison(proposed,after,api)
        api.save(journal,readbackComparison=unchanged)
        require(all(unchanged.values()),'CLIENT_READBACK_CHANGED_UNRELATED_FIELDS_RECONCILE_NO_ROLLBACK')
        final_realm=get('REALM',token,expiry=expiry)
        require(final_realm==realm,'REALM_CHANGED_DURING_SCOPED_CLIENT_UPDATE_RECONCILE')
        require(api.generation(engine.request('GET'),selection['keycloakContainer'])==before,
            'IAM_GENERATION_CHANGED_DURING_CLIENT_POLICY_UPDATE')
        check();del token,client,proposed,attrs,realm,after,final_realm
        result={'schema':'ouf.iam-client-lifetime-result.v1','status':'CLIENT_LIFETIME_OVERRIDE_READBACK_NO_RUNTIME_AUTHORITY',
            'contextPath':str(destination),'complete':True,'readOnly':False,'clientId':receipt['clientId'],
            'clientUuid':receipt['clientUuid'],'realm':receipt['realm'],'previousClientLifetimeAttribute':receipt['clientTimeoutAttributes']['access.token.lifespan'],
            'publishedClientLifetimeSeconds':seconds,'realmLifetimeUnchanged':True,
            'unrelatedClientFieldsUnchanged':True,'authenticationFlowFlagsUnchanged':True,'rolesChanged':False,
            'revocationFreshnessAllowanceApprovedSeconds':seconds,'revocationPropagationMeasured':False,
            'emergencyRevocationProven':False,'automaticOverrideExpiry':False,
            'manualRestorationRequiresSeparateReview':True,'effectiveFutureHumanIssuedLifetimeProven':False,
            'attempts':case['expectedAttempts']+1,'remainingAttempts':287-case['expectedAttempts'],
            'maximumCumulativeOAuthAttempts':288,'oauthRequestsReserved':1,'adminGetsReserved':5,
            'clientPutsReserved':1,'newEngineGets':2,'priorEngineRequestsRetained':9,'cumulativeEngineRequests':11,
            'iamMutations':1,'policyMutations':1,'newLoginPerformed':True,'refreshPerformed':False,
            'humanCredentialJournalsRead':1,'humanBearerFilesOpened':0,'credentialFilesRead':0,
            'credentialValuesPrinted':False,'credentialHashesPrinted':False,'secretValuesPersisted':False,
            'priorContextsAndClaimsRetained':True,'futureHumanMustConsumeSupplementaryLedger':True,
            'newHumanWindowOpened':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,
            'budgetReset':False,'automaticRollbackAllowed':False,'containerLifecycleOperations':0,
            'databaseCalls':0,'gatewayRequests':0,'completedTechnicalPhases':8,'functionalMilestonesProven':4,
            'notReleaseAcceptance':True,'observedAtUnix':time.time()}
        api.save(journal,state='COMPLETE',complete=True,result=result)
        return result
    except BaseException:
        api.save(journal,state='STOP_RECONCILE',complete=False)
        raise
    finally:
        password=None
        if ns is not None:os.close(ns)
        if process is not None:process.close()


def status(case,api,files,Journal):
    parent=Path(case['originalApiCase']['reconciledCase']['retainedContextPath'])/'explicit-admin-api-successor'
    destination=parent/'lifetime-policy-successor'
    row,_=files.selected(str(destination/'recovery.json'))
    require(row['schema']==SCHEMA and row['caseHash']==api.digest(case),'EXACT_CLIENT_LIFETIME_STATUS_REQUIRED')
    return {'schema':'ouf.iam-client-lifetime-result.v1','status':'RETAINED_LIFETIME_OPERATION_METADATA_ONLY',
        'contextPath':str(destination),'state':row['state'],'complete':row.get('complete',False),
        'attempts':row['attempts'],'maximumCumulativeOAuthAttempts':288,'remainingAttempts':288-row['attempts'],
        'oauthRequestsReserved':row['oauthRequestsReserved'],'engineRequestsReserved':row['engineRequestsReserved'],
        'adminGetsReserved':row['adminGetsReserved'],'clientPutsReserved':row['clientPutsReserved'],
        'requestsThisInvocation':0,'readOnly':True,'automaticReplayAllowed':False,'budgetReset':False,
        'runtimeAuthorityIssued':False,'automaticRollbackAllowed':False,
        'readbackComparison':row.get('readbackComparison')}
