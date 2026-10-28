"""One finite reviewed IAM operation; current state must equal retained intent."""
import json,os,time,types
from tools.managed_csv_recovery.retained_inputs import require,digest,decode
from tools.managed_profile_ths_scopes.contract import REQUIRED
from tools.managed_profile_ths_scopes.bindings import binding_report,scope_rows,configuration_profile
from tools.managed_profile_ths_scopes.iam_read import terminal,access
from tools.managed_profile_ths_scopes.iam_correction import CorrectionLedger,link_map,validate_created_scope,validate_location,verify_postcondition
from tools.managed_profile_ths_scopes.iam_correction_transport import dispatch_correction

def correction_snapshot(request,client_uuid,stage):
    client=request('client-'+stage,'CLIENT',uuid=client_uuid)
    require(client.get('id')==client_uuid,'SAME_APPROVED_CLIENT_UUID_REQUIRED')
    defaults=request('defaults-'+stage,'DEFAULTS',uuid=client_uuid)
    optionals=request('optionals-'+stage,'OPTIONALS',uuid=client_uuid)
    definitions=request('definitions-'+stage,'DEFINITIONS');named=scope_rows(definitions);mappings={}
    for i,name in enumerate(REQUIRED):
        if name in named:mappings[name]=request('roles-'+str(i)+'-'+stage,'SCOPE_ROLES',scope=named[name]['id'])
    observation=binding_report(client,defaults,optionals,definitions,mappings,expected_client=client['clientId'])
    integrity=request('client-integrity-'+stage,'CLIENT_INTEGRITY',uuid=client_uuid)
    require(integrity.get('id')==client_uuid and integrity.get('clientId')==client['clientId'],'CLIENT_INTEGRITY_IDENTITY_REQUIRED')
    return {'report':observation,'defaults':defaults,'optionals':optionals,'clientIntegrity':integrity,
            'definitionIntegrity':request('definition-integrity-'+stage,'DEFINITIONS_INTEGRITY'),
            'realmDefaults':{'DEFAULT':link_map(request('realm-defaults-'+stage,'REALM_DEFAULTS')),
                             'OPTIONAL':link_map(request('realm-optionals-'+stage,'REALM_OPTIONALS'))}}

def execute_correction(c,prepared,case,*,prompt=terminal,sender=dispatch_correction,wall=time.time):
    inputs,parent,plan,review,namespace,program,guard,containers=prepared
    ledger=CorrectionLedger(c,clock=wall);password=token=response=None
    try:
        print(json.dumps({'review':review,'reviewHash':digest(review),'runtimeAuthorityIssued':False},sort_keys=True),flush=True)
        prompt('Nuova correzione IAM condizionata alla baseline osservata.\n'
               'UNA definizione OAuth con UUID fissato,nessun mapper/ruolo/RealmDefault;TRE link OPTIONAL SOLO al client '+plan['clientId']+'.\n'
               'Tutti i '+str(plan['preservedDefaultScopeCount'])+' DEFAULT/'+str(plan['preservedOptionalScopeCount'])+' OPTIONAL esistenti sono preservati;massimo1auth amministrativa e4write.\n'
               'Prima degli effetti identita e snapshot correnti devono coincidere con la review;nessuna richiesta di scrivere in chat password/token.\n'
               'Nessun APPLY runtime,grant applicativo,budgetprofiling,resume,upload/job/acquisizione. STOP:non rilanciare.',
               'APPROVO CORREZIONE IAM '+digest(review))
        guard();ledger.approvedReviewHash=digest(review);ledger.deadline=wall()+210
        ledger.event('approval',reviewHash=ledger.approvedReviewHash,expiresAt=ledger.deadline,retainedAdministrativeAuthenticationReservations=1,
                     maximumNewAdministrativeAuthenticationRequests=1,oldBudgetsModified=False)
        endpoint=case['adminEndpoint'];password=prompt('Password IAM per '+endpoint['expectedAdminUser']+' (input nascosto):')
        ledger.deadline=min(ledger.deadline,wall()+120);deadline=ledger.deadline
        def live():guard();require(wall()<deadline,'FINITE_CORRECTION_WINDOW_EXPIRED')
        def payload(operation,credential,*,subject='',uuid='',scope='',name=''):
            return {'host':endpoint['connectHost'],'port':endpoint['connectPort'],'adminRealm':endpoint['adminRealm'],'clientId':endpoint['adminClientId'],
                    'expectedUser':endpoint['expectedAdminUser'],'targetRealm':case['realm'],'targetClient':case['clientId'],'operation':operation,
                    'credential':credential,'subject':subject,'clientUuid':uuid,'scopeUuid':scope,'scopeName':name,'operationRef':plan['operationRef']}
        def send(value):return sender(program,namespace,value)
        at=wall();response=ledger.request('authenticate','PASSWORD_GRANT',payload('PASSWORD_GRANT',password),send,live);password=None
        token,expiry,subject=access(types.SimpleNamespace(decode=decode),response,endpoint,case['issuer'],at);response=None;ledger.authenticated=True
        who=ledger.request('identity','IDENTITY',payload('IDENTITY',token,subject=subject),send,live,expiry=expiry)
        require(who.get('id')==subject and who.get('username')==endpoint['expectedAdminUser']and who.get('enabled')is True,'CURRENT_PROTECTED_IAM_ADMIN_IDENTITY_REQUIRED')
        ledger.identityVerified=True;del who
        def request(stage,operation,*,uuid='',scope='',name=''):
            return ledger.request(stage,operation,payload(operation,token,uuid=uuid,scope=scope,name=name),send,live,expiry=expiry)
        listing=request('client-list','CLIENT_LIST')
        require(type(listing)is list and len(listing)==1 and listing[0].get('id')==plan['clientUuid']and listing[0].get('clientId')==plan['clientId'],'SAME_RETAINED_CLIENT_NOT_A_NEW_CLIENT_REQUIRED')
        before=correction_snapshot(request,plan['clientUuid'],'before')
        require(before['report']==parent['bindingObservation'],'CURRENT_IAM_BASELINE_DRIFT_NO_WRITES')
        require(len(before['definitionIntegrity'])==plan['previousDefinitionCount']and plan['definitionToCreate']['id']not in before['definitionIntegrity'],'PREAPPROVED_NEW_SCOPE_ID_MUST_NOT_EXIST')
        c.put('before-invariants.json',before)
        containers();live();require(expiry>wall()+30,'INSUFFICIENT_CURRENT_TOKEN_WINDOW_BEFORE_FIRST_IAM_WRITE')
        definition=plan['definitionToCreate'];create_payload=payload('CREATE_SCOPE',token,uuid=plan['clientUuid'],scope=definition['id'],name=definition['name'])
        receipt=ledger.write('create-scope','CREATE_SCOPE',create_payload,send,live,expiry=expiry)
        require(receipt['status']in(0,201,429,500,502,503,504),'UNEXPECTED_SCOPE_CREATION_STATUS_NO_REPLAY')
        if receipt['status']==201:validate_location(receipt.get('location',''),plan,endpoint,case['issuer'])
        detail=request('created-scope-read','SCOPE_DETAIL',scope=definition['id'])
        validate_created_scope(detail,plan)
        roles=request('created-scope-roles','SCOPE_ROLES',scope=definition['id'])
        require(type(roles)is dict and not roles.get('realmMappings')and not roles.get('clientMappings'),'NEW_SCOPE_MUST_HAVE_NO_ROLE_RESTRICTIONS')
        ledger.observed('create-scope',ambiguous=receipt['status']!=201)
        initial_optionals=request('preassignment-optionals','OPTIONALS',uuid=plan['clientUuid'])
        require(link_map(initial_optionals)==link_map(before['optionals']),'OPTIONAL_BINDING_DRIFT_BEFORE_ASSIGNMENTS')
        expected=link_map(before['optionals'])
        for i,row in enumerate(plan['assignmentsToAdd']):
            stage='assign-'+str(i)
            value=payload('ASSIGN_OPTIONAL',token,uuid=plan['clientUuid'],scope=row['id'],name=row['name'])
            receipt=ledger.write(stage,'ASSIGN_OPTIONAL',value,send,live,expiry=expiry)
            require(receipt['status']in(0,204,429,500,502,503,504),'UNEXPECTED_OPTIONAL_ASSIGNMENT_STATUS_NO_REPLAY')
            expected={**expected,row['id']:row['name']}
            observed=request('optionals-after-'+str(i),'OPTIONALS',uuid=plan['clientUuid'])
            require(link_map(observed)==expected,'SAME_ASSIGNMENT_OUTCOME_NOT_PROVEN_NO_REPLAY')
            ledger.observed(stage,ambiguous=receipt['status']!=204)
        after=correction_snapshot(request,plan['clientUuid'],'after')
        verify_postcondition(before,after,plan);c.put('after-invariants.json',after)
        token=None;containers();guard()
        profile=configuration_profile(inputs['currentObservations']['onboarding'],after['report'],inputs['clientMetadata'],installation_ref=case['installationRef'])
        c.put('configuration-profile.json',profile)
        ledger.event('complete',configurationProfileHash=digest(profile),iamWritesObserved=4)
        result={'schema':'ouf.managed-profile-ths-iam-binding-correction-result.v1','status':'THS_IAM_BINDINGS_CORRECTED_CONFIGURATION_PROFILE_PREPARED_NOT_AUTHORIZED',
                'complete':True,'contextPath':str(c.root),'operationRef':plan['operationRef'],'reviewHash':digest(review),'parentResultHash':case['parentResultHash'],
                'counts':dict(c.counts),'bindingObservation':after['report'],'createdScopeId':definition['id'],'createdScopeName':definition['name'],
                'newScopeDefinitions':1,'newOptionalClientBindings':3,'preservedDefaultBindings':len(before['defaults']),'preservedOptionalBindings':len(before['optionals']),
                'nonCredentialClientPropertiesPreserved':True,'preexistingDefinitionsPreserved':True,'realmDefaultsPreserved':True,
                'configurationProfilePrepared':True,'configurationProfileHash':digest(profile),'addedRequestScopes':profile['addedRequestScopes'],
                'adminIdentityApiVerified':True,'adminSubjectFromSameFreshProviderIdToken':True,'jwtSignatureIndependentlyVerified':False,
                'humanIamCorrectionReviewApproved':True,'retainedAdministrativeAuthenticationReservations':parent['counts']['oauthRequestsReserved'],
                'cumulativeAdministrativeAuthenticationReservationsInThisLineage':parent['counts']['oauthRequestsReserved']+c.counts['oauthRequestsReserved'],
                'oldScopesAndFilesModified':False,'oldAuthenticationWindowsOrBudgetsReopened':False,'newAdministrativeCredentialValuesPersisted':False,
                'retainedEnvironmentMayContainCredentials':True,'credentialFilesRead':0,'configurationFileContentReads':0,'credentialValuesPrinted':False,
                'iamMutations':c.counts['iamWritesObserved'],'scopePatchApplied':False,'engineWrites':0,'sqlSessions':0,'imageImports':0,
                'newGrantsGranted':0,'humanBudgetsGranted':0,'resumes':0,'newJobs':0,'uploads':0,'sourceActivations':0,'acquisitionsExecuted':0,
                'historicalAuthorityReused':False,'currentJobOrBudgetStateObserved':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
                'automaticReplayAllowed':False,'budgetReset':False,'effectiveBrowserTokenScopesProven':False,'applicationE2EProven':False,'releaseAcceptance':False}
        c.put('result.json',result);return result
    finally:
        password=token=response=None;os.close(namespace)
