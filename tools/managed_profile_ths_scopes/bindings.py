"""Pure OIDC scope-binding inspection and additive owner configuration profile.

Inputs are authenticated observations, never user-supplied client routing. This
compiler performs no authentication, grant, IAM mutation or deployment. A new
execution review and current owner-state fences remain mandatory downstream.
"""
import copy,re
from tools.managed_csv_recovery.retained_inputs import require,digest
from tools.managed_profile_ths_scopes.contract import REQUIRED,scope_patch

def scope_rows(rows):
    require(type(rows)is list and len(rows)<=1024,'BOUNDED_COMPLETE_CLIENT_SCOPE_ROWS_REQUIRED')
    by_name={};ids=set()
    for row in rows:
        require(type(row)is dict and type(row.get('id'))is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',row['id'])
                and type(row.get('name'))is str and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',row['name'])
                and row['id']not in ids and row['name']not in by_name,'DISTINCT_LITERAL_CLIENT_SCOPE_IDENTITIES_REQUIRED')
        attrs=row.get('attributes')or{}
        require(type(attrs)is dict,'CLIENT_SCOPE_ATTRIBUTES_REQUIRED')
        flag=attrs.get('include.in.token.scope')
        require(flag in (None,'true','false'),'TYPED_INCLUDE_IN_TOKEN_SCOPE_REQUIRED')
        # Keycloak ClientScopeModel's documented default is true when absent.
        require(attrs.get('is.dynamic.scope')in(None,'true','false')and attrs.get('is.parameterized.scope')in(None,'true','false'),'TYPED_SCOPE_PARAMETERIZATION_REQUIRED')
        ids.add(row['id']);by_name[row['name']]={'id':row['id'],'name':row['name'],'protocol':row.get('protocol'),
                'includeInTokenScope':flag!='false','includeInTokenScopeAttribute':flag,
                'dynamic':attrs.get('is.dynamic.scope')=='true'or attrs.get('is.parameterized.scope')=='true'}
    return by_name

def binding_report(client,defaults,optionals,definitions,role_mappings,*,expected_client,required=REQUIRED):
    require(type(client)is dict and client.get('clientId')==expected_client and client.get('enabled')is True
            and client.get('protocol')=='openid-connect'and client.get('standardFlowEnabled')is True
            and type(client.get('id'))is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',client['id']),'EXACT_ENABLED_BROWSER_OIDC_CLIENT_REQUIRED')
    d,o,all_scopes=scope_rows(defaults),scope_rows(optionals),scope_rows(definitions)
    require(not(set(d)&set(o))and not({v['id']for v in d.values()}&{v['id']for v in o.values()}),'DISJOINT_DEFAULT_OPTIONAL_CLIENT_BINDINGS_REQUIRED')
    for name,row in {**d,**o}.items():
        require(name in all_scopes and row['id']==all_scopes[name]['id']
                and row['protocol']in(None,all_scopes[name]['protocol']),'ASSIGNED_SCOPE_DEFINITION_IDENTITY_DRIFT')
        # Assignment endpoints return lightweight representations on Keycloak26.
        # An omitted attribute there is not a definition default: eligibility
        # must come from the separately read realm definition of the same UUID.
        if row['includeInTokenScopeAttribute']is not None:
            require(row['includeInTokenScopeAttribute']==all_scopes[name]['includeInTokenScopeAttribute'],'EXPLICIT_ASSIGNED_SCOPE_ATTRIBUTE_DRIFT')
        require(not row['dynamic']or all_scopes[name]['dynamic'],'EXPLICIT_ASSIGNED_SCOPE_PARAMETERIZATION_DRIFT')
    require(type(required)in(tuple,list)and 0<len(required)<=128 and len(set(required))==len(required),'DISTINCT_REQUIRED_SCOPES_REQUIRED')
    rows=[]
    for name in required:
        definition=all_scopes.get(name);mapping=role_mappings.get(name)
        require(mapping is None or type(mapping)is dict and set(mapping)<={'realmMappings','clientMappings'},'CLOSED_SCOPE_ROLE_MAPPING_METADATA_REQUIRED')
        unrestricted=mapping is not None and not mapping.get('realmMappings')and not mapping.get('clientMappings')
        bound=name in d or name in o
        eligible=bool(definition and definition['protocol']=='openid-connect'and definition['includeInTokenScope']and not definition['dynamic']and bound and unrestricted)
        rows.append({'name':name,'id':definition['id']if definition else None,'defined':definition is not None,
                     'binding':'DEFAULT'if name in d else'OPTIONAL'if name in o else'NONE',
                     'includeInTokenScope':definition['includeInTokenScope']if definition else None,
                     'includeInTokenScopeAttribute':definition['includeInTokenScopeAttribute']if definition else None,
                     'roleMappingsObserved':mapping is not None,'unrestrictedByScopeRoleMappings':unrestricted,
                     'eligibleForExplicitRequest':eligible})
    return {'schema':'ouf.ths-oidc-client-binding-observation.v1','clientId':expected_client,'clientUuid':client['id'],
            'defaultScopeCount':len(d),'optionalScopeCount':len(o),'definitionCount':len(all_scopes),
            'bindingSnapshotHash':digest({'client':client,'defaults':d,'optionals':o,'definitions':all_scopes,'roleMappings':role_mappings}),
            'requiredScopes':rows,'bindingAndUnrestrictedEligibilityProven':all(r['eligibleForExplicitRequest']for r in rows),
            'blockedScopes':[r['name']for r in rows if not r['eligibleForExplicitRequest']],
            'effectiveBrowserTokenScopesProven':False,'iamMutations':0,'newGrantsGranted':0}

def configuration_profile(actual,observation,identity,*,installation_ref):
    require(type(installation_ref)is str and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',installation_ref),'EXPLICIT_INSTALLATION_REFERENCE_REQUIRED')
    require(observation.get('schema')=='ouf.ths-oidc-client-binding-observation.v1'
            and observation.get('clientId')==identity['clientId']and observation.get('bindingAndUnrestrictedEligibilityProven')is True
            and observation.get('blockedScopes')==[]and observation.get('iamMutations')==0
            and [r['name']for r in observation['requiredScopes']]==list(REQUIRED)
            and all(r['eligibleForExplicitRequest']is True for r in observation['requiredScopes'])
            and identity.get('registrationId')=='ouf-ths'and identity.get('fileSelectionAndPrecedenceVerified')is True,'CURRENT_EXACT_CLIENT_BINDING_PROOF_REQUIRED')
    summary,environment=scope_patch(actual)
    require(summary['missingRequestScopes'],'ALREADY_COMPLETE_REQUEST_RECONCILE_WITHOUT_NOOP_PATCH')
    original=copy.deepcopy(actual);candidate=copy.deepcopy(actual);candidate['Config']['Env']=environment
    unchanged=lambda value:{**value,'Config':{k:v for k,v in value['Config'].items()if k!='Env'}}
    require(unchanged(original)==unchanged(candidate),'ONLY_OWNER_ENVIRONMENT_MAY_CHANGE')
    profile={'schema':'ouf.ths-additive-owner-configuration-profile.v1','installationRef':installation_ref,
             'registrationId':'ouf-ths','clientId':identity['clientId'],'issuer':identity['issuer'],
             'ownerImageId':actual['Image'],'ownerContainerId':actual['Id'],'currentConfigurationHash':digest(actual['Config']),
             'proposedConfigurationHash':digest(candidate['Config']),'iamBindingSnapshotHash':observation['bindingSnapshotHash'],
             'requiredScopes':list(REQUIRED),'preservedRequestedScopes':summary['requestedScopes'],'addedRequestScopes':summary['missingRequestScopes'],
             'requestBeforeHash':summary['requestBeforeHash'],'requestAfterHash':summary['conditionalRequestAfterHash'],
             'replacementEnvironment':environment,'sameNativeImageRequired':True,'allOtherPropertiesPreserved':True,
             'iamConfigurationMutationAuthorized':False,'executionEntryQualified':False,'currentJobOrBudgetStateObserved':False,
             'freshRuntimeAndJobFencesRequired':True,'newHumanExecutionReviewRequired':True,'runtimeAuthorityIssued':False,
             'targetApplyAuthorized':False,'effectiveBrowserTokenScopesProven':False,'automaticReplayAllowed':False,'budgetReset':False}
    return profile
