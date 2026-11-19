"""Recompile Discovery capabilities/OAuth and the exact three additive routes.

Offline review only. The observed baseline is not authenticated by compilation;
current HUMAN, signatures, native admission and publication remain separate.
"""
import copy,re
from datetime import datetime,timezone
from .custody_capture import digest,encoded,require
from .private_review import absolute,hashed
from .native_profile import DiscoveryProfile,environment
from .publication_primitives import PublicationPrimitives,GATEWAY,ONBOARDING,GATEWAY_COMMIT,ONBOARDING_COMMIT
from tools.chatbot_file_cohort import authorization as auth
from tools.chatbot_file_cohort.gateway import PROFILE,route_map,publication_scope,ROUTE_ID
from tools.chatbot_file_cohort.gateway_runtime import proposed_transport
from tools.chatbot_file_cohort.gateway_preparation import lua_constant

SCHEMA='ouf.discovery-publication-review-inputs.v1'


def shape(v,keys,reason):require(type(v) is dict and set(v)==set(keys),reason)


def assemble(inputs,input_hash,cohort_inputs,primitives):
    shape(inputs,('schema','cohortInputsHash','authorization','gateway','journalDirectories'),
        'EXACT_DISCOVERY_PUBLICATION_INPUTS_REQUIRED')
    require(inputs['schema']==SCHEMA and hashed(input_hash) and digest(inputs)==input_hash
        and inputs['cohortInputsHash']==digest(cohort_inputs) and len(encoded(inputs))<=4194304
        and type(primitives) is PublicationPrimitives,'HASH_BOUND_DISCOVERY_PUBLICATION_INPUTS_REQUIRED')
    r=cohort_inputs['registry'];gp=cohort_inputs['gateway']['plan']
    profile=DiscoveryProfile(r['request'],**r['selection']);env=environment(r['request']['Env'])
    a,g,j=(inputs[k] for k in ('authorization','gateway','journalDirectories'))
    shape(a,('observed','selection','roleId','reviewTime','sessionBinding'),'EXPLICIT_DISCOVERY_AUTHORIZATION_REVIEW_REQUIRED')
    shape(g,('previousRoutes','installation','delegationKeyEnvironment','discoveryKeyEnvironment','upstream','routeIds'),
        'EXPLICIT_DISCOVERY_GATEWAY_REVIEW_REQUIRED')
    shape(j,('authorization','gateway'),'TWO_SEPARATE_PUBLICATION_JOURNALS_REQUIRED')
    shape(g['installation'],('issuerUrl','gatewayAudience','mcpServiceIdentity'),
        'EXACT_DISCOVERY_GATEWAY_IDENTITY_REQUIRED')
    require(g['installation']=={'issuerUrl':env['OUF_IAM_ISSUER'],'gatewayAudience':env['OUF_IAM_AUDIENCE'],
        'mcpServiceIdentity':r['selection']['mcp_workload']}
        and a['selection']['issuer']==env['OUF_IAM_ISSUER'],
        'SAME_DISCOVERY_REGISTRY_GATEWAY_AND_AUTHORIZATION_IDENTITY_REQUIRED')
    require(type(a['reviewTime']) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',a['reviewTime'])
        and datetime.fromisoformat(a['reviewTime'].replace('Z','+00:00')).tzinfo==timezone.utc
        and type(a['roleId']) is str and bool(a['roleId']),'EXPLICIT_DISCOVERY_AUTHORIZATION_REVIEW_TIME_REQUIRED')
    require(g['discoveryKeyEnvironment']==gp['proposalKeyEnvironment']
        and g['delegationKeyEnvironment']!=g['discoveryKeyEnvironment']
        and all(type(g[k]) is str and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',g[k]) for k in
            ('delegationKeyEnvironment','discoveryKeyEnvironment'))
        and all(environment(gp['creationRequest']['Env']).get(g[k]) for k in
            ('delegationKeyEnvironment','discoveryKeyEnvironment')),
        'SAME_DISCOVERY_RUNTIME_KEY_AND_DISTINCT_DELEGATION_KEY_REQUIRED')
    shape(g['routeIds'],('request','status','candidates'),'EXACT_THREE_DISCOVERY_ROUTE_NAMES_REQUIRED')
    require(all(type(v) is str and ROUTE_ID.fullmatch(v) for v in g['routeIds'].values())
        and len(set(g['routeIds'].values()))==3,'THREE_DISTINCT_DISCOVERY_ROUTE_IDS_REQUIRED')
    aliases=next(iter(r['request']['NetworkingConfig']['EndpointsConfig'].values())).get('Aliases',[])
    require(type(aliases) is list and bool(aliases)
        and all(type(a) is str and re.fullmatch('[a-z][a-z0-9-]{0,62}',a) for a in aliases)
        and any(g['upstream']=={'scheme':'http','nodes':{alias+':8080':1}} for alias in aliases),
        'EXACT_SELECTED_REGISTRY_DISCOVERY_UPSTREAM_REQUIRED')
    before=g['previousRoutes'];require(type(before) is dict and route_map(list(before.values()))==before,
        'COMPLETE_CURRENT_GATEWAY_REVIEW_MAP_REQUIRED')
    selectors={'/internal/capabilities/v1/execute/semantic/discovery/'+n for n in ('request','status','candidates')}
    require(all(not selectors.intersection([row.get('uri')]+row.get('uris',[]))
        for row in before.values() if 'methods' not in row or 'POST' in row['methods']),
        'RETAINED_DISCOVERY_ROUTE_SELECTOR_COLLISION_REQUIRES_RECONCILIATION')
    templates=[r for r in before.values() if r.get('uri')=='/internal/capabilities/v1/execute']
    require(len(templates)==1,'ONE_EXISTING_DISCOVERY_AUTHENTICATION_TEMPLATE_REQUIRED')
    for constant,value in {'DELEGATION_KEY_ENV':g['delegationKeyEnvironment'],
        'ISSUER':env['OUF_IAM_ISSUER'],'AUDIENCE':env['OUF_IAM_AUDIENCE'],
        'MCP_WORKLOAD':r['selection']['mcp_workload']}.items():
        require(lua_constant(templates[0],constant)==value,'EXISTING_DISCOVERY_AUTHENTICATION_TEMPLATE_IDENTITY_DRIFT')
    after=route_map(primitives.gateway.materialize({'routes':list(before.values())},g['installation'],
        g['delegationKeyEnvironment'],g['discoveryKeyEnvironment'],g['upstream'],g['routeIds'])['routes'])
    # Explicit APISIX defaults are part of each signed new row, as in the
    # existing route compiler. Retained rows stay byte-equivalent.
    for rid in g['routeIds'].values():after[rid].setdefault('status',1);after[rid].setdefault('priority',0)
    changes=[{'id':rid,'before':None,'after':after[rid]} for rid in sorted(g['routeIds'].values())]
    require(set(after)==set(before)|set(g['routeIds'].values()) and all(after[k]==v for k,v in before.items()),
        'ADDITIVE_THREE_ROUTE_DISCOVERY_REVIEW_REQUIRED')
    plan={'schema':PROFILE,'sourceCommit':GATEWAY_COMMIT,'gatewaySourceBindings':copy.deepcopy(GATEWAY),
        'transportBinding':proposed_transport(gp),'previousRuntimeHash':digest(before),'proposedRuntimeHash':digest(after),
        'previousRoutes':copy.deepcopy(before),'proposedRoutes':after,'changes':changes,
        'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False,
        'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}
    authorization=auth.compile_plan(a['observed'],primitives.owner,a['selection'],role_id=a['roleId'],
        include_ingestion_status=False,now=a['reviewTime'],session_binding=a['sessionBinding'])
    roots=[absolute(v) for v in j.values()]
    other=[absolute(p) for p in [*cohort_inputs['images']['journalDirectories'].values(),
        cohort_inputs['gateway']['journalDirectory'],cohort_inputs['mcp']['journalDirectory'],
        cohort_inputs['mcp']['readinessDirectory']]]
    protected=[absolute(v['source']) for v in r['selection']['files'].values()]
    protected += [absolute(r['selection'][k]['source']) for k in ('configtree','renewable_token')]
    protected += [absolute(v['archivePath']) for v in cohort_inputs['images']['images']]
    protected += [absolute(gp[k]['path']) for k in ('oldConfigBinding','newConfigBinding')]
    require(all(not a.is_relative_to(b) and not b.is_relative_to(a)
        for i,a in enumerate(roots) for b in roots[i+1:]+other+protected),
        'DISTINCT_PUBLICATION_JOURNALS_MUST_NOT_SHADOW_COHORT_OR_INPUTS')
    component={'schema':'ouf.discovery-governed-capability-publication-scope.v1',
        **{k:cohort_inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')},
        'registryCreationRequestHash':digest(r['request']),'registryExecutionProfileHash':profile.sha256,
        'gatewayRuntimePlanHash':digest(gp),'authorization':auth.authorization_scope(authorization),
        'gateway':publication_scope(plan),'routeIds':copy.deepcopy(g['routeIds']),
        'journalDirectories':copy.deepcopy(j),'sourceBindings':{'gateway':{'commit':GATEWAY_COMMIT,'files':copy.deepcopy(GATEWAY)},
            'onboarding':{'commit':ONBOARDING_COMMIT,'files':copy.deepcopy(ONBOARDING)}},
        'requiresCurrentNativeCohortBeforePublication':True,'requiresGovernedPublicationBeforeProducerRelease':True,
        'roleConfirmationRequiresOwnerHumanSession':True,
        'maximumDispatchAttemptsPerEffect':1,'historicalRecoveryAdoptionAllowed':False,
        'automaticReplayAllowed':False,'budgetReset':False,'sourceActivationAuthorized':False,'releaseAcceptance':False}
    return {'schema':'ouf.discovery-publication-review-fragment.v1','inputHash':input_hash,
        'cohortInputsHash':digest(cohort_inputs),'component':component,'authorizationPlan':authorization,'gatewayPlan':plan,
        'inputsAuthenticated':False,'currentNativeAdmissionProven':False,'publicationExecutorIntegrated':False,
        'signaturesIssued':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'capabilitiesPublished':False,
        'applicationE2EProven':False,'releaseAcceptance':False}
