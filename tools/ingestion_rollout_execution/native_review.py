"""Join explicit local transport profiles to retained plans, without any I/O.

Compilation neither reads the target nor grants authority. Historical Owner and
publication results are inputs to reconciliation, never executable predecessor
actions. A representative qualification and a fresh HUMAN/THS issue are separate.
"""
import copy
import re
from tools.ingestion_rollout_execution import contract as c
from tools.ingestion_rollout_execution import runtime_guard,owner_read,database_read,image_import,gateway_transport,readiness

PROFILE='ouf.ingestion-rollout-native-local-profile-set.v1'
BUDGETS={'maximumOwnerGetAttempts':512,'maximumDatabaseReadSessions':128,
         'maximumGatewayGetAttempts':512,'maximumIngestionReadinessGets':128,
         'maximumDirectEngineGets':4096,'maximumDirectEnginePosts':32}
FIELDS={'schema','engineBinding','runtimeGuardProfile','ownerControlProfile','databaseControlProfile',
        'imageImportProfile','retainedGatewayTransportProfile','retainedGatewayNamespace',
        'gatewayTransportProfile','ingestionReadinessProfile'}

def selected_file(binding):return {k:binding[k]for k in('path','sha256','metadata')}

def validate_profiles(profiles,packet):
    c.require(type(profiles)is dict and set(profiles)==FIELDS and profiles['schema']==PROFILE,
              'EXACT_NATIVE_LOCAL_PROFILE_SET_REQUIRED')
    runtime_guard.validate_profile(profiles['runtimeGuardProfile'],packet)
    owner=owner_read.validate_profile(profiles['ownerControlProfile'])
    db=database_read.validate_profile(profiles['databaseControlProfile'])
    image=image_import.validate_profile(profiles['imageImportProfile'],packet)
    old=gateway_transport.validate_profile(profiles['retainedGatewayTransportProfile'])
    new=gateway_transport.validate_profile(profiles['gatewayTransportProfile'])
    readiness.validate_profile(profiles['ingestionReadinessProfile'])
    c.require(profiles['engineBinding']==db['engineBinding']==image['engineBinding'],
              'ONE_EXPLICIT_LOCAL_ENGINE_BINDING_REQUIRED')
    c.require(all(db[k]==image[k]for k in('dockerExecutable','dockerConfigDirectory','dockerConfigIdentity')),
              'ONE_QUALIFIED_CREDENTIAL_FREE_DOCKER_CHANNEL_REQUIRED')
    pin=profiles['runtimeGuardProfile']['unchangedApplications']['onboarding']
    c.require(owner['runtimeBinding']==pin['binding']and owner['restartCount']==pin['restartCount']
              and owner['runtimeBindingProfile']==pin['bindingProfile'],
              'OWNER_READ_MUST_MATCH_UNCHANGED_ONBOARDING_GENERATION')
    ids={p['binding']['containerId']for p in profiles['runtimeGuardProfile']['unchangedApplications'].values()}
    ids.update(p['containerId']for p in packet['expectedRuntimeBindings'].values())
    c.require(db['postgresRuntimeBinding']['containerId']not in ids,'DISTINCT_POSTGRES_RUNTIME_REQUIRED')
    ns=profiles['retainedGatewayNamespace']
    c.require(type(ns)is dict and set(ns)=={'device','inode'}and all(type(v)is int and v>0 for v in ns.values()),
              'EXPLICIT_RETAINED_GATEWAY_NAMESPACE_REQUIRED')
    c.require(selected_file(old['config'])==packet['gatewayConfigBefore']
              and selected_file(new['config'])==packet['retainedGatewayConfig'],
              'EXACT_RETAINED_AND_STAGED_GATEWAY_CONFIG_BINDINGS_REQUIRED')
    c.require(all(old[k]==new[k]for k in('endpoint','pythonExecutable','adminKey')),
              'SAME_RETAINED_GATEWAY_ADMIN_CHANNEL_REQUIRED')
    cmd=packet['frames']['ingestion']['requestTemplate'].get('Cmd')
    c.require(type(cmd)is list and cmd[-2:]==['--spring.flyway.enabled=false',
              '--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY'],'EXPLICIT_VALIDATE_ONLY_STARTUP_REQUIRED')
    candidate=packet['candidate'];source=candidate.get('sourceCommit')
    c.require(type(source)is str and re.fullmatch('[0-9a-f]{40}',source)
              and candidate['imageConfig'].get('Labels',{}).get('org.opencontainers.image.revision')==source
              and packet['frames']['ingestion']['requestTemplate'].get('Labels',{}).get('org.opencontainers.image.revision')==source,
              'SAME_QUALIFIED_CANDIDATE_SOURCE_AND_RUNTIME_LABEL_REQUIRED')
    return profiles

def reconcile_owner(packet,profiles,owner_plan,completed_result):
    c.require(type(owner_plan)is dict and c.hashed(packet.get('ownerPlanSha256'))
              and c.digest(owner_plan)==packet['ownerPlanSha256'], 'EXACT_COMPLETED_OWNER_PLAN_REQUIRED')
    c.require(type(completed_result)is dict and completed_result.get('complete')is True
              and completed_result.get('planHash')==packet['ownerPlanSha256'],
              'EXACT_COMPLETED_OWNER_RESULT_REQUIRED')
    payload=owner_plan.get('bindingPlan',{}).get('candidatePayload')
    c.require(type(payload)is dict and c.encoded(payload)==c.encoded(profiles['ownerControlProfile']['expectedPayload']),
              'OWNER_CONTROL_PAYLOAD_MUST_MATCH_COMPLETED_PLAN')
    c.require(payload.get('secrets',{}).get('references',{}).get('ingestionReadOwnerKey')
              ==packet['dedicatedOwnerKey']['path'],'COMPLETED_OWNER_DEDICATED_KEY_REFERENCE_REQUIRED')
    return {'ownerPlanHash':c.digest(owner_plan),'completedResultHash':c.digest(completed_result),
            'completedOwnerActionReplayed':False,'completedPublicationReplayed':False,
            'retainedClaimsHash':c.digest(packet['retainedClaims'])}

def compile_native_review(packet,packet_binding,inputs,human_binding,execution_context,
                          profiles,owner_plan,completed_result):
    review=c.compile_review(packet,packet_binding,inputs,human_binding,execution_context)
    validate_profiles(profiles,packet)
    history=reconcile_owner(packet,profiles,owner_plan,completed_result)
    review.update({k:copy.deepcopy(v)for k,v in profiles.items()if k!='schema'})
    review.update(BUDGETS)
    review.update(nativeProfileSetSchema=PROFILE,retainedOwnerHistory=history,
                  nativeExecutorQualified=False,representativeQualificationRequired=True)
    c.scope(review)
    return review

def validate_review(review,packet):
    c.scope(review)
    c.require(review.get('nativeProfileSetSchema')==PROFILE
              and review.get('nativeExecutorQualified')is False
              and review.get('representativeQualificationRequired')is True
              and c.digest(packet)==review['packetBinding']['sha256']
              and all(type(review.get(k))is int and review[k]==v for k,v in BUDGETS.items()),
              'EXACT_FINITE_NATIVE_REVIEW_REQUIRED')
    validate_profiles({'schema':PROFILE,**{k:review.get(k)for k in FIELDS-{'schema'}}},packet)
    history=review.get('retainedOwnerHistory')
    c.require(type(history)is dict and set(history)=={'ownerPlanHash','completedResultHash',
              'completedOwnerActionReplayed','completedPublicationReplayed','retainedClaimsHash'}
              and history['ownerPlanHash']==packet.get('ownerPlanSha256')
              and c.hashed(history['completedResultHash'])
              and history['retainedClaimsHash']==c.digest(packet['retainedClaims'])
              and history['completedOwnerActionReplayed']is history['completedPublicationReplayed']is False,
              'RETAINED_OWNER_HISTORY_RECONCILIATION_REQUIRED')
    return review
