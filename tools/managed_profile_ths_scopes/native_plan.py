"""Compile a same-image owner request update from fresh, exact retained inputs.

No execution, SQL, authentication, secret-file access or lifecycle port exists
here. Reuses the Teatri native configuration/allocation and legacy-MAC rules.
The output is private and conditional; a new execution review and live database,
network and owner admission remain mandatory.
"""
import copy
from tools.managed_csv_recovery.retained_inputs import require, digest
from tools.managed_profile_ths_scopes.contract import REQUIRED, scope_patch
from tools.acquisition_read_native import plan_helper as plan_helpers
from tools.managed_csv_recovery.image_plan import retain_allocations
from tools.acquisition_read_native.retained_mac import policy as retained_mac_policy


def validate_profile(result, profile, actual, case):
    require(digest(result) == case['iamResultHash']
            and result['schema'] == 'ouf.managed-profile-ths-iam-binding-correction-result.v1'
            and result['status'] == 'THS_IAM_BINDINGS_CORRECTED_CONFIGURATION_PROFILE_PREPARED_NOT_AUTHORIZED'
            and result['complete'] is True and result['contextPath'] == case['iamRoot']
            and result['configurationProfileHash'] == case['configurationProfileHash']
            and result['configurationProfilePrepared'] is True
            and result['iamMutations'] == 4 and result['newScopeDefinitions'] == 1
            and result['newOptionalClientBindings'] == 3
            and result['preexistingDefinitionsPreserved'] is True
            and result['realmDefaultsPreserved'] is True
            and result['nonCredentialClientPropertiesPreserved'] is True
            and result['humanIamCorrectionReviewApproved'] is True
            and result['adminIdentityApiVerified'] is True
            and all(result[k] is False for k in ('scopePatchApplied','runtimeAuthorityIssued',
                'targetApplyAuthorized','automaticReplayAllowed','budgetReset')),
            'EXACT_SUCCESSFUL_CONSUMED_IAM_CORRECTION_REQUIRED')
    observed = result['bindingObservation']
    require(observed['bindingAndUnrestrictedEligibilityProven'] is True
            and observed['blockedScopes'] == [] and observed['defaultScopeCount'] == 14
            and observed['optionalScopeCount'] == 9 and observed['definitionCount'] == 70
            and [r['name'] for r in observed['requiredScopes']] == list(REQUIRED)
            and all(r['eligibleForExplicitRequest'] is True and r['binding'] == 'OPTIONAL'
                    for r in observed['requiredScopes']), 'PROVED_RETAINED_IAM_OPTIONAL_BINDINGS_REQUIRED')
    require(digest(profile) == case['configurationProfileHash']
            and profile['schema'] == 'ouf.ths-additive-owner-configuration-profile.v1'
            and profile['ownerContainerId'] == actual['Id']
            and profile['ownerImageId'] == actual['Image'] == case['nativeImageIds']['onboarding']
            and profile['currentConfigurationHash'] == digest(actual['Config'])
            and profile['clientId'] == observed['clientId'] == case['clientId']
            and profile['iamBindingSnapshotHash'] == observed['bindingSnapshotHash']
            and profile['requiredScopes'] == list(REQUIRED)
            and profile['sameNativeImageRequired'] is True
            and profile['allOtherPropertiesPreserved'] is True
            and profile['freshRuntimeAndJobFencesRequired'] is True
            and profile['newHumanExecutionReviewRequired'] is True
            and all(profile[k] is False for k in ('executionEntryQualified','runtimeAuthorityIssued',
                'targetApplyAuthorized','effectiveBrowserTokenScopesProven','automaticReplayAllowed','budgetReset')),
            'EXACT_PRIVATE_CONDITIONAL_SAME_OWNER_PROFILE_REQUIRED')
    summary, environment = scope_patch(actual)
    candidate = copy.deepcopy(actual['Config']); candidate['Env'] = environment
    require(environment == profile['replacementEnvironment']
            and summary['requestedScopes'] == profile['preservedRequestedScopes']
            and summary['missingRequestScopes'] == profile['addedRequestScopes'] == list(REQUIRED)
            and summary['requestBeforeHash'] == profile['requestBeforeHash']
            and summary['conditionalRequestAfterHash'] == profile['requestAfterHash']
            and digest(candidate) == profile['proposedConfigurationHash'],
            'EXACT_ADDITIVE_REQUEST_PROFILE_REQUIRED')
    return summary, environment


def compile_native_plan(capture, review, iam_result, profile, case):
    require(capture['engineInfo'].get('ServerVersion') == '29.8.1'
            and ['driver-type','io.containerd.snapshotter.v1'] in (capture['engineInfo'].get('DriverStatus') or []),
            'QUALIFIED_NATIVE_ENGINE_PROFILE_REQUIRED')
    actual = capture['currentObservations']['onboarding']
    summary, environment = validate_profile(iam_result, profile, actual, case)
    retained = review['nativePlan']['proposal']
    facts = retained['candidateApplicationFacts']
    require(len(facts['migrations']) == 36 and facts['applicationYamlSha256']
            and retained['databaseMigration'] == {'from':36,'to':36,'newMigrations':0},
            'RETAINED_SCHEMA36_FACTS_REQUIRED_NOT_DATABASE_ADMISSION')
    request = plan_helpers.config_copy(actual)
    request['Env'] = copy.deepcopy(environment)
    host = copy.deepcopy(actual['HostConfig']); restore = copy.deepcopy(host['RestartPolicy'])
    require(host.get('AutoRemove') is False and type(host.get('Memory')) is int
            and host['Memory'] >= 0
            and (host.get('OomKillDisable') is None or type(host['OomKillDisable']) is bool),
            'EXACT_RETAINED_OWNER_RESOURCE_POLICY_REQUIRED')
    host['RestartPolicy'] = {'Name':'no','MaximumRetryCount':0}
    request.update(Image=actual['Image'], HostConfig=host)
    network = retain_allocations(actual, request, plan_helpers)
    old = plan_helpers.stable_binding(actual)
    image = retained['readReplacements']['onboarding']['imageAudit']
    require(image['nativeIdentity']['nativeImageId'] == actual['Image'],
            'RETAINED_SAME_NATIVE_IMAGE_AUDIT_REQUIRED')
    defaults = image['imageConfig'].get('Labels') or {}
    labels = actual['Config'].get('Labels') or {}
    require(all(k.startswith('org.opencontainers.image.') for k in set(defaults)-set(labels)),
            'NO_UNREVIEWED_IMAGE_DEFAULT_LABEL_ADDITIONS')
    replacement = {'name':actual['Name'].removeprefix('/'),
        'retiredName':actual['Name'].removeprefix('/')+'-retained-ths-request-'+case['configurationProfileHash'][:12],
        'request':request, 'restoreRestartPolicy':restore, 'oldBinding':old,
        'oldNativeHostConfig':copy.deepcopy(actual['HostConfig']), 'network':network,
        'imageAudit':copy.deepcopy(image),
        'readiness':copy.deepcopy(retained['readReplacements']['onboarding']['readiness']),
        'runtimeLabelProjection':{'expectedLabels':{**defaults, **labels}},
        'oldRetainedStopped':True, 'oldMustBeStoppedAndDetachedBeforeNewStarts':True,
        'sameNativeImageRequired':True, 'nativeImageImportAuthorized':False}
    replacement['legacyConfigMacDetachPolicy'] = retained_mac_policy(actual) if actual['Config'].get('MacAddress') else {
        'profile':'NO_LEGACY_CONFIG_MAC_CHANGE_RETAIN_EXACT_V1',
        'originalConfigHash':digest(actual['Config']),
        'originalEndpointSetHash':digest(actual['NetworkSettings']['Networks']), 'originalHashesRewritten':False}
    if host.get('OomKillDisable') is None:
        replacement['runtimeHostProjection'] = {'profile':'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1',
            'requestedOomKillDisable':None,'materializedOomKillDisable':False,'retainedMemoryBytes':host['Memory']}
    require(len(capture['currentObservations']) == 13
            and set(capture['currentObservations']) == set(capture['currentProcessPins']),
            'EXACT_FRESH_COHORT13_REQUIRED')
    plan = {'schema':'ouf.ths-owner-request-conditional-native-plan.v1',
        'kind':'FROZEN_CONDITIONAL_PROPOSAL_NOT_EXECUTABLE',
        'configurationProfileHash':case['configurationProfileHash'], 'iamResultHash':case['iamResultHash'],
        'iamBindingSnapshotHash':iam_result['bindingObservation']['bindingSnapshotHash'],
        'bootId':capture['bootId'], 'engineBinding':copy.deepcopy(capture['engineBinding']),
        'engineInfoHash':digest(capture['engineInfo']),
        'currentRootProcessPins':copy.deepcopy(capture['currentRootProcessPins']),
        'currentProcessPins':copy.deepcopy(capture['currentProcessPins']),
        'existingApplications':{r:plan_helpers.stable_binding(v) for r,v in capture['currentObservations'].items()},
        'unchangedApplications':{r:plan_helpers.stable_binding(v) for r,v in capture['currentObservations'].items() if r != 'onboarding'},
        'replacements':{'onboarding':replacement}, 'targetRoles':['onboarding'],
        'boundDatabaseProfile':copy.deepcopy(retained['boundDatabaseProfile']),
        'nativeFlywayConfiguration':copy.deepcopy(retained['nativeFlywayConfiguration']),
        'candidateApplicationFacts':copy.deepcopy(facts), 'databaseMigration':{'from':36,'to':36,'newMigrations':0},
        'scopeRequestDelta':{k:summary[k] for k in ('requestedScopes','missingRequestScopes','requestBeforeHash','conditionalRequestAfterHash')},
        'futureRequirements':['NEW_CONCRETE_HUMAN_EXECUTION_REVIEW_AND_SIGNED_AUTHORITY',
            'FRESH_SCHEMA36_AND_EXACT_FAILED5_OPERATIONAL_STATE_ADMISSION',
            'CURRENT_NETWORK_MEMBERSHIP_AND_RETIRED_NAME_AVAILABILITY',
            'CURRENT_OWNER_OVERLAY_AND_PROCESS_ROOT_PRECEDENCE',
            'VERIFIED_QUIESCED_BACKUP', 'SEPARATE_HUMAN_JOB_BUDGET_AND_RESUME'],
        'executionEntryQualified':False, 'databaseAdmissionProven':False,
        'currentJobOrBudgetStateObserved':False, 'runtimeAuthorityIssued':False, 'targetApplyAuthorized':False,
        'iamConfigurationMutationAuthorized':False, 'imageImportAuthorized':False,
        'humanBudgetsOrResumeAuthorized':False, 'sourceActivationAuthorized':False,
        'automaticRollbackAllowed':False,'automaticReplayAllowed':False,'budgetReset':False,
        'applicationE2EProven':False,'releaseAcceptance':False}
    return plan
