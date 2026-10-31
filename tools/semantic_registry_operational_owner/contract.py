"""Compile a new operational installation proposal; never issue authority.

Finite recovery remains historical. Normal credential renewal is a distinct
installation decision, with inherited accounting and bounded issuance rate.
Nothing here refreshes a cancelled owner, native journal or signed caller token.
"""
from dataclasses import asdict
from pathlib import PurePosixPath
from .core import RenewalPolicy, digest, require


SCHEMA='ouf.registry-operational-token-installation-proposal.v1'
SCOPE='semanticRegistryOperationalTokenOwnerInstallation'
INPUT_SCHEMA='ouf.semantic-registry-running-policy-repair-inputs.v1'
SOURCE_NAMES=frozenset('tools.semantic_registry_operational_owner.'+name for name in
                       ('core','store','contract','guard','adapter','service','installation','entry'))


def absolute(value):
    require(type(value) is str and value.startswith('/') and '..' not in PurePosixPath(value).parts
            and str(PurePosixPath(value))==value and value!='/', 'EXACT_OPERATIONAL_INSTALLATION_PATH_REQUIRED')
    return value


def compile_proposal(inputs, binding, source_manifest, policy, destinations, iam_ca_binding):
    require(type(inputs) is dict and inputs.get('schema')==INPUT_SCHEMA and type(policy) is RenewalPolicy,
            'EXACT_RUNNING_POLICY_REPAIR_INPUTS_REQUIRED')
    require(type(binding) is dict and set(binding)=={'path','sha256'}
            and binding['sha256']==digest(inputs), 'HASH_BOUND_RUNNING_REPAIR_INPUTS_REQUIRED')
    absolute(binding['path'])
    require(all(inputs.get(k) is False for k in ('runtimeAuthorityIssued','newRuntimeBudgetGranted','targetApplyAuthorized','automaticReplayAllowed','budgetReset'))
            and inputs.get('grantAttemptAllowance')==0 and inputs.get('retainedControlledGrantAttempts')==321
            and inputs.get('oldClaimsRemainConsumed') is True, 'CAPTURE_CANNOT_GRANT_NEW_OPERATIONAL_AUTHORITY')
    prepared=inputs['prepared'];review=inputs['review']
    native=inputs['retainedNativeJournal'];reads=inputs['retainedNativeReads'];records=inputs['retainedOwnerRecords']
    owner=records['recovery.json'];scope=records['owner-session.json']
    require(review['currentContext']==prepared['nativeContext'] and review['ownerContext']==prepared['ownerContext']
            and scope==review['scopes']['semanticRegistryPostbootOwner']
            and native['nextStage']==11 and len(native['effects'])==12
            and all(e['state']=='APPLIED' for e in native['effects'][:11])
            and native['effects'][11]['state']=='CLAIMED' and native['originalSemanticGetSucceeded'] is False,
            'EXACT_HISTORICAL_RUNNING_REPAIR_PREFIX_REQUIRED')
    require(owner['state']=='CANCELLED' and owner['reason']=='CANCELLED_BY_OWNER'
            and owner['controlledPredecessorGrantAttempts']==320 and owner['attempts']==1
            and owner['controlledCumulativeGrantAttempts']==321 and owner['workerSessionHash']==digest(scope)
            and owner['policyHash']==digest(scope['policy'])
            and records['owner-admission.json']['state']=='BLOCKED'
            and owner['firstGrantReceiptHash']==scope['firstGrantReceiptHash']==digest(records['owner-first-grant.json'])
            and owner['bootId']==native['bootId']==scope['currentSessionBootId']
            and owner['gateGeneration']==native['newGeneration']
            and inputs['retainedFence']==scope['fenceBinding'], 'EXACT_CANCELLED321_OPERATIONAL_PREDECESSOR_REQUIRED')
    require(reads['counts']=={'databaseSessions':18,'gatewayAdminGets':18,'semanticGets':0}
            and all(type(v) is int for v in reads['counts'].values())
            and reads['scopeHash']==digest(review['scopes']['semanticRegistryRecoveryReads'])
            and reads['authorityHash']==native['authorityHash']
            and inputs['identity']['nativeJournalHash']==digest(native)
            and inputs['identity']['ownerJournalHash']==digest(owner), 'UNCHANGED_RUNNING_REPAIR_ACCOUNTING_REQUIRED')
    require(type(source_manifest) is dict and set(source_manifest)=={'schema','sourceCommit','sourceHashes','dependencyClosureHash','bootstrapHash'}
            and source_manifest['schema']=='ouf.registry-operational-owner-sources.v1'
            and type(source_manifest['sourceCommit']) is str and len(source_manifest['sourceCommit'])==40
            and set(source_manifest['sourceCommit'])<=set('0123456789abcdef')
            and type(source_manifest['sourceHashes']) is dict and set(source_manifest['sourceHashes'])==SOURCE_NAMES,
            'COMPLETE_OPERATIONAL_SOURCE_DECLARATION_REQUIRED')
    for sha in [source_manifest['dependencyClosureHash'],source_manifest['bootstrapHash'],*source_manifest['sourceHashes'].values()]:
        require(type(sha) is str and len(sha)==64 and set(sha)<=set('0123456789abcdef'), 'EXACT_OPERATIONAL_SOURCE_HASH_REQUIRED')
    require(type(destinations) is dict and set(destinations)=={'installationRoot','ledgerRoot','commonInvocationLock'},
            'EXACT_OPERATIONAL_INSTALLATION_DESTINATIONS_REQUIRED')
    for path in destinations.values():absolute(path)
    require(destinations['commonInvocationLock']==scope['journalPath']+'/invocation.lock'
            and destinations['installationRoot']!=destinations['ledgerRoot']
            and all(not path.startswith(prepared['nativeContext']['executionRoot']+'/') for path in
                    (destinations['installationRoot'],destinations['ledgerRoot'])), 'NEW_OWNER_MUST_NOT_OVERWRITE_NATIVE_RECOVERY')
    owner_inputs=prepared['ownerContext']['ownerInputs']
    require(digest(owner_inputs)==scope['ownerInputsHash'],'EXISTING_SIGNED_IAM_OWNER_INPUTS_REQUIRED')
    # The caller's API CA and the credential owner's IAM trust are separate
    # profiles. The native preparer must capture a public CA bundle reproducing
    # ownerInputs.tlsTrustHash, then bind its exact path/bytes in this review.
    require(type(iam_ca_binding) is dict and set(iam_ca_binding)=={'path','sha256'}
            and type(iam_ca_binding['sha256']) is str and len(iam_ca_binding['sha256'])==64
            and set(iam_ca_binding['sha256'])<=set('0123456789abcdef'),
            'INDEPENDENT_EXISTING_IAM_CA_BUNDLE_BINDING_REQUIRED')
    absolute(iam_ca_binding['path'])
    return {'schema':SCHEMA,'purpose':'INSTALL_NORMAL_REGISTRY_POLICY_TOKEN_RENEWAL',
            'inputsBinding':dict(binding),'predecessorNativeJournalHash':digest(native),
            'predecessorNativeReadHash':digest(reads),'predecessorOwnerRecordHashes':{k:digest(v) for k,v in records.items()},
            'predecessorFenceBinding':inputs['retainedFence'],'ownerInputs':owner_inputs,
            'publicTlsCaBinding':dict(iam_ca_binding),
            'sourceManifest':source_manifest,'sourceManifestHash':digest(source_manifest),
            'policy':asdict(policy),'policyHash':policy.sha256,'destinations':dict(destinations),
            'priorControlledGrantAttempts':321,
            'scheduledRenewalEnabledAfterInstallation':True,
            'operationalLifetime':'UNTIL_DISABLE_CUSTODY_CHANGE_OR_INSTALLATION_TRUST_REVOCATION',
            'finiteApprovalAuthorizesInstallationOnly':True,
            'existingIamIdentityAndPermissionsOnly':True,
            'grantAttemptReservationRequiredBeforeEveryRequest':True,
            'unknownGrantOrPublicationOutcomeRequiresReconciliation':True,
            'sameAttemptRedispatchAllowed':False,'cumulativeAttemptCounterResetAllowed':False,
            'legacyFiniteBudgetExtended':False,'newIamClientAllowed':False,'iamPermissionChangesAllowed':False,
            'nativeRecoveryEffectReplayAllowed':False,'nativeJournalWritesAllowed':False,
            'callerTokenRebindingAllowed':False,'gatewayWritesAllowed':False,'databaseWritesAllowed':False,
            'containerLifecycleOperationsAllowed':False,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'releaseAcceptance':False}
