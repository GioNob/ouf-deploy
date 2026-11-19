"""Pure compiler for a PRIVATE cold-stop proposal. No IO or execution authority.

The caller supplies the verified cold-backup definitions and retained inventory.
Output is data for review, never an executable shell script or an admission token.
"""
import copy
import re

GROUPS = (
    ('ingress', ('caddy', 'apisix', 'mcp', 'gateway-owner')),
    ('application', ('onboarding', 'ingestion', 'udp', 'semantic',
                     'ingestion-evidence-read', 'udp-evidence-read')),
    ('identity', ('keycloak',)),
    ('data', ('postgres', 'minio')),
    ('control', ('etcd',)),
)
REQUIRED_EVIDENCE = (
    'CURRENT_TARGET_GENERATIONS_AND_COMPLETE_HOST_INVENTORY',
    'ADMIN_EXTERNAL_WRITERS_AND_RECREATORS_CONTAINED',
    'NEW_APPLICATION_ADMISSIONS_BLOCKED',
    'OWNER_DRAIN_AND_AMBIGUOUS_EFFECT_DISPOSITIONS',
    'DATABASE_OPEN_AND_PREPARED_TRANSACTION_DISPOSITIONS',
    'EFFECTIVE_PROCESS_MOUNT_CUSTODY',
    'ACCEPTED_OUTAGE_WINDOW_AND_HOLD_ESCALATION',
    'APPLICABLE_EXACT_OPERATION_APPROVAL',
    'EXECUTION_DRIVER_AND_STOP_MECHANISMS_QUALIFIED',
)


def compile_proposal(plan, host, helper, plan_sha256, now, test_preservation=False):
    """Project exact IDs/policies, refusing expired or incompatible retained inputs.

    Retained metadata cannot prove any live prerequisite. In particular, neither a
    plan hash nor a decision-reference authenticates HUMAN/THS or grants Docker IO.
    """
    need = helper['need']
    need(helper['digest'](helper['canonical'](plan)) == plan_sha256, 'PLAN_DIGEST')
    need(plan['createdEpoch'] <= now <= plan['validUntilEpoch'], 'PLAN_EXPIRED_OR_FUTURE')
    expected_roles = {r for _, roles in GROUPS for r in roles}
    need(set(plan['roles']) == expected_roles, 'EXACT_STOP_ROSTER_REQUIRED')
    ids = {r['containerId'] for r in plan['roles'].values()}
    need(len(ids) == 14 and ids <= set(host), 'ROLE_MEMBERSHIP')
    need(len(host) <= 192 and all(re.fullmatch('[a-f0-9]{64}', cid) and
         d.get('Id') == cid for cid, d in host.items()), 'EXACT_CONTAINER_IDS')
    sharing = helper['shared_outside_bindings'](host, ids, plan['sources'])
    need(sharing == plan['stoppedSharingContainers'], 'SHARING_BINDINGS_CHANGED')
    for cid, doc in host.items():
        if cid not in ids:
            state = doc['State']
            need(not state.get('Running') and not state.get('Paused') and
                 not state.get('Restarting') and state.get('Pid') == 0,
                 'OUTSIDE_CONTAINER_NOT_STOPPED')
    prefix = ['/usr/bin/docker', '--config',
              '/var/lib/ouf-storage-migration/cold-stop-operation/docker-client',
              '--host', 'unix:///run/docker.sock']
    policies, signals = [], {}
    for role, row in sorted(plan['roles'].items()):
        doc = host[row['containerId']]
        need(helper['fingerprint'](doc) == row['fingerprint'], 'ROLE_FINGERPRINT_CHANGED')
        need(doc['HostConfig']['RestartPolicy'] == row['originalRestartPolicy'],
             'ORIGINAL_POLICY_CHANGED')
        state = doc['State']
        need(row['wasRunning'] and state.get('Running') and state.get('Pid', 0) > 0
             and not state.get('Paused') and not state.get('Restarting'), 'ROLE_NOT_STABLY_RUNNING')
        need(not doc['HostConfig'].get('AutoRemove'), 'AUTO_REMOVE_FORBIDDEN')
        need(not any(k.startswith('com.docker.swarm.') for k in
                     (doc['Config'].get('Labels') or {})), 'SWARM_RECREATOR_REQUIRES_REVIEW')
        signal = doc['Config'].get('StopSignal') or 'SIGTERM'
        if test_preservation:
            # Initial offline preservation of a non-production state, not proof of
            # completed business work. Explicit TERM for applications; PostgreSQL
            # may retain its configured INT fast clean shutdown. Never force kill.
            signal = signal if role == 'postgres' and signal in ('SIGINT', 'INT', '2') else 'SIGTERM'
        need(signal in ('SIGTERM', 'SIGINT', 'TERM', 'INT', '15', '2'),
             'UNREVIEWED_OR_FORCED_STOP_SIGNAL')
        signals[role] = signal
    for cid in sorted(ids | set(sharing)):
        original = host[cid]['HostConfig']['RestartPolicy']
        need(original.get('Name') in ('no', 'always', 'unless-stopped', 'on-failure'),
             'UNKNOWN_RESTART_POLICY')
        if original['Name'] != 'no':
            policies.append({'containerId': cid, 'selectedRole': cid in ids,
                'originalPolicy': copy.deepcopy(original),
                'proposedArgv': prefix + ['update', '--restart=no', cid],
                'postcondition': 'EXACT_ID_GENERATION_RETAINED_AND_RESTART_POLICY_NO',
                'automaticRetryAllowed': False})
    groups = []
    for name, roles in GROUPS:
        groups.append({'name': name, 'afterPreviousGroupVerified': True,
            'maximumWaitSeconds': 120,
            'signals': [{'role': role, 'containerId': plan['roles'][role]['containerId'],
                'proposedArgv': prefix + ['kill', '--signal=' + signals[role],
                                         plan['roles'][role]['containerId']],
                'requiredExitCodes': [0] if role in ('postgres', 'minio', 'etcd') else [0, 143],
                'exitCodeProvesApplicationDrain': False} for role in roles],
            'timeoutAction': 'HELD_PRESERVE_NO_SIGKILL_NO_REPLAY_NO_RESTART'})
    return {'schema': 'ouf.storage-cold-stop-proposal.v1',
        'status': 'DRAFT_NOT_EXECUTABLE_NOT_ADMITTED', 'planSha256': plan_sha256,
        'planValidUntilEpoch': plan['validUntilEpoch'],
        'privateOutputContainsContainerIdentities': True,
        'policyChanges': policies, 'stopGroups': groups,
        'selectedPolicyChanges': sum(x['selectedRole'] for x in policies),
        'sharingPolicyChanges': sum(not x['selectedRole'] for x in policies),
        'maximumPolicyMutations': len(policies), 'maximumStopSignals': 14,
        'maximumStopPhaseSecondsProposed': 1200,
        'maximumCaptureSeconds': plan['maximumSeconds'],
        'maximumProducedBytes': plan['maximumProducedBytes'],
        'stopPhaseBudgetIsNotOutageRto': True,
        'profile': 'NONPRODUCTION_TEST_STATE_PRESERVATION' if test_preservation else 'APPLICATION_CONSISTENT_CUTOVER',
        'remainingRequiredEvidence': ([
            'CURRENT_TARGET_GENERATIONS_AND_COMPLETE_HOST_INVENTORY',
            'EXCLUSIVE_OPERATOR_MAINTENANCE_AND_RECREATOR_SUSPENSION',
            'APPLICABLE_EXACT_OPERATION_APPROVAL',
            'EXECUTION_DRIVER_AND_STOP_MECHANISMS_QUALIFIED',
        ] if test_preservation else list(REQUIRED_EVIDENCE)),
        'unresolvedApplicationWorkMustBePreserved': True,
        'captureProgram': '/var/lib/ouf-storage-cold-backup-v3.py',
        'captureRecipientFile': '/var/lib/ouf-storage-cipher-preparation-20261106/recipient.pub',
        'decisionReference': None, 'approvedWindow': None,
        'runtimeAuthorityIssued': False, 'targetCommandAuthorized': False,
        'providerRequests': 0, 'targetWrites': 0, 'automaticReplayAllowed': False,
        'automaticRestartAllowed': False, 'sharedContainersToStart': 0,
        'applicationDrainProven': False, 'writerQuiescenceProven': False,
        'acceptanceCreditAdded': 0}
