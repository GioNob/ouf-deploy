#!/usr/bin/env python3
"""Prepare DB candidates after inspecting the two existing overlay formats.

No provider access or effective Spring configuration acceptance. The launcher
supplies the two exact public source dependencies; none is fetched as root.
"""
import ast
import json
import os
from pathlib import Path
import re
import sys
import time

STAGING = Path('/var/lib/ouf-g0-network-preparation-20261106')
SCOPE = 'database-draft-continuation-20261106'
PREPARATION_SHA = '03234abf4795d710fa1fbbfaeed04fb0a7f8cf54c2ee102ea08efe504694c071'
TARGETS = {'onboarding': '/run/secrets/onboarding-ths.yaml',
           'ingestion': '/run/secrets/ingestion-summary.properties'}


def predicates(source, m, private_reader):
    """Reuse only two unchanged pure validators, never a historical entry point."""
    m.require(m.sha(source.encode()) == PREPARATION_SHA, 'DB_EXACT_COHORT_VALIDATORS')
    names = {'validate_json_overlay', 'ingestion_properties'}
    nodes = [n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name in names]
    m.require({n.name for n in nodes} == names and len(nodes) == 2, 'DB_VALIDATOR_FUNCTION_SET')
    namespace = {'json': json, 're': re, 'require': m.require,
                 'INGESTION_CONFIG_TARGET': TARGETS['ingestion'], 'private_config': private_reader,
                 'environment': lambda rows: m.environment(('\0'.join(rows) + '\0').encode())}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<pinned-cohort-predicates>', 'exec'), namespace)
    return namespace


def overlay(raw, prefix, validators, m):
    # Decode with the existing strict decoder first (duplicate/nonfinite denied).
    value = m.decode(raw)
    m.require(type(value) is dict, 'DB_JSON_OBJECT_REQUIRED')
    validators['validate_json_overlay'](raw, prefix)
    pending = [('', value, 0)]
    seen = set()
    while pending:
        stem, obj, depth = pending.pop()
        m.require(depth <= 16, 'DB_JSON_DEPTH')
        for key, value in obj.items():
            m.require(re.fullmatch('[A-Za-z0-9_.-]{1,256}', key), 'DB_JSON_KEY_SHAPE')
            full = stem + '.' + key if stem else key
            canonical = re.sub('[^a-z0-9]', '', full.lower())
            m.require(canonical not in seen and len(seen) < 2048, 'DB_JSON_CANONICAL_COLLISION')
            seen.add(canonical)
            if type(value) is dict:
                pending.append((full, value, depth + 1))
            else:
                m.require(type(value) in (str, bool, int, float, list, type(None)), 'DB_JSON_VALUE_SHAPE')
                if type(value) is list:
                    m.require(len(value) <= 256 and all(type(v) in (str, bool, int, float, type(None)) for v in value),
                              'DB_JSON_COMPLEX_ARRAY_REQUIRES_REVIEW')
    return len(seen)


def cmdline(pid):
    fd = os.open('/proc/' + str(pid) + '/cmdline', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = os.read(fd, 65537)
    finally:
        os.close(fd)
    if not 0 < len(raw) <= 65536 or not raw.endswith(b'\0'):
        raise ValueError('DB_BOUNDED_COMMAND_LINE')
    return raw[:-1].decode().split('\0')


class ConfigurationView:
    """Adapt the qualified input observer to ONE fixed configuration path.

    Existing source owner/mode are not silently admitted or changed. Content is
    read through the pinned process root, not through the historical host path.
    """
    def __init__(self, role, selected, m, counts, guard, factory):
        self.role, self.m, self.counts, self.guard = role, m, counts, guard
        self.target = TARGETS[role]
        mounts = [x for x in selected['doc'].get('Mounts', []) if x.get('Destination') == self.target]
        m.require(len(mounts) == 1 and mounts[0].get('Type') == 'bind'
                  and mounts[0].get('RW') is False and type(mounts[0].get('Source')) is str,
                  'DB_EXPECTED_HISTORICAL_CONFIG_MOUNT')
        if role == 'onboarding':
            m.require(mounts[0]['Source'] == '/opt/ouf/secrets/onboarding-ths.yaml', 'DB_EXPECTED_THS_SOURCE')
        self.source = mounts[0]['Source']
        self.binding = factory(selected['pin']['pid'])
        self.raw = None

    def read(self, path, expected=None):
        m = self.m
        m.require(path == self.source and expected is None and self.raw is None, 'DB_ONE_SELECTED_CONFIG_READ')
        self.guard()
        key, row = self.binding.inspect(self.target, config=True)
        m.require(row.get('readEligible') is True and 0 < row['metadata'][6] <= 65536,
                  'DB_BOUNDED_REGULAR_CONFIGURATION_REQUIRED')
        # This is the complete preflight for this fixed, single selected input.
        self.binding.preflight_done = True
        self.counts['configurationFileReadsAttempted'] += 1
        self.raw = self.binding.read(self.target, 65536, config=True)
        self.counts['configurationFilesRead'] += 1
        self.counts['configurationBytesRead'] += len(self.raw)
        m.require(self.counts['configurationBytesRead'] <= 131072, 'DB_CONFIGURATION_BYTE_BUDGET')
        self.guard()
        self.binding.stable()
        return self.raw, {'processViewObserved': True, 'sourceCustodyAdmitted': False}

    def stable(self):
        self.binding.stable()

    def close(self):
        self.binding.close()


def reviewed_environment(role, env, args, selected, source, m, report, guard, factory, views):
    prefix = m.DB_PREFIX[role]
    protected = ('springdatasource', 'springconfig', 'springprofiles', 'springapplicationjson',
                 re.sub('[^a-z0-9]', '', prefix.lower()) + 'db')
    for key, value in env.items():
        norm = re.sub('[^a-z0-9]', '', key.lower())
        m.require(not norm.startswith('springdatasource'), 'DB_UNEXPECTED_DATASOURCE_ENVIRONMENT')
        if norm.startswith('springconfig'):
            m.require(key == 'SPRING_CONFIG_ADDITIONAL_LOCATION' and role in TARGETS,
                      'DB_UNREVIEWED_CONFIG_SELECTOR')
        if norm == 'springapplicationjson':
            m.require(key == 'SPRING_APPLICATION_JSON', 'DB_JSON_ENV_ALIAS')
    for text in args + [env.get(k, '') for k in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', 'JAVA_OPTS', '_JAVA_OPTIONS')]:
        normalized = re.sub('[^a-z0-9]', '', text.lower())
        m.require(not any(p in normalized for p in protected), 'DB_COMMAND_OR_JVM_OVERRIDE')
    view = None
    if role in TARGETS:
        value = env.get('SPRING_CONFIG_ADDITIONAL_LOCATION')
        allowed = {'file:' + TARGETS[role]}
        if role == 'ingestion':
            allowed.add('optional:file:' + TARGETS[role])
        m.require(value in allowed, 'DB_EXACT_RETAINED_CONFIG_SELECTION')
        view = ConfigurationView(role, selected, m, report, guard, factory)
        views.append(view)
    validators = predicates(source, m, view.read if view else lambda *_: m.require(False, 'DB_NO_EXTRA_FILE_READ'))
    summary = {'applicationJsonChecked': False, 'additionalConfigurationChecked': False,
               'effectiveConfigurationProven': False, 'sourceCustodyAdmitted': False}
    if 'SPRING_APPLICATION_JSON' in env:
        overlay(env['SPRING_APPLICATION_JSON'], prefix, validators, m)
        summary['applicationJsonChecked'] = True
    if role == 'onboarding':
        raw, _ = view.read(view.source)
        m.require(raw.lstrip().startswith(b'{'), 'DB_RETAINED_THS_JSON_REQUIRED')
        overlay(raw.decode(), prefix, validators, m)
        summary['additionalConfigurationChecked'] = True
    elif role == 'ingestion':
        actual = {'Config': {'Env': [k + '=' + v for k, v in env.items()]},
                  'Mounts': selected['doc']['Mounts']}
        validators['ingestion_properties'](actual)
        summary['additionalConfigurationChecked'] = True
    projected = dict(env)
    # Only inspected channels are omitted from the OLD broad guard's input.
    # Original code stays unchanged; unresolved selectors can never reach here.
    for key in ('SPRING_APPLICATION_JSON', 'SPRING_CONFIG_ADDITIONAL_LOCATION'):
        projected.pop(key, None)
    return projected, summary


def prepare(staging, profile, m, review_helper, source, *, env_reader=None, pin_reader=None,
            boot_reader=None, command_reader=cmdline, factory=None, clock=time.monotonic):
    m.require(os.geteuid() == os.getegid() == 0, 'DB_ROOT_REQUIRED')
    m.protected(staging / 'inputs')
    root = staging / 'inputs' / SCOPE
    if os.path.lexists(root):
        r = m.decode(m.read_private(root / 'result.json', 65536))
        r['existingResultReadOnly'] = True
        return r
    old = staging / 'inputs' / m.DRAFT
    prior_path = staging / 'inputs' / review_helper.SCOPE / 'result.json'
    prior_raw = m.read_private(prior_path, 65536)
    prior = m.decode(prior_raw)
    m.require(prior.get('status') == 'DATASOURCE_OVERRIDE_METADATA_OBSERVED_REVIEW_REQUIRED'
              and set(prior['roles']) == set(m.DB_PREFIX) and prior.get('providerRequests') == 0
              and prior.get('runtimeAuthorityIssued') is False, 'DB_COMPLETED_DIAGNOSTIC_REQUIRED')
    original = m.read_private(old / 'package-input.review.json', 65536)
    config = m.decode(original)
    old_result = m.read_private(old / 'result.json', 65536)
    m.require(config['connectionFiles']['s3'] == str(old / 's3.json'), 'DB_PRESERVED_S3_CONFIG_PATH')
    s3_raw = m.read_private(old / 's3.json', 65536)
    s3 = m.decode(s3_raw)
    m.require(s3.get('schema') == 'ouf.storage-g0-collection-input.v1'
              and s3.get('operationId') == profile['operationId'] + '-s3'
              and s3.get('installationRef') == profile['installationRef'], 'DB_PRESERVED_S3_CONFIG_IDENTITY')
    old_summary = m.decode(old_result)
    m.require(old_summary.get('schema') == 'ouf.storage-g0-input-draft-result.v1'
              and old_summary.get('status') == 'PRIVATE_INPUT_DRAFT_PREPARED_REVIEW_REQUIRED'
              and old_summary.get('connectionDraftsPrepared') == ['s3']
              and old_summary.get('runtimeAuthorityIssued') is False
              and old_summary.get('providerRequests') == 0
              and config['operationId'] == profile['operationId']
              and config['installationRef'] == profile['installationRef']
              and config['collectionDecisionRef'] is None, 'DB_S3_ONLY_UNADMITTED_DRAFT_REQUIRED')
    root.mkdir(mode=0o700)
    m.put(root / 'claim.json', m.encoded({'schema': 'ouf.storage-g0-db-continuation-claim.v1',
          'maximumAttempts': 1, 'maximumSeconds': 30, 'maximumEnvironmentReads': 3,
          'maximumCommandLineReads': 3, 'maximumConfigurationFileReads': 2,
          'maximumCredentialFileWrites': 3,
          'maximumConfigurationBytes': 131072, 'priorDiagnosticSha256': m.sha(prior_raw),
          'priorDraftSha256': m.sha(original), 'automaticReplayAllowed': False}))
    until = clock() + 30
    result = {'schema': 'ouf.storage-g0-db-continuation-result.v1', 'status': 'HELD', 'roles': {},
              'processEnvironmentsRead': 0, 'commandLinesRead': 0,
              'configurationFileReadsAttempted': 0, 'configurationFilesRead': 0, 'configurationBytesRead': 0,
              'credentialFileWritesAttempted': 0, 'credentialFilesWritten': 0,
              'credentialsMayBePresentInDraft': False, 'connectionDraftsPrepared': [],
              's3CredentialFilesRead': 0, 'originalPreparationChanged': False,
              'providerRequests': 0, 'collectionScopeCreated': False, 'runtimeAuthorityIssued': False,
              'targetInputCheckPassed': False, 'g0Complete': False, 'acceptanceCreditAdded': 0,
              'automaticReplayAllowed': False}
    views = []
    try:
        env_reader, pin_reader, factory = env_reader or m.live_environment, pin_reader or m.process_pin, factory or m.InputBinding
        boot_reader = boot_reader or (lambda: Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        seed_raw = m.read_private(Path(profile['seedPath']), 2 << 20)
        seed = m.decode(seed_raw)
        selected = m.bindings(seed, profile)

        def guard():
            m.require(clock() < until, 'DB_CONTINUATION_DEADLINE')
            m.require(boot_reader() == seed['bootId'], 'DB_BOOT_CHANGED')
            for role in m.ROLES_READ:
                pin = selected[role]['pin']
                m.require(pin_reader(pin['pid']) == pin, 'DB_PROCESS_CHANGED')

        guard()
        pending = {}
        for role in m.DB_PREFIX:
            result['currentRole'] = role
            guard()
            result['processEnvironmentsRead'] += 1
            env = env_reader(selected[role]['pin']['pid'])
            guard()
            m.require(review_helper.classify(role, env) == prior['roles'][role], 'DB_DIAGNOSTIC_CHANNELS_CHANGED')
            result['commandLinesRead'] += 1
            args = command_reader(selected[role]['pin']['pid'])
            guard()
            projected, summary = reviewed_environment(role, env, args, selected[role], source,
                                                      m, result, guard, factory, views)
            pending[role] = m.db_connection(role, projected, m.postgres_aliases(selected['postgres']['doc']),
                                           config['operationId'], config['installationRef'], root / (role + '.pass'))
            result['roles'][role] = summary
        for view in views:
            view.stable()
        guard()
        m.require(len(config['priorReceiptFiles']) == 17
                  and {row['control'] for row in config['priorReceiptFiles']} == set(range(1, 18)), 'DB_HISTORY_DOMAIN')
        for row in config['priorReceiptFiles']:
            m.require(m.sha(m.read_private(Path(row['path']), 2 << 20)) == row['sha256'], 'DB_HISTORY_CHANGED')
        m.require(m.read_private(Path(profile['seedPath']), 2 << 20) == seed_raw
                  and m.read_private(prior_path, 65536) == prior_raw
                  and m.read_private(old / 'package-input.review.json', 65536) == original
                  and m.read_private(old / 'result.json', 65536) == old_result
                  and m.read_private(old / 's3.json', 65536) == s3_raw, 'DB_ORIGINAL_INPUT_CHANGED')
        for role, (connection, password) in pending.items():
            result['currentRole'] = role
            guard()
            result['credentialFileWritesAttempted'] += 1
            result['credentialsMayBePresentInDraft'] = True
            m.put(root / (role + '.pass'), password)
            result['credentialFilesWritten'] += 1
            m.put(root / (role + '.json'), m.encoded(connection))
            config['connectionFiles'][role] = str(root / (role + '.json'))
            result['connectionDraftsPrepared'].append(role)
        guard()
        for view in views:
            view.stable()
        m.put(root / 'package-input.review.json', m.encoded(config))
        result.pop('currentRole', None)
        result['status'] = 'DATABASE_CONNECTION_DRAFTS_PREPARED_REVIEW_REQUIRED'
        result['s3DraftReusedWithoutCredentialRead'] = True
        result['allFourConnectionDraftsPresent'] = True
        result['missingInputs'] = ['CURRENT_DOCKER_ROLE_IMAGE_AND_MOUNT_REVIEW',
             'EFFECTIVE_APPLICATION_CONFIGURATION_REVIEW', 'ONBOARDING_RETAINED_PROFILE_REVIEW',
             'SOURCE_AND_PROPOSED_CAPACITY_PATH_CUSTODY_REVIEW',
             'OPERATOR_ACCESS_WRITERS_CAPACITY_CUSTODY_WINDOW', 'SEPARATE_COLLECTION_DECISION']
    except Exception as e:
        # All explicit guards carry constant codes. Parser/OS messages stay private.
        reason = str(e)
        result['reason'] = reason if type(e) is m.Stop and re.fullmatch('[A-Z][A-Z0-9_]{0,160}', reason) else 'DB_LOCAL_CONTINUATION_UNPROVEN'
    finally:
        for view in reversed(views):
            view.close()
    m.put(root / 'result.json', m.encoded(result))
    return result


def main(review_helper, source):
    try:
        review_helper.require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0
                              and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
                              'DB_ISOLATED_ROOT_ENTRY')
        os.umask(0o077)
        bundle = STAGING / 'input-tools-6c9de0f4'
        profile = review_helper.verify_bundle(bundle)
        sys.path.insert(0, str(bundle))
        from tools.storage_planning import g0_input_draft as m
        result = prepare(STAGING, profile, m, review_helper, source)
    except Exception:
        result = {'status': 'HELD', 'reason': 'DB_ENTRY_OR_EXISTING_SCOPE_UNPROVEN',
                  'providerRequests': 0, 'runtimeAuthorityIssued': False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'DATABASE_CONNECTION_DRAFTS_PREPARED_REVIEW_REQUIRED' else 1
