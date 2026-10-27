"""Bind a NEW two-owner execution to the prepared plan and qualified adapters."""
import copy
import hashlib
import os
from pathlib import Path
import re
import stat

TARGET = {
    'executionInputsHash': '900b09c6d29a20fda5dfff1f1333df167363c96e865cc2c13a7b58791f4e0c51',
    'conditionalPlanHash': '73d5733b86f2f8c8430a6a978540607557a8cd925911321ab58ae7b011bc1f7e',
    'inputsHash': '14a96f782827c8948fabd857d9e3958cbe588a38dc9bd0968c342467f09ca9c1',
    'preparedRoot': '/etc/ouf/deploy-snapshots/managed-csv-control-image-plan-14a96f782827c894-v1',
    'executionRoot': '/etc/ouf/deploy-snapshots/managed-csv-control-update-900b09c6d29a20fd-v1',
    'ownerOverlayPath': '/opt/ouf/secrets/onboarding-ths.yaml',
    'preparationCounts': {'privateMetadataReads': 3, 'privateMetadataBytes': 580635, 'ciZipReads': 2,
                           'nativeArchivesPrepared': 2, 'engineGets': 0, 'containerWrites': 0, 'imageImports': 0},
    'sources': {'onboarding': '9890b31868641e5be43c949a56f4ef69dd23bdfd', 'mcp': 'd2454f3cb8cd410d284b9dc78349a170187aea1c'},
    'testedSources': {'onboarding': 'de65795d07ede9ebca1bdea02ef250860d87f433', 'mcp': 'd2454f3cb8cd410d284b9dc78349a170187aea1c'},
    'nativeImageIds': {'onboarding': 'sha256:c512c24787304dc0ee40d2b5b1559d458ddf1d5a65a068775ef173c47ba849a3',
                       'mcp': 'sha256:a52180123104ac97e4979ad1b9b291654b076692da51708bb2a377301fef1220'},
    'archives': {'onboarding': '8571d101da6c06c87d3659c67f4c359f285a9e14a340baa30cbbcc54e147d554',
                 'mcp': '457d3ddc2a1a844a8e7851f75a7f3ada37b5f737d02c41ccbc9d11319a175f9b'},
    'transportHashes': {'retainedEngineBindingHash': '8e3adb93d5874ee423092e7171e501a2fcef3386c44fbe48ee40c7c92ef8bb01',
                        'capturedEngineBindingHash': 'c17569848d56b8efb49ded7ab94b9e4e307ecb0b80eead2fed42aa34d1ed5718',
                        'peerCredentialsHash': '7ff52993d5d3cb149089942de7fc7a6511db2671cf2125976c081ad6fff89772'}}


def bind(base):
    class Context(base.Context):
        def __init__(self, parts, auth, sign, journal, closure, *, case=TARGET, public_authority=None, runtime=None):
            self.core, self.p, self.images, self.mac, self.http, self.ports_module, self.watch, self.engine_helpers, self.terminal = [
                parts[key] for key in ('authority', 'plan_helper', 'image_custody', 'retained_mac', 'transport', 'ports', 'quarantine', 'engine_creation', 'terminal')]
            c = self.core
            self.auth, self.sign, self.journal_module, self.closure = auth, sign, journal, copy.deepcopy(closure)
            self.case, self.root, self.runtime = copy.deepcopy(case), Path(case['executionRoot']), runtime
            self.serial = 0; self.execution = None; self.responses = 0; self.receiptBytes = 0; self.issueStarted = False
            self.counts = {key: 0 for key in c.LIMITS}
            self.p.ancestry(self.root.parent); c.require(not os.path.lexists(self.root), 'CONTROL_UPDATE_SCOPE_CONSUMED_NO_REPLAY')
            self.root.mkdir(mode=0o700); self.root.chmod(0o700); self.sync(self.root.parent)
            self.write(self.root, 'preparation-claim.json', {'schema': 'ouf.managed-csv-control-preflight-claim.v1',
                       'executionInputsHash': case['executionInputsHash'], 'maximums': c.LIMITS,
                       'runtimeEffectsDispatched': 0, 'automaticReplayAllowed': False, 'budgetReset': False})
            prepared = Path(case['preparedRoot']); retained = {}
            for name, expected in [('execution-inputs.json', case['executionInputsHash']),
                                   ('execution-plan.json', case['conditionalPlanHash']), ('result.json', None)]:
                self.reserve('ownerConfigurationReads'); retained[name] = self.read(prepared/name, expected)
            native, plan, result = retained['execution-inputs.json'], retained['execution-plan.json'], retained['result.json']
            c.require(native['schema'] == 'ouf.managed-csv-control-private-execution-inputs.v1'
                      and native['capturedInputsHash'] == case['inputsHash']
                      and native['conditionalNativePlanHash'] == case['conditionalPlanHash']
                      and c.digest(native['currentCapture']) == case['inputsHash']
                      and all(native[key] is False for key in ('executionEntryQualified', 'runtimeAuthorityIssued', 'targetUpdateAuthorized',
                                                             'currentRuntimeRevalidated', 'automaticReplayAllowed', 'budgetReset')),
                      'EXACT_PREPARED_CONTROL_INPUTS_REQUIRED')
            c.require(result['schema'] == 'ouf.managed-csv-control-image-plan-result.v1'
                      and result['status'] == 'MANAGED_CSV_CONTROL_IMAGES_AND_CONDITIONAL_PLAN_PREPARED_NOT_AUTHORIZED'
                      and result['complete'] is True and result['executionInputsHash'] == case['executionInputsHash']
                      and result['conditionalNativePlanHash'] == case['conditionalPlanHash']
                      and result['capturedInputsHash'] == case['inputsHash']
                      and result['counts'] == case['preparationCounts']
                      and result['newDatabaseMigrations'] == 0 and result['runtimeAuthorityIssued'] is False,
                      'EXACT_SUCCESSFUL_CONSUMED_IMAGE_PLAN_REQUIRED')
            c.require(plan['schema'] == 'ouf.managed-csv-control-conditional-plan.v1'
                      and plan['kind'] == 'FROZEN_CONDITIONAL_PROPOSAL_NOT_EXECUTABLE'
                      and plan['capturedInputsHash'] == case['inputsHash'] and c.digest(plan) == case['conditionalPlanHash']
                      and set(plan['replacements']) == set(native['nativeArchives']) == set(native['imageAudits']) == set(c.ROLES)
                      and len(plan['existingApplications']) == 13 and len(plan['unchangedApplications']) == 11
                      and plan['databaseMigration'] == {'from': 36, 'to': 36, 'newMigrations': 0}
                      and all(plan[key] is False for key in ('executionEntryQualified', 'currentRuntimeRevalidated', 'databaseAdmissionProven',
                                                           'runtimeAuthorityIssued', 'targetApplyAuthorized', 'newGrantsAuthorized',
                                                           'humanBudgetsOrResumeAuthorized', 'databaseRestoreAuthorized', 'automaticRollbackAllowed',
                                                           'automaticReplayAllowed', 'budgetReset', 'applicationE2EProven', 'releaseAcceptance')),
                      'EXACT_TWO_OWNER_CONDITIONAL_PLAN_REQUIRED')
            self.prepared_inputs = native; self.native = copy.deepcopy(native)
            capture = native['currentCapture']; self.inputs = copy.deepcopy(capture); self.proposal = copy.deepcopy(plan)
            targets = plan['targetRoleKeys']; c.require(set(targets) == set(c.ROLES) and targets['onboarding'] == 'onboarding', 'EXACT_TARGET_ROLE_MAP_REQUIRED')
            renamed = {value: role for role, value in targets.items()}
            c.require(len(renamed) == 2 and all(value in capture['currentObservations'] for value in renamed), 'DISTINCT_CAPTURED_TARGET_KEYS_REQUIRED')
            for key in ('currentObservations', 'currentProcessPins'):
                self.inputs[key] = {renamed.get(role, role): copy.deepcopy(value) for role, value in capture[key].items()}
            self.proposal['existingApplications'] = {renamed.get(role, role): copy.deepcopy(value) for role, value in plan['existingApplications'].items()}
            c.require(len(self.proposal['existingApplications']) == 13, 'ALL_RETAINED_PEER_IDENTITIES_REQUIRED')
            self.proposal['readReplacements'] = self.proposal['replacements']
            self.proposal['nativeIdentityProfile'] = 'CONFIG_AND_NATIVE_MANIFEST'
            self.archives, self.facts = {}, {}
            for role in c.ROLES:
                row = self.proposal['readReplacements'][role]; archive = native['nativeArchives'][role]; audit = native['imageAudits'][role]
                c.require(audit['sourceCommit'] == case['testedSources'][role] and audit['nativeIdentity']['nativeImageId'] == case['nativeImageIds'][role]
                          and self.images.runtime_image_id(audit) == row['request']['Image'] == case['nativeImageIds'][role]
                          and archive['sha256'] == case['archives'][role]
                          and Path(archive['path']) == prepared/(role+'-native.tar')
                          and row['oldBinding'] == self.p.stable_binding(self.inputs['currentObservations'][role]),
                          'EXACT_TARGET_NATIVE_ARCHIVE_AND_OLD_OWNER_REQUIRED')
                self.archives[role] = copy.deepcopy(archive)
                self.facts[role] = {'audit': copy.deepcopy(audit), 'archive': copy.deepcopy(archive),
                                    'identity': {'nativeImageId': case['nativeImageIds'][role], 'configurationImageId': audit['imageId']}}
            self.proposal['readReplacements']['mcp']['readiness'] = {'readinessPort': 8080, 'readinessPath': '/health/ready', 'expectedStatus': 204}
            self.proposal['onboardingReplacement'] = self.proposal['readReplacements']['onboarding']
            self.application_facts = copy.deepcopy(plan['candidateApplicationFacts']); self.migrations = self.application_facts['migrations']
            c.require(len(self.migrations) == 36, 'EXACT_36_PACKAGED_MIGRATION_FENCE_REQUIRED')
            self.database_profile = copy.deepcopy(plan['boundDatabaseProfile'])
            self.database, self.fence, self.backup = parts['database'], parts['state_fence'], parts['backup']
            self.transport_compatibility = self.database.retained_transport(c, self.database_profile, capture['engineBinding'], case['transportHashes'])
            self.proposal['operationalSqlHash'] = c.sha(self.fence.query(False).encode())
            self.proposal['operationalSqlAfterHash'] = self.proposal['operationalSqlHash']
            overlays = plan['nativeFlywayConfiguration']['ownerOverlays']
            c.require(len(overlays) == 1 and overlays[0]['binding']['path'] == case['ownerOverlayPath'], 'ONE_RETAINED_OWNER_OVERLAY_REQUIRED')
            self.reserve('ownerConfigurationContentReads')
            self.owner_overlay_raw, self.owner_overlay_binding = self.p.private_config(overlays[0]['binding']['path'], overlays[0]['binding'])
            self.configuration_raw = parts['configuration_raw']
            self.native['imageAudit'] = self.facts['onboarding']['audit']
            self.native['currentOnboarding'] = self.inputs['currentObservations']['onboarding']
            self.archive = self.archives['onboarding']; self.onb_context = parts['onb_context']; self.mcp_http = parts['mcp_transport']
            self.engine = self.http.Engine(self.p, capture['engineBinding']); self.engine.before = self.before_dispatch; self.engine.retained = self.retained
            self.public_authority = public_authority or base.public_authority
            self.authority_metadata = self.refresh_authority(); self.profile = self.authority_metadata['profile']; self.openssl = self.executable()
            self.input_seals = {str(prepared/name): list(self.p.frame((prepared/name).lstat())) for name in retained}
            self.source_seals = {path: list(self.p.frame(Path(path).lstat())) for path in closure}
            self.verify_archive(); self.application_jar = self.extract_application()
            if runtime is not None:
                self.runtime_binding = self.runtime_snapshot()
            self.check_sources()

        def check_sources(self):
            super().check_sources()
            if hasattr(self, 'owner_overlay_binding'):
                self.core.require(list(self.p.frame(Path(self.owner_overlay_binding['path']).lstat())) == self.owner_overlay_binding['metadata'],
                                  'CLASSIFIED_OWNER_CONFIGURATION_SEAL_CHANGED')
            if hasattr(self, 'application_jar'):
                self.core.require(list(self.p.frame(Path(self.application_jar['path']).lstat())) == self.application_jar['metadata'],
                                  'QUALIFIED_APPLICATION_JAR_SEAL_CHANGED')
            capture = self.prepared_inputs['currentCapture']
            for value in capture['currentRootProcessPins'].values():
                pid = value['pid']; raw = Path('/proc/'+str(pid)+'/stat').read_bytes()
                self.core.require(0 < len(raw) < 16384 and b') ' in raw, 'BOUNDED_ROOT_PROCESS_PIN_REQUIRED')
                ns = {}
                for name in ('net', 'mnt'):
                    row = Path('/proc/'+str(pid)+'/ns/'+name).stat(); ns[name] = [row.st_dev, row.st_ino]
                current = {'pid': pid, 'startTicks': int(raw.rsplit(b') ', 1)[1].split()[19]), 'namespaces': ns}
                self.core.require(current == value, 'CAPTURED_PID1_AND_ENGINE_ROOT_GENERATION_REQUIRED')

        def before_dispatch(self, method, path, body):
            self.check_sources()
            return super().before_dispatch(method, path, body)

        def current(self):
            c = self.core; self.check_sources()
            print('Verifico le13generazioni correnti, i due owner, PostgreSQL e le reti; nessuna SQL prima della review.', flush=True)
            for role, binding in self.proposal['existingApplications'].items():
                status, actual = self.preflight_get('/v1.44/containers/'+binding['containerId']+'/json')
                c.require(status == 200 and actual['State']['Running'] is True and actual['State']['Paused'] is False
                          and actual['State']['Restarting'] is False and self.p.stable_binding(actual) == binding
                          and self.p.process_pin(actual['State']['Pid']) == self.inputs['currentProcessPins'][role], 'ALL_13_CURRENT_GENERATIONS_REQUIRED')
                if actual['Id'] == self.database_profile['postgresRuntimeBinding']['containerId']:
                    self.database.check_postgres(self, actual)
                    if not getattr(self, 'configuration_classified', False):
                        self.classify_configuration(actual)
            c.require(getattr(self, 'configuration_classified', False), 'OWNER_CONFIGURATION_PRECEDENCE_CLASSIFICATION_REQUIRED')
            for row in self.proposal['readReplacements'].values():
                status, _ = self.preflight_get('/v1.44/containers/'+row['retiredName']+'/json')
                c.require(status == 404, 'RETAINED_OWNER_NAME_ALREADY_EXISTS')
            status, info = self.preflight_get('/v1.44/info')
            c.require(status == 200 and info['ServerVersion'] == '29.8.1'
                      and ['driver-type', 'io.containerd.snapshotter.v1'] in (info.get('DriverStatus') or []), 'EXACT_NATIVE_ENGINE_PROFILE_REQUIRED')
            baseline = {}
            for row in self.proposal['readReplacements'].values():
                net = row['network']; status, value = self.preflight_get('/v1.44/networks/'+net['id'])
                c.require(status == 200 and value['Id'] == net['id'] and value['Name'] == net['name']
                          and value['Driver'] == 'bridge' and value['Scope'] == 'local', 'EXACT_CURRENT_OWNER_NETWORK_REQUIRED')
                members = value.get('Containers') or {}; wanted = row['request']['NetworkingConfig']['EndpointsConfig'][net['name']]['MacAddress'].lower()
                expected_members = {actual['Id'] for actual in self.inputs['currentObservations'].values()
                                    if any(endpoint.get('NetworkID') == net['id'] for endpoint in actual['NetworkSettings']['Networks'].values())}
                c.require(set(members) == expected_members, 'NO_NEW_OR_MISSING_NETWORK_PEER_ADOPTION')
                c.require([cid for cid, endpoint in members.items() if str(endpoint.get('MacAddress', '')).lower() == wanted] == [row['oldBinding']['containerId']],
                          'SOLE_CURRENT_TARGET_ENDPOINT_MAC_OWNER_REQUIRED')
                baseline[net['id']] = copy.deepcopy(members)
            if hasattr(self, 'network_baseline'):
                c.require(baseline == self.network_baseline, 'NETWORK_CHANGED_DURING_HUMAN_REVIEW')
            self.network_baseline = baseline; self.admission()

        def import_claim(self, role):
            row = self.execution.record(); stage = 'IMPORT_'+role.upper()+'_OWNER'
            self.core.require(self.core.STAGES[row['nextStage']] == stage and len(row['effects']) == row['nextStage']+1
                              and row['effects'][-1]['state'] == 'CLAIMED', 'EXACT_CLAIMED_NATIVE_OWNER_IMPORT_REQUIRED')
            self.gate.check(); self.verify_archive()
            self.evidence('native-import-dispatch-claim', {'role': role, 'archiveHash': self.archives[role]['sha256'], 'attemptNotCompletion': True})

        def candidate_configuration(self, role, value, started, restored, quarantine=False):
            request = self.proposal['readReplacements'][role]['request']
            expected = {**self.p.env(self.facts[role]['audit']['imageConfig']), **self.p.env(request)}
            self.core.require(self.p.env(value['Config']) == expected, 'EXACT_RETAINED_OWNER_ENV_MAP_REQUIRED')
            checked = copy.deepcopy(value); checked['Config']['Env'] = copy.deepcopy(request['Env'])
            return super().candidate_configuration(role, checked, started, restored, quarantine)

        def owner_health(self, role, pin):
            self.core.require(role in self.core.ROLES, 'TWO_OWNER_READINESS_ONLY')
            if role == 'mcp':
                return self.mcp_http.health(self.p, pin)
            return self.http.health(self.p, pin, self.proposal['readReplacements'][role]['readiness'])

        def extract_application(self):
            return self.onb_context.Context.extract_application(self)

        def classify_configuration(self, postgres):
            return self.onb_context.Context.classify_configuration(self, postgres)

    return Context
