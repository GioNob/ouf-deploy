"""Closed owner replacement commands, reused lifecycle primitives and V36 fences."""
import copy
import os
import time

SQL_STAGES = ('VERIFY_CURRENT_ADMISSION', 'VERIFY_PRESTOP_STATE', 'VERIFY_PRESTART_STATE',
              'VERIFY_POSTSTART_STATE', 'VERIFY_BEFORE_MCP', 'VERIFY_FINAL_STATE')


def bind(base):
    class NativePorts(base.NativePorts):
        def parse(self, stage):
            for role in self.core.ROLES:
                suffix = '_'+role.upper()+'_OWNER'
                if stage.endswith(suffix):
                    return stage[:-len(suffix)], role
            self.require(stage in (*SQL_STAGES, 'VERIFY_QUIESCED_BACKUP', 'VERIFY_FINAL'), 'EXACT_GLOBAL_OR_OWNER_STAGE_REQUIRED')
            return stage, None

        def guard(self, stage):
            self.gate.check(); self.ctx.check_sources()
            for role, binding in self.plan['existingApplications'].items():
                if role in self.core.ROLES:
                    continue
                value = self.container(binding['containerId'])
                self.require(value['State']['Running'] is True and value['State']['Paused'] is False
                             and value['State']['Restarting'] is False and self.ctx.p.stable_binding(value) == binding
                             and self.ctx.p.process_pin(value['State']['Pid']) == self.ctx.inputs['currentProcessPins'][role],
                             'ALL_11_UNCHANGED_PEER_GENERATIONS_REQUIRED')
            for role in self.core.ROLES:
                self.old_guard(role, stage)
            for role in self.execution.record()['candidates']:
                self.candidate_guard(role, stage=stage)

        def old_guard(self, role, stage):
            row = self.proposal(role); binding = row['oldBinding']; value = self.container(binding['containerId'])
            i = self.stages.index(stage); at = lambda action: self.stages.index(action+'_'+role.upper()+'_OWNER')
            expected_name = '/'+(row['name'] if i <= at('RENAME_OLD') else row['retiredName'])
            matches = self.core.digest(value['Config']) == binding['configHash']
            if i > at('DETACH_OLD'):
                effects = self.execution.record()['effects']; stopped, detached = effects[at('STOP_OLD')], effects[at('DETACH_OLD')]
                self.require(stopped['state'] == detached['state'] == 'APPLIED' and stopped['proof'].get('oldStopped') is True
                             and detached['proof'].get('oldDetached') is True, 'PROVEN_STOP_DETACH_PREFIX_REQUIRED')
                original = self.ctx.inputs['currentObservations'][role]; policy = row['legacyConfigMacDetachPolicy']
                self.require(self.core.digest(original['Config']) == binding['configHash'] and value['NetworkSettings']['Networks'] == {},
                             'EXACT_ORIGINAL_AND_DETACHED_ENDPOINT_SET_REQUIRED')
                if policy['profile'] == 'LEGACY_CONFIG_MAC_ABSENT_ONLY_AFTER_PROVEN_STOP_AND_DETACH_V1':
                    self.require(policy == self.ctx.mac.policy(original), 'SIGNED_LEGACY_MAC_TRANSITION_POLICY_REQUIRED')
                    proof = self.ctx.mac.verify_detached(original, value, expected_name=expected_name)
                    self.ctx.evidence('old-owner-mac-transition', {'role': role, 'proof': proof}); matches = True
                else:
                    self.require(not original['Config'].get('MacAddress') and policy == {
                        'profile': 'NO_LEGACY_CONFIG_MAC_CHANGE_RETAIN_EXACT_V1', 'originalConfigHash': binding['configHash'],
                        'originalEndpointSetHash': self.core.digest(original['NetworkSettings']['Networks']), 'originalHashesRewritten': False}
                        and matches, 'EXACT_NONLEGACY_CONFIG_WITHOUT_NORMALIZATION_REQUIRED')
            self.require(value['Image'] == binding['imageId'] and matches and value['Name'] == expected_name
                         and self.core.digest(sorted(value['Mounts'], key=lambda item: item['Destination'])) == binding['mountsHash']
                         and value['State']['StartedAt'] == binding['startedAt'], 'RETAINED_OLD_OWNER_CONFIG_AND_GENERATION_REQUIRED')
            host = copy.deepcopy(row['oldNativeHostConfig'])
            if i > at('DISABLE_OLD_RESTART'):
                host['RestartPolicy'] = {'Name': 'no', 'MaximumRetryCount': 0}
            self.require(value['HostConfig'] == host, 'RETAINED_OLD_OWNER_HOST_CONFIG_REQUIRED')
            if i <= at('STOP_OLD'):
                self.require(value['State']['Running'] is True and value['State']['Paused'] is False and value['State']['Restarting'] is False
                             and self.ctx.p.process_pin(value['State']['Pid']) == self.ctx.inputs['currentProcessPins'][role]
                             and self.core.digest(value['NetworkSettings']) == binding['networkSettingsHash'], 'EXACT_OLD_OWNER_BEFORE_STOP_REQUIRED')
            else:
                self.require(value['State']['Running'] is False and value['State']['Pid'] == 0, 'OLD_OWNER_MUST_REMAIN_STOPPED')
            if i > at('DETACH_OLD'):
                self.require(value['Id'] not in (self.network(role).get('Containers') or {}), 'OLD_ENDPOINT_MUST_REMAIN_RELEASED')
            return value

        def candidate_guard(self, role, stage=None, started=None, restored=None, actual=None):
            row = self.execution.record()['candidates'][role]; value = actual or self.container(row['id'])
            i = self.stages.index(stage) if stage else -1
            if started is None:
                started = i > self.stages.index('START_'+role.upper()+'_OWNER')
            if restored is None:
                restored = i > self.stages.index('RESTORE_RESTART_'+role.upper()+'_OWNER')
            self.ctx.candidate_configuration(role, value, started, restored)
            if started:
                pin = self.ctx.p.process_pin(value['State']['Pid'])
                self.require(row.get('generation') is None or pin == row['generation'], 'CREATED_PROCESS_GENERATION_CHANGED')
                if row.get('generation') is None:
                    self.execution.candidate(role, generation=pin)
            return value

        def owner_readiness(self, role, response):
            if response['status'] in (0, 502, 503, 504):
                return False
            if role == 'mcp':
                self.require(response['status'] == 204, 'PERMANENT_OR_UNKNOWN_MCP_READINESS_DENIAL')
                return True
            self.require(response['status'] == 200, 'PERMANENT_OR_UNKNOWN_ONBOARDING_READINESS_DENIAL')
            try:
                value = self.ctx.p.decode(bytes.fromhex(response['rawBodyHex']))
            except (ValueError, TypeError):
                self.require(False, 'MALFORMED_OWNER_READINESS_RESPONSE')
            self.require(type(value) is dict and value.get('status') in ('UP', 'DOWN'), 'UNKNOWN_OWNER_READINESS_STATE')
            return value['status'] == 'UP'

        def healthy(self, role):
            row = self.execution.record()['candidates'][role]; last = time.monotonic()
            while True:
                self.gate.check()
                self.require(time.time() < row['startupDeadlineWall'] and time.monotonic() < row['startupDeadlineMonotonic'], 'FINITE_CANDIDATE_STARTUP_DEADLINE')
                self.candidate_guard(role, started=True, restored=False); self.reserve('readinessGets')
                response = self.ctx.owner_health(role, self.execution.record()['candidates'][role]['generation'])
                self.ctx.evidence('owner-readiness', {'role': role, **response})
                good = self.owner_readiness(role, response)
                self.require(time.time() < row['startupDeadlineWall'] and time.monotonic() < row['startupDeadlineMonotonic'], 'READINESS_WITHIN_STARTUP_LEASE_REQUIRED')
                if good:
                    self.execution.candidate(role, readinessProven=True); return {'readinessProven': True, 'role': role}
                if time.monotonic()-last >= 10:
                    print('Attendo readiness del nuovo owner '+role+'; limite180secondi invariato.', flush=True); last = time.monotonic()
                self.require(self.gate.remaining() > 35, 'INSUFFICIENT_TIME_FOR_OWNER_READINESS'); time.sleep(2*(.8+.4*os.urandom(1)[0]/255))

        def execute(self, stage):
            row = self.execution.record(); i = row['nextStage']
            self.require(self.stages[i] == stage and len(row['effects']) == i+1 and row['effects'][-1]['state'] == 'CLAIMED', 'EXACT_CLAIMED_OWNER_STAGE_REQUIRED')
            if stage in SQL_STAGES:
                self.ctx.admission(); return self.ctx.database.observe(self, stage)
            if stage == 'VERIFY_QUIESCED_BACKUP':
                return self.ctx.backup.perform(self)
            if stage == 'VERIFY_FINAL':
                proofs = {}
                for role in self.core.ROLES:
                    candidate = row['candidates'][role]; self.require(candidate['readinessProven'] is True, 'BOTH_OWNER_READINESS_PROOFS_REQUIRED')
                    value = self.candidate_guard(role, started=True, restored=True); self.reserve('readinessGets')
                    response = self.ctx.owner_health(role, candidate['generation']); self.ctx.evidence('final-readiness', {'role': role, **response})
                    self.require(self.owner_readiness(role, response), 'FRESH_FINAL_OWNER_READINESS_REQUIRED')
                    proofs[role] = {'nativeBindingHash': self.core.digest(self.ctx.p.stable_binding(value)),
                                    'generation': candidate['generation'], 'readinessProven': True, 'oldRetainedStopped': True}
                return {'ownerProofs': proofs}
            # Qualified command allowlist, import/create/start and restart logic.
            return super().execute(stage)

        def final_result(self):
            self.guard('VERIFY_FINAL_STATE'); row = self.execution.record()
            proofs = next(effect['proof']['ownerProofs'] for effect in row['effects'] if effect['stage'] == 'VERIFY_FINAL')
            result = {'schema': 'ouf.managed-csv-control-update-result.v1', 'status': 'MANAGED_CSV_CONTROL_UPDATE_INSTALLED_E2E_NOT_ACCEPTED',
                      'complete': True, 'contextPath': str(self.root), 'executionInputsHash': self.ctx.case['executionInputsHash'],
                      'conditionalNativePlanHash': self.ctx.case['conditionalPlanHash'], 'frozenPlanHash': self.review['frozenPlanHash'],
                      'reviewHash': self.core.digest(self.review), 'authorityHash': self.core.sha(self.gate.raw),
                      'runtimeBindingHash': self.review['nativePlan']['runtimeBindingHash'], 'candidateSourceCommits': self.ctx.case['sources'],
                      'nativeImageIds': self.ctx.case['nativeImageIds'], 'counts': row['counts'], 'ownerProofs': proofs,
                      'componentReadinessProven': True, 'oldOwnersRetainedStopped': 2, 'unchangedPeers': 11,
                      'databaseMigrationsByRepair': 0, 'installedSchemaVersion': 36, 'operationalStateProof': row['effects'][-1]['proof'],
                      'backup': self.ctx.backup_proof, 'sqlSessionsByRepair': row['counts']['sqlSessions'],
                      'registryWorkerTouched': False, 'gatewayRequests': 0, 'credentialFileReads': 0, 'oauthRequestsByRepair': 0,
                      'normalOwnerOAuthBootstrapMayHaveOccurred': True, 'normalOwnerOAuthRequestsCountNotObserved': True,
                      'normalMcpManifestCatalogueUpdateMayHaveOccurred': True, 'installationSigningKeysRead': True,
                      'installationSigningOperations': 3, 'mountSourceContentIdentityProven': False, 'newGrantsGranted': 0,
                      'humanBudgetsGranted': 0, 'resumes': 0, 'sourceActivations': 0, 'acquisitionsExecuted': 0,
                      'runtimeAuthorityIssued': True, 'applicationE2EProven': False, 'releaseAcceptance': False,
                      'automaticReplayAllowed': False, 'budgetReset': False, 'automaticRollbackPerformed': False}
            return self.ctx.finalize(result)

    return NativePorts
