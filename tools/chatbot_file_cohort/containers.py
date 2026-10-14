"""Four container replacements under the single signed cohort action.

Registry quiescence and database/route owners run first through the aggregate
installer. This owner neither creates authority nor rolls back databases. Every
Docker effect has a durable, exclusive claim; an interrupted effect is only read
back. Readiness GETs use persisted finite budgets, without holding the CAS lock.
"""
import copy
import http.client
import ipaddress
import json
import time
from urllib.parse import quote

from engine_creation import Engine
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.plan import PROFILE, MODULES, NO_RESTART, digest, require, sha

STAGES = ('rename', 'create', 'start', 'ready', 'restart_policy')
READINESS_POLICY = {'profile':'ouf.chatbot-cohort-readiness.v1', 'maximumAttempts':128,
                    'maximumElapsedSeconds':3600, 'backoffSeconds':[5,15,60,300,900],
                    'maximumJitterPercent':20}


class CohortPaused(RuntimeError):
    def __init__(self, reason, next_attempt_at=None):
        self.reason, self.next_attempt_at = reason, next_attempt_at
        super().__init__(reason)


def installation_scope(plan):
    return {'profile':PROFILE, 'planHash':digest(plan),
            'cohortManifestHash':plan['cohortManifestHash'],
            'retiredContainerIds':sorted(r['oldRuntimeBinding']['containerId'] for r in plan['replacements']),
            'readinessPolicy':copy.deepcopy(READINESS_POLICY),
            'automaticRollbackAllowed':False, 'databaseRestoreAuthorized':False}


class CohortContainers:
    def __init__(self, action, engine, journal, plan, clock=time.time):
        require(type(action) is AggregateAction and type(engine) is Engine and type(journal) is Journal,
                'REAL_AGGREGATE_AUTHORITY_ENGINE_AND_JOURNAL_REQUIRED')
        require(plan.get('schema') == 'ouf.chatbot-file-cohort-installation-plan.v1'
                and [r['module'] for r in plan.get('replacements', [])] == list(MODULES),
                'EXACT_FOUR_REPLACEMENT_PLAN_REQUIRED')
        self.action, self.engine, self.journal, self.clock = action, engine, journal, clock
        self.plan = copy.deepcopy(plan)
        self.plan_hash = digest(plan)
        self.scope = installation_scope(plan)
        self.rows = {r['module']:r for r in self.plan['replacements']}
        self.steps = [m+'.'+s for m in MODULES for s in STAGES]

    def guard(self):
        require(digest(self.plan) == self.plan_hash and installation_scope(self.plan) == self.scope,
                'COHORT_PLAN_CHANGED_DURING_EXECUTION')
        self.action.guard('applicationCohortInstallation', self.scope)
        self.engine.check_socket()

    def initialize(self):
        self.guard()
        # Existing or partial journals are retained by Journal.initialize.
        self.journal.initialize({'schema':'ouf.chatbot-cohort-container-journal.v1',
            'planHash':self.plan_hash, 'authorityHash':self.action.authority_hash,
            'version':1, 'nextStep':0, 'effects':[], 'createdAt':self.clock(),
            'gates':{}, 'readiness':{}, 'incidentState':'OPEN', 'budgetReset':False})

    def record(self):
        value = self.journal.read()
        require(value.get('schema') == 'ouf.chatbot-cohort-container-journal.v1'
                and value.get('planHash') == self.plan_hash
                and value.get('authorityHash') == self.action.authority_hash
                and value.get('budgetReset') is False
                and type(value.get('nextStep')) is int and 0 <= value['nextStep'] <= len(self.steps),
                'COHORT_JOURNAL_SCOPE_OR_HISTORY_DRIFT')
        require(len(value['effects']) in (value['nextStep'], value['nextStep']+1)
                and [e['step'] for e in value['effects']] == self.steps[:len(value['effects'])]
                and all(e['state'] == 'APPLIED' for e in value['effects'][:value['nextStep']])
                and (len(value['effects']) == value['nextStep'] or value['effects'][-1]['state'] == 'CLAIMED'),
                'COHORT_ORDERED_EFFECT_HISTORY_REQUIRED')
        for effect in value['effects']:
            name, stage = effect['step'].split('.')
            require(effect.get('intentHash') == digest({'modulePlan':self.rows[name],'stage':stage}),
                    'COHORT_RETAINED_INTENT_DRIFT')
            if effect['state'] == 'APPLIED':
                require(type(effect.get('evidence')) is dict
                        and effect.get('evidenceHash') == digest(effect['evidence']),
                        'COHORT_RETAINED_EVIDENCE_DRIFT')
        require(type(value.get('readiness')) is dict and set(value['readiness']) <= set(MODULES),
                'COHORT_READINESS_HISTORY_INVALID')
        for budget in value['readiness'].values():
            require(type(budget) is dict and set(budget) == {'firstAttemptAt','attempts','nextAttemptAt'}
                    and type(budget['attempts']) is int and 1 <= budget['attempts'] <= 128
                    and all(type(budget[k]) in (int,float) and 0 <= budget[k] < float('inf')
                            for k in ('firstAttemptAt','nextAttemptAt'))
                    and budget['nextAttemptAt'] >= budget['firstAttemptAt'],
                    'COHORT_READINESS_HISTORY_INVALID')
        return value

    def save(self, previous, value):
        value['version'] = previous['version']+1
        self.journal.compare_and_save(previous, value)
        return value

    def accept_owner_gate(self, name, reviewed_scope_hash, observed_evidence_hash):
        """Aggregate installer records a completed concrete owner, never a flag.

        The evidence hash is subsequently checked by its owner in the aggregate
        checkpoint; this record only binds ordering to the reviewed scope.
        """
        require(name in ('registry','database','gateway','authorization')
                and sha(reviewed_scope_hash) and sha(observed_evidence_hash), 'EXACT_OWNER_GATE_BINDING_REQUIRED')
        expected = {'registry':self.plan['registryModulePackageHash'],
                    'database':self.plan['databasePlanHash'], 'gateway':self.plan['gatewayPlanHash'],
                    'authorization':self.plan['authorizationPlanHash']}
        require(reviewed_scope_hash == expected[name], 'OWNER_GATE_REVIEW_DRIFT')
        self.guard()
        with self.journal.invocation():
            previous = self.record()
            gate = {'scopeHash':reviewed_scope_hash, 'evidenceHash':observed_evidence_hash}
            if name in previous['gates']:
                require(previous['gates'][name] == gate, 'RETAINED_OWNER_GATE_CHANGED')
                return
            following = copy.deepcopy(previous)
            following['gates'][name] = gate
            self.save(previous, following)

    def inspect(self, identity):
        status, value = self.engine.request('GET','/v1.44/containers/'+quote(identity,safe='')+'/json')
        if status == 404:
            return None
        require(status == 200 and type(value) is dict, 'COHORT_CONTAINER_INSPECTION_FAILED')
        return value

    def retired(self, row, renamed):
        old = self.inspect(row['oldRuntimeBinding']['containerId'])
        pin = row['oldRuntimeBinding']
        require(old is not None and old['Id'] == pin['containerId'] and old['Image'] == pin['imageId']
                and digest(old['Config']) == pin['configHash'] and digest(old['Mounts']) == pin['mountsHash'],
                'RETIRED_COHORT_CONTAINER_CHANGED')
        host = copy.deepcopy(row['oldHostConfig'])
        host['RestartPolicy'] = NO_RESTART
        state = old['State']
        require(digest(old['HostConfig']) == digest(host) and state['Running'] is False
                and state['Paused'] is False and state['Status'] == 'exited' and state['Pid'] == 0
                and state['StartedAt'] == pin['startedAt'], 'OLD_COHORT_PRODUCER_NOT_QUIESCENT')
        require(old['Name'] == '/'+(row['retiredName'] if renamed else row['name']),
                'RETIRED_COHORT_NAME_DRIFT')
        return {'containerId':old['Id'], 'imageId':old['Image'], 'name':old['Name'],
                'configHash':pin['configHash'], 'hostConfigHash':digest(host), 'stopped':True}

    def candidate(self, row, restored_policy=False):
        actual = self.inspect(row['name'])
        if actual is None:
            return None
        request = row['creationRequest']
        require(actual['Name'] == '/'+row['name'] and actual['Image'] == request['Image']
                and sha(actual.get('Id')) and actual['Id'] != row['oldRuntimeBinding']['containerId'],
                'COHORT_REPLACEMENT_IDENTITY_DRIFT')
        for key, value in request.items():
            if key in ('HostConfig','NetworkingConfig') or (key == 'Hostname' and not value):
                continue
            require(actual['Config'].get(key) == value, 'COHORT_REPLACEMENT_PROCESS_CONFIG_DRIFT')
        host = copy.deepcopy(request['HostConfig'])
        if restored_policy:
            host['RestartPolicy'] = row['restoreRestartPolicy']
        require(all(actual['HostConfig'].get(k) == v for k, v in host.items()),
                'COHORT_REPLACEMENT_HOST_CONFIG_DRIFT')
        old_mounts = {(m['Type'],m['Source'],m['Destination'],m['RW']) for m in row['oldMounts']}
        new_mounts = {(m['Type'],m['Source'],m['Destination'],m['RW']) for m in actual['Mounts']}
        require(new_mounts == old_mounts, 'COHORT_REPLACEMENT_MOUNT_DRIFT')
        networks = actual['NetworkSettings'].get('Networks', {})
        expected = request['NetworkingConfig']['EndpointsConfig']['ouf-backend']
        require(set(networks) == {'ouf-backend'}
                and networks['ouf-backend']['NetworkID'] == expected['NetworkID']
                and set(expected['Aliases']) <= set(networks['ouf-backend'].get('Aliases') or []),
                'COHORT_REPLACEMENT_NETWORK_DRIFT')
        return actual

    def running(self, row, restored_policy=False):
        actual = self.candidate(row, restored_policy)
        if actual is None or actual['State']['Running'] is not True:
            return None
        state = actual['State']
        require(state['Paused'] is False and state['Status'] == 'running' and state['Pid'] > 1
                and actual.get('RestartCount') == 0, 'EXACT_FIRST_COHORT_PROCESS_GENERATION_REQUIRED')
        return actual

    def retained_generation(self, row, actual):
        """A later phase cannot adopt another matching-name container or process."""
        effects = {e['step']:e['evidence'] for e in self.record()['effects'] if e['state'] == 'APPLIED'}
        created = effects.get(row['module']+'.create')
        require(created is not None and actual['Id'] == created['containerId']
                and actual['Image'] == created['imageId'] and digest(actual['Config']) == created['configHash']
                and digest(actual['Mounts']) == created['mountsHash'], 'COHORT_CREATED_GENERATION_CHANGED')
        started = effects.get(row['module']+'.start')
        if started is not None:
            require(actual['State']['Pid'] == started['runtimeState']['Pid']
                    and actual['State']['StartedAt'] == started['runtimeState']['StartedAt'],
                    'COHORT_STARTED_GENERATION_CHANGED')

    def mutation(self, row, stage):
        self.guard()
        if stage == 'rename':
            self.retired(row, False)
            require(self.inspect(row['retiredName']) is None, 'RETIRED_NAME_ALREADY_EXISTS')
            status, _ = self.engine.request('POST','/v1.44/containers/'+row['oldRuntimeBinding']['containerId']
                +'/rename?name='+quote(row['retiredName'],safe=''))
            require(status == 204, 'COHORT_RENAME_REQUIRES_RECONCILIATION')
        elif stage == 'create':
            self.retired(row, True)
            require(self.inspect(row['name']) is None, 'COHORT_LIVE_NAME_ALREADY_EXISTS')
            status, value = self.engine.request('POST','/v1.44/containers/create?name='+quote(row['name'],safe=''),row['creationRequest'])
            require(status == 201 and type(value) is dict and sha(value.get('Id')),
                    'COHORT_CREATION_REQUIRES_RECONCILIATION')
        elif stage == 'start':
            self.retired(row, True)
            actual = self.candidate(row)
            require(actual is not None and actual['State']['Status'] == 'created'
                    and actual['State']['Running'] is False and actual['State']['Pid'] == 0,
                    'EXACT_CREATED_COHORT_GENERATION_REQUIRED')
            self.retained_generation(row, actual)
            status, _ = self.engine.request('POST','/v1.44/containers/'+actual['Id']+'/start')
            require(status == 204, 'COHORT_START_REQUIRES_RECONCILIATION')
        elif stage == 'restart_policy':
            actual = self.running(row)
            require(actual is not None, 'HEALTHY_COHORT_GENERATION_BEFORE_RESTART_POLICY_REQUIRED')
            self.retained_generation(row, actual)
            if row['restoreRestartPolicy'] != NO_RESTART:
                status, _ = self.engine.request('POST','/v1.44/containers/'+actual['Id']+'/update',
                                               {'RestartPolicy':row['restoreRestartPolicy']})
                require(status == 200, 'COHORT_RESTART_POLICY_REQUIRES_RECONCILIATION')
        else:
            require(stage == 'ready', 'UNKNOWN_COHORT_EFFECT')

    def observe(self, row, stage):
        self.guard()
        if stage == 'rename':
            return self.retired(row, True)
        self.retired(row, True)
        if stage == 'create':
            actual = self.candidate(row)
            if actual is None or actual['State']['Status'] != 'created' or actual['State']['Running']:
                return None
        else:
            actual = self.running(row, stage == 'restart_policy')
            if actual is None:
                return None
            self.retained_generation(row, actual)
        result = {'containerId':actual['Id'], 'imageId':actual['Image'],
                  'configHash':digest(actual['Config']), 'hostConfigHash':digest(actual['HostConfig']),
                  'mountsHash':digest(actual['Mounts']), 'runtimeState':copy.deepcopy(actual['State'])}
        if stage == 'ready':
            health = self.health(row, actual)
            if health is None:
                return None
            following = self.running(row)
            require(following is not None and Engine.runtime_binding(following) == Engine.runtime_binding(actual),
                    'COHORT_GENERATION_CHANGED_DURING_READINESS')
            result['health'] = health
        self.guard()
        return result

    @staticmethod
    def health(row, actual):
        address = actual['NetworkSettings']['Networks']['ouf-backend']['IPAddress']
        ip = ipaddress.ip_address(address)
        require(ip.version == 4 and ip.is_private and not ip.is_loopback and not ip.is_unspecified,
                'EXACT_PRIVATE_CONTAINER_HEALTH_ADDRESS_REQUIRED')
        client = http.client.HTTPConnection(address, 8080, timeout=5)
        try:
            client.request('GET',row['readinessPath'],headers={'Accept':'application/json','Connection':'close'})
            response = client.getresponse()
            raw = response.read(65537)
            require(len(raw) <= 65536, 'COHORT_HEALTH_RESPONSE_BOUND_EXCEEDED')
            if response.status in (502,503,504):
                return None
            if row['module'] == 'mcp':
                require(response.status == 204 and not raw, 'MCP_READINESS_CONTRACT_MISMATCH')
                return {'httpStatus':204, 'responseBytes':0}
            require(response.status == 200, 'COHORT_HEALTH_PERMANENT_HTTP_FAILURE')
            body = json.loads(raw)
            require(type(body) is dict, 'COHORT_HEALTH_RESPONSE_INVALID')
            require(body.get('status') == 'UP', 'COHORT_HEALTH_CONTRACT_MISMATCH')
            return {'httpStatus':200, 'bodyHash':digest(body)}
        except (OSError,http.client.HTTPException):
            return None
        finally:
            client.close()

    def run_until(self, module):
        require(module in MODULES, 'EXPLICIT_COHORT_BARRIER_REQUIRED')
        target = (list(MODULES).index(module)+1)*len(STAGES)
        with self.journal.invocation():
            while True:
                self.guard()
                previous = self.record()
                if previous['nextStep'] >= target:
                    return self.report(previous)
                required = {'registry','database','authorization'}
                if previous['nextStep'] >= 2*len(STAGES):
                    required.add('gateway')
                require(required <= set(previous['gates']), 'PRECEDING_COHORT_OWNER_NOT_RECONCILED')
                step = self.steps[previous['nextStep']]
                name, stage = step.split('.')
                row = self.rows[name]
                is_new = len(previous['effects']) == previous['nextStep']
                if is_new:
                    following = copy.deepcopy(previous)
                    following['effects'].append({'step':step, 'state':'CLAIMED',
                        'intentHash':digest({'modulePlan':row,'stage':stage}), 'claimedAt':self.clock()})
                    previous = self.save(previous, following)
                    self.mutation(row, stage)
                if stage == 'ready':
                    budget = previous['readiness'].get(name, {'firstAttemptAt':self.clock(),'attempts':0,'nextAttemptAt':self.clock()})
                    now = self.clock()
                    require(now >= budget['firstAttemptAt'], 'COHORT_READINESS_CLOCK_REGRESSED')
                    if budget['attempts'] >= 128 or now-budget['firstAttemptAt'] >= 3600:
                        raise CohortPaused('COHORT_READINESS_BUDGET_EXHAUSTED')
                    if now < budget['nextAttemptAt']:
                        raise CohortPaused('COHORT_READINESS_WAIT',budget['nextAttemptAt'])
                    following = copy.deepcopy(previous)
                    attempts = budget['attempts']+1
                    interval = READINESS_POLICY['backoffSeconds'][min(attempts-1,4)]
                    jitter = int(digest({'plan':self.plan_hash,'module':name,'attempt':attempts})[:8],16)/0xffffffff
                    # Reserve both attempt and retry time before the GET. An
                    # interrupted response never earns an immediate free retry.
                    following['readiness'][name] = {**budget,'attempts':attempts,
                        'nextAttemptAt':now+interval*(1+0.2*jitter)}
                    previous = self.save(previous, following)
                proof = self.observe(row, stage)
                if stage == 'ready':
                    finished = self.clock()
                    require(finished >= now, 'COHORT_READINESS_CLOCK_REGRESSED')
                    if finished-budget['firstAttemptAt'] >= 3600:
                        raise CohortPaused('COHORT_READINESS_BUDGET_EXHAUSTED')
                if proof is None:
                    if stage != 'ready':
                        raise CohortPaused('COHORT_EFFECT_UNPROVEN_RECONCILIATION_ONLY')
                    raise CohortPaused('COHORT_READINESS_TRANSIENT',previous['readiness'][name]['nextAttemptAt'])
                self.guard()
                following = copy.deepcopy(previous)
                following['effects'][-1].update(state='APPLIED',evidenceHash=digest(proof),evidence=proof)
                following['nextStep'] += 1
                if following['nextStep'] == len(self.steps):
                    following['incidentState'] = 'RESOLVED'
                self.save(previous,following)

    def verify_all(self):
        """Fresh read-only generation/readiness proof for aggregate release."""
        self.guard()
        record = self.record()
        require(record['nextStep'] == len(self.steps), 'ALL_COHORT_REPLACEMENTS_REQUIRED_BEFORE_RELEASE')
        proofs = []
        for name in MODULES:
            row = self.rows[name]
            self.retired(row, True)
            actual = self.running(row, True)
            require(actual is not None, 'COHORT_MEMBER_NOT_RUNNING_AT_RELEASE')
            prior = next(e['evidence'] for e in record['effects'] if e['step'] == name+'.restart_policy')
            require(actual['Id'] == prior['containerId']
                    and actual['State']['Pid'] == prior['runtimeState']['Pid']
                    and actual['State']['StartedAt'] == prior['runtimeState']['StartedAt'],
                    'COHORT_GENERATION_CHANGED_BEFORE_RELEASE')
            health = self.health(row,actual)
            if health is None:
                raise CohortPaused('COHORT_MEMBER_READINESS_NOT_CURRENT')
            after = self.running(row,True)
            require(after is not None and Engine.runtime_binding(after) == Engine.runtime_binding(actual),
                    'COHORT_GENERATION_CHANGED_DURING_RELEASE_CHECK')
            proofs.append({'module':name,'runtimeBinding':Engine.runtime_binding(actual),'health':health})
        self.guard()
        require(self.record() == record, 'COHORT_HISTORY_CHANGED_DURING_RELEASE_CHECK')
        return {'schema':'ouf.chatbot-cohort-current-containers.v1','planHash':self.plan_hash,
                'journalHash':digest(record),'members':proofs,'notReleaseAcceptance':True}

    def report(self, record=None):
        row = record or self.record()
        return {'schema':'ouf.chatbot-cohort-containers-receipt.v1', 'planHash':self.plan_hash,
                'completedEffects':row['nextStep'], 'totalEffects':len(self.steps),
                'allFourReplacementsVerified':row['nextStep'] == len(self.steps),
                'journalHash':digest(row), 'incidentState':row['incidentState'],
                'automaticRollbackAllowed':False, 'databaseRestoreAuthorized':False,
                'budgetReset':False, 'notReleaseAcceptance':True}
