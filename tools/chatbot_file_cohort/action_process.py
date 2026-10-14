"""A single finite systemd process for the reviewed acceptance action.

The process starts before the first token grant. SSH disconnection cannot create
a new worker invocation. Restart and boot enablement are absent; a consumed start
claim is reconciled, never repeated. Permanent service authority is not inferred.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

import iam_binding_candidate as evidence
import iam_governance_intake as governance
from iam_owner_action import publish
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def require(ok, reason):
    evidence.require(ok, reason)


def duration_microseconds(value):
    require(type(value) is str and re.fullmatch(r'\d+(?:us|ms|min|s|h)(?: \d+(?:us|ms|min|s|h))*',value),
            'FINITE_SYSTEMD_RUNTIME_DURATION_REQUIRED')
    units={'us':1,'ms':1000,'s':1000000,'min':60000000,'h':3600000000}
    return sum(int(number)*units[unit] for number,unit in re.findall(r'(\d+)(us|ms|min|s|h)',value))


def private_file(binding, maximum):
    require(type(binding) is dict and set(binding) == {'path','sha256'}
            and type(binding['path']) is str and Path(binding['path']).is_absolute()
            and re.fullmatch('[0-9a-f]{64}', str(binding['sha256'])), 'EXACT_PROCESS_ARTIFACT_BINDING_REQUIRED')
    path = Path(binding['path'])
    with protected_directory(path.parent) as directory:
        fd = os.open(path.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                    and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                    and 0 < before.st_size <= maximum, 'PRIVATE_PROCESS_ARTIFACT_CUSTODY_REQUIRED')
            raw = bytearray()
            while len(raw) <= maximum:
                part = os.read(fd, min(65536, maximum+1-len(raw)))
                if not part:
                    break
                raw.extend(part)
            require(len(raw) == before.st_size and evidence.identity(before) == evidence.identity(os.fstat(fd))
                    == evidence.identity(os.stat(path.name, dir_fd=directory, follow_symlinks=False))
                    and hashlib.sha256(raw).hexdigest() == binding['sha256'],
                    'PROCESS_ARTIFACT_CHANGED_OR_HASH_MISMATCH')
            return bytes(raw)
        finally:
            os.close(fd)


def compile_process_plan(*, logical_operation, source_closure_hash, programs,
                         bootstrap, bundle, authority_directory, directory_plan, maximum_seconds=3600):
    require(re.fullmatch('[0-9a-f]{64}', str(logical_operation))
            and re.fullmatch('[0-9a-f]{64}', str(source_closure_hash)), 'EXACT_FULL_ACTION_PROCESS_SCOPE_REQUIRED')
    require(type(programs) is dict and set(programs) == {'python', 'systemdRun', 'systemctl'}
            and all(type(v) is dict and set(v) == {'path','sha256'} for v in programs.values()),
            'QUALIFIED_NATIVE_PROCESS_COMMANDS_REQUIRED')
    for program in programs.values():
        require(governance.executable(program['path']) == program, 'PROCESS_COMMAND_BINDING_CHANGED')
    for value in (bootstrap, bundle):
        require(type(value) is dict and set(value) == {'path','sha256'}
                and Path(value['path']).is_absolute() and re.fullmatch('[0-9a-f]{64}', str(value['sha256'])),
                'QUALIFIED_PRIVATE_CHILD_SOURCE_BUNDLE_REQUIRED')
    parent = Path(authority_directory).parent
    require(parent == evidence.PARENT and re.fullmatch('chatbot-file-cohort-signed-[0-9a-f]{64}', Path(authority_directory).name),
            'FIXED_PRIVATE_AGGREGATE_AUTHORITY_DIRECTORY_REQUIRED')
    require(type(maximum_seconds) is int and 1 <= maximum_seconds <= 3600,
            'FINITE_PROCESS_DURATION_REQUIRED')
    require(type(directory_plan) is dict and 1 <= len(directory_plan) <= 24
            and all(type(name) is str and re.fullmatch('[A-Za-z][A-Za-z0-9]{0,63}', name)
                    and type(path) is str and Path(path).is_relative_to(authority_directory)
                    and Path(path) != Path(authority_directory) and '..' not in Path(path).parts
                    and str(Path(path)) == path for name,path in directory_plan.items())
            and len(set(directory_plan.values())) == len(directory_plan),
            'CLOSED_PRIVATE_ACTION_DIRECTORY_PLAN_REQUIRED')
    unit = 'ouf-file-cohort-'+logical_operation[:32]+'.service'
    argv = [programs['python']['path'], '-I', '-B', '-S', bootstrap['path'], bundle['path'], authority_directory]
    return {'profile':'ouf.chatbot-file-cohort-finite-process.v1',
        'logicalOperationHash':logical_operation, 'sourceClosureHash':source_closure_hash,
        'programs':copy.deepcopy(programs), 'bootstrap':copy.deepcopy(bootstrap), 'bundle':copy.deepcopy(bundle),
        'authorityDirectory':authority_directory, 'unit':unit, 'argv':argv,
        'directoryPlan':copy.deepcopy(directory_plan),
        'maximumElapsedSeconds':maximum_seconds, 'restart':'no', 'enableAtBoot':False,
        'startsBeforeFirstGrant':True, 'sameInvocationWorkerHandoffRequired':True,
        'automaticReplayAllowed':False, 'permanentRuntimeAcceptance':False}


class FiniteActionProcess:
    def __init__(self, action, plan):
        require(type(action) is AggregateAction, 'REAL_AGGREGATE_PROCESS_AUTHORITY_REQUIRED')
        expected = compile_process_plan(logical_operation=plan['logicalOperationHash'],
            source_closure_hash=plan['sourceClosureHash'], programs=plan['programs'],
            bootstrap=plan['bootstrap'], bundle=plan['bundle'], authority_directory=plan['authorityDirectory'],
            directory_plan=plan['directoryPlan'],
            maximum_seconds=plan['maximumElapsedSeconds'])
        require(plan == expected and plan['sourceClosureHash'] == action.closure,
                'EXACT_FULL_ACTION_PROCESS_PLAN_REQUIRED')
        self.action, self.plan, self.plan_hash = action, copy.deepcopy(plan), digest(plan)
        self.claim = 'chatbot-file-cohort-process-'+plan['logicalOperationHash']+'.claim.json'

    def guard(self):
        require(digest(self.plan) == self.plan_hash, 'PROCESS_PLAN_CHANGED')
        self.action.guard('finiteActionProcess', self.plan)
        for program in self.plan['programs'].values():
            require(governance.executable(program['path']) == program, 'PROCESS_COMMAND_CHANGED')
        private_file(self.plan['bootstrap'], 131072)
        private_file(self.plan['bundle'], 8388608)
        directory = Path(self.plan['authorityDirectory'])
        require(private_file({'path':str(directory/'authority.json'), 'sha256':self.action.authority_hash}, 131072)
                == self.action.raw, 'EXACT_CHILD_AUTHORITY_CONTEXT_REQUIRED')

    def properties(self):
        self.guard()
        result = subprocess.run([self.plan['programs']['systemctl']['path'], 'show', self.plan['unit'],
            '--property=Id,LoadState,ActiveState,SubState,MainPID,Transient,Restart,RuntimeMaxUSec,DropInPaths,EnvironmentFiles'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LANG':'C', 'LC_ALL':'C'})
        require(result.returncode == 0 and len(result.stdout) <= 8192, 'FINITE_PROCESS_STATE_UNAVAILABLE')
        rows = {}
        for line in result.stdout.decode('utf-8').splitlines():
            key, separator, value = line.partition('=')
            require(separator and key not in rows, 'FINITE_PROCESS_STATE_SHAPE_INVALID')
            rows[key] = value
        require(rows.get('Id') == self.plan['unit'], 'EXACT_FINITE_PROCESS_UNIT_REQUIRED')
        return rows

    def verify(self):
        rows = self.properties()
        with evidence.protected_parent() as directory:
            claim = evidence.decode(evidence.read_member(directory,self.claim))
        require(type(claim.get('runtimeMaxSeconds')) is int
                and 1 <= claim['runtimeMaxSeconds'] <= self.plan['maximumElapsedSeconds']
                and claim == {'schema':'ouf.chatbot-file-cohort-process-claim.v1',
                    'planHash':self.plan_hash, 'authorityHash':self.action.authority_hash,
                    'state':'START_CONSUMED_OUTCOME_UNPROVEN', 'automaticReplayAllowed':False,
                    'runtimeMaxSeconds':claim['runtimeMaxSeconds']}
                and duration_microseconds(rows.get('RuntimeMaxUSec')) == claim['runtimeMaxSeconds']*1000000,
                'ACTUAL_FINITE_PROCESS_RUNTIME_LIMIT_CHANGED')
        require(rows.get('LoadState') == 'loaded' and rows.get('ActiveState') == 'active'
                and rows.get('SubState') == 'running' and rows.get('Transient') == 'yes'
                and rows.get('Restart') == 'no' and not rows.get('DropInPaths')
                and not rows.get('EnvironmentFiles') and rows.get('MainPID', '').isdigit()
                and int(rows['MainPID']) > 1, 'EXACT_ACTIVE_FINITE_PROCESS_REQUIRED')
        pid = int(rows['MainPID'])
        # Actual process arguments, not only the service manager's declared row.
        raw = Path('/proc/'+str(pid)+'/cmdline').read_bytes()
        require(len(raw) <= 32768 and raw.endswith(b'\0')
                and raw[:-1].split(b'\0') == [v.encode() for v in self.plan['argv']],
                'ACTUAL_FINITE_PROCESS_ARGUMENTS_CHANGED')
        status = Path('/proc/'+str(pid)+'/status').read_text()
        require(re.search(r'^Uid:\s+0\s+0\s+0\s+0$', status, re.MULTILINE)
                and re.search(r'^Gid:\s+0\s+0\s+0\s+0$', status, re.MULTILINE),
                'ACTUAL_FINITE_PROCESS_ROOT_CUSTODY_REQUIRED')
        require(self.properties() == rows, 'FINITE_PROCESS_CHANGED_DURING_OBSERVATION')
        return {'schema':'ouf.chatbot-file-cohort-finite-process-observation.v1',
            'unit':self.plan['unit'], 'mainPid':pid, 'planHash':self.plan_hash,
            'authorityHash':self.action.authority_hash, 'sameInvocationWorkerRequired':True,
            'restart':'no', 'permanentRuntimeAcceptance':False, 'notReleaseAcceptance':True}

    def start(self):
        self.guard()
        with evidence.protected_parent() as directory:
            try:
                previous = evidence.decode(evidence.read_member(directory, self.claim))
            except FileNotFoundError:
                previous = None
            if previous is not None:
                require(previous == {'schema':'ouf.chatbot-file-cohort-process-claim.v1',
                    'planHash':self.plan_hash, 'authorityHash':self.action.authority_hash,
                    'state':'START_CONSUMED_OUTCOME_UNPROVEN', 'automaticReplayAllowed':False,
                    'runtimeMaxSeconds':previous.get('runtimeMaxSeconds')},
                    'FINITE_PROCESS_RETAINED_START_CLAIM_CHANGED')
                return self.verify()
            rows = self.properties()
            require(rows.get('LoadState') == 'not-found' and rows.get('ActiveState') == 'inactive'
                    and rows.get('MainPID') == '0', 'FINITE_ACTION_UNIT_ALREADY_EXISTS')
            remaining = int(evidence.decode(self.action.raw)['expiresAt']-time.time())
            require(0 < remaining <= self.plan['maximumElapsedSeconds'], 'FINITE_PROCESS_AUTHORITY_EXPIRED')
            claim = {'schema':'ouf.chatbot-file-cohort-process-claim.v1', 'planHash':self.plan_hash,
                'authorityHash':self.action.authority_hash, 'state':'START_CONSUMED_OUTCOME_UNPROVEN',
                'automaticReplayAllowed':False, 'runtimeMaxSeconds':remaining}
            require(publish(directory, self.claim, encoded(claim)), 'FINITE_PROCESS_START_ALREADY_CONSUMED')
        self.guard()
        argv = [self.plan['programs']['systemdRun']['path'], '--quiet', '--collect',
            '--unit='+self.plan['unit'], '--property=Type=exec', '--property=Restart=no',
            '--property=RuntimeMaxSec='+str(remaining), '--property=KillMode=control-group',
            '--property=TimeoutStopSec=30', '--property=UMask=0077', '--property=WorkingDirectory=/',
            '--', *self.plan['argv']]
        # A timeout/ambiguous result never submits systemd-run twice.
        try:
            subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=30, check=False,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LANG':'C', 'LC_ALL':'C'})
        except subprocess.TimeoutExpired:
            pass
        return self.verify()
