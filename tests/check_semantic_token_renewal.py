#!/usr/bin/env python3
"""Offline side-effect-order and binding checks; no systemd/OAuth calls."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import ExitStack

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE if (HERE / 'restore-current-semantic-policy-token-20261107.py').exists() else HERE.parent / 'scripts'
def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result
r = module('renewal', 'restore-current-semantic-policy-token-20261107.py')
p = module('policy_reader', 'read-current-semantic-policy-20261107.py')
SOURCE = b'''def config():
 runtime_dir = Path(required('OUF_POLICY_TOKEN_RUNTIME_DIR'))
 return {'runtime': runtime_dir}
def refresh(cfg):
 directory = cfg['runtime']
 os.replace(temporary, directory / 'token')
'''
ISSUER = 'https://issuer.example/realms/ouf'
cfg = {'OUF_POLICY_TOKEN_CLIENT_ID': 'semantic-fixture', 'OUF_POLICY_TOKEN_ENDPOINT': ISSUER+'/protocol/openid-connect/token',
       'OUF_POLICY_TOKEN_RUNTIME_DIR': '/private/semantic', 'OUF_POLICY_TOKEN_RUNTIME_GID': '10001',
       'OUF_POLICY_TOKEN_SECRET_FILE': '/private/secret', 'OUF_POLICY_TOKEN_REQUIRED_SCOPE': 'ouf.authorization.read'}
CONFIG = ('\n'.join(key+'='+value for key,value in cfg.items())+'\n').encode()
values = {'ouf.authorization.registry-token-file': '/run/semantic/token',
          'ouf.authorization.registry-url': 'https://policy.example'+p.POLICY_PATH,
          'ouf.authorization.refresh-seconds': '30', 'ouf.iam.issuer': ISSUER}
doc = {'Id': 'a'*64, 'Image': 'sha256:'+'b'*64, 'Config': {}, 'HostConfig': {},
       'NetworkSettings': {}, 'State': {'Pid': 123, 'StartedAt': 'fixture', 'Running': True, 'Restarting': False},
       'Mounts': [{'Type': 'bind', 'RW': False, 'Source': '/private/semantic', 'Destination': '/run/semantic'}]}
mount = {'gid': 10001, 'sameFileAsCurrentHostSource': True}
claims = {'exp': 900, 'iss': ISSUER, 'azp': 'semantic-fixture', 'scope': 'ouf.authorization.read'}
def token(exp):
    c = dict(claims, exp=exp)
    b64 = base64.urlsafe_b64encode(json.dumps(c).encode()).decode().rstrip('=')
    return ('eyJhbGciOiJSUzI1NiJ9.'+b64+'.U1lOVEhFVElD').encode()
def service():
    result = {key: '' for key in r.SERVICE_PROPERTIES}
    result.update(LoadState='loaded', ActiveState='inactive', SubState='dead', UnitFileState='static',
                  Type='oneshot', User='root', Restart='no', Result='success', ExecMainStatus='0',
                  ExecStart='{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 '+r.PRODUCER+' semantic ; ignore_errors=no ; }',
                  EnvironmentFiles='/etc/ouf/semantic.env (ignore_errors=no)')
    return result
def timer():
    return dict(LoadState='loaded', ActiveState='inactive', SubState='dead', UnitFileState='disabled',
                Unit=r.SERVICE, TimersMonotonic='{ OnUnitActiveUSec=1min ; next_elapse=1min }', TimersCalendar='')
def rejected(fn, reason):
    try: fn()
    except RuntimeError as exc: assert str(exc) == reason, str(exc)
    else: raise AssertionError('unexpected acceptance: '+reason)

assert r.output_member(SOURCE) == 'token'
assert r.parse_config(CONFIG) == cfg
r.verify_binding(doc, values, cfg, 'token', claims, mount)
for changes, reason in [({'OUF_POLICY_TOKEN_RUNTIME_DIR': '/wrong'}, 'PRODUCER_OUTPUT_NOT_CURRENT_MOUNTED_TOKEN'),
    ({'OUF_POLICY_TOKEN_ENDPOINT': 'https://other.example/token'}, 'TOKEN_ENDPOINT_NOT_CURRENT_ISSUER'),
    ({'OUF_POLICY_TOKEN_CLIENT_ID': 'other'}, 'PRODUCER_IDENTITY_NOT_MOUNTED_TOKEN_IDENTITY'),
    ({'OUF_POLICY_TOKEN_REQUIRED_SCOPE': 'admin'}, 'PRODUCER_REQUESTED_SCOPE_DIFFERS_FROM_RETAINED_TOKEN')]:
    rejected(lambda: r.verify_binding(doc, values, dict(cfg, **changes), 'token', claims, mount), reason)
masked = service(); masked['UnitFileState'] = 'masked'
rejected(lambda: r.producer_route(masked), 'EXISTING_UNMASKED_SERVICE_REQUIRED')
hooks = service(); hooks['ExecStartPost'] = 'unexpected'
rejected(lambda: r.producer_route(hooks), 'UNSUPPORTED_SERVICE_OVERRIDE_EXECSTARTPOST')
bad_timer = timer(); bad_timer['Unit'] = 'different.service'
rejected(lambda: r.timer_guard(bad_timer), 'EXISTING_SEMANTIC_TIMER_REQUIRED')

def scenario(*, wrong_output=False, start_failure=False, policy_status=200, fresh=False,
             claim_failure=False, source_changed=False, drift=False):
    state = {'commands': [], 'policy_calls': 0, 'renewed': False, 'timer': timer(), 'claims': 0}
    selected = dict(cfg)
    if wrong_output: selected['OUF_POLICY_TOKEN_RUNTIME_DIR'] = '/wrong'
    config_bytes = ('\n'.join(k+'='+v for k,v in selected.items())+'\n').encode()
    def read(path, *args, **kwargs): return SOURCE if str(path) == r.PRODUCER else config_bytes
    def units(unit, properties): return service() if unit == r.SERVICE else copy.deepcopy(state['timer'])
    def cmd(*args, **kwargs):
        state['commands'].append(args)
        if args == ('start', r.SERVICE):
            if start_failure: return SimpleNamespace(returncode=1)
            state['renewed'] = True
        elif args == ('enable', '--now', r.TIMER):
            state['timer'].update(ActiveState='active', SubState='waiting', UnitFileState='enabled')
        else: raise AssertionError(args)
        return SimpleNamespace(returncode=0)
    def claim(*args):
        state['claims'] += 1
        if claim_failure: raise FileExistsError()
        return '/private/attempt.json'
    def mounted(*args): return token(2000 if fresh or state['renewed'] else 900), mount
    def policy(*args):
        state['policy_calls'] += 1
        return {'httpStatus': policy_status, 'activePolicyResponseRead': policy_status == 200}
    current = copy.deepcopy(doc)
    if drift: current['State']['Pid'] = 999
    runtime = {'retained_semantic': lambda report: ({'semantic': doc['Id']}, {doc['Id']: doc}),
               'semantic_process': lambda doc: {'processKind': 'APPLICATION_RUNNING'},
               'inspect': lambda cid: {cid: current}}
    reader = {'declarations': lambda doc: (values, {}), 'mounted_read': mounted,
              'token_metadata': p.token_metadata, 'endpoint': p.endpoint, 'policy_get': policy}
    with ExitStack() as stack:
        for name, val in [('read_file', read), ('unit_read', units), ('command', cmd), ('claim_attempt', claim)]:
            stack.enter_context(patch.object(r, name, val))
        stack.enter_context(patch.object(r, 'PRODUCER_SHA', 'changed' if source_changed else hashlib.sha256(SOURCE).hexdigest()))
        stack.enter_context(patch.object(r.time, 'time', return_value=1000))
        sleep = stack.enter_context(patch.object(r.time, 'sleep'))
        report = {}
        try: r.execute(report, runtime, reader)
        except (RuntimeError, FileExistsError) as error: state['error'] = str(error) or type(error).__name__
        state['report'] = report; state['slept'] = sleep.call_args
    return state

s = scenario()
assert s['commands'] == [('start', r.SERVICE), ('enable', '--now', r.TIMER)]
assert s['policy_calls'] == 1 and s['claims'] == 1 and s['slept'].args == (32,)
assert s['report']['status'] == 'SEMANTIC_TOKEN_RENEWED_POLICY_GET_OK_TIMER_ACTIVE'
assert s['report']['applicationLoadedPolicyProven'] is False
assert token(2000).decode() not in json.dumps(s['report']) and ISSUER not in json.dumps(s['report'])
for opts, reason in [({'wrong_output': True}, 'PRODUCER_OUTPUT_NOT_CURRENT_MOUNTED_TOKEN'),
                     ({'source_changed': True}, 'PRODUCER_SOURCE_CHANGED'),
                     ({'drift': True}, 'SEMANTIC_RUNTIME_CHANGED'),
                     ({'claim_failure': True}, 'FileExistsError')]:
    s = scenario(**opts); assert s['error'] == reason and not s['commands'] and s['policy_calls'] == 0
s = scenario(start_failure=True)
assert s['error'] == 'EXISTING_TOKEN_PRODUCER_FAILED' and s['commands'] == [('start', r.SERVICE)] and s['policy_calls'] == 0
s = scenario(policy_status=401)
assert s['error'] == 'RENEWED_TOKEN_POLICY_READ_NOT_SUCCESSFUL' and s['commands'] == [('start', r.SERVICE)]
s = scenario(fresh=True)
assert s['commands'] == [('enable', '--now', r.TIMER)] and s['claims'] == 0
print('PASS: existing producer/output/issuer/client/scope, masked/foreign timer rejection, no effects before guards, one manual start, no retry after uncertain attempt, no timer enable on failed policy GET, fresh-token reuse, secret-free output, runtime drift')
