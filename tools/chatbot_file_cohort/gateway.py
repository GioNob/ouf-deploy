"""Exact APISIX route publication within the signed application cohort.

Production materializers are reused from the separately pinned Gateway package.
The installer retains the complete pre-existing route map; each changed row has
one durable write claim and exact GET reconciliation. No DELETE, rollback or
automatic replay follows an ambiguous HTTP result.
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
from urllib.parse import quote

from engine_creation import Engine
import iam_governance_intake as governance
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.plan import PlanDenied, digest, encoded, require, sha
from tools.chatbot_file_cohort.containers import installation_scope

PROFILE = 'ouf.chatbot-file-cohort.gateway-publication.v1'
MAX_RESPONSE = 8388608
MAX_ROUTES = 256
ROUTE_ID = re.compile(r'[A-Za-z0-9._-]{1,128}')
EXTERNAL_ADMIN_KEY = '/opt/ouf/secrets/apisix-admin-key'

MAX_NAMESPACE_INPUT = 655360
# Literal source is included in the sealed runtime module. No target path or
# downloaded Python module is executed by this child. Only the selected network
# namespace FD is inherited; the private credential crosses stdin, never argv.
NAMESPACE_CHILD_SOURCE = r'''import http.client,json,os,re,signal,sys
signal.alarm(12)
try:
    raw=sys.stdin.buffer.read(655361)
    if not 0<len(raw)<=655360:raise ValueError()
    v=json.loads(raw)
    if type(v)is not dict or set(v)!={'method','path','body','key'}:raise ValueError()
    method,path,body,key=(v[n] for n in ('method','path','body','key'))
    if method not in ('GET','PUT') or type(path)is not str:raise ValueError()
    if path!='/apisix/admin/routes' and not re.fullmatch(r'/apisix/admin/routes/[A-Za-z0-9._-]{1,128}',path):raise ValueError()
    if (method=='GET' and body is not None) or (method=='PUT' and type(body)is not dict):raise ValueError()
    if type(key)is not str or not 16<=len(key)<=4096 or not all(33<=ord(c)<=126 for c in key):raise ValueError()
    payload=None if body is None else json.dumps(body,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    if payload is not None and len(payload)>262144:raise ValueError()
    if len(sys.argv)!=2 or not re.fullmatch(r'[0-9]{1,10}',sys.argv[1]):raise ValueError()
    fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
    client=http.client.HTTPConnection('127.0.0.1',9180,timeout=10)
    client.request(method,path,body=payload,headers={'X-API-KEY':key,'Content-Type':'application/json','Accept':'application/json','Connection':'close'})
    response=client.getresponse();payload=response.read(8388609)
    if len(payload)>8388608:raise ValueError()
    result=json.dumps({'status':response.status,'body':json.loads(payload) if payload else {}},sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    if len(result)>8454144:raise ValueError()
    sys.stdout.buffer.write(result);sys.stdout.buffer.flush();client.close()
except BaseException:
    os._exit(1)
os._exit(0)
'''


def namespace_program():
    return governance.executable('/usr/bin/python3')


def route_value(doc):
    # Same APISIX envelope normalization used by the qualified route installers.
    value = doc.get('value', doc)
    if type(value) is dict and type(value.get('value')) is dict:
        value = value['value']
    require(type(value) is dict, 'APISIX_ROUTE_OBJECT_REQUIRED')
    return {k: v for k, v in value.items() if k not in ('create_time', 'update_time')}


def route_map(rows):
    require(type(rows) is list and 0 < len(rows) <= MAX_ROUTES, 'COMPLETE_BOUNDED_GATEWAY_ROUTES_REQUIRED')
    result = {}
    for row in rows:
        value = route_value(row)
        rid = value.get('id')
        require(type(rid) is str and ROUTE_ID.fullmatch(rid) and rid not in result,
                'UNIQUE_EXACT_GATEWAY_ROUTE_ID_REQUIRED')
        require(len(encoded(value)) <= 262144, 'GATEWAY_ROUTE_BOUND_EXCEEDED')
        result[rid] = value
    return result


def publication_scope(plan):
    return {'profile': PROFILE, 'planHash': digest(plan),
            'previousRuntimeHash': plan['previousRuntimeHash'],
            'proposedRuntimeHash': plan['proposedRuntimeHash'], 'automaticRollbackAllowed': False}


_EXISTING_CONFIG_CUSTODY = {
    # These are the observed, already-running selections on this host. Do not
    # change ownership of /opt/ouf or the files mounted into live containers.
    '/opt/ouf/installation/active-projection.json': {
        'parents': {'/opt/ouf': (1000, 1000, 0o750),
                    '/opt/ouf/installation': (0, 0, 0o700)},
        'file': (0, 0, 0o600)},
    '/opt/ouf/secrets/onboarding-ths.yaml': {
        'parents': {'/opt/ouf': (1000, 1000, 0o750),
                    '/opt/ouf/secrets': (1000, 1000, 0o700)},
        'file': (10003, 10003, 0o400)},
    EXTERNAL_ADMIN_KEY: {
        'parents': {'/opt/ouf': (1000, 1000, 0o750),
                    '/opt/ouf/secrets': (1000, 1000, 0o700)},
        # 0600 does not grant group access. The observed uid/mode are fixed;
        # the actual gid is pinned by the returned file metadata.
        'file': (1000, None, 0o600)},
    '/etc/ouf/deploy-snapshots/consultation-human-read-20261002-1153/prepared/apisix-config.yaml': {
        'parents': {}, 'file': (636, 636, 0o400)},
}


def selected_directory_custody(info, path, exception):
    selected = exception['parents'].get(path) if exception else None
    if selected is not None:
        return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == selected
    return info.st_uid == 0 and not info.st_mode & 0o022


def selected_file_custody(info, exception):
    selected = exception['file'] if exception else None
    if selected is not None:
        uid,gid,mode=selected
        return info.st_uid==uid and (gid is None or info.st_gid==gid) and stat.S_IMODE(info.st_mode)==mode
    return info.st_uid == 0 and stat.S_IMODE(info.st_mode) in (0o400,0o440,0o444,0o600,0o640,0o644)


def private_config(path, expected=None):
    """Read an exact selected file with pinned, no-follow path custody.

    The three existing selections above have different named owners. All
    other paths, including newly staged APISIX config, retain root custody.
    """
    target = Path(path)
    require(target.is_absolute() and '..' not in target.parts, 'EXACT_APISIX_CONFIG_PATH_REQUIRED')
    exception = _EXISTING_CONFIG_CUSTODY.get(str(target))
    fds = []; ancestors = []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); fds.append(parent)
        current = '/'
        for name in target.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(child); info = os.fstat(child)
            current = os.path.join(current, name)
            require(selected_directory_custody(info,current,exception),'APISIX_CONFIG_ANCESTRY_NOT_CUSTODIED')
            ancestors.append((parent,name,child,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)))
            parent = child
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent); fds.append(fd)
        s = os.fstat(fd)
        pin = lambda v: (v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 < s.st_size <= 1048576
                and selected_file_custody(s,exception),
                'ROOT_CONTROLLED_SELECTED_APISIX_CONFIG_REQUIRED')
        raw = b''
        while len(raw) <= 1048576:
            part = os.read(fd,65536)
            if not part: break
            raw += part
        require(len(raw) == s.st_size and pin(s) == pin(os.fstat(fd))
                == pin(os.stat(target.name, dir_fd=parent, follow_symlinks=False)), 'APISIX_CONFIG_READ_DRIFT')
        binding = {'path': str(target), 'sha256': hashlib.sha256(raw).hexdigest(), 'metadata': list(pin(s))}
        require(expected is None or binding == expected, 'APISIX_SELECTED_CONFIG_CHANGED')
        identity=lambda v:(v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode)
        for parent,name,child,seal in ancestors:
            require(seal == identity(os.fstat(child)) == identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                    'APISIX_CONFIG_ANCESTRY_CHANGED')
        return raw, binding
    finally:
        for fd in reversed(fds): os.close(fd)


def selected_admin_key(raw, external_key=None):
    # Closed scalar/list subset of the selected APISIX admin_key section only.
    # No YAML dependency, interpolation, aliases, tags or arbitrary configuration
    # execution in the isolated installer. Unsupported syntax requires review.
    lines = raw.decode('utf-8').splitlines()
    entries = [(i, len(line)-len(line.lstrip(' '))) for i,line in enumerate(lines)
               if re.fullmatch(r' *admin_key: *(?:#.*)?',line)]
    require(len(entries) == 1, 'ONE_LITERAL_ADMIN_KEY_SECTION_REQUIRED')
    start, indentation = entries[0]
    parents=[]
    for line in lines[:start]:
        if not line.strip() or line.lstrip().startswith('#'): continue
        match=re.fullmatch(r'( *)([A-Za-z_][A-Za-z0-9_]*): *(?:#.*)?',line)
        depth=len(line)-len(line.lstrip(' '))
        parents=[p for p in parents if p[0]<depth]
        if match: parents.append((depth,match[2]))
    require([p[1] for p in parents if p[0]<indentation] == ['deployment','admin'],
            'SELECTED_DEPLOYMENT_ADMIN_SECTION_REQUIRED')
    candidates=[]; row=None
    for line in lines[start+1:]:
        if not line.strip() or line.lstrip().startswith('#'): continue
        require('\t' not in line, 'LITERAL_ADMIN_KEY_INDENTATION_REQUIRED')
        depth=len(line)-len(line.lstrip(' '))
        if depth <= indentation: break
        match=re.fullmatch(r' +(- +)?(name|key|role): *(.*?) *',line)
        require(match is not None, 'UNSUPPORTED_ADMIN_KEY_SYNTAX')
        if match[1]:
            if row is not None: candidates.append(row)
            row={}
        require(row is not None and match[2] not in row, 'DUPLICATE_OR_UNBOUNDED_ADMIN_KEY_FIELD')
        value=match[3]
        if value.startswith('"'):
            value=json.loads(value)
        elif value.startswith("'"):
            require(len(value)>=2 and value.endswith("'"), 'ADMIN_KEY_SCALAR_INVALID')
            value=value[1:-1].replace("''", "'")
        else:
            value=value.split(' #',1)[0].strip()
        require(type(value) is str and re.fullmatch(r'[A-Za-z0-9._=+-]{1,4096}',value),
                'LITERAL_ADMIN_KEY_SCALAR_REQUIRED')
        row[match[2]]=value
    if row is not None: candidates.append(row)
    require(len(candidates)<=8 and all(set(r)=={'name','key','role'} for r in candidates),
            'CLOSED_ADMIN_CREDENTIAL_RECORD_REQUIRED')
    admin=[r for r in candidates if r.get('role') == 'admin']
    # The selected live config has a literal but empty admin_key section.
    # Its separate existing admin-key file was observed to authorize a GET.
    # No fallback is permitted for ambiguous/nonempty credential records.
    if not candidates and external_key is not None:
        key=external_key
    else:
        require(external_key is None and len(admin)==1,
                'ONE_SELECTED_APISIX_ADMIN_CREDENTIAL_REQUIRED')
        key=admin[0].get('key')
    require(type(key) is str and 16 <= len(key) <= 4096 and all(33 <= ord(c) <= 126 for c in key)
            and not key.startswith(('$ENV', '${', '$secret')), 'LITERAL_SELECTED_ADMIN_CREDENTIAL_REQUIRED')
    return key


class NamespaceAdmin:
    """Bounded loopback HTTP in a child; no image, exec, proxy or redirect.

    The parent never changes namespaces. All response contents stay private.
    Existing Engine socket custody and the exact APISIX generation are checked
    before and after each request, including namespace inode and selected bind.
    """
    def __init__(self, engine, binding, runtime_owner=None):
        require(type(engine) is Engine and os.geteuid() == 0
                and hasattr(os, 'setns'), 'QUALIFIED_ROOT_NAMESPACE_TRANSPORT_REQUIRED')
        self.engine, self.binding = engine, copy.deepcopy(binding)
        self.binding_hash = digest(binding)
        self.runtime_owner=runtime_owner
        self.reviewed_binding=copy.deepcopy(binding)
        if runtime_owner is not None:
            from tools.chatbot_file_cohort.gateway_runtime import GatewayRuntime, proposed_transport
            require(type(runtime_owner) is GatewayRuntime and runtime_owner.engine is engine,
                    'CONCRETE_SAME_ENGINE_APISIX_RUNTIME_OWNER_REQUIRED')
            require(Engine.runtime_binding(runtime_owner.generation())==binding['runtimeBinding'],
                    'NEW_APISIX_GENERATION_NOT_PROVEN_BY_OWNER')
            self.reviewed_binding=proposed_transport(runtime_owner.plan)

    @staticmethod
    def observe(engine, selected_config):
        require(type(engine) is Engine, 'CUSTODIED_ENGINE_REQUIRED')
        status, actual = engine.request('GET', '/v1.44/containers/ouf-apisix/json')
        require(status == 200 and actual.get('Name') == '/ouf-apisix'
                and actual['State']['Running'] and not actual['State']['Paused'], 'RUNNING_SELECTED_APISIX_REQUIRED')
        mounts = [m for m in actual['Mounts'] if m.get('Destination') == '/usr/local/apisix/conf/config.yaml']
        require(len(mounts) == 1 and mounts[0].get('Type') == 'bind' and mounts[0].get('RW') is False
                and mounts[0].get('Source') == selected_config, 'EXACT_SELECTED_APISIX_CONFIG_BIND_REQUIRED')
        raw, config = private_config(selected_config)
        admin_binding=None
        try:selected_admin_key(raw)
        except PlanDenied as error:
            if str(error)!='ONE_SELECTED_APISIX_ADMIN_CREDENTIAL_REQUIRED':raise
            admin_raw,admin_binding=private_config(EXTERNAL_ADMIN_KEY)
            selected_admin_key(raw,admin_raw.decode('ascii').strip())
        s = os.stat('/proc/'+str(actual['State']['Pid'])+'/ns/net')
        return {'runtimeBinding': Engine.runtime_binding(actual), 'configBinding': config,
                'adminKeyBinding':admin_binding,
                'networkNamespace': {'device': s.st_dev, 'inode': s.st_ino},
                'transport': 'EXACT_APISIX_NETNS_LOOPBACK_HTTP', 'port': 9180,
                'maximumResponseBytes': MAX_RESPONSE, 'timeoutSeconds': 10,
                'pythonExecutable': namespace_program()}

    def check(self):
        require(digest(self.binding) == self.binding_hash, 'APISIX_TRANSPORT_BINDING_CHANGED')
        if self.runtime_owner is not None:
            from tools.chatbot_file_cohort.gateway_runtime import proposed_transport
            require(self.reviewed_binding==proposed_transport(self.runtime_owner.plan)
                    and Engine.runtime_binding(self.runtime_owner.generation())==self.binding['runtimeBinding'],
                    'APISIX_RUNTIME_OWNER_OR_REVIEW_CHANGED')
        current = self.observe(self.engine, self.binding['configBinding']['path'])
        require(current == self.binding, 'APISIX_GENERATION_OR_NAMESPACE_CHANGED')

    def request(self, method, path, body=None):
        require(method in ('GET','PUT') and (path == '/apisix/admin/routes'
                or re.fullmatch(r'/apisix/admin/routes/[A-Za-z0-9._-]{1,128}', path))
                and ((method == 'PUT' and type(body) is dict) or (method == 'GET' and body is None)),
                'CLOSED_GATEWAY_ADMIN_OPERATION_REQUIRED')
        raw = None if body is None else encoded(body)
        require(raw is None or len(raw) <= 262144, 'BOUNDED_GATEWAY_ADMIN_BODY_REQUIRED')
        self.check()
        program=self.binding['pythonExecutable']
        require(program==namespace_program(),'APPROVED_NAMESPACE_PYTHON_CHANGED')
        config, _ = private_config(self.binding['configBinding']['path'], self.binding['configBinding'])
        admin_binding=self.binding.get('adminKeyBinding')
        external=None
        if admin_binding is not None:
            raw_key,_=private_config(EXTERNAL_ADMIN_KEY,admin_binding)
            external=raw_key.decode('ascii').strip()
        request=encoded({'method':method,'path':path,'body':body,'key':selected_admin_key(config,external)})
        require(len(request)<=MAX_NAMESPACE_INPUT,'APISIX_PRIVATE_STDIN_BOUND_EXCEEDED')
        pid = self.binding['runtimeBinding']['pid']
        ns = os.open('/proc/'+str(pid)+'/ns/net', os.O_RDONLY)
        child = None
        try:
            s = os.fstat(ns)
            require({'device':s.st_dev,'inode':s.st_ino} == self.binding['networkNamespace'], 'APISIX_NAMESPACE_FD_CHANGED')
            # Popen performs only native fork/exec internals (no preexec_fn).
            # No Python executes in a copy of the multithreaded owner process.
            child=subprocess.Popen([program['path'],'-I','-B','-S','-c',NAMESPACE_CHILD_SOURCE,str(ns)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                pass_fds=(ns,),close_fds=True,cwd='/',env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            try:
                output,_=child.communicate(request,timeout=15)
            except subprocess.TimeoutExpired:
                require(False,'APISIX_OUTCOME_REQUIRES_RECONCILIATION')
            require(child.returncode==0 and 0<len(output)<=MAX_RESPONSE+65536,
                    'APISIX_OUTCOME_REQUIRES_RECONCILIATION')
            self.check()
            result=json.loads(output)
            require(type(result)is dict and set(result)=={'status','body'} and type(result['status'])is int
                    and 100<=result['status']<=599,'APISIX_TYPED_RESPONSE_REQUIRED')
            return result['status'],result['body']
        finally:
            if child is not None:
                if child.poll() is None:child.kill()
                child.wait(timeout=5)
                for pipe in (child.stdin,child.stdout):
                    if pipe is not None:pipe.close()
            os.close(ns)

    def routes(self):
        status, body = self.request('GET','/apisix/admin/routes')
        require(status == 200 and type(body) is dict and type(body.get('list')) is list
                and body.get('total') == len(body['list']), 'COMPLETE_APISIX_ROUTE_INVENTORY_REQUIRED')
        return route_map(body['list'])


class GatewayRoutes:
    def __init__(self, action, cohort_plan, plan, journal, transport):
        require(type(action) is AggregateAction and type(journal) is Journal
                and type(transport) is NamespaceAdmin, 'CONCRETE_SIGNED_GATEWAY_COMPONENTS_REQUIRED')
        require(plan.get('schema') == PROFILE and cohort_plan['gatewayPlanHash'] == digest(plan)
                and cohort_plan['gatewayModulePackageHash'] == plan['gatewayModulePackageHash']
                and transport.reviewed_binding == plan['transportBinding'], 'GATEWAY_COHORT_PLAN_BINDING_REQUIRED')
        before,after = plan['previousRoutes'],plan['proposedRoutes']
        require(type(before) is dict and type(after) is dict and set(before) <= set(after)
                and route_map(list(before.values())) == before and route_map(list(after.values())) == after
                and digest(before) == plan['previousRuntimeHash'] and digest(after) == plan['proposedRuntimeHash']
                and plan['changes'] == [{'id':name,'before':before.get(name),'after':after[name]}
                    for name in sorted(after) if before.get(name) != after[name]]
                and plan['automaticRollbackAllowed'] is False and plan['automaticWriteReplayAllowed'] is False,
                'COMPLETE_RETAINED_ROUTE_MAP_AND_EXACT_DIFF_REQUIRED')
        self.action, self.journal, self.transport = action, journal, transport
        self.plan, self.cohort_plan = copy.deepcopy(plan), copy.deepcopy(cohort_plan)
        self.plan_hash, self.scope = digest(plan), publication_scope(plan)
        self.installation_scope = installation_scope(cohort_plan)

    def guard(self):
        require(digest(self.plan) == self.plan_hash and publication_scope(self.plan) == self.scope
                and installation_scope(self.cohort_plan) == self.installation_scope, 'GATEWAY_EXECUTION_PLAN_CHANGED')
        self.action.guard('applicationCohortInstallation', self.installation_scope)
        self.action.guard('gatewayRoutePublication', self.scope)
        self.transport.check()

    def initialize(self):
        self.guard()
        require(self.transport.routes() == self.plan['previousRoutes'], 'GATEWAY_BASELINE_DRIFT')
        self.journal.initialize({'schema':PROFILE, 'planHash':self.plan_hash,
            'authorityHash':self.action.authority_hash, 'version':1, 'nextStep':0,
            'effects':[], 'budgetReset':False, 'automaticRollbackAllowed':False})

    def record(self):
        record = self.journal.read(); n = record.get('nextStep')
        require(record.get('schema') == PROFILE and record.get('planHash') == self.plan_hash
                and record.get('authorityHash') == self.action.authority_hash and record.get('budgetReset') is False
                and type(n) is int and 0 <= n <= len(self.plan['changes']), 'GATEWAY_JOURNAL_BINDING_DRIFT')
        effects = record.get('effects')
        require(type(effects) is list and len(effects) in (n,n+1)
                and [e['routeId'] for e in effects] == [r['id'] for r in self.plan['changes'][:len(effects)]]
                and all(e['state'] == 'APPLIED' for e in effects[:n])
                and all(e['intentHash'] == digest(self.plan['changes'][i]) for i,e in enumerate(effects))
                and (len(effects) == n or effects[-1]['state'] == 'CLAIMED'), 'GATEWAY_EFFECT_HISTORY_INVALID')
        return record

    def save(self, previous, following):
        following['version'] = previous['version']+1
        self.journal.compare_and_save(previous,following)
        return following

    def expected(self, count):
        rows = copy.deepcopy(self.plan['previousRoutes'])
        for change in self.plan['changes'][:count]: rows[change['id']] = change['after']
        return rows

    def apply(self):
        with self.journal.invocation():
            while True:
                self.guard(); record = self.record(); n = record['nextStep']
                if n == len(self.plan['changes']):
                    return self.verify()
                change = self.plan['changes'][n]
                if len(record['effects']) == n:
                    require(self.transport.routes() == self.expected(n), 'GATEWAY_ROUTE_MAP_CHANGED_BEFORE_CLAIM')
                    following = copy.deepcopy(record)
                    following['effects'].append({'routeId':change['id'], 'intentHash':digest(change), 'state':'CLAIMED'})
                    record = self.save(record,following)
                    self.guard()
                    # Exactly one PUT. Its acknowledgement alone is never accepted.
                    self.transport.request('PUT','/apisix/admin/routes/'+quote(change['id'],safe=''),change['after'])
                # Resuming a CLAIMED row performs GET only, even if the row is absent.
                require(self.transport.routes() == self.expected(n+1), 'GATEWAY_WRITE_OUTCOME_UNPROVEN_NO_REPLAY')
                self.guard()
                following = copy.deepcopy(record)
                following['effects'][-1].update(state='APPLIED',observedMapHash=digest(self.expected(n+1)))
                following['nextStep'] = n+1
                self.save(record,following)

    def verify(self):
        self.guard()
        record = self.record()
        require(record['nextStep'] == len(self.plan['changes'])
                and self.transport.routes() == self.plan['proposedRoutes'], 'COMPLETE_GATEWAY_PUBLICATION_UNPROVEN')
        return {'schema':'ouf.chatbot-file-cohort.gateway-receipt.v1', 'planHash':self.plan_hash,
                'authorityHash':self.action.authority_hash, 'runtimeHash':self.plan['proposedRuntimeHash'],
                'routeCount':len(self.plan['proposedRoutes']), 'reconciledWrites':len(self.plan['changes']),
                'existingRoutesRetained':True, 'automaticRollbackAllowed':False,
                'runtimeAuthorityIssued':False, 'notReleaseAcceptance':True}
