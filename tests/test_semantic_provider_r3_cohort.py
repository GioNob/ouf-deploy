"""Opt-in offline Docker cohort: real Engine, runc, broker, epochs and operate.

The WAITING systemd observer and quiescer are explicit fixture programs.
The creation frame observer is the real source-sealed v2, without fixture hooks.
They never publish ACTIVE or grant a lease. nft, ip and nsenter are real. A private Docker daemon
and locally imported rootfs avoid registry access and host Docker changes.
"""
import ast
import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_semantic_provider_operation_issuance as F
from tools.semantic_provider_r3 import operate as O
from tools.semantic_provider_admission_v2 import broker_v2 as B
from tools.semantic_provider_admission_v2 import l2_binding as L

ROOT, A, C = F.ROOT, F.A, F.C
NATIVE = os.environ.get("OUF_R3_COHORT_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_R3_COHORT_NATIVE requires Linux root:root; refusing to skip")

CAPTURE = r'''
import json,os,pathlib,subprocess,sys
args=sys.argv[1:]
if 'create' not in args:
    raise SystemExit(subprocess.run([RUNC,*args]).returncode)
cid=args[-1]; option='--bundle' if '--bundle' in args else '-b'
bundle=pathlib.Path(args[args.index(option)+1]).resolve()
oci=json.loads((bundle/'config.json').read_bytes())
if not pathlib.Path(oci['root']['path']).is_absolute():
    oci['root']['path']=str((bundle/oci['root']['path']).resolve())
for ns in oci['linux']['namespaces']:
    if ns.get('type')=='network' and ns.get('path'):
        ns['path']=str(pathlib.Path(ns['path']).resolve())
network=next((ns.get('path') for ns in oci['linux']['namespaces'] if ns['type']=='network'), None)
# Docker may create the netns at runc create and attach NICs only afterwards.
links=(json.loads(subprocess.run([CAPTURE_NSENTER,'--net='+network,CAPTURE_IP,'-j','addr','show'],
                               capture_output=True,check=True).stdout) if network else [])
path=pathlib.Path(BASE)/('capture-'+cid+'.json')
path.write_text(json.dumps({'oci':oci,'bundle':str(bundle),
                          'childLinks':links,'runtimeNetns':os.readlink('/proc/self/ns/net'),
                          'root':str(pathlib.Path(args[args.index('--root')+1]).resolve()),'argv':args},
                          sort_keys=True,separators=(',',':')))
path.chmod(0o600)
raise SystemExit(1) # read-only qualification: never create/start an application
'''

SYSTEMCTL = "print('ActiveState=active\\nSubState=running\\nNRestarts=0')\n"
NFT = "print('{\"nftables\":[]}')\n"
QUIESCE = r'''
import argparse,hashlib,json,pathlib
parser=argparse.ArgumentParser()
parser.add_argument('--configuration',required=True)
parser.add_argument('--configuration-sha256',required=True)
parser.add_argument('--quiesce-only',action='store_true',required=True)
args=parser.parse_args()
raw=pathlib.Path(args.configuration).read_bytes()
if hashlib.sha256(raw).hexdigest()!=args.configuration_sha256:
    raise SystemExit(1)
config=json.loads(raw)
journal=json.loads(pathlib.Path(config['coordinator']['journalPath']).read_bytes())
# The isolated fixture can only prove existing quiescence; it cannot activate.
raise SystemExit(0 if all(journal.get(k)==v for k,v in
    dict(state='QUIESCED',leaseAuthorized=False,startAuthorized=False).items()) else 1)
'''

FRAME_TARGET = '/run/role.json'
TMPFS_TARGET = '/run/ouf-southbound-runtime'
TMPFS_OPTIONS = 'rw,noexec,nosuid,nodev,uid=636,gid=636,mode=0700,size=1m'
FRAME_PATH = ROOT / C.OBSERVER_V2
FIXTURE_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


def frame_policy(oci, role, source):
    """Synthetic expectations fixed by create argv/source, before authority signs.

    Only full OCI/hooks are independently captured by the refusing runtime.
    Startup, source custody/hash and tmpfs declaration are not copied from OCI.
    """
    binding = dict(source=str(source), target=FRAME_TARGET, readOnly=True)
    return dict(schema='ouf.semantic-configured-creation-frame-policy.v1', expectedOci=oci,
        manifest=dict(user='636:636', readOnlyRoot=True, memoryBytes=268435456, pidsLimit=128,
                      mounts=[binding], tmpfs={TMPFS_TARGET: TMPFS_OPTIONS} if role == 'southbound' else {}),
        sources=[dict(**binding, uid=0, gid=0, mode=0o644, sha256=A.sha(source.read_bytes()), maxBytes=1024)],
        startup=dict(args=['/sleep', '300'], cwd='/', env=['PATH=' + FIXTURE_PATH, 'HOSTNAME=cohort-' + role],
                     uid=636, gid=636, umask=None), approvedHooks=copy.deepcopy(oci.get('hooks') or {}))

DIAGNOSTIC = r'''
import json,os,pathlib,re,sys,tempfile,time,traceback,types
runtime_path=pathlib.Path(RUNTIME)
runtime=types.ModuleType('cohort_installed_runtime')
runtime.__file__=str(runtime_path)
sys.argv=[str(runtime_path),'--configuration',CONFIGURATION,*sys.argv[1:]]
def trace(frame,event,arg):
    # Observe exceptions before operate/quiesce/main redact or suppress them.
    # Execute the installed bytes unchanged, including main's runc JSON output.
    if (frame.f_code.co_filename!=str(runtime_path)
            or frame.f_code.co_name not in ('operate','quiesce','main')):
        return None
    if event=='exception':
        try:
            path=pathlib.Path(TRACE_ROOT)/('runtime-'+str(os.getpid())+'.log')
            with path.open('a',encoding='utf-8') as stream:
                stream.write(''.join(traceback.format_exception(*arg)))
        except OSError:
            pass # Diagnostics must not change the runtime's exit/output protocol.
    return trace
exec(compile(runtime_path.read_bytes(),str(runtime_path),'exec'),runtime.__dict__)
native_run=runtime.subprocess.run
def diagnostic_run(args,**kwargs):
    programs={'semantic-provider-deployment-broker-v2.py','semantic-provider-preexec-hook-v2.py'}
    if '--mode' not in args or not any(pathlib.Path(a).name in programs for a in args):
        return native_run(args,**kwargs)
    mode=args[args.index('--mode')+1]
    if (DENY_FIRST_EPOCH and mode=='cohort-ready' and '--epoch' in args
            and args[args.index('--epoch')+1]=='1'):
        # A deliberate negative input at the broker boundary, after real create.
        # Execute the REAL broker: it must reject the mismatched live PID and
        # publish its own validated receipt. Never fabricate a process result.
        state=json.loads(kwargs['input']);state['pid']=0
        kwargs={**kwargs,'input':runtime.canonical(state)}
    if kwargs.get('stderr')!=runtime.subprocess.DEVNULL:
        return native_run(args,**kwargs)
    started=time.monotonic();result=None;failure=None
    with tempfile.TemporaryFile() as errors:
        try:
            result=native_run(args,**{**kwargs,'stderr':errors})
            return result
        except Exception as error:
            failure=type(error).__name__
            raise
        finally:
            elapsed=time.monotonic()-started
            try:
                errors.seek(0);raw=errors.read(16385)
                # Only closed public codes; never log private argv/config/data.
                codes=re.findall(rb'(?:SEMANTIC_DEPLOYMENT_BROKER|SEMANTIC_PREEXEC_HOOK)=DENIED ([A-Z0-9_]{1,80})(?:\r?\n|$)',raw)
                output=kwargs.get('stdout')
                output_bytes=(os.fstat(output.fileno()).st_size if hasattr(output,'fileno') else
                              len(result.stdout) if result is not None and isinstance(result.stdout,bytes) else None)
                row=dict(runtimePid=os.getpid(),mode=mode,epoch=args[args.index('--epoch')+1] if '--epoch' in args else None,
                         elapsedSeconds=elapsed,returncode=result.returncode if result is not None else None,
                         stdoutBytes=output_bytes,exception=failure,codes=[c.decode('ascii') for c in codes])
                path=pathlib.Path(TRACE_ROOT)/('command-'+str(os.getpid())+'.jsonl')
                with path.open('a',encoding='utf-8') as stream:
                    stream.write(json.dumps(row,sort_keys=True)+'\n')
            except OSError:
                pass # Preserve the original return/exception and suppressed stderr.
runtime.subprocess.run=diagnostic_run
sys.settrace(trace)
try:
    raise SystemExit(runtime.main())
finally:
    sys.settrace(None)
'''

def native_child_argv():
    # Docker/libnetwork may resolve the initial namespace via /proc/1/ns/net.
    # Give dockerd, its private containerd/shims and the broker one consistent
    # host view, including PID 1. Never expose the runner's proc inside this netns.
    # Like the VPS: host network, host PID view and the host's containerd.
    return [shutil.which("unshare"), "--mount", "--fork",
            sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--native-child"]


def diagnostic_source(runtime_path, configuration, trace_root, deny_first_epoch=False):
    return (f'RUNTIME={str(runtime_path)!r}\nCONFIGURATION={str(configuration)!r}\n'
            f'TRACE_ROOT={str(trace_root)!r}\nDENY_FIRST_EPOCH={deny_first_epoch!r}\n' + DIAGNOSTIC)


def initialize_registry(registry, cids):
    """A fresh fixture needs the initial-install locks omitted by compose v3."""
    for cid in cids:
        base = registry / cid
        base.mkdir(mode=0o700, exist_ok=True)
        (base / 'epochs').mkdir(mode=0o700, exist_ok=True)
        lock = base / 'operation.lock'
        with lock.open('xb'):
            pass
        lock.chmod(0o600)


def collect_codes():
    """Read the real collect's public codes; no assumption about Docker's result."""
    path = ROOT / C.SOURCE_MAP["tools/semantic_provider_peer_bindings.py"]
    tree = ast.parse(path.read_bytes())
    collect = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "collect")
    return {n.args[-1].value for n in ast.walk(collect) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name) and n.func.id == "require" and n.args
            and isinstance(n.args[-1], ast.Constant) and type(n.args[-1].value) is str}


class PortableTests(unittest.TestCase):
    def test_fixture_programs_compile_and_collect_codes_are_real(self):
        for source in (CAPTURE, SYSTEMCTL, NFT, QUIESCE, DIAGNOSTIC):
            compile(source, "<cohort-fixture>", "exec")
        compile(FRAME_PATH.read_bytes(), str(FRAME_PATH), 'exec')
        self.assertIn("PEER_MAC_IP_DRIFT", collect_codes())

    def test_cohort_policy_satisfies_real_embedded_reviewer_for_both_roles(self):
        from test_frame_observer_v2 import reviewer, policy
        module, schema = reviewer()
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'role.json'
            source.write_bytes(b'{"fixture":true}')
            for role in O.ROLES:
                oci = copy.deepcopy(policy(role)['expectedOci'])
                # Portable POSIX source; native path comes from /var/lib.
                p = frame_policy(oci, role, source)
                p['sources'][0]['source'] = p['manifest']['mounts'][0]['source'] = '/fixture/role.json'
                original_bind = next(m for m in oci['mounts'] if m['type'] == 'bind'
                                     and m['destination'] not in ('/etc/hosts', '/etc/hostname', '/etc/resolv.conf'))
                oci['mounts'] = [m for m in oci['mounts'] if m['type'] != 'bind'
                    or m['destination'] in ('/etc/hosts', '/etc/hostname', '/etc/resolv.conf')]
                oci['mounts'].append(dict(original_bind, destination=FRAME_TARGET, source='/fixture/role.json'))
                oci['process'].update(args=p['startup']['args'], cwd='/', env=p['startup']['env'])
                oci['process']['user'] = dict(uid=636, gid=636, additionalGids=[636])
                oci['root']['readonly'] = True
                oci['linux']['resources'].update(memory=dict(limit=268435456, swap=268435456), pids=dict(limit=128))
                self.assertTrue(module.configured_profile(oci, oci, p['manifest'], p['startup'],
                                                         p['approvedHooks'], schema)['configuredPolicyConforms'])

    def test_native_child_uses_host_network_and_pid_views(self):
        args = native_child_argv()
        self.assertEqual(args[1:3], ["--mount", "--fork"])
        self.assertNotIn("--net", args)
        self.assertNotIn("--pid", args)

    def test_fresh_v3_registry_has_locks_and_never_replaces_them(self):
        result = C.compose(F.fixtures.fixture(), 3, sequence=3, supersedes="a" * 64)
        cids = [v['containerId'] for v in json.loads(result['authorization'])['roles'].values()]
        self.assertFalse(any(p.endswith('/operation.lock') for p in result['documents']))
        with tempfile.TemporaryDirectory() as folder:
            registry = Path(folder)
            initialize_registry(registry, cids)
            for cid in cids:
                self.assertEqual((registry / cid / 'operation.lock').read_bytes(), b'')
                self.assertEqual(list((registry / cid / 'epochs').iterdir()), [])
                self.assertFalse((registry / cid / 'current').exists())
            retained = registry / cids[0] / 'operation.lock'
            retained.write_bytes(b'retained')
            with self.assertRaises(FileExistsError):
                initialize_registry(registry, cids)
            self.assertEqual(retained.read_bytes(), b'retained')

    def test_diagnostic_preserves_protocol_and_captures_suppressed_exception(self):
        source = '''
import subprocess,sys
def operate():
    if sys.argv[-1]=='unmasked':
        raise FileNotFoundError('operation.lock')
    if sys.argv[-1]=='success':
        return 0
    try:
        raise KeyError('missing-fixture-lock')
    except Exception:
        raise RuntimeError('DOCKER_RUNTIME_OPERATION_UNPROVEN') from None
def main():
    assert sys.flags.isolated and sys.dont_write_bytecode
    assert sys.argv[1:-1]==['--configuration','fixture.json','create']
    try:
        return operate()
    except Exception as error:
        print('SEMANTIC_DOCKER_RUNTIME=BLOCKED REASON='+str(error),file=sys.stderr)
        return 1
if __name__=='__main__': raise SystemExit(main())
'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            runtime, diagnostic = root / 'runtime.py', root / 'diagnostic.py'
            runtime.write_text(source)
            for mode in ('unmasked', 'redacted', 'success'):
                with self.subTest(mode=mode):
                    traces = root / mode
                    traces.mkdir()
                    diagnostic.write_text(diagnostic_source(runtime, 'fixture.json', traces))
                    args = ['--configuration', 'fixture.json', 'create', mode]
                    canonical = subprocess.run([sys.executable, '-I', '-B', str(runtime), *args], capture_output=True)
                    wrapped = subprocess.run([sys.executable, '-I', '-B', str(diagnostic), *args[2:]], capture_output=True)
                    self.assertEqual((wrapped.returncode, wrapped.stdout, wrapped.stderr),
                                     (canonical.returncode, canonical.stdout, canonical.stderr))
                    self.assertEqual(wrapped.returncode, 0 if mode == 'success' else 1)
                    trace = ''.join(p.read_text(encoding='utf-8') for p in traces.glob('runtime-*.log'))
                    if mode == 'success':
                        self.assertEqual(trace, '')
                    else:
                        self.assertIn('Traceback (most recent call last):', trace)
                        self.assertIn('FileNotFoundError: operation.lock' if mode == 'unmasked'
                                      else "KeyError: 'missing-fixture-lock'", trace)
                        if mode == 'redacted':
                            self.assertIn('DOCKER_RUNTIME_OPERATION_UNPROVEN', trace)

    def test_first_epoch_negative_input_executes_broker_and_keeps_public_diagnostics(self):
        source = '''
import json,subprocess,sys
def canonical(value): return json.dumps(value).encode()
def main():
    broker,epoch=sys.argv[-2:]
    result=subprocess.run([sys.executable,'-I','-B',broker,'--mode','cohort-ready','--epoch',epoch],
        input=canonical(dict(pid=42)),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20)
    sys.stdout.buffer.write(result.stdout)
    return result.returncode
'''
        broker_source = '''
import json,sys
state=json.load(sys.stdin)
print(json.dumps(state))
print('PRIVATE/path/never-report',file=sys.stderr)
if state['pid']==0:
    print('SEMANTIC_DEPLOYMENT_BROKER=DENIED BROKER_LIVE_CREATED_STATE_DRIFT',file=sys.stderr)
    raise SystemExit(1)
'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            runtime, diagnostic = root / 'runtime.py', root / 'diagnostic.py'
            broker = root / 'semantic-provider-deployment-broker-v2.py'
            runtime.write_text(source)
            broker.write_text(broker_source)
            for deny, epoch in ((False, '1'), (True, '1'), (True, '2')):
                traces = root / (str(deny) + epoch)
                traces.mkdir()
                diagnostic.write_text(diagnostic_source(runtime, 'fixture.json', traces, deny))
                result = subprocess.run([sys.executable, '-I', '-B', str(diagnostic), str(broker), epoch],
                                        capture_output=True)
                rejected = deny and epoch == '1'
                self.assertEqual(result.returncode, int(rejected))
                # This stdout can only come from the child; no CompletedProcess stub.
                self.assertEqual(json.loads(result.stdout), dict(pid=0 if rejected else 42))
                self.assertEqual(result.stderr, b'')
                rows = [json.loads(line) for p in traces.glob('command-*.jsonl')
                        for line in p.read_text().splitlines()]
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual((row['mode'], row['epoch'], row['returncode']),
                                 ('cohort-ready', epoch, result.returncode))
                self.assertIsNone(row['exception'])
                self.assertGreaterEqual(row['elapsedSeconds'], 0)
                self.assertEqual(row['stdoutBytes'], len(result.stdout))
                self.assertEqual(row['codes'], ['BROKER_LIVE_CREATED_STATE_DRIFT'] if rejected else [])
                self.assertNotIn('PRIVATE', json.dumps(rows))

    def test_driver_diagnostics_preserve_failure_and_timeout_protocol(self):
        source = '''
import subprocess,sys
def main():
    driver,mode=sys.argv[-2:]
    try:
        return subprocess.run([sys.executable,'-I','-B',driver,'--mode',mode],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=.1 if mode=='timeout' else 20).returncode
    except subprocess.TimeoutExpired:
        print('TIMEOUT_REDACTED')
        return 7
if __name__=='__main__': raise SystemExit(main())
'''
        driver_source = '''
import sys,time
if sys.argv[-1]=='timeout': time.sleep(10)
print('SEMANTIC_PREEXEC_HOOK=DENIED L2_BINDING_CHANGED',file=sys.stderr)
print('PRIVATE/path/never-report',file=sys.stderr)
raise SystemExit(1)
'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            runtime, diagnostic = root / 'runtime.py', root / 'diagnostic.py'
            driver = root / 'semantic-provider-preexec-hook-v2.py'
            runtime.write_text(source)
            driver.write_text(driver_source)
            for mode in ('start', 'rollback', 'timeout'):
                traces = root / mode
                traces.mkdir()
                diagnostic.write_text(diagnostic_source(runtime, 'fixture.json', traces))
                args = [str(driver), mode]
                canonical = subprocess.run([sys.executable, '-I', '-B', str(runtime), *args], capture_output=True)
                wrapped = subprocess.run([sys.executable, '-I', '-B', str(diagnostic), *args], capture_output=True)
                self.assertEqual((wrapped.returncode, wrapped.stdout, wrapped.stderr),
                                 (canonical.returncode, canonical.stdout, canonical.stderr))
                rows = [json.loads(line) for p in traces.glob('command-*.jsonl')
                        for line in p.read_text().splitlines()]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['mode'], mode)
                self.assertIsNone(rows[0]['epoch'])
                self.assertEqual(rows[0]['codes'], [] if mode == 'timeout' else ['L2_BINDING_CHANGED'])
                self.assertEqual(rows[0]['exception'], 'TimeoutExpired' if mode == 'timeout' else None)
                self.assertEqual(rows[0]['returncode'], None if mode == 'timeout' else 1)
                self.assertNotIn('PRIVATE', json.dumps(rows))

    def admission_timeline(self, holder_seconds):
        """Real scheduler, virtual clock/POSIX IO; owner completion is an event.

        The holder's work can legally take e.g. prepare=17s, hook=2s,
        start/readback=2s. None exceeds its own subprocess deadline, but the
        waiter gets only 20s for the WHOLE protected section. No Docker/root.
        """
        runtime = C.contract_module((ROOT / C.RUNTIME).read_bytes(), 'cohort_schedule')
        now, owner, descriptors = [0.0], [None], iter((1, 2))
        closed = []
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0, st_dev=1, st_ino=2)
        class Registry:
            def __truediv__(self, name): return '/registry/' + name
            def lstat(self): return info
        registry = Registry()
        def flock(fd, flags):
            if owner[0] is not None:
                raise BlockingIOError()
            owner[0] = fd
        def close(fd):
            closed.append(fd)
            if owner[0] == fd:
                owner[0] = None
        holder = None
        def sleep(seconds):
            now[0] += seconds
            if holder is not None and owner[0] == 1 and now[0] >= holder_seconds:
                holder.__exit__(None, None, None)
        io = SimpleNamespace(O_RDONLY=0, O_DIRECTORY=0, O_NOFOLLOW=0,
                             open=lambda *_: next(descriptors), fstat=lambda _: info, close=close)
        with patch.object(runtime, 'ancestors'), patch.object(runtime, 'os', io), \
                patch.object(runtime, 'fcntl', SimpleNamespace(flock=flock, LOCK_EX=1, LOCK_NB=2)), \
                patch.object(runtime, 'time', SimpleNamespace(monotonic=lambda: now[0], sleep=sleep)):
            holder = runtime.admission_schedule(registry)
            holder.__enter__()
            entered, failure = False, None
            try:
                with runtime.admission_schedule(registry):
                    entered = True
            except runtime.Denied as error:
                if str(error) != 'ADMISSION_SCHEDULE_TIMEOUT':
                    raise
                failure = str(error)
            finally:
                if owner[0] == 1:
                    holder.__exit__(None, None, None)
        self.assertCountEqual(closed, [1, 2])
        return dict(waiterEntered=entered, failure=failure, elapsed=now[0])

    def test_admission_schedule_waits_for_a_holder_inside_its_deadline(self):
        outcome = self.admission_timeline(19)
        self.assertTrue(outcome['waiterEntered'])
        self.assertIsNone(outcome['failure'])
        self.assertLess(outcome['elapsed'], 20)

    @unittest.expectedFailure
    def test_admission_schedule_admits_both_roles_when_legal_phases_total_21_seconds(self):
        # Desired liveness property; v5.2 currently times out the waiting role.
        # Keep this failure visible instead of extending deadlines in the fixture.
        outcome = self.admission_timeline(21)
        self.assertTrue(outcome['waiterEntered'], outcome)

    def test_timed_out_peer_cleanup_invalidates_prepared_driver_l2_reauthorization(self):
        # Model Docker cleanup after the sibling's scheduler denial. The real
        # driver's L2 reauthorization must fail closed; this proves the cascade
        # is reachable, not that the retained logs expose its private cause.
        self.assertEqual(self.admission_timeline(21)['failure'], 'ADMISSION_SCHEDULE_TIMEOUT')
        from test_semantic_provider_admission_v2 import libraries
        from tools.semantic_provider_admission_v2 import driver_v7 as driver
        cid, peer = 'a' * 64, 'b' * 64
        nic = dict(interface=L.live_interface(0), mac=L.L2_LIVE_MAC, ipv4='10.10.0.2',
                   bridge='br_test', workloadRef='provider', bindingRef='provider_nic')
        peer_nic = {**nic, 'ipv4': '10.10.0.3', 'bindingRef': 'peer_nic'}
        signed = dict(networkBindings=[nic], transport=[dict(peerIngress=dict(kind='CREATED_CANDIDATE',
            bindingRef='peer_nic', declaration=dict(containerId=peer, applicationHash='c' * 64,
                                                   networkBindings=[peer_nic])))])
        states = {cid: dict(id=cid, status='created', pid=42), peer: dict(id=peer, status='created', pid=43)}
        def generation(pid): return dict(pid=pid, startTicks=123, namespaceInode=456 + pid)
        def observed(member, gen, *args, network_bindings, **kwargs):
            return dict(containerId=member, generation=gen, bindings=[{**network_bindings[0],
                'interface': 'eth0', 'mac': '62:a3:21:47:8b:96', 'childIfindex': 12, 'hostIfindex': 13,
                'hostInterface': 'veth_test'}])
        rows = {member: observed(member, generation(state['pid']), network_bindings=[nic if member == cid else peer_nic])
                for member, state in states.items()}
        value = dict(l2Binding=dict(signedTransport=signed, commandBindings={}), consumptionJournal='/epoch/deployment.json',
            runtimeBinding=dict(path='/runc', sha256='d' * 64, root='/runtime'),
            profile=dict(containerId=cid, policy=dict(attachments=rows[cid]['bindings'])))
        raw = A.canonical(dict(schema=L.SCHEMA, containers=rows))
        run = lambda binding, args, limit: A.canonical(states[args[-1]])
        with libraries():
            from tools.semantic_provider_preexec_native import NativeBackend
            with patch.object(NativeBackend, 'generation', side_effect=lambda self, pid: generation(pid)), \
                    patch.object(L, 'observe', side_effect=observed), patch.object(B, 'private', return_value=raw):
                digest = A.sha(A.canonical(signed))
                self.assertEqual(driver.verify_l2(value, digest, SimpleNamespace(), run), L.effective(signed, rows, container_id=cid))
                states[peer] = dict(id=peer, status='stopped', pid=0)
                with self.assertRaisesRegex(A.OperationDenied, '^L2_BINDING_CHANGED$'):
                    driver.verify_l2(value, digest, SimpleNamespace(), run)

    def test_quiescer_requires_bound_configuration_and_existing_quiescence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            script, config, journal = [root / name for name in ('quiesce.py', 'config.json', 'lease.json')]
            script.write_text(QUIESCE)
            raw = A.canonical({'coordinator': {'journalPath': str(journal)}})
            config.write_bytes(raw)
            args = [sys.executable, '-I', '-B', str(script), '--configuration', str(config),
                    '--configuration-sha256', A.sha(raw), '--quiesce-only']
            journal.write_bytes(A.canonical(dict(state='QUIESCED', leaseAuthorized=False, startAuthorized=False)))
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
            journal.write_bytes(A.canonical(dict(state='QUIESCED', leaseAuthorized=False, startAuthorized=True)))
            retained = journal.read_bytes()
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 1)
            self.assertEqual(journal.read_bytes(), retained)
            config.write_bytes(raw + b'\n')
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 1)


class CohortFixture(F.NativeTests):
    __unittest_skip__ = False

    def setUp(self):
        F.fixtures.SOURCE_CACHE = {p: (ROOT / p).read_bytes() for p in C.SOURCE_INPUTS}
        super().setUp()
        self.assertTrue(str(self.root).startswith("/var/lib/"))
        self.python = Path(sys.executable).resolve()
        self.wrapper = self.root / "admitted-runtime"
        self.runtime_wrapper = self.root / "diagnostic-runtime"
        self.trace_root = self.root / "runtime-tracebacks"
        self.trace_root.mkdir(mode=0o700)
        self.real_ip = Path(shutil.which("ip")).resolve()
        self.real_runc = Path(shutil.which("runc")).resolve()
        self.real_nft = Path(shutil.which("nft")).resolve()
        self.docker_binary = Path(shutil.which("docker")).resolve()
        self.socket = "unix://" + str(self.root / "docker.sock")
        self.script(self.runtime_wrapper,
            f'CAPTURE_IP={str(self.real_ip)!r}\nCAPTURE_NSENTER={str(Path(shutil.which("nsenter")).resolve())!r}\n' +
            CAPTURE.replace("RUNC", repr(str(self.real_runc))).replace("BASE", repr(str(self.root))))
        log = (self.root / "dockerd.log").open("wb")
        self.addCleanup(log.close)
        # Do not inherit /etc/docker/daemon.json or a runner containerd address.
        daemon_config = self.root / "dockerd.json"
        self.write(daemon_config, b"{}")
        daemon = subprocess.Popen([shutil.which("dockerd"), "--config-file=" + str(daemon_config), "--host=" + self.socket,
            "--data-root=" + str(self.root / "docker-data"), "--exec-root=" + str(self.root / "docker-exec"),
            "--pidfile=" + str(self.root / "dockerd.pid"), "--storage-driver=vfs", "--bridge=none",
            "--iptables=false", "--ip6tables=false", "--ip-forward=false", "--ip-masq=false",
            "--add-runtime=ouf-semantic-admitted-v2=" + str(self.runtime_wrapper)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        def stop_daemon():
            daemon.terminate()
            try:
                daemon.wait(timeout=30)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=5)
        self.addCleanup(stop_daemon)
        end = time.monotonic() + 45
        while True:
            probe = self.engine("info", check=False)
            if probe.returncode == 0:
                break
            self.assertIsNone(daemon.poll(), (self.root / "dockerd.log").read_text())
            self.assertLess(time.monotonic(), end, "isolated dockerd readiness timeout")
            time.sleep(.1)
        print("COHORT_DOCKER_VERSION=" + self.engine("version", "--format", "{{json .}}").stdout.decode(), flush=True)
        self.assertEqual(os.readlink("/proc/1/ns/net"), os.readlink("/proc/self/ns/net"))
        self.import_image()
        self.ids = {}
        self.networks = []
        for n in (1, 2):
            name = "cohort" + str(n)
            self.engine("network", "create", "--driver", "bridge", "--internal", "--subnet", f"172.30.{90+n}.0/24",
                        "--opt", "com.docker.network.bridge.name=oufcohort" + str(n), name)
            self.networks.append(name)
        self.print_network_views()
        host_links = json.loads(subprocess.run([str(self.real_ip), "-j", "link", "show"],
                                               capture_output=True, check=True).stdout)
        self.assertTrue({"oufcohort1", "oufcohort2"} <= {n["ifname"] for n in host_links},
                        "Docker bridges must be in the fixture/broker host netns")
        self.frame_sources = {}
        for index, role in enumerate(O.ROLES, 2):
            source = self.root / (role + '-source.json')
            self.write(source, A.canonical(dict(role=role, fixture=True)))
            source.chmod(0o644)
            self.assertEqual((source.stat().st_uid, source.stat().st_gid, source.stat().st_nlink), (0, 0, 1))
            self.frame_sources[role] = source
            tmpfs = ['--tmpfs', TMPFS_TARGET + ':' + TMPFS_OPTIONS] if role == 'southbound' else []
            cid = self.engine("create", "--runtime", "ouf-semantic-admitted-v2", "--read-only", "--restart=no",
                '--user', '636:636', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--memory', '256m', '--memory-swap', '256m', '--pids-limit', '128',
                '--hostname', 'cohort-' + role, '--env', 'PATH=' + FIXTURE_PATH,
                '--mount', 'type=bind,src=' + str(source) + ',dst=' + FRAME_TARGET + ',readonly', *tmpfs,
                "--network", self.networks[0], "--ip", f"172.30.91.{index}", "--entrypoint", "/sleep",
                "cohort-local:fixture", "300").stdout.decode().strip()
            self.assertRegex(cid, r"^[0-9a-f]{64}$")
            self.ids[role] = cid
            self.engine("network", "connect", "--ip", f"172.30.92.{index}", self.networks[1], cid)
            self.addCleanup(lambda cid=cid: self.engine("rm", "--force", cid, check=False))
            frame = json.loads(self.engine("inspect", cid).stdout)[0]
            self.assertEqual(frame["HostConfig"]["Runtime"], "ouf-semantic-admitted-v2")
            endpoints = frame["NetworkSettings"]["Networks"]
            self.assertEqual(set(endpoints), set(self.networks))
            for n, name in enumerate(self.networks, 91):
                self.assertEqual(endpoints[name]["IPAMConfig"]["IPv4Address"], f"172.30.{n}.{index}")
                self.assertFalse(endpoints[name].get("DriverOpts"))
            # Capture independent full OCI expectations before signing. This
            # runtime intentionally denies create, so no epoch/application runs.
            started = self.engine("start", cid, check=False)
            self.assertNotEqual(started.returncode, 0)
            captured = (self.root / ("capture-" + cid + ".json")).exists()
            if not captured:
                log = self.root / "dockerd.log"
                tail = log.read_text(errors="replace").splitlines()[-40:] if log.exists() else []
                print("COHORT_CAPTURE_START_STDERR=" + started.stderr.decode("utf-8", "replace").strip(), flush=True)
                print("COHORT_CAPTURE_DOCKERD_TAIL=" + json.dumps(tail), flush=True)
            self.assertTrue(captured)
        self.publish_runtime()

    def script(self, path, body):
        self.write(Path(path), ("#!" + str(self.python) + "\n" + body).encode())
        Path(path).chmod(0o755)
        return {"path": str(path), "sha256": A.sha(Path(path).read_bytes())}

    def engine(self, *args, check=True):
        result = subprocess.run([str(self.docker_binary), "--host", self.socket, *args],
                                capture_output=True, timeout=90)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result

    def import_image(self):
        sleep = Path(shutil.which("sleep")).resolve()
        linked = subprocess.run(["ldd", str(sleep)], capture_output=True, check=True).stdout.decode()
        dependencies = set(re.findall(r"(/[A-Za-z0-9_./+-]+)", linked))
        archive = self.root / "rootfs.tar"
        with tarfile.open(archive, "w") as tar:
            tar.add(sleep, arcname="sleep")
            # Pre-existing mountpoints keep runc create from altering the
            # independently sealed rootfs. No seal is re-baselined after create.
            for directory in ('run', TMPFS_TARGET.lstrip('/')):
                info = tarfile.TarInfo(directory)
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            info = tarfile.TarInfo(FRAME_TARGET.lstrip('/'))
            info.size, info.mode = 0, 0o644
            tar.addfile(info, io.BytesIO(b''))
            for path in sorted(dependencies):
                # Dereference host symlinks so no link escapes the image.
                raw = Path(path).read_bytes()
                info = tarfile.TarInfo(path.lstrip("/"))
                info.size, info.mode = len(raw), 0o755
                tar.addfile(info, io.BytesIO(raw))
        self.engine("import", str(archive), "cohort-local:fixture")

    def publish_runtime(self):
        # Use the real composed closure as a skeleton. Fixture-only bindings
        # below describe the independently captured Docker candidates; they are
        # signed afterwards with the existing native authority fixture keys.
        inputs = copy.deepcopy(self.inputs)
        inputs['sources'].pop(C.OBSERVER)
        inputs['sources'][C.OBSERVER_V2] = FRAME_PATH.read_bytes()
        result = C.compose(inputs, 6, sequence=6, supersedes="a" * 64)
        self.code = self.install / "versions/6"
        docs = copy.deepcopy(result["documents"])
        original = json.loads(result["authorization"])
        old_ids = {r: original["roles"][r]["containerId"] for r in O.ROLES}
        def substitute(value):
            if type(value) is str:
                for r in O.ROLES:
                    value = value.replace(old_ids[r], self.ids[r])
                return value
            if type(value) is dict:
                return {substitute(k): substitute(v) for k, v in value.items()}
            if type(value) is list:
                return [substitute(v) for v in value]
            return value
        for name, raw in list(docs.items()):
            if "/source/" not in name:
                docs[name] = A.canonical(substitute(json.loads(raw)))
        for directory in sorted(result["layout"]["directories0700"], key=lambda p: (p.count("/"), p)):
            directory = substitute(directory)
            (self.install / directory).mkdir(parents=True, mode=0o700, exist_ok=True)
        for name, raw in docs.items():
            path = self.install / substitute(name)
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            self.write(path, raw)
        initialize_registry(self.install / "registry", self.ids.values())
        def document(relative, value):
            path = self.code / relative
            self.write(path, A.canonical(value))
            return {"path": str(path), "sha256": A.sha(path.read_bytes())}
        self.script(self.root / "systemctl", SYSTEMCTL)
        quiescer = self.root / "quiesce.py"
        self.write(quiescer, QUIESCE.encode())
        qbinding = {"path": str(quiescer), "sha256": A.sha(quiescer.read_bytes())}
        runtime = json.loads((self.code / "runtime-configuration.json").read_bytes())
        captures = {r: json.loads((self.root / ("capture-" + cid + ".json")).read_bytes()) for r, cid in self.ids.items()}
        for role, capture in captures.items():
            print("COHORT_CAPTURE_LINKS=" + json.dumps(dict(role=role, runtimeNetns=capture["runtimeNetns"],
                                                          links=capture["childLinks"]), sort_keys=True), flush=True)
        real = {"path": str(self.real_runc), "sha256": A.sha(self.real_runc.read_bytes())}
        python = {"path": str(self.python), "sha256": A.sha(self.python.read_bytes())}
        # Install an empty, quiescent lease footprint inside this test's netns.
        # No resolver is queried and no lease is activated.
        kernel = dict(tableName="ouf_cohort_lease", guardedInterfaces=["oufcohort2"], existingInterfaces=[], staticFlows=[],
            providerFlows=[dict(endpointRef="fixture", endpoint="https://provider.example", source="172.30.92.2",
                addresses=[], leaseSeconds=60, resolutionEvidenceRef="fixture_dns", allowedPrivateAddresses=[])])
        with F.fixtures.grant_fixture.part_a.libraries():
            from tools.materialize_southbound_kernel import materialize
            from tools.semantic_provider_lease_nft import structure_hash
            rules = materialize(kernel, empty_provider_sets=True)["nftRules"]
            subprocess.run([str(self.real_nft), "-f", "-"], input=rules.encode(), capture_output=True, check=True)
            tables = {f: json.loads(subprocess.run([str(self.real_nft), "-j", "list", "table", f, kernel["tableName"]],
                capture_output=True, check=True).stdout) for f in ("inet", "bridge")}
            coordination = dict(transactionId="c" * 64, configurationHash=A.sha(A.canonical(kernel)),
                                leaseStructureHash=structure_hash(tables))
        lease_journal = {"schema": "ouf.semantic-lease-coordination.v1", **coordination,
            "state": "QUIESCED", "leaseAuthorized": False, "startAuthorized": False, "leaseAddresses": [[]]}
        self.write(self.root / "lease.json", A.canonical(lease_journal))
        frame_path = self.code / 'source' / C.OBSERVER_V2
        self.assertEqual(frame_path.read_bytes(), FRAME_PATH.read_bytes())
        frame_binding = {"path": str(frame_path), "sha256": A.sha(frame_path.read_bytes())}
        self.assertEqual(len({v["root"] for v in captures.values()}), 1)
        runtime.update(runtimePath=real["path"], runtimeSha256=real["sha256"],
                       pythonPath=python["path"], pythonSha256=python["sha256"],
                       runtimeStateRoot=str(Path(captures["adapter"]["root"]).parent))
        all_nics = {}
        for index, role in enumerate(O.ROLES, 2):
            # Choose the adapter's signed order opposite to independently
            # captured Docker names, before signing. Docker's allocation order
            # can differ even between two containers in the same test.
            captured = {n["ifname"]: n for n in captures[role]["childLinks"] if n["ifname"] != "lo"}
            if set(captured) == {"eth0", "eth1"}:
                first_ip = next(a["local"] for a in captured["eth1"]["addr_info"] if a["family"] == "inet")
                first = int(first_ip.split(".")[2]) - 90
                self.assertIn(first, (1, 2))
                self.names_known = True
            else:
                # NICs not yet attached at create: still sign an order opposite to the network list.
                self.assertEqual(captured, {})
                first = 2
                self.names_known = getattr(self, "names_known", False)
            order = (first, 3-first) if role == "adapter" else (1, 2)
            all_nics[role] = [dict(interface=L.live_interface(position), ipv4=f"172.30.{90+n}.{index}",
                mac=L.L2_LIVE_MAC, bridge="oufcohort" + str(n),
                bindingRef=role + "_" + str(n), workloadRef=role) for position, n in enumerate(order)]
        for role in O.ROLES:
            cid = self.ids[role]
            other = next(r for r in O.ROLES if r != role)
            cfg = json.loads((self.code / "broker" / (role + ".json")).read_bytes())
            template = json.loads(Path(cfg["preparerTemplate"]["path"]).read_bytes())
            template.update(pythonPath=python["path"], pythonHash=python["sha256"])
            template.update(kernel=kernel, coordinationBinding=coordination, coordinationJournal=str(self.root / "lease.json"),
                hostNetworkNamespace=os.stat("/proc/self/ns/net").st_ino,
                dns=dict(resolvers=["172.30.92.1"], resolverPort=53, timeoutSeconds=1, maxLeaseSeconds=60, applyBudgetSeconds=1))
            cfg["creationFrameObserverBinding"]["python"] = python
            cfg["creationFrameObserverBinding"]["source"] = frame_binding
            own = next(n for n in all_nics[role] if n["bridge"] == "oufcohort1")
            peer = next(n for n in all_nics[other] if n["bridge"] == "oufcohort1")
            flow = dict(purpose="GATEWAY_ADAPTER", authorityRef="provider", protocol="tcp", port=9443,
                source=own["ipv4"], destination=peer["ipv4"], peerIngress={
                    "kind": "CREATED_CANDIDATE", "bindingRef": peer["bindingRef"], "declaration": {
                        "containerId": self.ids[other], "applicationHash": A.sha(A.canonical(captures[other]["oci"])),
                        "networkBindings": all_nics[other]}})
            template["candidate"].update(networkBindings=all_nics[role], transport=[flow], runtimeBinding=real)
            for name in ("ip", "nsenter", "nft", "mount", "umount", "unshare"):
                # Run the source-bound native binary directly. The old Python
                # proxy added /proc walks, a second ip and JSON IO to EVERY
                # observation inside the broker/driver's 18s/5s deadlines.
                path = Path(shutil.which(name)).resolve()
                template["commands"][name], template["commandHashes"][name] = str(path), A.sha(path.read_bytes())
            lock = self.root / "common.lock"
            self.write(lock, b"")
            template["lockFile"] = str(lock)
            cfg.update(preparerTemplate=document("documents/" + role + "/preparer-template.json", template),
                runtimeRootParent=runtime["runtimeStateRoot"])
            policy = frame_policy(captures[role]['oci'], role, self.frame_sources[role])
            from test_frame_observer_v2 import reviewer
            review, schema = reviewer()
            self.assertTrue(review.configured_profile(policy['expectedOci'], policy['expectedOci'], policy['manifest'],
                policy['startup'], policy['approvedHooks'], schema)['configuredPolicyConforms'])
            cfg["framePolicyBinding"] = document("documents/" + role + "/frame-policy.json", policy)
            policy_path = Path(cfg['framePolicyBinding']['path'])
            self.assertEqual((policy_path.parent.stat().st_uid, policy_path.parent.stat().st_gid,
                              policy_path.parent.stat().st_mode & 0o777), (0, 0, 0o700))
            self.assertEqual((policy_path.stat().st_uid, policy_path.stat().st_gid, policy_path.stat().st_nlink,
                              policy_path.stat().st_mode & 0o777), (0, 0, 1, 0o600))
            cfg["creationFrameObserverBinding"]["configuration"] = cfg["framePolicyBinding"]
            with F.fixtures.grant_fixture.part_a.libraries():
                from tools.semantic_provider_node_observation import rootfs_seal
                from tools.semantic_provider_deployment_authentication import VerificationBudget
                seal = rootfs_seal(Path(captures[role]["oci"]["root"]["path"]), cfg["rootfsLimits"], VerificationBudget(18))
            cfg["rootfsSealBinding"] = document("documents/" + role + "/rootfs-seal.json", seal)
            cfg["transportBinding"] = document("documents/" + role + "/transport.json",
                {k: template["candidate"][k] for k in ("networkBindings", "transport", "tableName")})
            bound = document("broker/" + role + ".json", cfg)
            B.validate(A.canonical(cfg))
            runtime["admissionConfigurations"][cid] = bound
            runtime["candidates"][cid]["bundleParents"] = [str(Path(captures[role]["bundle"]).parent)]
            original["roles"][role].update(containerId=cid, admissionConfigurationSha256=bound["sha256"],
                framePolicySha256=cfg["framePolicyBinding"]["sha256"], transportSha256=cfg["transportBinding"]["sha256"],
                rootfsSealSha256=cfg["rootfsSealBinding"]["sha256"])
        sup = {"registryRoot": str(self.install / "registry"), "authorizationRoot": str(self.chain),
               "statusPath": str(self.code / "supervisor/status.json"),
               "coordinator": {"journalPath": str(self.root / "lease.json")}}
        supbinding = document("supervisor/configuration.json", sup)
        self.write(Path(sup["statusPath"]), A.canonical(dict(schema="ouf.semantic-provider-lease-supervisor-status.v1",
            state="WAITING", reason="EPOCH_NOT_LIVE", epochs=dict.fromkeys(O.ROLES), activationsLastHour=0,
            authorizationSequence=1)))
        runtime["leaseQuiesce"] = dict(entrypoint=qbinding, configuration=supbinding)
        runtimebinding = document("runtime-configuration.json", runtime)
        original.update(sequence=1, supersedes=None, runtimeConfigurationSha256=runtimebinding["sha256"])
        self.chain.mkdir(mode=0o700, exist_ok=True)
        self.put(1, A.canonical(original))
        self.verify_pre_epoch(runtime, captures)
        # Operate checks the exact canonical wrapper; only this private daemon
        # executes the diagnostic wrapper, with the same isolated main/argv.
        self.write(self.wrapper, O.I.wrapper_bytes(str(self.python), self.code))
        self.wrapper.chmod(0o755)
        diagnostic = self.root / "runtime-diagnostic.py"
        self.write(diagnostic, diagnostic_source(self.code / "source" / C.RUNTIME,
                   self.code / "runtime-configuration.json", self.trace_root, deny_first_epoch=True).encode())
        self.write(self.runtime_wrapper, (f'#!/bin/sh\nexec {self.python} -I -B {diagnostic} "$@"\n').encode())
        self.runtime_wrapper.chmod(0o755)

    def verify_pre_epoch(self, expected, captures):
        path = self.code / "source" / C.RUNTIME
        runtime = O.I.compiled(path.read_bytes(), path, "cohort_pre_epoch_runtime", expected["sourceHash"])
        cfg, raw = runtime.load_configuration(self.code / "runtime-configuration.json")
        self.assertEqual(cfg, expected)
        runtime.verify_files(cfg)
        auth, epochs = runtime.operation_modules(cfg)
        epochs.boot_id()
        for role, cid in self.ids.items():
            operation, captured_cid, options = runtime.arguments(captures[role]["argv"])
            self.assertEqual((operation, captured_cid), ("create", cid))
            root, parent = Path(options["--root"]).resolve(), Path(cfg["runtimeStateRoot"])
            self.assertTrue(root.is_relative_to(parent) and root != parent)
            self.assertEqual(root, Path(captures[role]["root"]))
            base = Path(cfg["registryRoot"]) / cid
            runtime.private_directory(base)
            self.assertEqual(runtime.read(base / "operation.lock"), b"")
            self.assertIsNone(epochs.current(cfg["registryRoot"], cid))
            self.assertEqual(runtime.epoch_inventory(base, epochs, None), [])
            self.assertEqual(runtime.authorization_head(cfg, raw, cid, auth), self.head())
        runtime.quiesce(cfg)

    def print_tracebacks(self):
        paths = sorted(self.trace_root.glob("runtime-*.log"))
        if not paths:
            print("COHORT_RUNTIME_TRACEBACK=[]", flush=True)
        for path in paths:
            print("COHORT_RUNTIME_TRACEBACK=" + json.dumps(
                {"file": path.name, "traceback": path.read_text(encoding="utf-8", errors="replace")}), flush=True)
        for path in sorted(self.trace_root.glob("command-*.jsonl")):
            for line in path.read_text(encoding="utf-8").splitlines():
                print("COHORT_RUNTIME_COMMAND=" + line, flush=True)

    def print_network_views(self):
        for detailed in (False, True):
            args = [str(self.real_ip), "-j", *(["-d"] if detailed else []), "link", "show"]
            links = json.loads(subprocess.run(args, capture_output=True, check=True).stdout)
            print("COHORT_FIXTURE_HOST_LINKS=" + json.dumps(dict(detailed=detailed,
                netns=os.readlink("/proc/self/ns/net"), links=links), sort_keys=True), flush=True)
        processes = []
        for proc in Path("/proc").iterdir():
            if not proc.name.isdecimal():
                continue
            try:
                comm = (proc / "comm").read_text().strip()
                if comm.startswith(("dockerd", "containerd", "runc")):
                    processes.append(dict(pid=int(proc.name), comm=comm, netns=os.readlink(proc / "ns/net")))
            except (FileNotFoundError, ProcessLookupError):
                pass
        print("COHORT_PROCESS_NETNS=" + json.dumps(processes, sort_keys=True), flush=True)

    def scenario(self):
        def argv(mode="--plan", digest=None):
            result = [mode, "--action", "start", "--install-root", str(self.install), "--wrapper", str(self.wrapper),
                "--wrapper-sha256", A.sha(self.wrapper.read_bytes()), "--docker", str(self.docker_binary),
                "--docker-sha256", A.sha(self.docker_binary.read_bytes()), "--docker-socket", self.socket,
                "--timeout-seconds", "45", "--output-directory", str(self.root / ("operate-result-" + str(attempt)))]
            for name, path in (("systemctl", self.root / "systemctl"), ("nft", self.real_nft)):
                result.extend(["--" + name, str(path), "--" + name + "-sha256", A.sha(path.read_bytes())])
            return result + (["--plan-sha256", digest] if digest else [])
        def operate(args):
            try:
                p = subprocess.run([str(self.python), "-I", "-B", str(ROOT / "scripts/operate-semantic-provider-r3.py"), *args],
                                   capture_output=True, timeout=150)
            finally:
                self.print_tracebacks()
                self.print_network_views()
                for role, cid in self.ids.items():
                    state = self.engine("inspect", "-f", "{{json .State}}", cid, check=False)
                    print("COHORT_DOCKER_STATE_" + role.upper() + "=" + state.stdout.decode("utf-8", "replace").strip(), flush=True)
                    for log in (self.root / "docker-exec").rglob(cid + "/log.json"):
                        print("COHORT_SHIM_LOG_" + role.upper() + "=" + log.read_text(errors="replace")[-1500:], flush=True)
            self.assertEqual(p.stderr, b"")
            return p.returncode, json.loads(p.stdout)
        attempt = 1
        code, plan = operate(argv())
        self.assertEqual(code, 0, plan)
        code, result = operate(argv("--apply", plan["planSha256"]))
        print("COHORT_START_ATTEMPT_1=" + json.dumps(dict(exitCode=code, result=result), sort_keys=True), flush=True)
        self.assertEqual(code, 1, result)
        old_generations, first_denials = {}, {}
        for role, cid in self.ids.items():
            folder = self.install / "registry" / cid / "epochs/1"
            row = json.loads((folder / "adapter.json").read_bytes())
            self.assertEqual(row["state"], "FAILED", row)
            self.assertIsNone(row["driverHash"], row)
            self.assertEqual(row["failure"], "TWO_PHASE_BROKER_DENIED", row)
            self.assertFalse((folder / "driver.json").exists())
            consumed = json.loads((folder / "deployment.json").read_bytes())
            self.assertEqual(consumed["state"], "CREATED", consumed)
            old_generations[cid] = consumed["generation"]
            denial = folder / "broker-denial-cohort-ready.json"
            first_denials[cid] = B.validate_denial(denial.read_bytes(), cid, 1, "cohort-ready")
            self.assertEqual(first_denials[cid]["reason"], "BROKER_LIVE_CREATED_STATE_DRIFT")
            self.assertEqual(denial.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result["lastObservation"]["candidates"][role]["denials"], [first_denials[cid]])
        # Docker owns stale containerd task cleanup. Do not issue an out-of-band
        # runc delete, kill a PID or reset any journal between the two starts.
        attempt = 2
        code, plan = operate(argv())
        self.assertEqual(code, 0, plan)
        code, result = operate(argv("--apply", plan["planSha256"]))
        print("COHORT_START_ATTEMPT_2=" + json.dumps(dict(exitCode=code, result=result), sort_keys=True), flush=True)
        # Print both diagnostics before asserting, even if one side is missing.
        for role, cid in self.ids.items():
            folder = self.install / "registry" / cid / "epochs/2"
            path = folder / "broker-denial-cohort-ready.json"
            print("COHORT_BROKER_DENIAL_" + role.upper() + "=" +
                  (path.read_text() if path.exists() else "MISSING"), flush=True)
            binding = folder / "l2-binding.json"
            print("COHORT_L2_BINDING_" + role.upper() + "=" +
                  (binding.read_text() if binding.exists() else "MISSING"), flush=True)
            state = self.engine("inspect", "-f", "{{json .State}}", cid, check=False)
            print("COHORT_DOCKER_STATE_" + role.upper() + "=" + state.stdout.decode("utf-8", "replace").strip()
                  + state.stderr.decode("utf-8", "replace").strip(), flush=True)
        summary = {k: result.get(k) for k in ("status", "reason", "requestErrors", "observationError")}
        summary["candidates"] = {r: {k: v.get(k) for k in ("epoch", "previousEpoch", "denials")}
                                 for r, v in (result.get("lastObservation") or {}).get("candidates", {}).items()}
        print("COHORT_OPERATE_RESULT=" + json.dumps(summary, sort_keys=True), flush=True)
        log = self.root / "dockerd.log"
        if log.exists():
            lines = [l for l in log.read_text(errors="replace").splitlines() if "level=error" in l or "BLOCKED" in l]
            print("COHORT_DOCKERD_ERRORS=" + json.dumps(lines[-20:]), flush=True)
        self.assertEqual(code, 1, result)
        self.assertEqual(result["status"], "HELD")
        self.assertEqual(result["reason"], "R3_READBACK_TIMEOUT")
        self.assertEqual(result["requestErrors"], [])
        observation = result["lastObservation"]
        self.assertEqual(observation["lease"], {"state": "QUIESCED", "leaseAuthorized": False})
        reversed_names = set()
        for role, cid in self.ids.items():
            row = observation["candidates"][role]
            folder = self.install / "registry" / cid / "epochs/2"
            self.assertEqual(row["epoch"]["epoch"], 2, row)
            old_folder = self.install / "registry" / cid / "epochs/1"
            old_row = json.loads((old_folder / "adapter.json").read_bytes())
            self.assertEqual(old_row["state"], "FAILED")
            receipt = json.loads((old_folder / "runtime-cleanup.json").read_bytes())
            self.assertEqual(receipt["schema"], "ouf.semantic-docker-runtime-cleanup.v1")
            self.assertEqual((receipt["epoch"], receipt["operation"]), (1, "delete"))
            self.assertEqual((old_folder / "runtime-cleanup.json").stat().st_mode & 0o777, 0o600)
            previous = old_generations[cid]
            old_stat = Path('/proc') / str(previous['pid']) / 'stat'
            if old_stat.exists():
                self.assertNotEqual(int(old_stat.read_text().rsplit(')', 1)[1].split()[19]), previous['startTicks'],
                                    'epoch 1 runc init survived the second start')
            self.assertFalse((folder / "broker-denial-cohort-ready.json").exists(), row["denials"])
            self.assertEqual(row["denials"], [first_denials[cid]])
            binding_path = folder / "l2-binding.json"
            self.assertEqual(binding_path.stat().st_mode & 0o777, 0o600)
            binding = json.loads(binding_path.read_bytes())
            self.assertEqual(binding["schema"], L.SCHEMA)
            self.assertEqual(set(binding["containers"]), set(self.ids.values()))
            for member, bound in binding["containers"].items():
                frame = json.loads(self.engine("inspect", member).stdout)[0]
                expected = {n["IPAddress"]: n["MacAddress"] for n in frame["NetworkSettings"]["Networks"].values()}
                self.assertEqual({n["ipv4"]: n["mac"] for n in bound["bindings"]}, expected)
                self.assertEqual(bound["generation"]["pid"], frame["State"]["Pid"])
                proc = Path("/proc") / str(frame["State"]["Pid"])
                self.assertEqual(bound["generation"]["namespaceInode"], (proc / "ns/net").stat().st_ino)
                self.assertEqual(bound["generation"]["startTicks"], int((proc / "stat").read_text().rsplit(")", 1)[1].split()[19]))
                self.assertNotIn(L.L2_LIVE_MAC, expected.values())
                self.assertEqual({n["interface"] for n in bound["bindings"]}, {"eth0", "eth1"})
                if bound["bindings"][0]["interface"] == "eth1":
                    reversed_names.add(member)
            for denial in row["denials"]:
                self.assertNotIn(denial.get("reason"), {"PEER_MAC_IP_DRIFT", "APPROVED_MAC_IP_BINDING_DRIFT",
                                                      "NAMESPACE_PORT_BINDING_DRIFT"})
            self.assertEqual(row["epoch"]["state"], "STARTED", row)
            self.assertTrue(row["docker"]["Running"])
            self.assertEqual(json.loads((folder / "deployment.json").read_bytes())["state"], "STARTED")
            evidence = json.loads((folder / 'evidence.json').read_bytes())
            self.assertRegex(evidence['creationFrameHash'], r'^[0-9a-f]{64}$')
            cfg = json.loads((self.code / 'broker' / (role + '.json')).read_bytes())
            self.assertEqual(Path(cfg['creationFrameObserverBinding']['source']['path']).read_bytes(), FRAME_PATH.read_bytes())
            self.assertEqual(evidence['rootfsSeal'], json.loads(Path(cfg['rootfsSealBinding']['path']).read_bytes()))
            grant = json.loads((folder / "driver.json").read_bytes())
            self.assertEqual(grant["l2Binding"]["signedTransport"]["networkBindings"][0]["mac"], L.L2_LIVE_MAC)
            self.assertEqual([n["interface"] for n in grant["l2Binding"]["signedTransport"]["networkBindings"]],
                             [L.live_interface(i) for i in range(2)])
            self.assertEqual({n["mac"] for n in grant["profile"]["policy"]["attachments"]},
                             {n["mac"] for n in binding["containers"][cid]["bindings"]})
            table = grant["profile"]["policy"]["tableName"]
            nft = subprocess.run([str(self.real_nft), "list", "table", "bridge", table], capture_output=True, check=True).stdout.decode()
            for nic in binding["containers"][cid]["bindings"]:
                self.assertIn(nic["mac"], nft)
        # Check all runc init processes rooted in either candidate's rootfs,
        # not just Docker's current PID. Only a new-epoch generation is allowed.
        generations = [json.loads((self.install / 'registry' / cid / 'epochs/2/adapter.json').read_bytes())['generation']
                       for cid in self.ids.values()]
        allowed = {g['pid']: g['startTicks'] for g in generations}
        roots = {str(Path(json.loads((self.root / ('capture-' + cid + '.json')).read_bytes())['oci']['root']['path']).resolve())
                 for cid in self.ids.values()}
        remaining = []
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                cmdline = (proc / 'cmdline').read_bytes()
                comm = (proc / 'comm').read_text()
                if not ((b'runc' in cmdline and b'init' in cmdline) or ('runc' in comm and 'INIT' in comm)):
                    continue
                if str((proc / 'root').resolve()) not in roots:
                    continue
                ticks = int((proc / 'stat').read_text().rsplit(')', 1)[1].split()[19])
                remaining.append(dict(pid=int(proc.name), startTicks=ticks))
                self.assertEqual(allowed.get(int(proc.name)), ticks, 'stale candidate runc init')
            except (FileNotFoundError, ProcessLookupError):
                continue
        print('COHORT_FINAL_STATE=' + json.dumps(dict(epochs={r: v['epoch'] for r, v in observation['candidates'].items()},
              remainingRuncInit=remaining), sort_keys=True), flush=True)
        print("COHORT_REVERSED_NAMES=" + json.dumps(sorted(reversed_names)), flush=True)
        if getattr(self, "names_known", False):
            self.assertTrue(reversed_names, "fixture must exercise a signed NIC order different from Docker names")


@unittest.skipUnless(NATIVE, "set OUF_R3_COHORT_NATIVE=1 under Linux root:root")
class NativeTests(unittest.TestCase):
    def test_real_docker_random_macs_through_started(self):
        for name in ("docker", "dockerd", "runc", "unshare", "mount", "ip", "nsenter", "nft", "openssl", "ldd", "sleep"):
            self.assertIsNotNone(shutil.which(name), "native prerequisite: " + name)
        result = subprocess.run(native_child_argv(), capture_output=True, timeout=360)
        print(result.stdout.decode("utf-8", "replace"), flush=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([loader.loadTestsFromTestCase(PortableTests), loader.loadTestsFromTestCase(NativeTests)])


if __name__ == "__main__":
    if sys.argv[1:] == ["--native-child"]:
        if not NATIVE:
            raise RuntimeError("disabled native scenario")
        subprocess.run([shutil.which("mount"), "--make-rprivate", "/"], check=True)
        # Like the VPS: host net/PID views and the host's system containerd, so
        # shims, runtime and broker see the same links, processes and bundles.
        suite = unittest.TestSuite([CohortFixture("scenario")])
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    unittest.main()
