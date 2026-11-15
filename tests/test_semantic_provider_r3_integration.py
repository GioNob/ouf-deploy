"""R3 native integration: composed bytes, real issuer/runtime/broker/preparer/v7.

OUF_R3_INTEGRATION_NATIVE=1 requires Linux root. Each scenario reexecutes in
private mount/network namespaces; no Docker, network traffic or host nft writes.
The real frame observer sees a chrooted process with real read-only file binds.
Only runc, NIC command reports, nft and lease quiescence are fixture programs.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_semantic_provider_operation_issuance as issuance
import test_semantic_provider_admission_v2_preparer as admission_fixture

ROOT, A, C = issuance.ROOT, issuance.A, issuance.C
NATIVE = os.environ.get("OUF_R3_INTEGRATION_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_R3_INTEGRATION_NATIVE requires Linux root:root; refusing to skip")


# This transparent interpreter launcher records argv and public child stderr even
# when production deliberately discards stderr. It forwards stdin/stdout, env,
# flags and exit status unchanged; no repository source is instrumented.
PYTHON_TRACE = r'''
import hashlib,json,os,pathlib,subprocess,sys
assert hashlib.sha256(pathlib.Path(PYTHON).read_bytes()).hexdigest()==PYTHON_SHA256
log=pathlib.Path(BASE)/'python.jsonl'
def record(value):
    with log.open('a') as stream: stream.write(json.dumps(value)+'\n')
record({'event':'invoke','pid':os.getpid(),'argv':sys.argv[1:]})
p=subprocess.run([PYTHON,*sys.argv[1:]],stderr=subprocess.PIPE)
record({'event':'exit','pid':os.getpid(),'returncode':p.returncode,
        'stderr':p.stderr.decode('utf-8','replace')[-8192:]})
sys.stderr.buffer.write(p.stderr)
raise SystemExit(p.returncode)
'''

QUIESCE = r'''
import hashlib,json,pathlib,sys
base=pathlib.Path(BASE)
with (base/'quiesce.jsonl').open('a') as stream: stream.write(json.dumps(sys.argv[1:])+'\n')
assert len(sys.argv)==6 and sys.argv[1]=='--configuration' and sys.argv[3]=='--configuration-sha256'
assert sys.argv[5]=='--quiesce-only'
assert hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()==sys.argv[4]
raise SystemExit(1 if (base/'quiesce-fail').exists() else 0)
'''

# Executed under unshare --mount --net by fake runc create. Mounts are private;
# the process retains the real /proc PID/startTicks/network namespace identity.
CONTAINER = r'''
import json,os,pathlib,subprocess,sys,time
bundle,ready,mount=sys.argv[1:]
oci=json.loads((pathlib.Path(bundle)/'config.json').read_bytes())
root=pathlib.Path(oci['root']['path'])
def run(*args): subprocess.run([mount,*map(str,args)],check=True)
run('--make-rprivate','/')
run('--bind',root,root)
for row in oci['mounts']:
    target=root/row['destination'].lstrip('/')
    run('--bind',row['source'],target)
    run('-o','remount,bind,ro',target)
if oci['root'].get('readonly'): run('-o','remount,bind,ro',root)
pathlib.Path(ready).write_text(str(os.getpid()))
os.chroot(root); os.chdir('/')
while True: time.sleep(1)
'''

RUNC = r'''
import json,os,pathlib,signal,subprocess,sys,time
base=pathlib.Path(BASE); args=sys.argv[1:]
with (base/'runc.jsonl').open('a') as stream: stream.write(json.dumps(args)+'\n')
if args==['--version']:
    print('runc version fixture-r3'); raise SystemExit(0)
assert args[0]=='--root'
root=pathlib.Path(args[1]); mode=args[2]; cid=args[-1]
path=root/(cid+'.json')
if mode=='create':
    assert args[3]=='--bundle' and not path.exists()
    bundle=args[4]; ready=root/(cid+'.ready')
    if ready.exists(): ready.unlink()
    with (base/'container-errors.log').open('ab') as errors:
        p=subprocess.Popen([UNSHARE,'--mount','--net',PYTHON,'-I','-B',str(base/'container.py'),
            bundle,str(ready),MOUNT],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=errors,
            start_new_session=True)
    deadline=time.monotonic()+5
    while not ready.exists():
        if p.poll() is not None or time.monotonic()>deadline:
            if p.poll() is None: p.kill()
            p.wait(timeout=3)
            raise RuntimeError('FIXTURE_CREATE_FAILED')
        time.sleep(.01)
    pid=int(ready.read_text())
    # ready is written immediately before chroot; wait for the observed root.
    expected=os.stat(json.loads((pathlib.Path(bundle)/'config.json').read_bytes())['root']['path'])
    while True:
        actual=os.stat('/proc/'+str(pid)+'/root')
        if (actual.st_dev,actual.st_ino)==(expected.st_dev,expected.st_ino): break
        if time.monotonic()>deadline:
            p.kill(); p.wait(timeout=3)
            raise RuntimeError('FIXTURE_CHROOT_TIMEOUT')
        time.sleep(.01)
    path.write_text(json.dumps({'id':cid,'pid':pid,'bundle':bundle,'status':'created'}))
    with (base/'pids.jsonl').open('a') as stream:
        ticks=int(pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19])
        stream.write(json.dumps({'pid':pid,'startTicks':ticks})+'\n')
elif mode=='list':
    print(json.dumps([json.loads(p.read_text()) for p in sorted(root.glob('*.json'))]))
elif not path.exists():
    print('container does not exist',file=sys.stderr); raise SystemExit(1)
elif mode=='state': print(path.read_text())
elif mode=='start':
    row=json.loads(path.read_text()); assert row['status']=='created'
    row['status']='running'; path.write_text(json.dumps(row))
elif mode in ('delete','kill'):
    row=json.loads(path.read_text()); os.kill(row['pid'],signal.SIGKILL)
    deadline=time.monotonic()+3
    while pathlib.Path('/proc/'+str(row['pid'])+'/ns/net').exists():
        if time.monotonic()>deadline: raise RuntimeError('FIXTURE_DELETE_TIMEOUT')
        time.sleep(.01)
    path.unlink()
else: raise SystemExit(2)
'''

IP = r'''
import json,pathlib,sys
base=pathlib.Path(BASE); args=sys.argv[1:]
with (base/'ip.jsonl').open('a') as stream: stream.write(json.dumps(args)+'\n')
if args[:2]==['link','add']: raise SystemExit(0)  # isolated template mirrors
hosts=json.loads((base/'topology.json').read_bytes())['hosts']
assert args[:5]==['-j','link','show','dev',args[-1]]
print(json.dumps([v for v in hosts if v['ifname']==args[-1]]))
'''

NSENTER = r'''
import json,os,pathlib,sys
base=pathlib.Path(BASE); args=sys.argv[1:]
assert args[0].startswith('--net=')
inode=os.stat(args[0].split('=',1)[1]).st_ino
topology=json.loads((base/'topology.json').read_bytes())
states=[json.loads(p.read_bytes()) for p in (base/'runtime/owned').glob('*.json')]
matches=[r for r in states if os.stat('/proc/'+str(r['pid'])+'/ns/net').st_ino==inode]
assert len(matches)==1
children=topology['children'][matches[0]['id']]
if 'dev' in args: children=[r for r in children if r['ifname']==args[-1]]
print(json.dumps(children))
'''


def render(source, **values):
    # Replace whole Python NAME tokens only, never substrings inside literals.
    import io
    import tokenize
    return tokenize.untokenize((token.type, repr(values[token.string])
        if token.type == tokenize.NAME and token.string in values else token.string)
        for token in tokenize.generate_tokens(io.StringIO(source).readline)).encode()


def fixture_recipe(template, launch, context, sources):
    """Synthetic launch: retain hardening, bind metadata and public fixture files.

    Keep the role's original one/two source targets and read-only-root setting.
    The application-specific tmpfs is outside this admission-chain fixture.
    """
    template, launch = copy.deepcopy(template), copy.deepcopy(launch)
    launch['sources'] = copy.deepcopy(sources)
    launch['manifest']['mounts'] = [{k: row[k] for k in ('source', 'target', 'readOnly')} for row in sources]
    launch['manifest'].pop('tmpfs', None)
    by_target = {row['target']: row for row in sources}
    mounts = [v for v in template['expectedOci']['mounts'] if v['type'] == 'bind']
    for row in mounts:
        if row['destination'] in by_target: row['source'] = by_target[row['destination']]['source']
        row['options'] = ['bind', 'ro', 'rprivate']
    template['expectedOci']['mounts'] = mounts
    recipe = {'template': template, 'launch': launch, 'context': context}
    return {**recipe, 'policy': C.compile_policy(**recipe)}


class PortableTests(unittest.TestCase):
    def test_fixture_programs_compile(self):
        for source in (PYTHON_TRACE, QUIESCE, CONTAINER, RUNC, IP, NSENTER, admission_fixture.FAKE_NFT):
            compile(render(source, BASE="/run/fixture", PYTHON="/usr/bin/python3",
                           UNSHARE="/usr/bin/unshare", MOUNT="/usr/bin/mount", SEED="{}"),
                    "<r3-native-fixture>", "exec")

    def test_both_fixture_recipes_pass_real_observer_policy_contract(self):
        import ast
        import types
        packed = ast.parse((ROOT / C.OBSERVER).read_bytes())
        constants = {node.targets[0].id: ast.literal_eval(node.value) for node in packed.body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in ('SOURCES', 'SCHEMA_BYTES')}
        reviewer = types.ModuleType('r3_fixture_policy_reviewer')
        exec(compile(constants['SOURCES']['review_semantic_oci_policy'], '<real-frame-reviewer>', 'exec'), reviewer.__dict__)
        inputs = issuance.fixtures.fixture()['files']
        for role in C.ROLES:
            launch = json.loads(inputs[role + '/launch'])
            sources = [{**row, 'source': '/run/fixture/' + role + '-source-' + str(i), 'uid': 0, 'gid': 0}
                       for i, row in enumerate(launch['sources'])]
            recipe = fixture_recipe(json.loads(inputs[role + '/template']), launch,
                                    json.loads(inputs[role + '/context']), sources)
            p = recipe['policy']
            result = reviewer.configured_profile(p['expectedOci'], p['expectedOci'], p['manifest'],
                p['startup'], p['approvedHooks'], reviewer.schema_from_source_closure(constants['SCHEMA_BYTES']))
            self.assertTrue(result['configuredPolicyConforms'])


class IntegrationFixture(issuance.NativeTests):
    """Reuse only issuance setup/helpers, not its tests (see load_tests below)."""
    __unittest_skip__ = False

    def setUp(self):
        # Use current checkout bytes, including any integration fix, not HEAD.
        issuance.fixtures.SOURCE_CACHE = {p: (ROOT / p).read_bytes() for p in C.SOURCE_INPUTS}
        super().setUp()
        self.assertNotEqual(os.stat('/proc/self/ns/net').st_ino, os.stat('/proc/1/ns/net').st_ino)
        self.assertNotEqual(os.stat('/proc/self/ns/mnt').st_ino, os.stat('/proc/1/ns/mnt').st_ino)
        self.python = Path(sys.executable).resolve(strict=True)
        self.commands = {k: str(Path(shutil.which(k)).resolve(strict=True))
                         for k in ('mount', 'umount', 'unshare', 'ip')}
        # Keep bind mounts below /run private even on a shared runner mount tree.
        subprocess.run([self.commands['mount'], '--make-rprivate', '/'], check=True)
        self.addCleanup(self.cleanup_native)
        self.trace_python = self.script('python-trace', PYTHON_TRACE)
        self.script('container.py', CONTAINER, executable=False)
        self.runtime = self.script('runc', RUNC)
        self.runtime_root = self.root / 'runtime/owned'
        self.runtime_root.mkdir(parents=True, mode=0o700)
        (self.root / 'runtime').chmod(0o700)
        self.registry = self.install / 'registry'
        self.ids = {r: json.loads(self.inputs['files']['acceptance'])['roles'][r]['containerId'] for r in C.ROLES}
        self.bundles = self.root / 'bundles'
        self.bundles.mkdir(mode=0o700)
        self.make_topology()
        self.make_inputs()
        self.publish_inputs()
        self.composed = C.compose(self.inputs)
        plan = self.issuer_cli(self.argv())
        self.assertEqual(plan['payloadSha256'], A.sha(self.composed['authorization']))
        result = self.issuer_cli(self.argv('--apply', plan['planSha256']))
        self.assertEqual((result['privateKeysRead'], result['signaturesIssued'],
                          result['installationDocumentsPublished'], result['runtimeActions']), (1, 1, 0, 0))
        self.authority_bytes = {p.name: p.read_bytes() for p in self.chain.iterdir()}
        # Publication is deliberately test-owned, not the future 41b installer.
        for relative in sorted(self.composed['layout']['directories0700'], key=lambda p: (p.count('/'), p)):
            path = self.install / relative
            path.mkdir(mode=0o700, exist_ok=True)
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        for relative, raw in self.composed['documents'].items():
            path = self.install / relative
            with path.open('xb') as stream:
                stream.write(raw)
            path.chmod(0o600)
            self.assertEqual(A.sha(path.read_bytes()), self.composed['hashes'][relative])
        self.configuration = self.install / 'runtime-configuration.json'
        runtime_source = self.install / 'source' / C.RUNTIME
        self.runtime_module = issuance.fixtures.load(str(runtime_source), 'r3_integration_runtime')
        self.assertEqual(self.runtime_module.load_configuration(self.configuration)[1],
                         self.composed['documents']['runtime-configuration.json'])

    def script(self, name, source, executable=True, **values):
        path = self.root / name
        raw = render(source, BASE=str(self.root), PYTHON=str(self.python),
                     PYTHON_SHA256=A.sha(self.python.read_bytes()),
                     UNSHARE=self.commands['unshare'], MOUNT=self.commands['mount'], **values)
        self.write(path, b'#!' + str(self.python).encode() + b'\n' + raw, 0o700 if executable else 0o600)
        return {'path': str(path), 'sha256': A.sha(path.read_bytes())}

    def make_topology(self):
        templates = {r: json.loads(self.inputs['files'][r + '/historicalTemplate']) for r in C.ROLES}
        hosts, children = [], {}
        # Real, inert dummy indexes exist only in this scenario's private netns.
        # All later ip/nsenter reports are synthetic, as in task-38b.
        for role in C.ROLES:
            rows = []
            for n, nic in enumerate(templates[role]['candidate']['networkBindings']):
                name = 'r3_' + role[:1] + str(n)
                subprocess.run([self.commands['ip'], 'link', 'add', name, 'type', 'dummy'], check=True)
                index = socket.if_nametoindex(name)
                hosts.append({'ifname': name, 'ifindex': index, 'link_index': 12 + n, 'master': nic['bridge']})
                rows.append({'ifname': nic['interface'], 'ifindex': 12 + n, 'link_index': index,
                    'address': nic['mac'], 'addr_info': [{'family': 'inet', 'local': nic['ipv4']}]})
            children[self.ids[role]] = rows
        subprocess.run([self.commands['ip'], 'link', 'add', 'r3_semantic', 'type', 'dummy'], check=True)
        self.ingress = socket.if_nametoindex('r3_semantic')
        hosts.append({'ifname': 'r3_semantic', 'ifindex': self.ingress, 'master': 'br-backend'})
        self.write(self.root / 'topology.json', A.canonical({'hosts': hosts, 'children': children}))
        self.ip = self.script('ip', IP)
        self.nsenter = self.script('nsenter', NSENTER)

    def make_inputs(self):
        files = self.inputs['files']
        def put(name, value, lf=False): files[name] = A.canonical(value) + (b'\n' if lf else b'')
        # Same empty provider-set model and per-netns nft storage as task-38b.
        kernel = {'tableName': 'ouf_sem_provider', 'guardedInterfaces': ['oufsp-egress'], 'existingInterfaces': [],
            'staticFlows': [], 'providerFlows': [{'endpointRef': 'fixture_' + role, 'endpoint': 'https://provider.example',
                'source': source, 'addresses': [], 'leaseSeconds': 60, 'resolutionEvidenceRef': 'fixture_dns',
                'allowedPrivateAddresses': []} for role, source in (('adapter', '172.22.0.3'), ('southbound', '172.22.0.2'))]}
        tables = {f: {'nftables': [{'table': {'family': f, 'name': kernel['tableName']}},
            *({'set': {'family': f, 'table': kernel['tableName'], 'name': 'provider_' + str(i), 'type': 'ipv4_addr',
                      'flags': ['timeout']}} for i in range(len(kernel['providerFlows'])))]} for f in ('inet', 'bridge')}
        nft = self.script('nft', admission_fixture.FAKE_NFT,
                          SEED=json.dumps({f + ':' + kernel['tableName']: t for f, t in tables.items()}))
        # structure_hash strips counters/elem; seed has neither.
        binding = {'transactionId': 'c' * 64, 'configurationHash': A.sha(A.canonical(kernel)),
                   'leaseStructureHash': A.sha(A.canonical(tables))}
        owner = json.loads(files['coordinator'])
        owner.update(binding=binding, expectedStructureHash=binding['leaseStructureHash'], kernel=kernel,
            journalFile=str(self.root / 'coordination.json'), commonLockFile=str(self.root / 'common.lock'),
            nftPath=nft['path'], nftSha256=nft['sha256'], dns={'resolvers': ['10.20.0.53'], 'resolverPort': 53,
                'timeoutSeconds': 1, 'maxLeaseSeconds': 60, 'applyBudgetSeconds': 1})
        put('coordinator', owner)
        self.write(self.owner, files['coordinator'])
        put('coordinationJournal', {'schema': 'ouf.semantic-lease-coordination.v1', **binding,
            'state': 'QUIESCED', 'leaseAuthorized': False, 'startAuthorized': False, 'leaseAddresses': [[], []]})
        self.write(owner['journalFile'], files['coordinationJournal'])
        self.write(owner['commonLockFile'], b'')
        settings = json.loads(files['settings'])
        settings.update(coordinatorBinding={'path': str(self.owner), 'sha256': A.sha(files['coordinator'])},
            runtimeBinding=self.runtime, runtimeRootParent=str(self.runtime_root.parent),
            rootfsLimits={'maxEntries': 1000, 'maxBytes': 1048576, 'maxDepth': 16})
        put('settings', settings)
        self.settings = settings
        commands = {'ip': self.ip, 'nsenter': self.nsenter, 'nft': nft,
            **{k: {'path': self.commands[k], 'sha256': A.sha(Path(self.commands[k]).read_bytes())}
               for k in ('mount', 'umount', 'unshare')}}
        accepted, rootfs = json.loads(files['acceptance']), json.loads(files['rootfs'])
        # Use the actual v1 sealing function already loaded by the native fixture.
        with admission_fixture.part_a.libraries():
            from tools.semantic_provider_node_observation import rootfs_seal
            from tools.semantic_provider_deployment_authentication import VerificationBudget
            for role in C.ROLES:
                cid = self.ids[role]
                bundle = self.bundles / cid
                bundle.mkdir(mode=0o700)
                root = bundle / 'rootfs'
                root.mkdir(mode=0o700)
                (root / 'etc').mkdir(mode=0o700)
                for name in ('etc/hosts', 'etc/hostname', 'etc/resolv.conf'):
                    self.write(root / name, b'fixture mount target\n')
                launch, template = json.loads(files[role + '/launch']), json.loads(files[role + '/template'])
                sources = []
                for i, row in enumerate(launch['sources']):
                    source = self.root / (role + '-source' + ('' if i == 0 else '-' + str(i)))
                    self.write(source, b'R3 synthetic source\n')
                    target = root / row['target'].lstrip('/')
                    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                    self.write(target, b'fixture source target\n')
                    sources.append({**row, 'source': str(source), 'uid': 0, 'gid': 0,
                                    'mode': 0o600, 'maxBytes': 4096, 'sha256': A.sha(source.read_bytes())})
                storage = self.root / 'storage'
                metadata = storage / 'containers' / cid
                metadata.mkdir(parents=True, mode=0o700)
                storage.chmod(0o700); metadata.parent.chmod(0o700)
                for name in ('hosts', 'hostname', 'resolv.conf'):
                    self.write(metadata / name, b'R3 synthetic metadata\n')
                context = json.loads(files[role + '/context'])
                context.update(bundleParent=str(self.bundles), metadataParent=str(storage / 'containers'),
                    networkNamespaceParent=str(self.root / 'network-namespaces'), rootfsPath=str(root), storageParent=str(storage))
                recipe = fixture_recipe(template, launch, context, sources)
                self.write(bundle / 'config.json', A.canonical(recipe['policy']['expectedOci']))
                for part, value in recipe.items():
                    put(role + '/' + part, value, lf=True)
                    accepted['roles'][role]['recipe'][part]['sha256'] = A.sha(files[role + '/' + part])
                seal = rootfs_seal(root, settings['rootfsLimits'], VerificationBudget(18))
                rootfs['roles'][role]['effectiveSeal'] = seal
                accepted['roles'][role]['rootfs']['effectiveSeal'] = seal
                historical = json.loads(files[role + '/historicalTemplate'])
                historical.update(pythonPath=self.trace_python['path'], pythonHash=self.trace_python['sha256'],
                    commands={k: v['path'] for k, v in commands.items()}, commandHashes={k: v['sha256'] for k, v in commands.items()},
                    hostNetworkNamespace=os.stat('/proc/self/ns/net').st_ino)
                if role == 'southbound': historical['candidate']['transport'][1]['peerIngress']['ifindex'] = self.ingress
                put(role + '/historicalTemplate', historical)
        peer = json.loads(files['semanticPeer'])
        peer['binding']['hostIfindex'] = peer['proposedIngress']['ifindex'] = self.ingress
        put('semanticPeer', peer)
        manifest = json.loads(files['a2Manifest'])
        manifest['manifest']['semanticPeer'] = peer
        for row in manifest['manifest']['filesCreated']:
            if row['path'].endswith('/semantic-peer.json'): row['sha256'] = A.sha(files['semanticPeer'])
        put('a2Manifest', manifest)
        for name, field in (('a2Manifest', 'manifest'), ('semanticPeer', 'semanticPeer')):
            accepted['preparationA']['files'][field]['sha256'] = A.sha(files[name])
        put('rootfs', rootfs)
        put('acceptance', accepted, lf=True)
        # The only substituted source blob is the explicitly fake quiescer.
        self.inputs['sources']['scripts/semantic-provider-lease-supervisor-v2.py'] = render(QUIESCE, BASE=str(self.root))

    def issuer_cli(self, args):
        result = subprocess.run([str(self.python), '-I', '-B', str(ROOT / 'scripts/issue-semantic-provider-operation-authorization.py'),
            *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
        self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
        return json.loads(result.stdout)

    def row(self, role='adapter'):
        return self.e.current(self.registry, self.ids[role])

    def folder(self, role='adapter', epoch=None):
        return self.registry / self.ids[role] / 'epochs' / str(epoch or self.row(role)['epoch'])

    def diagnostic(self):
        # Synthetic fixture data only. Never traverse blobs, ledger or key files.
        data = {}
        for name in ('python.jsonl', 'runc.jsonl', 'quiesce.jsonl', 'container-errors.log'):
            path = self.root / name
            if path.exists(): data[name] = path.read_text()[-48000:]
        if self.registry.exists():
            data['journals'] = {str(p.relative_to(self.registry)): json.loads(p.read_bytes())
                for p in self.registry.rglob('*.json') if p.name in
                ('adapter.json', 'broker-state.json', 'deployment.json', 'admission.json', 'preexec.json')}
        return json.dumps(data, indent=2)

    def run_op(self, mode, role='adapter', denied=None):
        args = ['--root', str(self.runtime_root), mode]
        if mode == 'create': args += ['--bundle', str(self.bundles / self.ids[role])]
        if mode == 'delete': args += ['--force']
        args += [self.ids[role]]
        try:
            result = self.runtime_module.operate(self.configuration, args)
        except self.runtime_module.Denied as error:
            if denied is None or str(error) != denied:
                self.fail('runtime ' + mode + ': ' + str(error) + '\n' + self.diagnostic())
            return
        self.assertIsNone(denied, 'expected ' + str(denied) + '\n' + self.diagnostic())
        self.assertEqual(result, 0, self.diagnostic())

    def unchanged_authority(self):
        self.assertEqual({p.name: p.read_bytes() for p in self.chain.iterdir()}, self.authority_bytes)
        result = json.loads((self.output / 'result.json').read_bytes())
        self.assertEqual(result['signaturesIssued'], 1)

    def assert_started(self, role, epoch):
        row = self.row(role)
        self.assertEqual((row['epoch'], row['state'], row['authorizationSha256']),
                         (epoch, 'STARTED', A.sha(self.composed['authorization'])), self.diagnostic())
        self.assertEqual(row['generation']['startTicks'], self.e.start_ticks(row['generation']['pid']))
        root = self.folder(role)
        for filename, state in (('deployment.json', 'STARTED'), ('preexec.json', 'PROTECTED'),
                                ('broker-state.json', 'PROTECTED'), ('admission.json', 'PROTECTED')):
            self.assertEqual(json.loads((root / filename).read_bytes())['state'], state, self.diagnostic())
        grant = json.loads((root / 'driver.json').read_bytes())
        self.assertEqual(grant['schema'], 'ouf.semantic-preexec-driver.v7')
        self.assertEqual(grant['operationBinding']['epoch'], epoch)
        self.assertEqual(grant['operationBinding']['configurationHash'],
                         A.sha(self.composed['documents']['broker/' + role + '.json']))
        self.assertEqual(row['driverHash'], A.sha((root / 'driver.json').read_bytes()))

    def scenario_lifecycle(self):
        self.assertEqual(self.runtime_module.operate(self.configuration, ['--version']), 0)
        for role in C.ROLES:
            self.run_op('create', role)
            self.assertEqual((self.row(role)['epoch'], self.row(role)['state']), (1, 'CREATED'))
        for role in C.ROLES:
            self.run_op('start', role); self.assert_started(role, 1)
        for role in C.ROLES:
            self.run_op('delete', role)
            self.assertEqual(self.row(role)['state'], 'DELETED')
            self.assertEqual(json.loads((self.folder(role) / 'admission.json').read_bytes())['state'], 'CLEANED')
            self.assertFalse((self.folder(role) / 'netns').exists())
        for role in C.ROLES:
            self.run_op('create', role)
            self.assertEqual((self.row(role)['epoch'], self.row(role)['state']), (2, 'CREATED'))
        for role in C.ROLES:
            self.run_op('start', role); self.assert_started(role, 2)
        self.unchanged_authority()
        # Simulate reboot for ALL readers, including real child entrypoints.
        # Neither the signed bytes nor old journals are rewritten by the test.
        old_boot = self.e.boot_id()
        for role in C.ROLES:
            self.stop_pid(self.row(role)['generation'])
            (self.runtime_root / (self.ids[role] + '.json')).unlink()
            (self.runtime_root / (self.ids[role] + '.ready')).unlink()
            self.native_command('umount', str(self.folder(role) / 'netns'))
        boot = self.root / 'boot-id'
        self.write(boot, b'6dc087ac-1111-4222-8333-444455556666\n')
        self.assertNotEqual(boot.read_text().strip(), old_boot)
        self.native_command('mount', '--bind', str(boot), '/proc/sys/kernel/random/boot_id')
        self.addCleanup(self.native_command, 'umount', '/proc/sys/kernel/random/boot_id')
        for role in C.ROLES:
            self.run_op('create', role)
            old = json.loads((self.folder(role, 2) / 'adapter.json').read_bytes())
            self.assertEqual((old['state'], old['bootId']), ('ABANDONED', old_boot))
            self.assertEqual((self.row(role)['epoch'], self.row(role)['state'], self.row(role)['bootId']),
                             (3, 'CREATED', boot.read_text().strip()))
        self.unchanged_authority()
        calls = [json.loads(line) for line in (self.root / 'python.jsonl').read_text().splitlines()]
        invoked = [r['argv'] for r in calls if r['event'] == 'invoke']
        for entry, modes in ((admission_fixture.b.ENTRYPOINTS[0], ('authorize-create', 'record-created', 'cohort-ready', 'prepare', 'cleanup')),
                             (admission_fixture.b.ENTRYPOINTS[1], ('prepare', 'template', 'cleanup')),
                             (admission_fixture.b.ENTRYPOINTS[2], ('plan', 'apply', 'verify', 'hook', 'start', 'rollback'))):
            for mode in modes:
                self.assertTrue(any(argv[2].endswith(entry) and argv[-2:] == ['--mode', mode]
                                    for argv in invoked), (entry, mode, self.diagnostic()))
        # 3 create rounds x 2 roles + 1 delete round x 2 roles (task-42c: delete quiesces before rollback).
        self.assertEqual(len((self.root / 'quiesce.jsonl').read_text().splitlines()), 8)
        self.assertEqual(sum(argv[-2:] == ['--mode', 'rollback'] for argv in invoked), 2)

    def scenario_stop(self):
        payload = json.loads(self.composed['authorization'])
        payload.update(sequence=2, supersedes=A.sha(self.composed['authorization']), decision='STOP', issuedAt=self.now)
        self.put(2, A.canonical(payload))  # real domain-separated fixture signature
        self.assertEqual((self.head()['sequence'], self.head()['decision']), (2, 'STOP'))
        self.run_op('create', denied='OPERATION_NOT_OPERATE')
        self.assertIsNone(self.row())
        self.assertEqual(list((self.registry / self.ids['adapter'] / 'epochs').iterdir()), [])
        self.assertFalse((self.root / 'quiesce.jsonl').exists())
        self.assertFalse((self.root / 'runc.jsonl').exists())

    def scenario_frame_drift(self):
        for role in C.ROLES: self.run_op('create', role)
        # Change an actual mounted source after create, preserving policy/hash.
        self.write(self.root / 'adapter-source', b'changed source frame\n')
        self.run_op('start', denied='TWO_PHASE_BROKER_DENIED')
        self.assertEqual((self.row()['state'], self.row()['failure']), ('FAILED', 'TWO_PHASE_BROKER_DENIED'))
        self.assertFalse((self.folder() / 'driver.json').exists())
        errors = (self.root / 'python.jsonl').read_text()
        self.assertIn('SEMANTIC_DEPLOYMENT_BROKER=DENIED', errors, self.diagnostic())
        self.unchanged_authority()

    def scenario_quiesce_failure(self):
        self.write(self.root / 'quiesce-fail', b'fail')
        self.run_op('create', denied='LEASE_QUIESCENCE_UNPROVEN')
        self.assertIsNone(self.row())
        self.assertEqual(list((self.registry / self.ids['adapter'] / 'epochs').iterdir()), [])
        self.assertEqual(len((self.root / 'quiesce.jsonl').read_text().splitlines()), 1)
        self.assertFalse((self.root / 'runc.jsonl').exists())
        self.unchanged_authority()

    def native_command(self, name, *args):
        subprocess.run([self.commands[name], *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)

    def stop_pid(self, generation):
        pid = generation['pid']
        if self.e.start_ticks(pid) != generation['startTicks']: return
        if not Path('/proc/' + str(pid) + '/ns/net').exists(): return
        os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 3
        while Path('/proc/' + str(pid) + '/ns/net').exists():
            self.assertLess(time.monotonic(), deadline, 'fixture PID did not exit')
            time.sleep(.01)

    def cleanup_native(self):
        # Cleanup precedes TemporaryDirectory cleanup even after partial prepare.
        pids = self.root / 'pids.jsonl'
        if pids.exists():
            for line in pids.read_text().splitlines(): self.stop_pid(json.loads(line))
        if self.registry.exists():
            for path in self.registry.glob('*/epochs/*/netns'):
                if os.path.ismount(path): self.native_command('umount', str(path))


@unittest.skipUnless(NATIVE, 'set OUF_R3_INTEGRATION_NATIVE=1 under Linux root:root')
class NativeTests(unittest.TestCase):
    def scenario(self, name):
        for command in ('unshare', 'mount', 'umount', 'ip', 'openssl'):
            self.assertIsNotNone(shutil.which(command), 'required native fixture command: ' + command)
        result = subprocess.run([shutil.which('unshare'), '--mount', '--net', '--fork',
            sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--native-child', name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())

    def test_lifecycle_two_epochs_reboot_and_real_entrypoints(self): self.scenario('scenario_lifecycle')
    def test_stop_supersedes_denies_before_create(self): self.scenario('scenario_stop')
    def test_real_frame_drift_marks_epoch_failed(self): self.scenario('scenario_frame_drift')
    def test_quiescence_failure_opens_no_epoch(self): self.scenario('scenario_quiesce_failure')


def load_tests(loader, tests, pattern):
    # Do not discover inherited issuance tests or fixtures imported above.
    return unittest.TestSuite([loader.loadTestsFromTestCase(PortableTests), loader.loadTestsFromTestCase(NativeTests)])


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--native-child':
        if not NATIVE: raise RuntimeError('native child requires the integration gate')
        name = sys.argv[2]
        if name not in {'scenario_lifecycle', 'scenario_stop', 'scenario_frame_drift', 'scenario_quiesce_failure'}:
            raise RuntimeError('unknown native scenario')
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([IntegrationFixture(name)]))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    unittest.main()
