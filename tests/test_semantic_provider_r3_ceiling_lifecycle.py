"""One signed supersession, stopped upgrade and start using portable host boundaries."""
from contextlib import ExitStack, nullcontext
import os
from pathlib import Path, PurePosixPath
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_semantic_provider_r3_ceiling import C, with_ceiling, v27
from test_semantic_provider_operation_issuance import issue, gate
from tools.semantic_provider_r3 import install_common as I, operate as O, upgrade as U

V12 = v27.v25.v24.v20.V12
AUTH = v27.overlay.AUTH


class Reader:
    def __init__(self, public, private=()):
        self.public = public
        self.private_paths = set(map(PurePosixPath, private))
        self.hashes = {}

    def read(self, path, digest, limit=None):
        C.require(C.sha(self.public[path]) == digest, 'INPUT_SHA256_MISMATCH')
        self.hashes[path] = digest
        return self.public[path]

    def bound(self, binding):
        return self.read(binding['path'], binding['sha256'])

    def verify(self):
        for path, digest in self.hashes.items():
            self.read(path, digest)


def input_index(inputs, public):
    index = {'schema': 'ouf.semantic-provider-r3-inputs.v1'}
    for section, records in inputs.items():
        index[section] = {}
        for name, raw in records.items():
            path = f'/inputs/{section}/{name}'
            public[path] = raw
            index[section][name] = dict(path=path, sha256=C.sha(raw))
    return index


class Replay(unittest.TestCase):
    def prepare_chain(self, sequence):
        self.assertGreaterEqual(sequence, 28)
        self.sequence = sequence
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.base = v27.fixture(27)[0]
        self.settings = C.document(self.base['files']['settings'])
        scope = {k: self.settings[k] for k in ('installationRef', 'entityRef', 'issuerRef')}
        self.chain = v27.Chain(self.temp, scope=scope)
        self.profile_path = str(self.temp / 'profile.json')
        c = self.chain
        self.profile = C.canonical(dict(schema='ouf.semantic-existing-installation-authority-bindings.v1',
            authorities=dict(installationRef=scope['installationRef'], entityRef=scope['entityRef'],
                             intentIssuerRef=scope['issuerRef'], approvalIssuerRef=scope['issuerRef']),
            keyBindings={'installer': dict(path=str(c.key), sha256=C.sha(c.key.read_bytes()))},
            keyRefs={'installer': 'fixture'}, policyBinding=dict(path=str(self.temp / 'policy'), sha256='1'*64)))
        self.anchor_bytes = C.canonical(C.document(Path(c.anchor['path']).read_bytes()) | dict(
            authorityProfile=dict(path=self.profile_path, sha256=C.sha(self.profile)),
            basePolicy=C.document(self.profile)['policyBinding']))
        c.write(Path(c.anchor['path']), self.anchor_bytes)
        c.anchor['sha256'] = C.sha(self.anchor_bytes)
        self.settings.update(anchorBinding=dict(path='/anchor', sha256=c.anchor['sha256']),
                             opensslBinding=dict(c.ssl, path='/openssl'))
        acceptance = C.document(self.base['files']['acceptance'])
        acceptance['trustPolicy'] = self.settings['anchorBinding']
        self.base = dict(self.base, files=dict(self.base['files'], settings=C.canonical(self.settings),
                                               acceptance=C.canonical(acceptance) + b'\n'))
        for number in range(self.chain.count + 1, sequence):
            self.old = C.compose(self.base, number, sequence=number, supersedes=self.chain.digest)
            self.chain.payload = C.A.validate(self.old['authorization'])
            self.chain.append()
            self.assertEqual(self.old['authorization'], (self.chain.directory / f'{number}.json').read_bytes())
        self.root = PurePosixPath(self.settings['installRoot'])
        self.disk = {}
        self.started = {}
        self.patch(I, 'Path', PurePosixPath)
        self.patch(I.V, 'absolute', PurePosixPath)
        self.patch(I.V, 'private_directory', Mock())
        self.patch(I, 'output_directory', Mock())
        self.patch(v27.v25.live, 'semantic_kernel', Mock())
        self.m = C.contract_module(self.base['sources'][C.MANDATES], 'mandates')
        # POSIX custody is the host boundary. Ledger replay, signature frames,
        # Ed25519 signing/verification and the two inventories are real.
        self.m.Path = Path
        self.m.private_bytes = lambda path, *args: path.read_bytes()
        self.m.ancestors = lambda path: None
        self.m.ledger_directory = Path.lstat
        self.m.ENV = dict(os.environ, OPENSSL_CONF=os.devnull)
        def executable(verifier):
            verifier.budget.check()
            self.assertEqual(C.sha(c.openssl.read_bytes()), verifier.openssl_binding['sha256'])
            return str(c.openssl)
        self.m.MandateAuthenticator.executable = executable
        self.configure_auth(C.A)

    def patch(self, obj, name, value):
        return self.enterContext(patch.object(obj, name, value))

    def configure_auth(self, auth):
        self.patch(auth, 'Path', Path)
        self.patch(auth, 'os', SimpleNamespace(lstat=lambda _: SimpleNamespace(st_mode=0o40700, st_uid=0),
                                               listdir=os.listdir))
        self.patch(auth, 'private_file', Path.read_bytes)

    def head(self, auth):
        c = self.chain
        return auth.head(self.m, c.anchor, str(c.ledger), c.ssl, str(c.directory),
                         c.scope['installationRef'], c.scope['entityRef'], c.scope['issuerRef'], lambda: c.now)

    def inputs(self, cap):
        prepare = V12.F.load('scripts/prepare-semantic-provider-r3-v25-inputs.py', f'prepare_{self.sequence}')
        base = self.base if cap is None else with_ceiling(self.base, cap)
        public = {}
        files = {k: base['files'][k] for k in C.DATA_INPUTS_V24}
        files['leaseRenewal'] = V12.blob('ops/vps/r3-lease-renewal-v22.json')
        sources = {k: base['sources'][k] for k in C.SOURCE_INPUTS_V24}
        index = input_index(dict(files=files, sources=sources), public)
        public['/base'] = C.canonical(index)
        args = SimpleNamespace(sequence=self.sequence, mode='inputs', v24_inputs='/base', v24_inputs_sha256=C.sha(public['/base']))
        if cap != 24:
            public['/profile'] = base['files']['semanticProfile']
            public['/renewal'] = v27.fixture(cap or 27)[0]['files']['leaseRenewal']
            public[str(I.ROOT / C.SEMANTIC_IDENTITY)] = base['sources'][C.SEMANTIC_IDENTITY]
            args.profile, args.profile_sha256 = '/profile', C.sha(public['/profile'])
            args.lease_renewal, args.lease_renewal_sha256 = '/renewal', C.sha(public['/renewal'])
            args.source_sha256 = C.sha(base['sources'][C.SEMANTIC_IDENTITY])
        reader = Reader(public)
        prepared = prepare.prepare(args, reader)
        if cap == 24:
            self.assertEqual(prepared, index)
            self.assertEqual(set(reader.hashes), {'/base', index['files']['settings']['path']})
        return {s: {k: reader.bound(b) for k, b in prepared[s].items()} for s in ('files', 'sources')}

    def issue(self, inputs, cap):
        c = self.chain
        previous = self.head(C.A)
        self.assertEqual((previous['sequence'], previous['authorization']), (self.sequence - 1, c.payload))
        public = {self.profile_path: self.profile, '/anchor': self.anchor_bytes,
                  '/openssl': c.openssl.read_bytes(),
                  self.settings['coordinatorBinding']['path']: inputs['files']['coordinator']}
        public['/index'] = C.canonical(input_index(inputs, public))

        # Map the fixture's POSIX installation paths to its temporary native files.
        def ledger(anchor, path, *args):
            self.assertEqual(anchor, self.settings['anchorBinding'])
            self.assertEqual(path, self.settings['mandateRoot'])
            return self.m.MandateLedger(c.anchor, str(c.ledger), *args)

        def verifier(anchor, path, ssl, *args):
            self.assertEqual(ssl, self.settings['opensslBinding'])
            return self.m.MandateAuthenticator(c.anchor, str(c.ledger), c.ssl, *args)

        mapped = SimpleNamespace(MandateLedger=ledger, MandateAuthenticator=verifier,
                                 MandateDenied=self.m.MandateDenied, B1B2_ANCHOR_SCHEMA=self.m.B1B2_ANCHOR_SCHEMA)
        output = self.temp / 'issued'
        identity = (1,)
        paths = (output, c.directory, identity, identity)
        args = SimpleNamespace(supersede=True, plan=True, issued_at=c.now,
            authority_profile=self.profile_path, authority_profile_sha256=C.sha(self.profile),
            inputs='/index', inputs_sha256=C.sha(public['/index']), install_root=str(self.root),
            private_key_path=[str(c.key)], output_directory=str(output),
            table_name=[f'{k}={v}' for k, v in self.settings['tableNames'].items()])
        progress = issue.progress_initial()

        def write(fd, name, raw):
            folder = c.directory if fd == 1 else output
            with (folder / name).open('xb') as stream:
                stream.write(raw)

        # execute/publish manage the plan digest, sole signing call, exclusive
        # records and full readback. Model only host locks and directory FDs.
        host = SimpleNamespace(mkdir=os.mkdir, chmod=os.chmod, open=lambda *_: 2, close=lambda _: None,
            fchmod=lambda *_: None, fsync=lambda _: None, fstat=lambda _: identity,
            O_RDONLY=0, O_DIRECTORY=0, O_NOFOLLOW=0)
        with ExitStack() as stack:
            for obj, name, value in (
                (issue, 'destinations', lambda _: paths), (issue, 'Reader', lambda private: Reader(public, private)),
                (issue, 'load_mandates', lambda *_: mapped), (issue.AUTH, 'absolute', PurePosixPath),
                (I, 'coordinator_state', lambda *_: {'state': 'QUIESCED'}),
                (issue, 'authorization_head', lambda *_: previous), (issue, 'directory', lambda *a, **kw: identity),
                (issue, 'chain_lock', lambda *_: 1), (issue, 'os', host), (issue, 'write_once', write),
                (issue, 'ENV', self.m.ENV), (issue.AUTH, 'public_bytes', lambda path, _: path.read_bytes()),
                (issue.AUTH, 'attributes', lambda stat: stat), (gate, 'observe', lambda *_: {}),
                (gate, 'operation_locks', lambda *_: nullcontext())):
                stack.enter_context(patch.object(obj, name, value))
            probe = stack.enter_context(patch.object(v27.v25.live, 'semantic_kernel_probe'))
            proposal = issue.execute(args, progress, clock=lambda: c.now)
            args.plan, args.plan_sha256 = False, proposal['planSha256']
            receipt = issue.execute(args, progress, clock=lambda: c.now)
            self.assertEqual(probe.call_count, 2 if cap != 24 else 0)
        payload = proposal['payload']
        self.assertEqual(payload.get('compositionCeiling'), cap)
        self.assertEqual('compositionCeiling' in payload, cap is not None)
        self.assertEqual(payload['supersedes'], previous['sha256'])
        result = C.compose(inputs, self.sequence, sequence=self.sequence, supersedes=previous['sha256'])
        self.assertEqual(proposal['documentHashes'], result['hashes'])
        self.assertEqual((receipt['sequence'], receipt['signaturesIssued']), (self.sequence, 1))
        self.assertEqual(progress['writtenFiles'], [f'{self.sequence}.json', f'{self.sequence}.signature.json'])
        self.assertEqual((c.directory / f'{self.sequence}.json').read_bytes(), result['authorization'])
        self.assertEqual(C.document((output / 'result.json').read_bytes()), receipt)
        if cap == 26:
            # Even after updating payloadHash in the public envelope, the same
            # signature cannot authorize a different valid cap on identical documents.
            tampered = C.canonical(dict(payload, compositionCeiling=25))
            envelope = C.document((c.directory / f'{self.sequence}.signature.json').read_bytes())
            envelope['payloadHash'] = C.sha(tampered)
            with self.assertRaisesRegex(C.A.OperationDenied, '^OPERATION_SIGNATURE_INVALID$'):
                ledger_view = ledger(self.settings['anchorBinding'], self.settings['mandateRoot'],
                                     c.scope['installationRef'], c.scope['entityRef'], lambda: c.now)
                ledger_view.refresh(c.now)
                authenticator = self.m.MandateAuthenticator(c.anchor, str(c.ledger), c.ssl, lambda: c.now)
                C.A.verify_entry(self.m, ledger_view, authenticator, tampered, C.canonical(envelope),
                                 (c.scope['installationRef'], c.scope['entityRef'], c.scope['issuerRef']))
        return result

    def upgrade(self, inputs, issued, head):
        root, disk = self.root, self.disk
        args = SimpleNamespace(install_root=str(root), output_directory='/upgrade', wrapper='/wrapper',
            lock='/lock', docker='/docker', docker_sha256='a'*64, docker_socket='unix:///docker.sock',
            systemctl='/systemctl', systemctl_sha256='b'*64)
        disk.update({str(root / p): raw for p, raw in self.old['documents'].items()})
        sequence = head['sequence']
        self.assertEqual(sequence, self.sequence)
        for number in (sequence - 1, sequence):
            disk[str(root / 'authorization' / f'{number}.json')] = (self.chain.directory / f'{number}.json').read_bytes()
        before = root / 'versions' / str(sequence - 1)
        old_cfg = C.document(disk[str(before / 'runtime-configuration.json')])
        old_sup = disk[str(before / 'supervisor/configuration.json')]
        disk[args.wrapper] = I.wrapper_bytes(old_cfg['pythonPath'], before)
        args.current_wrapper_sha256 = C.sha(disk[args.wrapper])
        disk[str(I.UNIT_PATH)] = I.unit_bytes(root, old_cfg, C.document(old_sup), before)
        identity = tuple(range(9))

        def write(path, raw, report):
            self.assertNotIn(str(path), disk)
            disk[str(path)] = raw

        def switch(wrapper, expected, raw, output, lock, inode, verify):
            self.assertEqual(C.sha(disk[wrapper]), expected)
            verify(0, 'BEFORE_RENAME')
            disk[wrapper] = raw
            verify(0, 'AFTER_RENAME')
            return {'status': 'WRAPPER_SWITCHED'}

        def publication(root, composed, *, code_root, require_no_epochs):
            self.assertEqual({p: disk[str(root / p)] for p in composed['documents']}, issued['documents'])
            raw = disk[str(code_root / 'runtime-configuration.json')]
            self.assertEqual(C.sha(raw), head['authorization']['runtimeConfigurationSha256'])
            return C.document(raw)

        self.switch = SimpleNamespace(custody=lambda p, _: (disk[str(p)], identity),
                                      sync=lambda _: None, switch_existing_wrapper=switch)
        self.patch(I, 'native_switch', lambda: self.switch)
        reader = SimpleNamespace(verify=lambda: None, hashes={})
        properties = (f'FragmentPath={I.UNIT_PATH}\nNeedDaemonReload=no\nDropInPaths=\nLoadState=loaded\n').encode()
        with ExitStack() as stack:
            for obj, name, value in (
                (U, 'Path', PurePosixPath),
                (U, 'read_inputs', lambda _: (reader, inputs['files'], inputs['sources'],
                                              C.document(inputs['files']['settings']))),
                (I, 'authorization', lambda *_: (self.m, head)),
                (U, 'installed_runtime', lambda *_: (SimpleNamespace(bound_bytes=lambda _: old_sup), old_cfg, b'')),
                (U, 'stopped_provider', lambda *_: {}), (I, 'coordinator_state', lambda *_: {'state':'QUIESCED'}),
                (I.V, 'guard_lock', lambda *_: {'identity': list(identity)}), (I, 'systemctl', lambda *_: properties),
                (I, 'guard', lambda *_: nullcontext(0)), (I, 'operation_locks', lambda *_: nullcontext()),
                (I, 'write_once', write), (I, 'mkdir_once', Mock()), (I, 'command', Mock()),
                (I, 'verify_publication', publication), (I, 'service_readback', Mock()),
                (U, 'os', SimpleNamespace(path=SimpleNamespace(lexists=lambda _: False),
                    fstat=lambda _: SimpleNamespace(st_dev=0, st_ino=1),
                    replace=lambda src, dst: disk.update({str(dst): disk.pop(str(src))})))):
                stack.enter_context(patch.object(obj, name, value))
            if head['authorization'].get('compositionCeiling') == 26:
                changed = with_ceiling(inputs, 25)
                with patch.object(U, 'read_inputs', return_value=(reader, changed['files'], changed['sources'],
                                  C.document(changed['files']['settings']))), self.assertRaisesRegex(
                                  C.A.OperationDenied, '^R3_AUTHORIZATION_PAYLOAD_MISMATCH$'):
                    U.observe(args)
            state, result = U.observe(args)
            self.assertEqual(result, issued)
            plan = I.digest_plan(state)
            args.plan_sha256 = plan['planSha256']
            report = dict(I.COUNTERS)
            U.apply(args, plan, result, report)
        self.assertEqual((report['status'], report['versionBefore'], report['versionAfter']),
                         ('SEMANTIC_PROVIDER_R3_UPGRADED_WAITING', sequence - 1, sequence))
        self.assertEqual(report['signaturesIssued'], 0)
        return report['wrapperAfter']


    def start(self, inputs, head, wrapper_hash, cap):
        disk, root = self.disk, self.root
        installed = root / 'versions' / str(self.sequence)
        source = installed / 'source'
        cfg = C.document(disk[str(installed / 'runtime-configuration.json')])
        sup_cfg = C.document(disk[str(installed / 'supervisor/configuration.json')])
        auth = C.contract_module(disk[str(source / AUTH)], 'installed_auth')
        self.configure_auth(auth)
        with patch.object(C, 'A', auth):
            sup = C.contract_module(disk[str(source / C.SUPERVISOR)], 'installed_supervisor')
        self.assertIs(sup.authorization, auth)
        rows = self.started
        epochs = SimpleNamespace(current=lambda _, cid: rows.get(cid), live=lambda row, boot: row['bootId'] == boot,
                                 boot_id=lambda: 'boot')
        configuration = SimpleNamespace(value=self.chain.configure(sup_cfg))
        guard = sup.Guards(configuration, self.m, head['authorization']['lease']['leaseStructureHash'], RuntimeError,
                           head=auth.SignatureMemo().head if hasattr(auth, 'SignatureMemo') else auth.head,
                           current=epochs.current, live=epochs.live, boot=epochs.boot_id, clock=lambda: self.chain.now)
        self.assertEqual(hasattr(auth, 'SignatureMemo'), cap is None)
        runtime = C.contract_module(disk[str(source / C.RUNTIME)], 'installed_runtime')
        runtime.read = lambda p: disk[str(p)]
        runtime.__file__ = str(source / C.RUNTIME)
        runtime.executable = lambda *_: None
        disk[self.settings['anchorBinding']['path']] = self.anchor_bytes
        runtime_auth, _ = runtime.operation_modules(cfg)
        self.configure_auth(runtime_auth)
        verify_head = runtime_auth.head

        def runtime_head(mandates, anchor, ledger, ssl, directory, installation, entity, issuer, clock):
            self.assertEqual((anchor, ledger, ssl, directory),
                             (self.settings['anchorBinding'], self.settings['mandateRoot'],
                              self.settings['opensslBinding'], str(root / 'authorization')))
            c = self.chain
            return verify_head(self.m, c.anchor, str(c.ledger), c.ssl, str(c.directory),
                               installation, entity, issuer, lambda: c.now)

        runtime_auth.head = runtime_head
        runtime.operation_modules = lambda _: (runtime_auth, epochs)
        owner = C.document(inputs['files']['coordinator'])
        disk[sup_cfg['coordinator']['ownerConfiguration']['path']] = inputs['files']['coordinator']
        args = V12.OF.arguments(install_root=str(root), output=str(self.temp / 'start'), wrapper='/wrapper',
                                wrapper_sha256=wrapper_hash, nft=owner['nftPath'], nft_sha256=owner['nftSha256'])
        args.timeout_seconds = 180
        delivery = self.temp / 'delivery'
        for name in (C.RUNTIME, 'tools/semantic_provider_operation/epochs.py'):
            path = delivery / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(inputs['sources'][name])
        self.patch(I, 'ROOT', delivery)
        self.patch(I, 'compiled', lambda *_: runtime)
        self.patch(O.VR, 'plan', lambda *_: {})
        self.patch(O.VR, 'apply', Mock())
        self.patch(I, 'write_once', lambda path, raw, _: path.write_bytes(raw))
        self.patch(O, 'broker_denials', lambda *_: [])
        self.patch(v27.v25.live, 'semantic_observe', Mock(return_value=('a'*64, {})))
        journal = C.document(inputs['files']['coordinationJournal'])
        table = owner['kernel']['tableName']
        tables = V12.fixture()[3]

        def service_status():
            status = dict(schema=sup.STATUS_SCHEMA, state='WAITING', reason='EPOCH_NOT_LIVE',
                          epochs=dict.fromkeys(O.ROLES), authorizationSequence=self.sequence, activationsLastHour=0)
            if len(rows) == 2:
                guard.scope_guard()
                status.update(state='ACTIVE', reason=None, epochs=guard.epochs, authorizationSequence=guard.sequence)
                if 'semanticIngress' in sup_cfg:
                    status['semanticEpoch'] = 'a'*64
            return C.canonical(status)

        def custody(path, _):
            if str(path) == sup_cfg['statusPath']:
                return service_status(), ()
            if str(path) == sup_cfg['coordinator']['journalPath']:
                state = dict(state='LEASE_READY', leaseAuthorized=True) if len(rows) == 2 else {}
                return C.canonical(journal | state), ()
            return disk[str(path)], ()
        self.switch.custody = custody

        def docker(args, verb, cid, **kwargs):
            if verb == 'start':
                self.assertIn(cid, cfg['candidates'])
                self.assertNotIn(cid, rows)
                rows[cid] = dict(epoch=1, bootId='boot', state='STARTED', generation=dict(pid=101),
                                 failure=None, configurationHash=head['authorization']['runtimeConfigurationSha256'],
                                 authorizationSha256=head['sha256'])
                return b''
            self.assertEqual(verb, 'inspect')
            live = cid in rows
            return C.canonical([dict(Id=cid, State=dict(Pid=101 if live else 0, Running=live,
                Status='running' if live else 'exited', StartedAt='2026-11-17T00:00:00Z'), RestartCount=0,
                HostConfig=dict(Runtime='ouf-semantic-admitted-v2', RestartPolicy=dict(Name='no')))])

        def command(path, digest, argv, timeout):
            if path == args.systemctl:
                return b'ActiveState=active\nSubState=running\nNRestarts=0\n'
            self.assertEqual(path, args.nft)
            if argv == ['-j', 'list', 'tables']:
                names = [table] + [head['authorization']['roles'][cfg['candidates'][c]['role']]['tableName']
                                   for c in rows]
                return C.canonical({'nftables': [{'table': {'family': f, 'name': n}}
                                    for f in ('inet', 'bridge') for n in names]})
            self.assertEqual(argv[:3], ['-j', 'list', 'table'])
            return C.canonical(tables[argv[3]])

        self.patch(O, 'docker', docker)
        self.patch(O, 'command', command)
        plan = O.proposal(args, O.observe(args))
        args.plan_sha256 = plan['planSha256']
        report = dict(O.COUNTERS)
        O.apply(args, plan, report)
        self.assertEqual((report['status'], report['dockerStartRequests'], report['signaturesIssued']),
                         ('SEMANTIC_PROVIDER_R3_STARTED', 2, 0))
        self.assertEqual(guard.sequence, self.sequence)
        self.assertEqual('semanticEpoch' in report['lastObservation']['supervisor'], cap != 24)

    def replay(self, cap, sequence=28):
        self.prepare_chain(sequence)
        inputs = self.inputs(cap)
        result = self.issue(inputs, cap)
        head = self.head(C.A)
        self.assertEqual(head['sha256'], C.sha(result['authorization']))
        wrapper_hash = self.upgrade(inputs, result, head)
        self.start(inputs, head, wrapper_hash, cap)

    def test_return_to_v24(self):
        self.replay(24)

    def test_return_to_v26(self):
        self.replay(26)

    def test_return_head_30(self):
        self.replay(None, sequence=30)

    def test_return_head_31(self):
        self.replay(None, sequence=31)

    def test_uncapped_successor(self):
        self.replay(None)

