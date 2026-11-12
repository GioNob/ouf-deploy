"""V5 contract, native custody and real ephemeral Ed25519 signatures.

No Docker daemon or external service. runc/broker/driver are simulated; only
OpenSSL operates natively, using keys generated solely inside each test fixture.
"""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT/'tools/semantic_runtime_v5'
HISTORICAL = ROOT/'tools/semantic_cohort_admission/cohort-draft/scripts'
CID, PEER = 'a'*64, 'b'*64
NATIVE = os.environ.get('OUF_RUNTIME_V5_NATIVE') == '1'
if NATIVE and (sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError('OUF_RUNTIME_V5_NATIVE requires Linux root:root; refusing to skip')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


@unittest.skipUnless(NATIVE, 'set OUF_RUNTIME_V5_NATIVE=1 under native Linux root')
class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ouf-runtime-v5-', dir='/run')
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.addCleanup(os.umask, os.umask(0o077))
        self.runtime_source = self.root/'semantic_provider_docker_runtime_v5.py'
        self.verifier_source = self.root/'arming_verifier.py'
        self.authority_source = self.root/'authority.py'
        for source, destination in ((SOURCES/self.runtime_source.name, self.runtime_source),
                (SOURCES/self.verifier_source.name, self.verifier_source),
                (ROOT/'tools/semantic_b1b2_authority/authority.py', self.authority_source)):
            self.write(destination, source.read_bytes())
        self.r = module(self.runtime_source, 'runtime_v5_fixture')
        self.v = module(self.verifier_source, 'arming_verifier_fixture')
        self.a = module(self.authority_source, 'authority_fixture')
        self.arming_root = self.root/'arming'; self.arming_root.mkdir(mode=0o700)
        self.registry = self.root/'registry'; self.registry.mkdir(mode=0o700)
        self.bundle_parent = self.root/'bundles'; self.bundle_parent.mkdir(mode=0o700)
        self.bundle = self.bundle_parent/CID; self.bundle.mkdir(mode=0o700)
        self.oci = {'root': {'path': str(self.root/'rootfs')}, 'linux': {'namespaces': [{'type':'network'}]}}
        self.write(self.bundle/'config.json', self.oci)
        self.runtime = self.root/'runc'; self.write(self.runtime, b'#!/bin/sh\nexit 99\n', 0o700)
        self.driver = self.root/'driver.py'; self.write(self.driver, b'# simulated driver\n')
        self.broker = self.root/'broker.py'; self.write(self.broker, (HISTORICAL/'semantic_provider_deployment_broker.py').read_bytes())
        self.openssl = Path('/usr/bin/openssl').resolve(strict=True)
        self.python = Path(sys.executable).resolve(strict=True)
        self.key = self.root/'EPHEMERAL-TEST-KEY.pem'
        self.native('genpkey', '-algorithm', 'Ed25519', '-out', str(self.key)); self.key.chmod(0o600)
        public = self.native('pkey', '-in', str(self.key), '-pubout', '-outform', 'DER')[12:].hex()
        self.policy_path = self.root/'policy.json'
        self.policy = {'schema':self.a.POLICY_SCHEMA, 'installationRef':'test-installation', 'entityRef':'test-entity',
            'basePolicy':{'path':str(self.root/'unopened-base.json'), 'sha256':'c'*64},
            'authorityProfile':{'path':str(self.root/'unopened-authority.json'), 'sha256':'d'*64},
            'keys':[{'keyRef':'test-key', 'issuerRef':'test-issuer', 'roles':['RUNTIME_ARMING','ARTIFACT_ACCEPTANCE'],
                     'publicKey':public, 'notBefore':0, 'expiresAt':4102444800, 'state':'ACTIVE'}]}
        self.write(self.policy_path, self.policy)
        self.acceptance = self.root/'acceptance.json'; self.write(self.acceptance, {'fixture':'B1 manifest bytes'})
        ssl = self.pin(self.openssl) | {'version':self.native('version').decode().split()[1]}
        self.admissions = {}
        for cid in (CID, PEER):
            path = self.root/(cid+'.broker.json')
            cfg = {'schema':'ouf.semantic-deployment-broker.v1', 'sourceRoot':str(self.root), 'sourceHashes':{},
                'authorities':{}, 'intentBinding':{'path':str(self.root/(cid+'.intent.json')), 'sha256':'e'*64},
                'policyBinding':{}, 'signatureDirectory':str(self.root), 'opensslBinding':ssl, 'producers':{},
                'preparerTemplate':{}, 'candidateRoot':str(self.registry/cid), 'runtimeRootParent':str(self.root/'state')}
            self.write(path, cfg); self.admissions[cid] = path
        self.config_path = self.root/'runtime.json'
        self.config = {'schema':self.r.SCHEMA, 'sourceHash':sha(self.runtime_source.read_bytes()),
            'runtimePath':str(self.runtime), 'runtimeSha256':sha(self.runtime.read_bytes()),
            'pythonPath':str(self.python), 'pythonSha256':sha(self.python.read_bytes()),
            'driverPath':str(self.driver), 'driverSha256':sha(self.driver.read_bytes()),
            'admissionPath':str(self.broker), 'admissionSha256':sha(self.broker.read_bytes()),
            'registryRoot':str(self.registry), 'runtimeStateRoot':str(self.root/'state'),
            'acceptance':self.pin(self.acceptance), 'b1b2TrustPolicy':self.pin(self.policy_path),
            'armingRoot':str(self.arming_root), 'armingVerifierPath':str(self.verifier_source),
            'armingVerifierSha256':sha(self.verifier_source.read_bytes()), 'b1b2AuthorityModule':self.pin(self.authority_source),
            'opensslBinding':ssl, 'armingIssuerRef':'test-issuer',
            'candidates':{cid:{'phase':'INACTIVE','bundleParents':[str(self.bundle_parent)]} for cid in (CID,PEER)}}
        self.refresh()
        self.calls = []; self.exists = False; self.verifier_ok = True; self.broker_ok = True
        self.runc_create_ok = True

    def write(self, path, value, mode=0o600):
        path.write_bytes(value if isinstance(value, bytes) else encoded(value)); path.chmod(mode)

    def pin(self, path): return {'path':str(path), 'sha256':sha(path.read_bytes())}

    def refresh(self): self.write(self.config_path, self.config)

    def native(self, *args):
        return subprocess.run([str(self.openssl), *args], check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'}).stdout

    def sign(self, raw, role='RUNTIME_ARMING', issuer='test-issuer', wrong_domain=False):
        header = {'schema':self.a.SIGNATURE_SCHEMA, 'algorithm':'Ed25519','keyRef':'test-key', 'role':role,
            'issuerRef':issuer,'installationRef':'test-installation','entityRef':'test-entity','payloadHash':sha(raw)}
        frame = self.a.signing_bytes(raw, header)
        if wrong_domain: frame = b'OUF-DEPLOYMENT-EVIDENCE\0V1\0'+frame[len(self.a.DOMAIN):]
        frame_path = self.root/'test-signing-frame'; self.write(frame_path, frame)
        signature = self.native('pkeyutl', '-sign','-rawin','-inkey',str(self.key),'-in',str(frame_path)).hex()
        return encoded(header | {'signature':signature})

    def arm(self, generation=1, changes=None, role='RUNTIME_ARMING', issuer='test-issuer', wrong_domain=False):
        value = {'schema':self.r.ARMING_SCHEMA, 'installationRef':'test-installation','entityRef':'test-entity',
            'generation':generation, 'runtimeConfigurationSha256':sha(self.config_path.read_bytes()),
            'acceptanceSha256':self.config['acceptance']['sha256'], 'issuedAt':1,
            'candidates':{cid:{'intentRef':'e'*64,'admissionConfiguration':str(path),
                              'admissionConfigurationHash':sha(path.read_bytes())} for cid,path in self.admissions.items()}}
        if changes: value.update(changes)
        raw = encoded(value); self.write(self.arming_root/(str(generation)+'.json'), raw)
        self.write(self.arming_root/(str(generation)+'.RUNTIME_ARMING.json'), self.sign(raw,role,issuer,wrong_domain))
        return value, raw

    def marker(self, generation=1): return self.arming_root/(str(generation)+'.'+CID+'.consumed')

    def stage(self, raw, state='STAGED'):
        directory = self.registry/CID; directory.mkdir(mode=0o700, exist_ok=True)
        self.write(directory/'operation.lock', b'lock')
        self.write(directory/'adapter.json', {'schema':'ouf.semantic-docker-runtime-journal.v1','containerId':CID,
            'configurationHash':self.r.binding_v5(self.config,CID,raw), 'state':state, 'runtimeRoot':None,
            'bundleHash':self.r.digest(self.oci) if state != 'STAGED' else None, 'driverHash':None,
            'armingGeneration':json.loads(raw)['generation']})
        if state != 'STAGED':
            (directory/'bundle').mkdir(mode=0o700,exist_ok=True); self.write(directory/'bundle/config.json',self.oci)

    def args(self, operation):
        values = ['--root',str(self.root/'state/moby'),operation]
        if operation == 'create': values += ['--bundle',str(self.bundle)]
        values += [CID]
        if operation == 'kill': values += ['SIGTERM']
        return values

    def prepare_driver(self):
        directory = self.registry/CID
        arming = json.loads((self.arming_root/'1.json').read_bytes()); entry = arming['candidates'][CID]
        binding = {'installationRef':'test-installation','entityRef':'test-entity','containerId':CID,'transactionId':'tx',
            'intentHash':entry['intentRef'],'configurationHash':entry['admissionConfigurationHash']}
        grant = {'schema':'ouf.semantic-preexec-driver.v5','sourceRoot':str(self.root),
            'sourceHashes':{'scripts/semantic_provider_preexec_hook.py':self.config['driverSha256']},
            'profile':{'containerId':CID,'bundlePath':str(directory/'bundle'),'bundleHash':self.r.digest(self.oci),
                'applicationStartAuthorized':True,'infrastructureAuthorityComplete':True,'namespaceInode':42},
            'runtimeBinding':{'path':str(self.runtime),'sha256':self.config['runtimeSha256'],'root':str(self.root/'state/moby')},
            'consumptionBinding':{'journalPath':str(directory/'deployment.json'),'binding':binding,'evidenceHash':'f'*64},
            'authorityScope':binding,'authorityBinding':{'sha256':'1'*64}}
        # The historical driver contract uses this exact source-owned filename.
        grant['sourceRoot'] = str(self.driver.parent.parent)
        raw = encoded(grant); self.write(directory/'driver.json',raw)
        self.write(directory/'deployment.json',binding | {'state':'READY','evidenceHash':'f'*64,'driverHash':sha(raw),
            'bundleHash':self.r.digest(self.oci),'approvalHash':'1'*64,'generation':{'pid':123,'namespaceInode':42}})

    def simulate(self, argv, **kwargs):
        self.calls.append(list(argv)); code = 0; output = b''; error = b''
        if str(self.verifier_source) in argv:
            self.assertFalse(self.marker().exists()); self.assertEqual(argv[1:3],['-I','-B'])
            self.assertEqual(kwargs['timeout'],20); self.assertEqual(kwargs['env'],self.r.ENV)
            code = 0 if self.verifier_ok else 1; output = b'RUNTIME_ARMING_VERIFIED\n'
        elif str(self.broker) in argv:
            self.assertNotIn('--arming',argv); self.assertNotIn('--b1b2-trust-policy',argv)
            mode = argv[-1]
            if mode == 'authorize-create':
                self.assertTrue(self.marker().exists()); self.assertEqual(stat.S_IMODE(self.marker().stat().st_mode),0o600)
                code = 0 if self.broker_ok else 1
            if mode == 'prepare': self.prepare_driver()
        elif argv[0] == str(self.runtime):
            if 'state' in argv:
                if self.exists: output = encoded({'id':CID,'bundle':str(self.registry/CID/'bundle'),'status':'created','pid':123})
                else: code = 1; error = b'container does not exist\n'
            elif 'create' in argv:
                self.exists = self.runc_create_ok; code = 0 if self.runc_create_ok else 1
        elif str(self.driver) not in argv:
            self.fail('unexpected subprocess')
        if hasattr(kwargs.get('stdout'), 'write'): kwargs['stdout'].write(output)
        if hasattr(kwargs.get('stderr'), 'write'): kwargs['stderr'].write(error)
        return subprocess.CompletedProcess(argv, code)

    def operate(self, operation):
        with patch.object(self.r.subprocess,'run',side_effect=self.simulate):
            return self.r.operate(self.config_path,self.args(operation))


class RuntimeTests(Fixture):
    def test_valid_v5_and_reject_v4_missing_unknown_fields(self):
        self.assertEqual(self.r.load_configuration(self.config_path)[0],self.config)
        for change in ({'schema':'ouf.semantic-docker-runtime-adapter.v4'},{'extra':True},
                       {'candidates':{CID:self.config['candidates'][CID]}}, {'armingIssuerRef':'bad/issuer'}):
            self.write(self.config_path,self.config | change)
            with self.subTest(change=change), self.assertRaises(self.r.Denied): self.r.load_configuration(self.config_path)
        for key in self.config:
            value = copy.deepcopy(self.config); del value[key]; self.write(self.config_path,value)
            with self.subTest(missing=key), self.assertRaises(self.r.Denied): self.r.load_configuration(self.config_path)

    def test_bad_candidate_schema_and_bundle_parents(self):
        for entry in ({'phase':'ACTIVE','bundleParents':[str(self.bundle_parent)]},
                      {'phase':'INACTIVE','bundleParents':[]}, {'phase':'INACTIVE','bundleParents':['relative']},
                      {'phase':'INACTIVE','bundleParents':[str(self.bundle_parent)],'intentRef':'e'*64}):
            cfg = copy.deepcopy(self.config); cfg['candidates'][CID] = entry; self.write(self.config_path,cfg)
            with self.subTest(entry=entry), self.assertRaises(self.r.Denied): self.r.load_configuration(self.config_path)

    def test_inactive_create_start_kill_never_call_children_or_create_journal(self):
        for operation in ('create','start','kill'):
            with self.subTest(operation=operation), self.assertRaisesRegex(self.r.Denied,'RUNTIME_PHASE_INACTIVE'):
                self.operate(operation)
        self.assertEqual(self.calls,[]); self.assertEqual(list(self.registry.iterdir()),[])

    def test_inactive_state_delete_absent_pass_runc_result(self):
        for operation in ('state','delete'):
            with self.subTest(operation=operation): self.assertEqual(self.operate(operation),1 if operation == 'state' else 0)
        self.assertEqual(list(self.registry.iterdir()),[])
        self.assertEqual(len(self.calls),4)

    def test_inactive_state_delete_existing_container_denied(self):
        self.exists = True
        for operation in ('state','delete'):
            with self.subTest(operation=operation), self.assertRaisesRegex(self.r.Denied,'RUNTIME_PHASE_INACTIVE_UNEXPECTED_CONTAINER'):
                self.operate(operation)
        self.assertTrue(all('state' in call for call in self.calls))

    def test_inactive_generic_runc_error_is_not_absence(self):
        def failed(argv, **kwargs):
            kwargs['stderr'].write(b'permission denied'); return subprocess.CompletedProcess(argv,1)
        with patch.object(self.r.subprocess,'run',side_effect=failed), self.assertRaisesRegex(self.r.Denied,'INACTIVE_RUNTIME_ABSENCE_UNPROVEN'):
            self.r.operate(self.config_path,self.args('delete'))

    def test_staged_journal_without_arming_still_inactive(self):
        _, raw = self.arm(); self.stage(raw)
        for path in self.arming_root.iterdir(): path.unlink()
        for operation in ('create','start','kill'):
            with self.subTest(operation=operation), self.assertRaisesRegex(self.r.Denied,'RUNTIME_PHASE_INACTIVE'):
                self.operate(operation)
        self.assertEqual(self.operate('state'),1); self.assertEqual(self.operate('delete'),0)

    def test_selection_absent_one_two_no_latest_and_per_cid_consumption(self):
        with self.assertRaisesRegex(self.r.Denied,'RUNTIME_PHASE_INACTIVE'):
            self.r.select_arming(self.config,self.config_path.read_bytes(),CID)
        one, raw = self.arm()
        self.assertEqual(self.r.select_arming(self.config,self.config_path.read_bytes(),CID),(one,raw))
        self.arm(2)
        with self.assertRaisesRegex(self.r.Denied,'ARMING_GENERATION_AMBIGUOUS'):
            self.r.select_arming(self.config,self.config_path.read_bytes(),CID)
        self.r.consume_arming(self.config,CID,raw)
        self.assertEqual(self.r.select_arming(self.config,self.config_path.read_bytes(),CID)[0]['generation'],2)
        with self.assertRaisesRegex(self.r.Denied,'ARMING_GENERATION_AMBIGUOUS'):
            self.r.select_arming(self.config,self.config_path.read_bytes(),PEER)

    def test_arming_wrong_configuration_manifest_cids_generation_and_schema(self):
        one, _ = self.arm()
        for change in ({'runtimeConfigurationSha256':'0'*64}, {'acceptanceSha256':'0'*64},
                {'candidates':{CID:one['candidates'][CID],'c'*64:one['candidates'][PEER]}},
                {'generation':2},{'generation':True},{'schema':'wrong'},{'extra':True}):
            self.arm(changes=change)
            with self.subTest(change=change), self.assertRaises(self.r.Denied):
                self.r.load_arming(self.config,self.config_path.read_bytes(),1)

    def test_root_file_modes_owner_links_and_symlinks_fail_closed(self):
        self.arm()
        paths = [self.config_path,self.arming_root/'1.json',self.arming_root/'1.RUNTIME_ARMING.json']
        for path in paths:
            for defect in ('mode','uid','gid','hardlink','symlink'):
                saved = self.root/'saved'
                if defect == 'mode': path.chmod(0o644)
                elif defect in ('uid','gid'): os.chown(path,int(defect == 'uid'),int(defect == 'gid'))
                elif defect == 'hardlink': os.link(path,saved)
                else: path.rename(saved); path.symlink_to(saved)
                try:
                    with self.subTest(path=path.name,defect=defect), self.assertRaises((self.r.Denied,OSError)):
                        if path == self.config_path: self.r.load_configuration(path)
                        else: self.r.load_arming(self.config,self.config_path.read_bytes(),1)
                finally:
                    if defect == 'hardlink': saved.unlink()
                    if defect == 'symlink': path.unlink(); saved.rename(path)
                    os.chown(path,0,0); path.chmod(0o600)
        self.arming_root.chmod(0o755)
        with self.assertRaises(self.r.Denied): self.r.load_configuration(self.config_path)

    def test_all_hashes_checked_on_every_cid_operation(self):
        for key in ('sourceHash','runtimeSha256','pythonSha256','driverSha256','admissionSha256','armingVerifierSha256'):
            self.write(self.config_path,self.config | {key:'0'*64})
            with self.subTest(key=key), self.assertRaises(self.r.Denied): self.operate('state')
        for key in ('acceptance','b1b2TrustPolicy','b1b2AuthorityModule','opensslBinding'):
            self.write(self.config_path,self.config | {key:self.config[key] | {'sha256':'0'*64}})
            with self.subTest(key=key), self.assertRaises(self.r.Denied): self.operate('state')
        self.assertEqual(self.calls,[])

    def test_binding_is_deterministic_exact_bytes_merged_and_distinct_from_v4(self):
        value, raw = self.arm(); result = self.r.binding_v5(self.config,CID,raw)
        expected = {k:v for k,v in self.config.items() if k != 'candidates'}
        expected.update(candidate=self.config['candidates'][CID] | value['candidates'][CID],
                        armingGeneration=1,armingPayloadSha256=sha(raw))
        self.assertEqual(result,self.r.digest(expected))
        self.assertEqual(result,self.r.binding_v5(dict(reversed(list(self.config.items()))),CID,raw))
        self.assertNotEqual(result,self.r.binding_v5(self.config,CID,raw+b'\n'))
        self.assertNotEqual(result,self.r.binding(self.config,CID))

    def test_marker_atomic_precedes_broker_failed_create_is_consumed(self):
        _, raw = self.arm(); self.stage(raw); self.broker_ok = False
        with self.assertRaisesRegex(self.r.Denied,'TWO_PHASE_BROKER_DENIED'): self.operate('create')
        self.assertEqual(json.loads(self.marker().read_bytes()),{'generation':1,'armingPayloadSha256':sha(raw)})
        self.assertEqual(self.marker().stat().st_nlink,1)
        with self.assertRaises(FileExistsError): self.r.consume_arming(self.config,CID,raw)
        before = len(self.calls)
        with self.assertRaisesRegex(self.r.Denied,'RUNTIME_PHASE_INACTIVE'): self.operate('create')
        self.assertEqual(len(self.calls),before)
        self.assertEqual(json.loads((self.registry/CID/'adapter.json').read_bytes())['state'],'STAGED')

    def test_failed_runc_create_leaves_marker_and_creating_journal(self):
        _, raw = self.arm(); self.stage(raw); self.runc_create_ok = False
        with self.assertRaisesRegex(self.r.Denied,'RUNTIME_CREATE_DENIED'): self.operate('create')
        self.assertTrue(self.marker().exists())
        self.assertEqual(json.loads((self.registry/CID/'adapter.json').read_bytes())['state'],'CREATING')

    def test_verifier_failure_no_marker_no_broker_and_no_journal_write(self):
        _, raw = self.arm(); self.stage(raw); self.verifier_ok = False
        path = self.registry/CID/'adapter.json'; before = path.read_bytes()
        with self.assertRaises(self.r.Denied): self.operate('create')
        self.assertFalse(self.marker().exists()); self.assertEqual(path.read_bytes(),before)
        self.assertEqual(len(self.calls),1)

    def test_create_passes_historical_broker_arguments_and_records_generation(self):
        _, raw = self.arm(); self.stage(raw)
        self.assertEqual(self.operate('create'),0)
        record = json.loads((self.registry/CID/'adapter.json').read_bytes())
        self.assertEqual((record['state'],record['armingGeneration']),('CREATED',1))
        modes = [call[-1] for call in self.calls if str(self.broker) in call]
        self.assertEqual(modes,['authorize-create','record-created'])

    def test_start_uses_only_journal_generation_even_with_two_new_ones(self):
        # Use the actual legacy source-owned driver filename for admit().
        directory = self.root/'scripts'; directory.mkdir(mode=0o700)
        self.driver = directory/'semantic_provider_preexec_hook.py'; self.write(self.driver,b'# simulated driver\n')
        self.config['driverPath'] = str(self.driver); self.refresh()
        _, raw = self.arm(); self.stage(raw)
        self.assertEqual(self.operate('create'),0)
        self.arm(2); self.arm(3); self.calls.clear()
        self.assertEqual(self.operate('start'),0)
        record = json.loads((self.registry/CID/'adapter.json').read_bytes())
        self.assertEqual((record['state'],record['armingGeneration']),('STARTED',1))
        self.assertFalse(any(str(self.verifier_source) in call for call in self.calls))
        self.assertFalse(self.marker(2).exists()); self.assertFalse(self.marker(3).exists())

    def test_wrong_journal_generation_binding_and_consumed_payload_denied(self):
        _, raw = self.arm(); self.stage(raw,'CREATED'); self.r.consume_arming(self.config,CID,raw)
        self.arm(2)
        path = self.registry/CID/'adapter.json'; old = json.loads(path.read_bytes())
        self.write(path,old | {'armingGeneration':2})
        with self.assertRaisesRegex(self.r.Denied,'V5_JOURNAL_BINDING_DRIFT'): self.operate('start')
        self.write(path,old); self.write(self.marker(),{'generation':1,'armingPayloadSha256':'0'*64})
        with self.assertRaisesRegex(self.r.Denied,'CONSUMED_ARMING_BINDING_DRIFT'): self.operate('state')

    def test_absence_read_only_includes_orphans_and_markers(self):
        empty = {'armingGenerations':[],'consumedMarkers':[]}
        with patch.object(self.r.subprocess,'run',side_effect=AssertionError('no child')):
            self.assertEqual(self.r.arming_absence(self.config_path),empty)
        _, raw = self.arm(); self.r.consume_arming(self.config,CID,raw)
        (self.arming_root/'1.json').unlink()
        before = {p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(self.r.subprocess,'run',side_effect=AssertionError('no child')):
            self.assertEqual(self.r.arming_absence(self.config_path),{'armingGenerations':[1],'consumedMarkers':[self.marker().name]})
            self.assertEqual(before,{p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        self.write(self.arming_root/'unexpected',b'unknown')
        with self.assertRaises(self.r.Denied): self.r.arming_absence(self.config_path)

    def test_no_cid_operations_still_delegate(self):
        with patch.object(self.r.subprocess,'run',return_value=subprocess.CompletedProcess([],0)) as run:
            self.assertEqual(self.r.operate(self.config_path,['--version']),0)
        self.assertEqual(run.call_args.args[0],[str(self.runtime),'--version'])


class VerifierTests(Fixture):
    def cli(self):
        return subprocess.run([str(self.python),'-I','-B',str(self.verifier_source),'--configuration',str(self.config_path),
            '--container-id',CID,'--generation','1'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=25,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})

    def test_real_signature_and_isolated_cli_constant_stdout(self):
        self.arm(); result = self.cli()
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'RUNTIME_ARMING_VERIFIED\n',b''))

    def test_wrong_role_domain_issuer_scope_and_expired_mandate(self):
        for options in ({'role':'ARTIFACT_ACCEPTANCE'},{'wrong_domain':True},{'issuer':'other-issuer'},
                        {'changes':{'installationRef':'other-installation'}},{'changes':{'entityRef':'other-entity'}}):
            self.arm(**options)
            with self.subTest(options=options): self.assertNotEqual(self.cli().returncode,0)
        self.policy['keys'][0]['expiresAt'] = 1; self.write(self.policy_path,self.policy)
        self.config['b1b2TrustPolicy'] = self.pin(self.policy_path); self.refresh(); self.arm()
        self.assertNotEqual(self.cli().returncode,0)

    def test_historical_envelope_schema_rejected(self):
        self.arm(); path = self.arming_root/'1.RUNTIME_ARMING.json'; value = json.loads(path.read_bytes())
        self.write(path,value | {'schema':'ouf.semantic-deployment-detached-signature.v1'})
        self.assertNotEqual(self.cli().returncode,0)

    def test_module_hash_mismatch_rejected_before_execution(self):
        sentinel = self.root/'MODULE-WAS-EXECUTED'
        self.write(self.authority_source,('from pathlib import Path\nPath('+repr(str(sentinel))+').touch()\n').encode())
        self.arm(); self.assertNotEqual(self.cli().returncode,0); self.assertFalse(sentinel.exists())

    def test_admission_hash_and_intent_binding_mismatch(self):
        value, _ = self.arm(); value['candidates'][CID]['admissionConfigurationHash'] = '0'*64
        self.arm(changes={'candidates':value['candidates']}); self.assertNotEqual(self.cli().returncode,0)
        value, _ = self.arm(); value['candidates'][CID]['intentRef'] = '0'*64
        self.arm(changes={'candidates':value['candidates']}); self.assertNotEqual(self.cli().returncode,0)

    def test_current_configuration_manifest_policy_and_signature_custody(self):
        self.arm(changes={'runtimeConfigurationSha256':'0'*64}); self.assertNotEqual(self.cli().returncode,0)
        self.arm(changes={'acceptanceSha256':'0'*64}); self.assertNotEqual(self.cli().returncode,0)
        self.arm(); path = self.arming_root/'1.RUNTIME_ARMING.json'; path.chmod(0o644)
        self.assertNotEqual(self.cli().returncode,0); path.chmod(0o600)
        self.policy['entityRef'] = 'other'; self.write(self.policy_path,self.policy)
        self.config['b1b2TrustPolicy'] = self.pin(self.policy_path); self.refresh(); self.arm()
        self.assertNotEqual(self.cli().returncode,0)

    def test_temporary_umask_cleanup_and_no_persistent_writes_success_and_error(self):
        self.arm()
        active = [False]
        violations = []
        tempdir = self.root/'private-temporaries'; tempdir.mkdir(mode=0o700)
        def audit(event, args):
            if not active[0]: return
            if event == 'open' and args[0] == str(self.key): violations.append('private-key-read')
            if event == 'subprocess.Popen' and str(self.key) in args[1]: violations.append('private-key-subprocess')
            writing = event == 'open' and bool(args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            mutating = event in ('os.mkdir','os.remove','os.rmdir','os.rename','os.link','os.symlink','os.chmod')
            if writing or mutating:
                path = args[0]
                if isinstance(path, (str,bytes,os.PathLike)):
                    path = Path(os.fsdecode(path))
                    if not path.is_absolute() and event in ('os.remove','os.rmdir','os.mkdir','os.chmod'):
                        directory_fd = args[-1]
                        if type(directory_fd) is int and directory_fd >= 0:
                            path = Path(os.readlink('/proc/self/fd/'+str(directory_fd)))/path
                    if not (path == tempdir or path.is_relative_to(tempdir)): violations.append(str(path))
                if event in ('os.rename','os.link','os.symlink'):
                    violations.append(event)
        sys.addaudithook(audit)
        for invalid in (False,True):
            if invalid: self.arm(wrong_domain=True)
            before = {p:(p.read_bytes(),self.a.attributes(p.lstat())) for p in self.root.rglob('*') if p.is_file()}
            original_dir, original_file = self.a.tempfile.TemporaryDirectory,self.a.tempfile.TemporaryFile
            observed = []
            def temporary_directory(*args,**kwargs):
                observed.append(os.umask(0o077)); kwargs['dir'] = tempdir
                result = original_dir(*args,**kwargs)
                self.assertEqual(stat.S_IMODE(Path(result.name).stat().st_mode),0o700)
                return result
            def temporary_file(*args,**kwargs):
                observed.append(os.umask(0o077)); kwargs['dir'] = tempdir
                result = original_file(*args,**kwargs)
                self.assertEqual(stat.S_IMODE(os.fstat(result.fileno()).st_mode),0o600)
                return result
            # Authority is loaded afresh by the verifier; tempfile is the shared
            # stdlib module, so these wrappers observe the actual crypto path.
            with patch.object(tempfile,'TemporaryDirectory',side_effect=temporary_directory), \
                    patch.object(tempfile,'TemporaryFile',side_effect=temporary_file):
                active[0] = True
                try:
                    if invalid:
                        with self.assertRaises(Exception): self.v.verify(self.config_path,CID,1)
                    else: self.v.verify(self.config_path,CID,1)
                finally: active[0] = False
            self.assertTrue(observed); self.assertEqual(set(observed),{0o077})
            self.assertEqual(violations,[])
            self.assertEqual(list(tempdir.iterdir()),[])
            self.assertEqual(before,{p:(p.read_bytes(),self.a.attributes(p.lstat())) for p in self.root.rglob('*') if p.is_file()})


if __name__ == '__main__': unittest.main()
