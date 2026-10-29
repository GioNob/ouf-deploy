"""Root publication/refusal tests and optional real isolated Docker registration."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('registration',ROOT/'register-provider-v2-runtime.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class RegistrationTest(unittest.TestCase):
    def setUp(self):
        self.root=Path(tempfile.mkdtemp(prefix='ouf-registration-',dir='/root'));self.root.chmod(0o700)
        self.addCleanup(shutil.rmtree,self.root)
        self.package=self.root/'package';self.package.mkdir(mode=0o700)
        shutil.copytree(ROOT/'source',self.package/'source')
        for p in (self.package/'source').rglob('*'):p.chmod(0o700 if p.is_dir() else 0o600)
        for n in ('sources.json',m.SELF):shutil.copyfile(ROOT/n,self.package/n);(self.package/n).chmod(0o600)
        self.daemon=self.root/'daemon.json';self.wrapper=self.root/'wrapper'
        self.guard=self.root/'guard.json';self.lock=self.root/'guard.lock'
        self.guard.write_bytes(m.encoded({'lockFile':str(self.lock)}));self.guard.chmod(0o600)
        self.lock.touch(mode=0o600)
        self.execfile=self.root/'command';self.execfile.write_bytes(b'#!/bin/sh\nexit 0\n');self.execfile.chmod(0o755)
        self.patches=[patch.object(m,'DAEMON',self.daemon),patch.object(m,'WRAPPER',self.wrapper),
            patch.object(m,'GUARD',self.guard),patch.object(m,'GUARD_HASH',m.sha(self.guard.read_bytes())),
            patch.object(m,'BINDS',{k:(str(self.execfile),m.sha(self.execfile.read_bytes())) for k in ('python','runc','docker')}),
            patch.object(m,'daemon_pid',return_value=123),patch.object(m,'identity',return_value={'pid':123,'birth':'1','path':str(self.execfile),'sha256':m.sha(self.execfile.read_bytes())}),
            patch.object(m,'preflight',return_value={'custody':True}),patch.object(m,'inventory',return_value=['old-running']),
            patch.object(m,'capture',return_value=b'runc version 1.3'),patch.object(m.os,'pidfd_open',side_effect=lambda pid:os.open('/dev/null',os.O_RDONLY)),
            patch.object(m.signal,'pidfd_send_signal')]
        for p in self.patches:p.start();self.addCleanup(p.stop)
        self.old={'default':'runc','runtimes':{'runc':{'path':'runc'},'io.containerd.runc.v2':{'path':'runc'}}}
        self.new={'default':'runc','runtimes':{**self.old['runtimes'],m.NAME:{'path':str(self.wrapper)}}}
        self.hash=m.sha((self.package/'sources.json').read_bytes())
    def run_register(self, catalogues=None):
        with patch.object(m,'runtimes',side_effect=catalogues or [self.old,self.new]):return m.operate(self.package,self.hash)
    def test_registration_adds_only_runtime_and_never_allows_candidate(self):
        r=self.run_register();cfg=m.parse((self.package/'adapter-configuration.json').read_bytes())
        self.assertEqual(cfg['candidates'],{});self.assertFalse(r['startAuthorized'])
        self.assertEqual(m.parse(self.daemon.read_bytes()),{'runtimes':{m.NAME:{'path':str(self.wrapper)}}})
        self.assertTrue(r['daemonPidUnchanged']);self.assertTrue(r['existingContainerStatesUnchanged'])
        self.assertEqual(m.signal.pidfd_send_signal.call_count,1)
    def test_foreign_daemon_is_preserved_without_signal(self):
        self.daemon.write_bytes(b'foreign');self.daemon.chmod(0o600)
        with self.assertRaisesRegex(m.Denied,'FOREIGN_CONFIGURATION'):self.run_register()
        self.assertEqual(self.daemon.read_bytes(),b'foreign');m.signal.pidfd_send_signal.assert_not_called()
    def test_foreign_wrapper_is_preserved(self):
        self.wrapper.symlink_to('/no-such-target')
        with self.assertRaisesRegex(m.Denied,'FOREIGN_CONFIGURATION'):self.run_register()
        self.assertFalse(self.daemon.exists())
    def test_source_tampering_blocks_before_claim(self):
        p=self.package/'source/scripts/semantic_provider_docker_runtime.py';p.write_bytes(p.read_bytes()+b'#changed\n')
        with self.assertRaisesRegex(m.Denied,'SOURCE_CLOSURE_DRIFT'):self.run_register()
        self.assertFalse((self.package/'installation-claim.json').exists())
    def test_default_runtime_drift_is_refused_and_partial_claim_retained(self):
        wrong={**self.new,'default':m.NAME}
        with self.assertRaisesRegex(m.Denied,'RUNTIME_REGISTRATION_READBACK'):self.run_register([self.old,wrong])
        self.assertTrue((self.package/'installation-claim.json').exists());self.assertFalse((self.package/'registration-receipt.json').exists())
    def test_existing_container_restart_is_not_reported_as_preserved(self):
        m.inventory.side_effect=[['old-running'],['old-running'],['old-restarted']]
        with self.assertRaisesRegex(m.Denied,'LIVE_STATE_OR_OWNED_FILES'):self.run_register()
        self.assertFalse((self.package/'registration-receipt.json').exists())
    def test_completed_apply_cannot_be_replayed(self):
        self.run_register();receipt=(self.package/'registration-receipt.json').read_bytes()
        with self.assertRaisesRegex(m.Denied,'FOREIGN_CONFIGURATION'):self.run_register()
        self.assertEqual(receipt,(self.package/'registration-receipt.json').read_bytes())
    def test_source_failure_after_claim_retains_files_without_second_signal(self):
        def changed(*args):
            p=self.package/m.SELF;p.write_bytes(p.read_bytes()+b'\n')
        m.signal.pidfd_send_signal.side_effect=changed
        with self.assertRaisesRegex(m.Denied,'INSTALLATION_INPUT_DRIFT'):self.run_register()
        self.assertTrue(self.daemon.exists());self.assertFalse((self.package/'registration-receipt.json').exists())

if __name__=='__main__':unittest.main()
