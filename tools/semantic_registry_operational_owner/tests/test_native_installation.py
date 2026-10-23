"""Real installation/manager sandbox, with declared synthetic history and IAM."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

import test_native_transport as fixture_transport
import native_installation_fixture as fixture_installation
from tools.semantic_registry_operational_owner import core,installation,guard

ROOT=Path(__file__).resolve().parents[3]


@unittest.skipUnless(os.environ.get('OUF_NATIVE_OPERATIONAL_OWNER')=='1','Explicit disposable native root scope required')
class Installation(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture_transport.NativeOwner(methodName='runTest');self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_dual_signature_installation_commits_fence_last_and_cannot_replay(self):
        f=fixture_installation.prepare(self.fixture,ROOT);review=f['review'];before=core.encoded(f['inputs'])
        result=installation.install_files(review,f['authority'],f['attestor'])
        self.assertEqual(result['status'],'NORMAL_RENEWAL_INSTALLED_NOT_STARTED')
        self.assertEqual((result['engineGets'],result['tokenGrants']),(2,0))
        c=review['configuration'];root=Path(c['destinations']['installationRoot'])
        self.assertEqual(installation.read_object(f['legacyFence']),c['fenceBinding']['value'])
        self.assertEqual(installation.read_object(c['fenceBinding']['path']),c['fenceBinding']['value'])
        self.assertEqual(installation.read_object(Path(c['destinations']['ledgerRoot'])/'state.json')['cumulativeAttempts'],321)
        self.assertTrue((root/'installed.json').exists());self.assertEqual(core.encoded(f['inputs']),before)
        with self.assertRaises((FileExistsError,core.Denied)):installation.install_files(review,f['authority'],f['attestor'])
        self.assertEqual(len(f['calls']),2);self.assertEqual(self.fixture.calls,[])

    def test_last_generation_change_leaves_inactive_fence_and_consumed_claim(self):
        f=fixture_installation.prepare(self.fixture,ROOT);bad=copy.deepcopy(f['registryRow']);bad['State']['Dead']=True
        f['responses'].extend((f['registryRow'],bad));review=f['review']
        with self.assertRaisesRegex(core.Denied,'RUNNING_REGISTRY_GENERATION'):
            installation.install_files(review,f['authority'],f['attestor'])
        self.assertEqual(installation.read_object(f['legacyFence']),f['inputs']['retainedFence']['value'])
        self.assertFalse(installation.read_object(review['configuration']['fenceBinding']['path'])['active'])
        with self.assertRaises(FileExistsError):installation.install_files(review,f['authority'],f['attestor'])
        self.assertEqual(len(f['calls']),2);self.assertEqual(self.fixture.calls,[])

    def test_missing_actual_final_signature_denies_before_file_or_engine_effect(self):
        f=fixture_installation.prepare(self.fixture,ROOT)
        path=f['authority'].verifier.signature_directory/(hashlib.sha256(f['authority'].raw).hexdigest()+'.FINAL_DEPLOYMENT_APPROVAL.json')
        path.unlink()
        with self.assertRaises(Exception):installation.install_files(f['review'],f['authority'],f['attestor'])
        self.assertEqual(f['calls'],[])
        self.assertFalse(Path(f['review']['configuration']['destinations']['installationRoot']).exists())

    def manager(self,*args):
        result=subprocess.run(['/usr/bin/systemctl',*args],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr);return result.stdout

    def cleanup_unit(self,unit,path):
        subprocess.run(['/usr/bin/systemctl','disable','--now',unit],capture_output=True,timeout=30)
        path.unlink(missing_ok=True)
        subprocess.run(['/usr/bin/systemctl','daemon-reload'],capture_output=True,timeout=30)

    def wait_publications(self,c,number,seconds):
        until=time.monotonic()+seconds;path=Path(c['destinations']['ledgerRoot'])/'state.json'
        while time.monotonic()<until:
            row=installation.read_object(path)
            if row['publications']>=number:return row
            if row['state']=='BLOCKED':self.fail('Actual operational owner parked: '+row['reason'])
            time.sleep(0.5)
        logs=subprocess.run(['/usr/bin/journalctl','-u',Path(c['serviceUnitPath']).name,'--no-pager','-n','30'],capture_output=True,text=True,timeout=10)
        self.fail('Native manager publication deadline: '+logs.stdout)

    def test_actual_systemd_private_root_sealed_capsule_restart_renewal_and_fence_revocation(self):
        self.assertEqual(subprocess.run(['/usr/bin/systemctl','is-system-running'],capture_output=True).returncode in(0,1),True)
        f=fixture_installation.prepare(self.fixture,ROOT,real_unit=True);review=f['review'];c=review['configuration']
        unit=Path(c['serviceUnitPath']);self.addCleanup(self.cleanup_unit,unit.name,unit)
        installation.install_files(review,f['authority'],f['attestor'])
        self.manager('daemon-reload');self.manager('start',unit.name)
        first=self.wait_publications(c,1,45)
        pid=int(self.manager('show',unit.name,'--property=MainPID','--value').strip());self.assertGreater(pid,0)
        process_root=Path('/proc')/str(pid)/'root'
        self.assertFalse((process_root/str(self.fixture.signing_key).lstrip('/')).exists())
        self.assertFalse((process_root/'run/docker.sock').exists())
        self.assertFalse((process_root/'proc/1/root').exists())
        self.assertTrue((process_root/str(self.fixture.secret).lstrip('/')).exists())
        self.manager('restart',unit.name);after=self.wait_publications(c,1,30)
        self.assertEqual(first['cumulativeAttempts'],after['cumulativeAttempts'])
        second=self.wait_publications(c,2,80)
        self.assertEqual(second['cumulativeAttempts'],323);self.assertEqual(second['publications'],2)
        # Atomic replacement must be seen through the DIRECTORY bind. A bind
        # of just fence.json would incorrectly keep the old inode forever.
        fence=Path(c['fenceBinding']['path']);replacement=fence.with_name('fixture-revoke.json')
        self.fixture.write(replacement,core.encoded(dict(c['fenceBinding']['value'],active=False)));os.replace(replacement,fence)
        until=time.monotonic()+12
        while time.monotonic()<until:
            state=self.manager('show',unit.name,'--property=MainPID','--value').strip()
            if state=='0':break
            time.sleep(0.5)
        self.assertEqual(state,'0')
        self.assertEqual(sum(p.endswith('/token') for p,_ in self.fixture.calls),2)


if __name__=='__main__':unittest.main()
