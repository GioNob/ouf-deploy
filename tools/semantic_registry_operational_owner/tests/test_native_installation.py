"""Real installation/manager sandbox, with declared synthetic history and IAM."""
import copy
import hashlib
import importlib.util
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

    def test_temporary_network_probe_actual_cgroup_root_allow_and_deny_without_worker_restart(self):
        spec=importlib.util.spec_from_file_location('actual_worker_network_probe',ROOT/'scripts/probe-registry-operational-network-20261024.py')
        probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
        f=fixture_installation.prepare(self.fixture,ROOT,real_unit=True);review=f['review'];c=review['configuration']
        unit=Path(c['serviceUnitPath']);self.addCleanup(self.cleanup_unit,unit.name,unit)
        installation.install_files(review,f['authority'],f['attestor'])
        self.manager('daemon-reload');self.manager('start',unit.name);self.wait_publications(c,1,45)
        pid=int(self.manager('show',unit.name,'--property=MainPID','--value').strip())
        group=self.manager('show',unit.name,'--property=ControlGroup','--value').strip()
        ledger=Path(c['destinations']['ledgerRoot'])/'state.json';before=ledger.read_bytes()
        ca=Path(c['tlsCa']['path']).read_bytes();calls=sum(path.endswith('/token') for path,_ in self.fixture.calls)
        result=probe.in_worker_group(c,pid,group,ca)
        self.assertTrue(result['probeProcessExited'] and result['workerGenerationUnchanged'])
        self.assertEqual(result['probe']['httpStatus'],200);self.assertTrue(result['probe']['discoveryMatchesConfiguredEndpoints'])
        self.assertTrue(result['probe']['privateRootEntered'] and result['probe']['capabilitiesDropped'])
        self.assertTrue(result['probe']['mountNamespaceJoined'])
        self.assertEqual(ledger.read_bytes(),before)
        self.assertEqual(sum(path.endswith('/token') for path,_ in self.fixture.calls),calls)
        self.assertEqual(int(self.manager('show',unit.name,'--property=MainPID','--value').strip()),pid)
        # A separate disposable sleep unit has the SAME private root and deny
        # policy but no IP allow rule. No production unit is edited here.
        deny=unit.with_name(unit.stem+'-probe-deny.service');self.addCleanup(self.cleanup_unit,deny.name,deny)
        lines=[]
        for line in review['serviceUnit']['body'].splitlines():
            if line.startswith('IPAddressAllow='):continue
            if line.startswith('ExecStart='):line='ExecStart=/usr/bin/sleep 60'
            lines.append(line)
        deny.write_text('\n'.join(lines)+'\n');deny.chmod(0o644)
        self.manager('daemon-reload');self.manager('start',deny.name)
        denied_pid=int(self.manager('show',deny.name,'--property=MainPID','--value').strip())
        denied_group=self.manager('show',deny.name,'--property=ControlGroup','--value').strip()
        # Type=simple may return from start before the child has entered its
        # root. Wait for the exact frame; never weaken the production guard.
        until=time.monotonic()+10
        while True:
            try:
                probe.frame(denied_pid,denied_group,Path(c['destinations']['installationRoot'])/'sandbox');break
            except (ValueError,OSError):
                if time.monotonic()>=until:raise
                time.sleep(0.05)
        denied=probe.in_worker_group(c,denied_pid,denied_group,ca)
        self.assertFalse(denied['probe']['tcpConnected']);self.assertFalse(denied['probe']['httpGetAttempted'])
        self.assertIn(denied['probe']['errorClass'],('TIMEOUT','CONNECTION_ERROR'))



    def test_actual_dnat_requires_physical_endpoint_in_ip_projection(self):
        import shutil
        probe_spec=importlib.util.spec_from_file_location('nat_probe',ROOT/'scripts/probe-registry-operational-network-20261024.py')
        probe=importlib.util.module_from_spec(probe_spec);probe_spec.loader.exec_module(probe)
        cap_spec=importlib.util.spec_from_file_location('nat_capture',ROOT/'scripts/capture-registry-network-policy-20261024.py')
        capture=importlib.util.module_from_spec(cap_spec);cap_spec.loader.exec_module(capture)
        f=fixture_installation.prepare(self.fixture,ROOT,real_unit=True);review=f['review'];c=review['configuration']
        original=Path(c['serviceUnitPath']);self.addCleanup(self.cleanup_unit,original.name,original)
        installation.install_files(review,f['authority'],f['attestor'])
        port=self.fixture.server.server_port;iptables=shutil.which('iptables');self.assertIsNotNone(iptables)
        match=['-p','tcp','-d','127.0.0.2','--dport',str(port),'-m','comment','--comment',
            'ouf-native-nat-'+self.fixture.root.name,'-j','DNAT','--to-destination','127.0.0.1:'+str(port)]
        self.addCleanup(lambda:subprocess.run([iptables,'-t','nat','-D','OUTPUT',*match],capture_output=True,timeout=10))
        subprocess.run([iptables,'-t','nat','-I','OUTPUT','1',*match],check=True,capture_output=True,timeout=10)
        altered=copy.deepcopy(c);altered['ownerInputs']['iamProfile']['peer_addresses']=['127.0.0.2']
        ca=Path(c['tlsCa']['path']).read_bytes()
        baseline=probe.host_tls(altered['ownerInputs']['iamProfile'],ca)
        self.assertTrue(baseline['certificateChainAndHostnameVerified'])
        def dummy(suffix,allowed):
            path=original.with_name(original.stem+suffix+'.service');self.addCleanup(self.cleanup_unit,path.name,path)
            lines=[]
            for line in review['serviceUnit']['body'].splitlines():
                if line.startswith('IPAddressAllow='):continue
                if line.startswith('ExecStart='):line='ExecStart=/usr/bin/sleep 90'
                lines.append(line)
                if line.startswith('IPAddressDeny='):lines.extend('IPAddressAllow='+address for address in allowed)
            path.write_text('\n'.join(lines)+'\n');path.chmod(0o644)
            self.manager('daemon-reload');self.manager('start',path.name)
            pid=int(self.manager('show',path.name,'--property=MainPID','--value').strip())
            group=self.manager('show',path.name,'--property=ControlGroup','--value').strip()
            until=time.monotonic()+10
            while True:
                try:probe.frame(pid,group,Path(c['destinations']['installationRoot'])/'sandbox');break
                except (ValueError,OSError):
                    if time.monotonic()>=until:raise
                    time.sleep(0.05)
            return path,pid,group
        public,pid,group=dummy('-nat-public',['127.0.0.2'])
        capture.DEADLINE=time.monotonic()+30;capture.COUNTS.update(nativeCommandAttempts=0,engineGetAttempts=0)
        manager=capture.program(('/usr/bin/systemctl',));properties=capture.unit_properties(manager,public.name)
        self.assertTrue(capture.permitted('127.0.0.2',properties));self.assertFalse(capture.permitted('127.0.0.1',properties))
        ip_program=capture.program(('/usr/sbin/ip','/usr/bin/ip'));self.assertTrue(capture.route_data(ip_program,'127.0.0.2')['routeTypeLocal'])
        save=capture.program(('/usr/sbin/iptables-save','/sbin/iptables-save'));code,raw=capture.invoke(save,['-t','nat'])
        self.assertEqual(code,0);candidates,_=capture.parse_save(raw,'127.0.0.2',port)
        self.assertTrue(any(row['address']=='127.0.0.1' and row['port']==port for row in candidates))
        blocked=probe.in_worker_group(altered,pid,group,ca)
        self.assertFalse(blocked['probe']['tcpConnected']);self.assertFalse(blocked['probe']['httpGetAttempted'])
        projected,fixed_pid,fixed_group=dummy('-nat-projected',['127.0.0.2','127.0.0.1'])
        fixed=probe.in_worker_group(altered,fixed_pid,fixed_group,ca)
        self.assertEqual(fixed['probe']['httpStatus'],200);self.assertTrue(fixed['probe']['discoveryMatchesConfiguredEndpoints'])
        self.assertEqual(sum(path.endswith('/token') for path,_ in self.fixture.calls),0)


if __name__=='__main__':unittest.main()
