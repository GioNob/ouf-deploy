"""Actual conntrack/TLS/Ed25519 and live IP update; declared proxy metadata fixture.

No production identity, target repair or original-request200 is claimed here.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest

import test_native_transport as transport
import native_installation_fixture as history
from tools.semantic_registry_operational_owner import installation,core
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer

ROOT=Path(__file__).resolve().parents[3]


@unittest.skipUnless(os.environ.get('OUF_NATIVE_OPERATIONAL_OWNER')=='1','Explicit disposable native network scope required')
class Projection(unittest.TestCase):
    def load(self,name,path):
        spec=importlib.util.spec_from_file_location(name,ROOT/path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

    def setUp(self):
        self.fixture=transport.NativeOwner(methodName='runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.repair=self.load('native_network_repair','scripts/repair-registry-network-projection-20261024.py')
        self.capture=self.load('native_network_capture','scripts/capture-registry-network-policy-20261024.py')
        self.probe=self.load('native_network_probe','scripts/probe-registry-operational-network-20261024.py')
        self.repair.CAPTURE_HELPER=str(ROOT/'scripts/capture-registry-network-policy-20261024.py')
        self.repair.PROBE_HELPER=str(ROOT/'scripts/probe-registry-operational-network-20261024.py')
        self.repair.CAPSULE=str(ROOT/'releases/semantic-registry-checkpoint-successor-20261023.py')

    def manager(self,*args):
        result=subprocess.run(['/usr/bin/systemctl',*args],capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr);return result.stdout

    def cleanup_unit(self,path):
        subprocess.run(['/usr/bin/systemctl','disable','--now',path.name],capture_output=True,timeout=20)
        path.unlink(missing_ok=True)
        drop=Path('/etc/systemd/system.control')/(path.name+'.d')/'50-IPAddressAllow.conf'
        drop.unlink(missing_ok=True)
        if drop.parent.exists():drop.parent.rmdir()
        subprocess.run(['/usr/bin/systemctl','daemon-reload'],capture_output=True,timeout=20)

    def nat(self):
        port=self.fixture.server.server_port;program=shutil.which('iptables');self.assertIsNotNone(program)
        match=['-p','tcp','-d','127.0.0.2','--dport',str(port),'-m','comment','--comment',
            'ouf-signed-projection-'+self.fixture.root.name,'-j','DNAT','--to-destination','127.0.0.1:'+str(port)]
        self.addCleanup(lambda:subprocess.run([program,'-t','nat','-D','OUTPUT',*match],capture_output=True,timeout=10))
        subprocess.run([program,'-t','nat','-I','OUTPUT','1',*match],check=True,capture_output=True,timeout=10)

    def wait_state(self,c,state,seconds=45):
        until=time.monotonic()+seconds
        while time.monotonic()<until:
            row=installation.read_object(Path(c['destinations']['ledgerRoot'])/'state.json')
            if row['state']==state:return row
            self.assertNotIn(row['state'],('BLOCKED','REVOKED'));time.sleep(0.2)
        self.fail('Native owner did not reach expected state')

    def authority(self,review,root):
        r=self.repair;ctx=review['verification']['context'];now=int(time.time())
        signatures=root/'authority';signatures.mkdir(mode=0o700)
        raw=r.encoded({'schema':r.AUTHORITY_SCHEMA,'scope':r.scope(review),'issuedAt':now,'expiresAt':now+900,
            'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],
            'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False})
        human={'schema':r.HUMAN_SCHEMA,'reviewHash':r.digest(review),'authorityHash':r.sha(raw),'decision':r.DECISION,
            'state':'ACTIVE','issuedAt':now,'expiresAt':now+900}
        r.new_file(signatures,'human.json',human)
        verifier=DetachedAuthenticator(review['verification']['trustPolicy'],str(signatures),review['verification']['openssl'])
        for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
            signer=ExistingEd25519Signer(self.fixture.binding(self.fixture.signing_key),'fixture-installer-key',verifier,
                {'role':role,'issuerRef':ctx[key],'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef']})
            r.new_file(signatures,r.sha(raw)+'.'+role+'.json',signer.sign(raw))
        gate=r.SignedProjection(review,raw,str(signatures/'human.json'),r.digest(human),verifier)
        attestor=ExistingEd25519Signer(self.fixture.binding(self.fixture.signing_key),'fixture-attestor-key',verifier,
            {'role':'CREATION_ATTESTATION','issuerRef':ctx['attestorRef'],'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef']})
        return gate,attestor

    def test_actual_kernel_tuple_binds_configured_tls_origin_to_dnat_endpoint(self):
        self.nat();profile=copy.deepcopy(self.fixture.config['ownerInputs']['iamProfile']);profile['peer_addresses']=['127.0.0.2']
        result=self.repair.prove_origin(profile,self.fixture.ca.read_bytes(),{'address':'127.0.0.1','port':self.fixture.server.server_port})
        self.assertTrue(result['publicDiscoveryMatched'] and result['flow']['kernelOriginAuthenticated'])
        self.assertEqual(result['flow']['original']['destination'],'127.0.0.2')
        self.assertEqual(result['flow']['reply']['source'],'127.0.0.1')
        self.assertEqual(sum(path.endswith('/token')for path,_ in self.fixture.calls),0)
        self.assertEqual(self.repair.COUNTS['conntrackGetAttempts'],1)

    def test_signed_live_projection_preserves_pid_and_counters_and_existing_worker_publishes(self):
        self.nat();self.fixture.config['ownerInputs']['iamProfile']['peer_addresses']=['127.0.0.2']
        f=history.prepare(self.fixture,ROOT,real_unit=True);old=f['review'];c=old['configuration']
        unit=Path(c['serviceUnitPath']);self.addCleanup(self.cleanup_unit,unit)
        installation.install_files(old,f['authority'],f['attestor']);self.manager('daemon-reload');self.manager('start',unit.name)
        baseline=self.wait_state(c,'RETRY_WAIT');self.assertGreaterEqual(baseline['cumulativeAttempts'],322)
        self.assertEqual(baseline['publications'],0);self.repair.CONFIG_HASH=core.digest(c)
        manager=self.capture.program(('/usr/bin/systemctl',));self.capture.DEADLINE=time.monotonic()+90
        before=self.capture.unit_properties(manager,unit.name);pid=int(before['MainPID'])
        candidate={'address':'127.0.0.1','port':self.fixture.server.server_port,'chainTraversalProven':False}
        owner={'Id':'d'*64,'Image':'sha256:'+'e'*64,'RestartCount':0,'Config':{'declaredSyntheticProxy':True},'HostConfig':{},'Mounts':[],
            'State':{'Pid':os.getpid(),'StartedAt':'declared-native-fixture','Running':True,'Paused':False,'Restarting':False,'Dead':False},
            'NetworkSettings':{'Networks':{'fixture':{'IPAddress':'127.0.0.1','IPAMConfig':{'IPv4Address':'127.0.0.1'}}},
                'Ports':{str(candidate['port'])+'/tcp':[{'HostIp':'0.0.0.0','HostPort':str(candidate['port'])}]}}}
        proof=self.repair.prove_origin(c['ownerInputs']['iamProfile'],self.fixture.ca.read_bytes(),candidate)
        inputs={'configurationHash':self.repair.CONFIG_HASH,'reviewHash':self.repair.REVIEW_HASH,'routes':{'peerIsLocal':True},'policies':[{'properties':before}]}
        source={'path':str(ROOT/'scripts/repair-registry-network-projection-20261024.py'),
            'sha256':hashlib.sha256((ROOT/'scripts/repair-registry-network-projection-20261024.py').read_bytes()).hexdigest()}
        review=self.repair.compile_review(c,old,inputs,candidate,owner,proof,before,self.capture,source,baseline)
        repair_root=self.repair.exclusive_root(Path(c['destinations']['installationRoot']),'fixture-network-projection')
        self.repair.new_file(repair_root,'review.json',review);gate,attestor=self.authority(review,repair_root)
        approval=gate.verifier.signature_directory/(self.repair.sha(gate.raw)+'.FINAL_DEPLOYMENT_APPROVAL.json')
        hidden=approval.with_suffix('.held');approval.rename(hidden)
        try:
            with self.assertRaises(Exception):
                self.repair.SignedProjection(review,gate.raw,gate.human_path,gate.human_hash,gate.verifier)
            self.assertEqual(self.repair.COUNTS['managerMutationAttempts'],0)
        finally:hidden.rename(approval)
        # Legacy installation authority cannot authorize this host projection.
        with self.assertRaises(self.repair.Denied):self.repair.apply_projection(review,f['authority'],repair_root,self.capture,lambda *_:None,attestor)
        bad=copy.deepcopy(review);bad['projectedAllowlist'].append('192.0.2.50/32')
        with self.assertRaises(self.repair.Denied):self.repair.scope(bad)
        fresh=self.repair.prove_origin(c['ownerInputs']['iamProfile'],self.fixture.ca.read_bytes(),candidate)
        self.repair.new_file(repair_root,'fresh-origin-proof.json',fresh)
        phases=[]
        def current_guard(phase):
            phases.append(phase)
            current=installation.read_object(Path(c['destinations']['ledgerRoot'])/'state.json')
            self.assertGreaterEqual(current['cumulativeAttempts'],baseline['cumulativeAttempts'])
        after=self.repair.apply_projection(review,gate,repair_root,self.capture,current_guard,attestor)
        self.assertEqual(phases,['BEFORE_AUTHORITY','BEFORE_EFFECT','AFTER_EFFECT'])
        self.assertEqual(int(after['MainPID']),pid);self.assertEqual(self.repair.COUNTS['managerMutationAttempts'],1)
        verification=self.probe.in_worker_group(c,pid,after['ControlGroup'],self.fixture.ca.read_bytes())
        self.assertEqual(verification['probe']['httpStatus'],200)
        final=self.wait_state(c,'ACTIVE');self.assertGreater(final['cumulativeAttempts'],baseline['cumulativeAttempts'])
        self.assertGreaterEqual(final['publications'],1);self.assertEqual(final['priorControlledAttempts'],321)
        self.assertEqual(int(self.manager('show',unit.name,'--property=MainPID','--value').strip()),pid)
        self.assertEqual(unit.read_bytes(),old['serviceUnit']['body'].encode('ascii'))
        self.assertTrue((Path('/etc/systemd/system.control')/(unit.name+'.d')/'50-IPAddressAllow.conf').exists())
        with self.assertRaises((FileExistsError,self.repair.Denied)):
            self.repair.apply_projection(review,gate,repair_root,self.capture,current_guard,attestor)
        self.assertEqual(self.repair.COUNTS['managerMutationAttempts'],1)


if __name__=='__main__':unittest.main()
