import importlib.util
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lateral33', ROOT / 'scripts/run-storage-generation33-lateral-isolation.py')
lab = importlib.util.module_from_spec(spec); spec.loader.exec_module(lab)


class PolicyTests(unittest.TestCase):
    def test_complete_interrole_matrix_is_default_deny(self):
        rows = lab.matrix()
        self.assertEqual(32, len(rows)); self.assertEqual(10, sum(row[3] for row in rows))
        self.assertEqual(32, len({row[:3] for row in rows}))
        self.assertEqual({('client','s3',18333)}, {x for x in lab.ALLOW if x[0]=='client'})
        self.assertFalse(any(dst=='client' for _,dst,_ in lab.ALLOW))

    def test_rules_have_symmetric_exact_allow_and_observable_denials(self):
        for role in lab.ROLES:
            rules = lab.nft_rules(role)
            self.assertEqual(3, rules.count('policy drop;'))
            self.assertNotIn('/24 accept', rules)
            for src,dst,port,allowed in lab.matrix():
                if src==role:
                    clause=f'ip daddr {lab.IPS[dst]} tcp dport {port} '
                    self.assertIn(clause+('accept' if allowed else f'counter name deny_{dst}_{port} reject'),rules)
                if dst==role and allowed:
                    self.assertIn(f'ip saddr {lab.IPS[src]} tcp dport {port} accept',rules)

    def test_embedded_dns_block_precedes_loopback_and_destination_nat(self):
        for role in lab.ROLES:
            rules=lab.nft_rules(role)
            self.assertIn('hook output priority -150',rules)
            for name in ('dns_tcp','dns_udp'):
                self.assertLess(rules.index('counter name '+name),rules.index('oifname "lo" accept'))
            self.assertIn('counter name egress_tcp reject',rules)

    def test_application_cannot_reach_internal_or_admin_ports(self):
        rules=lab.nft_rules('client')
        for role,ports in lab.PORTS.items():
            for port in ports:
                if (role,port)!=('s3',18333): self.assertIn(f'deny_{role}_{port} reject',rules)

    def test_role_bindings_use_exact_advertised_ips(self):
        for role in lab.PORTS:
            args=lab.role_args(role)
            self.assertIn('-ip='+lab.IPS[role],args)
            self.assertNotIn('-ip=127.0.0.1',args)
        self.assertIn('-cert.file=/config/tls/server.pem',lab.role_args('s3'))
        with self.assertRaises(ValueError):lab.nft_rules('host')

    def test_real_socket_probe_distinguishes_listener_from_refusal(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen(1);port=server.getsockname()[1]
            self.assertTrue(lab.socket_probe('127.0.0.1',port,'tcp')['connected'])
        result=lab.socket_probe('127.0.0.1',port,'tcp')
        self.assertFalse(result['connected']);self.assertIsNotNone(result['errno'])
        # Refusal alone is deliberately not a firewall PASS; native runner also
        # requires an increase of the dedicated destination deny counter.
        with self.assertRaises(ValueError):lab.socket_probe('example.com',443,'tcp')


class LaunchBarrierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name);cls.binary=cls.root/'gate'
        subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-static',
                        str(ROOT/'tests/fixtures/storage-recovery/network-gate.c'),'-o',str(cls.binary)],
                       check=True,capture_output=True,timeout=30)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def launch(self,gate):
        process=subprocess.Popen([str(self.binary),str(gate),'--hold'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def cleanup():
            if process.poll() is None:process.terminate()
            process.communicate(timeout=3)
        self.addCleanup(cleanup);return process

    def test_no_service_release_before_exact_gate_then_clean_stop(self):
        gate=self.root/'release';process=self.launch(gate)
        self.assertFalse(select.select([process.stdout],[],[],0.15)[0]);self.assertIsNone(process.poll())
        gate.write_text('READY\n')
        self.assertTrue(select.select([process.stdout],[],[],2)[0])
        self.assertEqual(b'NETWORK_GATE_RELEASED\n',process.stdout.readline())
        process.terminate();self.assertEqual(0,process.wait(timeout=3))

    def test_invalid_marker_never_releases(self):
        gate=self.root/'invalid';gate.write_text('READY\nEXTRA')
        process=self.launch(gate);out,_=process.communicate(timeout=3)
        self.assertEqual(65,process.returncode);self.assertEqual(b'',out)

    def test_symlink_gate_cannot_release(self):
        target=self.root/'target';target.write_text('READY\n');gate=self.root/'linked';gate.symlink_to(target)
        process=self.launch(gate)
        self.assertFalse(select.select([process.stdout],[],[],0.15)[0]);self.assertIsNone(process.poll())

    def test_arbitrary_entrypoint_is_rejected(self):
        result=subprocess.run([str(self.binary),str(self.root/'unused'),'/bin/sh'],capture_output=True,timeout=3)
        self.assertEqual(64,result.returncode)


if __name__=='__main__':unittest.main()
