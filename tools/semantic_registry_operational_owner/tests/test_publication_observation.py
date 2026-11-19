"""Actual bounded reads, reservation and unauthenticated loopback TLS.

No target or production-worker connectivity is asserted by these fixtures.
"""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('initial_publication_observation',ROOT/'scripts/observe-registry-operational-owner-20261024.py')
observer=importlib.util.module_from_spec(spec);spec.loader.exec_module(observer)


class Observation(unittest.TestCase):
    def setUp(self):
        parent=Path('/root/.codex/skills/remote-skills')
        if not parent.is_dir() or not os.access(parent,os.W_OK):parent=ROOT
        self.temp=tempfile.TemporaryDirectory(dir=parent,prefix='ouf-observation-fixture-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)

    def test_read_hash_limit_symlink_and_writable_ancestry(self):
        path=self.root/'metadata';path.write_bytes(b'private metadata');path.chmod(0o600)
        self.assertEqual(observer.read(path,100,hashlib.sha256(path.read_bytes()).hexdigest()),b'private metadata')
        for maximum,sha in((1,None),(100,'0'*64)):
            with self.assertRaises(ValueError):observer.read(path,maximum,sha)
        link=self.root/'link';link.symlink_to(path)
        with self.assertRaises(OSError):observer.read(link,100)
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):observer.read(path,100)

    def test_one_durable_attempt_cannot_be_replayed(self):
        observer.reserve(self.root);path=self.root/'host-tls-observation-v1.claim.json'
        before=path.read_bytes();self.assertIn(b'"httpRequests":0',before)
        with self.assertRaises(FileExistsError):observer.reserve(self.root)
        self.assertEqual(path.read_bytes(),before)

    def test_projection_counters_and_redaction(self):
        row={'schema':'ouf.registry-operational-token-ledger.v1','installationHash':'a'*64,'state':'RETRY_WAIT',
             'reason':'NO_SUBMISSION_PROVEN_BOUNDED_BACKOFF','attempts':3,'priorControlledAttempts':321,
             'cumulativeAttempts':324,'publications':0,'consecutiveFailures':3,'version':10,
             'lastWall':100,'nextWall':400,'tokenExpiresWall':None,'tokenHash':'NEVER_PRINT_THIS'}
        p=observer.project(row,'a'*64,110);self.assertEqual(p['nextAttemptInSeconds'],290)
        self.assertNotIn('NEVER_PRINT_THIS',str(p));self.assertNotIn('tokenHash',p)
        bad=copy.deepcopy(row);bad['cumulativeAttempts']=321
        with self.assertRaises(ValueError):observer.project(bad,'a'*64,110)
        bad=copy.deepcopy(row);bad['reason']='untrusted raw error secret'
        with self.assertRaises(ValueError):observer.project(bad,'a'*64,110)

    def tls_fixture(self,hostname):
        ca=self.root/'ca.pem';key=self.root/'key.pem'
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=iam.fixture.test','-addext','subjectAltName=DNS:iam.fixture.test',
            '-keyout',str(key),'-out',str(ca)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(ca,key)
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(10)
        port=listener.getsockname()[1];received=[]
        def serve():
            try:
                conn,_=listener.accept()
                with conn:
                    try:
                        with context.wrap_socket(conn,server_side=True) as tls:
                            tls.settimeout(2);received.append(tls.recv(1))
                    except (ssl.SSLError,ConnectionResetError,BrokenPipeError):pass
            finally:listener.close()
        thread=threading.Thread(target=serve);thread.start()
        try:result=observer.host_tls({'issuer':f'https://{hostname}:{port}/realms/fixture','peer_addresses':['127.0.0.1']},ca.read_bytes())
        finally:thread.join(10)
        self.assertFalse(thread.is_alive());return result,received

    def test_real_tls_verifies_identity_without_sending_http_or_bearer(self):
        result,received=self.tls_fixture('iam.fixture.test')
        self.assertTrue(result['certificateChainAndHostnameVerified']);self.assertFalse(any(received))
        self.assertEqual(result['scope'],'HOST_OUTSIDE_WORKER_CGROUP')
        self.assertNotIn('127.0.0.1',str(result));self.assertNotIn('iam.fixture.test',str(result))

    def test_real_tls_hostname_failure_has_no_raw_error(self):
        result,_=self.tls_fixture('wrong.fixture.test')
        self.assertFalse(result['certificateChainAndHostnameVerified']);self.assertEqual(result['errorClass'],'CERTIFICATE_REJECTED')
        self.assertNotIn('fixture.test',str(result))

    def test_real_connection_refusal_is_bounded_and_not_a_worker_result(self):
        ca=self.root/'ca.pem';key=self.root/'key.pem'
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=fixture','-keyout',str(key),'-out',str(ca)],check=True,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        listener=socket.socket();listener.bind(('127.0.0.1',0));port=listener.getsockname()[1];listener.close()
        result=observer.host_tls({'issuer':f'https://fixture:{port}/realms/fixture','peer_addresses':['127.0.0.1']},ca.read_bytes())
        self.assertEqual(result['errorClass'],'CONNECTION_ERROR');self.assertFalse(result['tlsHandshakeAttempted'])

    def test_full_observation_preserves_ledger_and_uses_show_only_without_credentials(self):
        def write(path,raw):path.write_bytes(raw);path.chmod(0o600);return hashlib.sha256(raw).hexdigest()
        state=self.root/'ledger';state.mkdir(mode=0o700)
        ca=self.root/'ca';ca_sha=write(ca,b'fixture public CA')
        unit=self.root/'owner.service';unit_sha=write(unit,b'fixture reviewed unit')
        program=self.root/'systemctl';program_sha=write(program,b'fixture manager program')
        c={'destinations':{'installationRoot':str(self.root),'ledgerRoot':str(state)},
           'serviceUnitPath':str(unit),'tlsCa':{'path':str(ca),'sha256':ca_sha},
           'ownerInputs':{'iamProfile':{'issuer':'https://fixture.test/realms/fixture','peer_addresses':['127.0.0.1']},
                          'credentialPath':'/must/never/be/opened'}}
        c_sha=write(self.root/'configuration.json',observer.encoded(c))
        review={'configuration':c,'serviceUnit':{'path':str(unit),'sha256':unit_sha},
                'executables':{'systemctl':{'path':str(program),'sha256':program_sha}}}
        review_path=self.root/'review.json';review_sha=write(review_path,observer.encoded(review))
        row={'schema':'ouf.registry-operational-token-ledger.v1','installationHash':c_sha,'state':'RETRY_WAIT',
             'reason':'NO_SUBMISSION_PROVEN_BOUNDED_BACKOFF','attempts':3,'priorControlledAttempts':321,
             'cumulativeAttempts':324,'publications':0,'consecutiveFailures':3,'version':10,
             'lastWall':100,'nextWall':400,'tokenExpiresWall':None}
        ledger=state/'state.json';write(ledger,observer.encoded(row));original=ledger.read_bytes();stamp=ledger.stat().st_mtime_ns
        props=('ActiveState=active\nSubState=running\nMainPID=123\nNRestarts=0\nResult=success\n'
               'ExecMainStatus=0\nRootDirectory='+str(self.root/'sandbox')+'\nNoNewPrivileges=yes\n').encode()
        opened=[];actual_read=observer.read
        def recorded(path,*args,**kwargs):opened.append(str(path));return actual_read(path,*args,**kwargs)
        with mock.patch.object(observer,'REVIEW',str(review_path)),mock.patch.object(observer,'REVIEW_SHA',review_sha),\
             mock.patch.object(observer,'CONFIG_SHA',c_sha),mock.patch.object(observer.sys,'argv',['observer']),\
             mock.patch.object(observer,'read',side_effect=recorded),\
             mock.patch.object(observer,'host_tls',return_value={'scope':'EXPLICIT_TRANSPORT_FIXTURE'}) as tls,\
             mock.patch.object(observer.subprocess,'run',return_value=subprocess.CompletedProcess([],0,props)) as manager:
            result=observer.observe()
        self.assertEqual(ledger.read_bytes(),original);self.assertEqual(ledger.stat().st_mtime_ns,stamp)
        self.assertNotIn('/must/never/be/opened',opened);self.assertEqual(tls.call_count,1)
        self.assertEqual(manager.call_count,1);self.assertEqual(manager.call_args.args[0][1],'show')
        self.assertEqual(result['after']['controlledCumulativeGrantAttempts'],324)
        self.assertEqual(result['oauthRequests'],0);self.assertFalse(result['applicationReadinessProven'])


if __name__=='__main__':unittest.main()
