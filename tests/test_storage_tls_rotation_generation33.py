import copy
import importlib.util
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('tls_rotation33',ROOT/'scripts/run-storage-generation33-tls-rotation.py')
rotation=importlib.util.module_from_spec(spec);spec.loader.exec_module(rotation)


def handshake(config,generation,trust,hostname='localhost'):
    directory='tls' if generation=='a' else 'tls-next'
    server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(config/directory/'server.pem',config/directory/'server.key')
    client_context=ssl.create_default_context(cafile=str(rotation.trust_file(config,trust)))
    client_in,client_out,server_in,server_out=[ssl.MemoryBIO() for _ in range(4)]
    client=client_context.wrap_bio(client_in,client_out,server_hostname=hostname)
    server=server_context.wrap_bio(server_in,server_out,server_side=True)
    done=[False,False]
    for _ in range(30):
        for index,peer in enumerate((client,server)):
            if done[index]:continue
            try:peer.do_handshake();done[index]=True
            except ssl.SSLWantReadError:pass
        if client_out.pending:server_in.write(client_out.read())
        if server_out.pending:client_in.write(server_out.read())
        if all(done):return rotation.sha(client.getpeercert(binary_form=True))
    raise AssertionError('bounded TLS handshake did not terminate')


class RotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.config=Path(cls.temp.name)
        def command(args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=15).stdout.strip()
        cls.certs=rotation.make_certificates(cls.config,command)

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_real_tls_overlap_accepts_both_generations_and_fingerprints(self):
        for generation in ('a','b'):
            for trust in (generation,'overlap'):
                self.assertEqual(handshake(self.config,generation,trust),self.certs[generation]['leaf']['derSha256'])
        self.assertEqual(self.certs['a']['leaf']['serialHex'],'65')
        self.assertEqual(self.certs['b']['leaf']['serialHex'],'CA')

    def test_real_tls_opposite_trust_and_hostname_fail_closed(self):
        for generation,opposite in (('a','b'),('b','a')):
            with self.assertRaises(ssl.SSLCertVerificationError):handshake(self.config,generation,opposite)
            with self.assertRaises(ssl.SSLCertVerificationError):handshake(self.config,generation,generation,'127.0.0.1')

    def test_private_keys_are_restricted_and_never_overlap_input(self):
        for key in self.config.rglob('*.key'):self.assertEqual(key.stat().st_mode&0o777,0o600)
        bundle=(self.config/'ca-overlap.pem').read_bytes()
        self.assertEqual(bundle.count(b'BEGIN CERTIFICATE'),2)
        self.assertNotIn(b'PRIVATE KEY',bundle)

    def requester(self,calls,corrupt=False,truncate=False):
        def request(module,config,trust,generation,method,path,*args,**kwargs):
            calls.append((method,trust,path));headers={'content-length':str(len(rotation.BODY)),'content-type':rotation.MIME}
            body=b'' if method=='HEAD' else rotation.BODY
            if '?' in path:
                body=('<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>'
                      +('true' if truncate else 'false')+'</IsTruncated><Contents><Key>'+rotation.KEY
                      +'</Key></Contents></ListBucketResult>').encode()
            elif corrupt and method=='GET':body=b'X'+body[1:]
            return {'body':body,'headers':headers,'peerCertificateSha256':self.certs[generation]['leaf']['derSha256']}
        return request

    def rejector(self,config,trust,hostname='localhost'):
        return {'trust':trust,'hostname':hostname,'verificationRejected':True,'attempts':1}

    def test_after_stage_reads_only_and_proves_both_trust_modes(self):
        calls=[];module=types.SimpleNamespace(BUCKET='ouf-identity-fixture')
        result=rotation.verify_stage(module,self.config,'b',self.requester(calls),self.rejector)
        self.assertEqual([x['trust'] for x in result['positiveTrustCases']],['b','overlap'])
        self.assertEqual([x['trust'] for x in result['negativeTrustCases']],['a','b'])
        self.assertEqual([x[0] for x in calls],['GET','HEAD','GET','HEAD','GET'])
        self.assertEqual(result['mutatingRequests'],0)

    def test_equal_length_corruption_fails(self):
        with self.assertRaisesRegex(ValueError,'BODY_MISMATCH'):
            rotation.verify_stage(types.SimpleNamespace(BUCKET='fixture'),self.config,'b',self.requester([],True),self.rejector)

    def test_incomplete_list_fails_even_with_expected_object(self):
        with self.assertRaisesRegex(ValueError,'EXACT_LIST'):
            rotation.verify_stage(types.SimpleNamespace(BUCKET='fixture'),self.config,'b',self.requester([],truncate=True),self.rejector)

    def test_after_client_cannot_repeat_seed(self):
        module=types.SimpleNamespace(BUCKET='fixture')
        with patch.object(rotation,'request') as writer,patch.object(rotation,'verify_stage',return_value={'mutatingRequests':0}):
            result=rotation.client(module,self.config,'verify-b')
        writer.assert_not_called();self.assertEqual(result['mutatingRequests'],0)
        with self.assertRaisesRegex(ValueError,'KNOWN_ROTATION_ACTION'):
            rotation.client(module,self.config,'seed-again')

    def snapshots(self):
        lab=types.SimpleNamespace(prefix='fixture',data=Path('/synthetic/data'))
        base=[]
        for role in ('master','volume','filer','s3'):
            base.append({'Id':role+'-id','RestartCount':0,'State':{'Running':True,'OOMKilled':False,'StartedAt':'initial'},
                         'Image':'sha256:expected'})
        after=copy.deepcopy(base);after[-1].update({'Id':'s3-next-id','Config':{'User':'65532:65532',
            'Cmd':['s3','-key.file=/config/tls-next/server.key','-cert.file=/config/tls-next/server.pem']},
            'HostConfig':{'ReadonlyRootfs':True,'CapDrop':['ALL'],'PortBindings':{},'NetworkMode':'container:master-id'},
            'Mounts':[{'Destination':'/data','Source':'/synthetic/data/s3','RW':True},
                      {'Destination':'/config','Source':'/synthetic/data/config','RW':False}]})
        return lab,base,after

    def test_replacement_requires_new_gateway_same_storage_no_restart(self):
        lab,before,after=self.snapshots();rotation.validate_replacement(before,after,lab,'sha256:expected')
        for mutate,reason in (
            (lambda x:x[0].update(Id='other-master'),'MASTER_VOLUME_FILER'),
            (lambda x:x[-1].update(Id='s3-id'),'DISTINCT_GATEWAY'),
            (lambda x:x[1]['State'].update(StartedAt='restarted'),'STORAGE_ROLES'),
            (lambda x:x[-1]['HostConfig'].update(PortBindings={'18333/tcp':[{}]}),'ISOLATION'),
            (lambda x:x[-1]['Config'].update(Cmd=['s3','-cert.file=/config/tls/server.pem']),'NEW_CERTIFICATE')):
            changed=copy.deepcopy(after);mutate(changed)
            with self.assertRaisesRegex(ValueError,reason):rotation.validate_replacement(before,changed,lab,'sha256:expected')

    def test_gateway_arguments_pin_only_second_certificate_and_existing_roots(self):
        lab=types.SimpleNamespace(prefix='fixture',data=Path('/synthetic/data'))
        args=rotation.replacement_argv(lab,'sha256:expected')
        self.assertIn('-cert.file=/config/tls-next/server.pem',args)
        self.assertIn('-key.file=/config/tls-next/server.key',args)
        self.assertIn('container:fixture-master',args)
        self.assertNotIn('--publish',args);self.assertNotIn('--privileged',args)
        self.assertEqual(args.count('sha256:expected'),1)

    def test_wrong_certificate_rejected_before_http_request(self):
        module=types.SimpleNamespace(signed_headers=lambda *a:{},OWNER=('x','y'),APP=('a','b'))
        fake=types.SimpleNamespace(connect=lambda:None,sock=types.SimpleNamespace(getpeercert=lambda **k:b'wrong-leaf'),
                                   request=lambda *a,**k:self.fail('HTTP sent before peer identity validation'),close=lambda:None)
        with patch.object(rotation.http.client,'HTTPSConnection',return_value=fake):
            with self.assertRaisesRegex(ValueError,'UNEXPECTED_PRESENTED_CERTIFICATE'):
                rotation.request(module,self.config,'b','b','GET','/fixture')


if __name__=='__main__':unittest.main()
