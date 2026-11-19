import copy
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import test_storage_tls_rotation_generation33 as tls_tests
spec = importlib.util.spec_from_file_location('credentials33', ROOT / 'scripts/run-storage-generation33-credential-rotation.py')
rotation = importlib.util.module_from_spec(spec); spec.loader.exec_module(rotation)
identity = rotation.tls_rotation.load('identity_test', ROOT / 'scripts/run-seaweedfs-452-identity-tls.py')


class S3:
    def __init__(self, stage):
        self.stage = stage; self.calls = []; self.bad_denial = None
        self.bodies = {rotation.KEY: rotation.BODY}
        if stage == 'restarted': self.bodies[rotation.NEW_KEY] = rotation.NEW_BODY
        self.truncated = False; self.metadata = {}; self.corrupt = False
    def __call__(self, module, tls, credentials, method, key='', body=b'', query=None):
        self.calls.append((credentials, method, key, body))
        active = [module.APP] if self.stage == 'old' else [module.APP, rotation.NEW] if self.stage == 'overlap' else [rotation.NEW]
        code = None
        if credentials[0] not in [x[0] for x in active]: code = 'InvalidAccessKeyId'
        elif credentials not in active: code = 'SignatureDoesNotMatch'
        elif method == 'DELETE' or (key and not key.startswith('staging/')): code = 'AccessDenied'
        if code:
            status, code = self.bad_denial or (403, code)
            return {'status': status, 'body': b'' if method == 'HEAD' else f'<Error><Code>{code}</Code></Error>'.encode(),
                    'headers': {}, 'peerSha256': 'fixed-peer'}
        if method == 'PUT': self.bodies[key] = body; data = b''; headers = {}
        elif query:
            data = ('<ListBucketResult xmlns="'+rotation.NS['s']+'"><IsTruncated>'
                + ('true' if self.truncated else 'false') + '</IsTruncated>'
                + ''.join('<Contents><Key>'+k+'</Key></Contents>' for k in sorted(self.bodies)) + '</ListBucketResult>').encode()
            headers = {}
        else:
            data = self.bodies[key]
            headers = {'content-length': str(len(data)), 'content-type': rotation.MIME, **self.metadata}
            if method == 'HEAD': data = b''
            elif self.corrupt: data = b'X' + data[1:]
        return {'status': 200, 'body': data, 'headers': headers, 'peerSha256': 'fixed-peer'}


class CredentialTests(unittest.TestCase):
    def test_rotation_changes_only_credentials_preserving_identity_and_policy(self):
        base = identity.fixture_config()
        for stage, pairs in [('old',[identity.APP]),('overlap',[identity.APP,rotation.NEW]),
                             ('new',[rotation.NEW]),('restarted',[rotation.NEW])]:
            config = rotation.config_for(identity, stage)
            self.assertEqual(pairs, [(x['accessKey'],x['secretKey']) for x in config['identities'][1]['credentials']])
            config['identities'][1]['credentials'] = base['identities'][1]['credentials']
            self.assertEqual(base, config)

    def test_unissued_key_rejected_before_rotation(self):
        report = rotation.verify_stage(identity, None, 'old', S3('old'))
        self.assertEqual(['old'], list(report['reads']))
        self.assertEqual('InvalidAccessKeyId', report['denied'][0]['code'])

    def test_overlap_reads_identical_bytes_with_both_keys(self):
        api = S3('overlap'); report = rotation.verify_stage(identity, None, 'overlap', api)
        self.assertEqual(report['reads']['old'], report['reads']['new'])
        self.assertTrue(all(method in ('GET','HEAD') for _,method,_,_ in api.calls))

    def test_new_key_writes_once_retired_key_never_changes_objects(self):
        api = S3('new'); report = rotation.verify_stage(identity, None, 'new', api)
        self.assertEqual(9, len(report['denied']))
        self.assertEqual(6, sum(x['identity']=='retired' for x in report['denied']))
        self.assertEqual(1, report['successfulObjectPuts'])
        self.assertEqual(rotation.expected_objects('new'), api.bodies)
        self.assertEqual(1, sum(c==rotation.NEW and m=='PUT' and k==rotation.NEW_KEY for c,m,k,_ in api.calls))
        head = [x for x in report['denied'] if x['method']=='HEAD'][0]
        self.assertEqual(403, head['status']); self.assertIsNone(head['code'])

    def test_restart_does_not_repeat_successful_mutation(self):
        api = S3('restarted'); report = rotation.verify_stage(identity, None, 'restarted', api)
        self.assertEqual(0, report['successfulObjectPuts'])
        self.assertFalse(any(m=='PUT' and k==rotation.NEW_KEY for _,m,k,_ in api.calls))
        self.assertEqual(rotation.expected_objects('restarted'), api.bodies)

    def test_wrong_status_or_error_code_cannot_prove_revocation(self):
        for wrong in [(200,'InvalidAccessKeyId'),(500,'InvalidAccessKeyId'),(403,'AccessDenied')]:
            api = S3('new'); api.bad_denial = wrong
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                rotation.verify_stage(identity, None, 'new', api)

    def test_truncated_list_or_wrong_body_or_metadata_fails(self):
        for field, value in [('truncated',True),('corrupt',True),('metadata',{'content-type':'text/plain'})]:
            api = S3('overlap'); setattr(api,field,value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                rotation.verify_stage(identity, None, 'overlap', api)

    def test_extra_object_after_denied_put_fails_parity(self):
        api = S3('restarted'); api.bodies['staging/retired-key-must-not-create.bin'] = b'bad'
        with self.assertRaisesRegex(ValueError,'EXACT_COMPLETE_OBJECT_LIST'):
            rotation.verify_stage(identity,None,'restarted',api)

    def test_replacement_retains_storage_and_tls_roots(self):
        lab,before,after = tls_tests.RotationTests.snapshots(None)
        after[-1]['Config']['Cmd'] = ['s3','-config=/config/s3.json',
            '-key.file=/config/tls/server.key','-cert.file=/config/tls/server.pem']
        rotation.validate_replacement(before,after,lab,'sha256:expected')
        for mutate in (lambda x:x[0].update(Id='different'),lambda x:x[1].update(RestartCount=1),
                       lambda x:x[-1]['HostConfig'].update(PortBindings={'18333/tcp':[{}]}),
                       lambda x:x[-1]['Config'].update(Cmd=['s3'])):
            changed=copy.deepcopy(after); mutate(changed)
            with self.assertRaises(ValueError): rotation.validate_replacement(before,changed,lab,'sha256:expected')

    def test_gateway_argv_changes_name_but_not_tls_or_namespace(self):
        lab=types.SimpleNamespace(prefix='fixture',data=Path('/synthetic/data'))
        for stage in ('overlap','new','restarted'):
            args=rotation.replacement_argv(lab,'sha256:expected',stage)
            self.assertIn('fixture-s3-'+stage,args)
            self.assertIn('-cert.file=/config/tls/server.pem',args)
            self.assertIn('container:fixture-master',args)
            self.assertNotIn('--publish',args);self.assertNotIn('--privileged',args)

    def test_restarted_client_cannot_seed_again(self):
        with patch.object(rotation,'request') as writer, patch.object(rotation,'verify_stage',return_value={'successfulObjectPuts':0}):
            result=rotation.client(identity,Path('/fixture'),'restarted')
        writer.assert_not_called();self.assertEqual(0,result['successfulObjectPuts'])
        with self.assertRaises(ValueError):rotation.config_for(identity,'unknown')

    def test_peer_change_rejected_before_signed_http(self):
        fake=types.SimpleNamespace(connect=lambda:None,sock=types.SimpleNamespace(getpeercert=lambda **k:b'wrong-peer'),
            request=lambda *a,**k:self.fail('request sent before TLS identity check'),close=lambda:None)
        with patch.object(rotation.ssl,'create_default_context'),patch.object(rotation.ssl,'PEM_cert_to_DER_cert',return_value=b'right-peer'),\
             patch.object(Path,'read_text',return_value='fixture cert'),patch.object(rotation.http.client,'HTTPSConnection',return_value=fake):
            with self.assertRaisesRegex(ValueError,'UNCHANGED_TLS_IDENTITY'):
                rotation.request(identity,Path('/fixture'),rotation.NEW,'GET',rotation.KEY)


if __name__ == '__main__': unittest.main()
