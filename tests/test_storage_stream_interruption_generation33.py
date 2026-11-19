import copy
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('stream_lab33',ROOT/'scripts/run-storage-generation33-lateral-isolation.py')
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
stream=lab.stream


class StreamTests(unittest.TestCase):
    def test_fixture_is_incomplete_and_distinct_from_acknowledged_object(self):
        payload=stream.body()
        self.assertEqual(len(payload),stream.BODY_BYTES)
        self.assertLess(stream.CHUNK_BYTES,stream.PREFIX_BYTES)
        self.assertLess(stream.PREFIX_BYTES,len(payload))
        self.assertNotIn(payload[:stream.CHUNK_BYTES],lab.volume_body())

    def test_observed_volume_requires_an_exact_complete_chunk(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);p=root/'1.dat';chunk=stream.body()[:stream.CHUNK_BYTES]
            p.write_bytes(b'header'+chunk+b'footer')
            r=stream.persisted_prefix(root)
            self.assertTrue(r['persistedPrefixFound'])
            self.assertEqual(r['matches'],[{'file':'1.dat','offset':6,'bytes':len(chunk),'sha256':stream.sha(chunk)}])
            for bad in (chunk[:-1],b'x'+chunk[1:]):
                p.write_bytes(b'header'+bad)
                self.assertFalse(stream.persisted_prefix(root)['persistedPrefixFound'])

    def test_empty_or_symlink_volume_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with self.assertRaises(ValueError):stream.persisted_prefix(root)
            (root/'target').write_bytes(b'x');(root/'1.dat').symlink_to(root/'target')
            with self.assertRaises(ValueError):stream.persisted_prefix(root)

    def test_volume_scan_has_a_per_file_size_budget(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with (root/'1.dat').open('wb') as f:f.truncate(33*1024*1024+1)
            with self.assertRaisesRegex(ValueError,'STREAM_DAT_BUDGET'):stream.persisted_prefix(root)

    def responses(self):
        listing=('<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                 '<IsTruncated>false</IsTruncated><Contents><Key>'+lab.VOLUME_KEY+'</Key><Size>'+str(lab.VOLUME_BYTES)+
                 '</Size></Contents></ListBucketResult>').encode()
        return [{'status':404,'body':b'<Error><Code>NoSuchKey</Code></Error>','peerSha256':'peer'},
                {'status':404,'body':b'','peerSha256':'peer'},
                {'status':200,'body':listing,'peerSha256':'peer'}]

    def verify(self,responses):
        requester=Mock(side_effect=responses);signer=SimpleNamespace(APP='app')
        value=stream.verify_absent(signer,Path('/tls'),requester,lab.VOLUME_KEY,lab.VOLUME_BYTES)
        self.assertEqual([c.args[3] for c in requester.call_args_list],['GET','HEAD','GET'])
        self.assertEqual(requester.call_count,3)
        return value

    def test_absence_is_reconciled_using_only_three_reads(self):
        value=self.verify(self.responses())
        self.assertEqual(value['outcome'],'ABSENT_NO_REPLAY')
        self.assertEqual(value['mutatingRequests'],0)

    def test_successful_or_partial_object_response_is_rejected(self):
        for method in (0,1):
            for status in (200,206,500,403):
                responses=self.responses();responses[method]['status']=status
                with self.subTest(method=method,status=status),self.assertRaises(ValueError):self.verify(responses)

    def test_wrong_error_code_and_nonempty_head_are_rejected(self):
        for index,body in ((0,b'<Error><Code>NoSuchBucket</Code></Error>'),(1,b'partial')):
            responses=self.responses();responses[index]['body']=body
            with self.assertRaises(ValueError):self.verify(responses)

    def test_incomplete_extra_missing_or_wrong_size_listing_is_rejected(self):
        original=self.responses()[2]['body']
        for bad in (original.replace(b'false',b'true'),original.replace(b'</ListBucketResult>',b'<NextContinuationToken>x</NextContinuationToken></ListBucketResult>'),
                    original.replace(lab.VOLUME_KEY.encode(),stream.KEY.encode()),original.replace(str(lab.VOLUME_BYTES).encode(),b'1'),
                    original.replace(b'<Contents>',b'<Contents><Key>extra</Key><Size>1</Size></Contents><Contents>'),
                    original[:original.index(b'<Contents>')]+b'</ListBucketResult>'):
            responses=self.responses();responses[2]['body']=bad
            with self.assertRaises(ValueError):self.verify(responses)

    def test_tls_peer_changes_are_rejected(self):
        responses=self.responses();responses[2]['peerSha256']='other'
        with self.assertRaises(ValueError):self.verify(responses)

    def test_single_signed_put_sends_prefix_and_closes_without_reading_ack(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);control=root/'control';control.mkdir();(root/'server.pem').write_text('PEM')
            connection=Mock();peer=Mock();peer.getpeercert.return_value=b'DER'
            context=Mock();context.wrap_socket.return_value=peer
            signer=SimpleNamespace(BUCKET='bucket',APP='app',signed_headers=Mock(return_value={'host':'localhost:18333'}))
            def sent(payload):
                self.assertEqual(payload,stream.body()[:stream.PREFIX_BYTES]);(control/'abort').write_text('ABORT\n')
            connection.send.side_effect=sent
            with patch.object(stream.ssl,'create_default_context',return_value=context),patch.object(stream.ssl,'PEM_cert_to_DER_cert',return_value=b'DER'),patch.object(stream.socket,'create_connection'),patch.object(stream.http.client,'HTTPConnection',return_value=connection):
                value=stream.send_prefix(root,signer,'127.0.0.1',control)
            connection.putrequest.assert_called_once();connection.send.assert_called_once();connection.getresponse.assert_not_called()
            self.assertIn(('content-length',str(stream.BODY_BYTES)),[c.args for c in connection.putheader.call_args_list])
            self.assertEqual(signer.signed_headers.call_args.args[3],stream.body())
            self.assertTrue(value['clientConnectionClosed']);self.assertFalse(value['ackObserved']);self.assertFalse(value['responseRead'])
            self.assertEqual(value['putAttempts'],1);self.assertEqual(value['mutatingRetries'],0)
            self.assertTrue((control/'prefix-sent.json').is_file());self.assertFalse((control/'prefix-sent.tmp').exists())

    def test_preexisting_control_marker_prevents_any_connection(self):
        with tempfile.TemporaryDirectory() as temp:
            control=Path(temp);(control/'abort').write_text('ABORT\n')
            with patch.object(stream.socket,'create_connection') as connect,self.assertRaises(ValueError):stream.send_prefix(control,None,'127.0.0.1',control)
            connect.assert_not_called()

    def test_stream_mode_cannot_be_combined_with_other_fault_modes(self):
        for other in ('crash_volume','crash_filer','crash_master','crash_all'):
            with self.assertRaisesRegex(ValueError,'ONE_CRASH_ROLE'):
                lab.run(None,None,None,None,interrupt_stream=True,**{other:True})


if __name__=='__main__':unittest.main()
