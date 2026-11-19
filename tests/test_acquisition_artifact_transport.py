import hashlib,importlib.util,io,json,os,tempfile,unittest
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[1]/'scripts/transport-acquisition-read-artifacts-20261025.py'
spec=importlib.util.spec_from_file_location('transport',SOURCE);t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
class Response(io.BytesIO):
    def __init__(self,status,body=b'',headers=None):super().__init__(body);self.status=status;self.headers=headers or{}
class ArtifactTransportTest(unittest.TestCase):
    def setUp(self):
        self.fixture=tempfile.TemporaryDirectory(dir=SOURCE.parents[1]);self.root=Path(self.fixture.name);self.body=b'CI-archive-fixture'
        self.descriptor={'repository':'GioNob/ouf-mcp-server','artifactId':12589824695,'zipBytes':len(self.body),'zipSha256':hashlib.sha256(self.body).hexdigest()}
        self.calls=[];self.storage='https://productionresultssa1.blob.core.windows.net/actions-results/test?sig=private-signed-query';self.storageStatus=200
    def tearDown(self):self.fixture.cleanup()
    def opener(self,url,headers):
        self.calls.append((url,headers))
        if url.startswith('https://api.github.com/'):
            return Response(302,headers={'Location':self.storage})
        return Response(self.storageStatus,self.body,{'Content-Length':str(len(self.body))})
    def test_exact_zip_bytes_are_private_and_authorization_only_reaches_github_api(self):
        result=t.download('mcp',self.descriptor,'fixture-token',self.root,self.opener)
        self.assertTrue(result['verified']);self.assertEqual((self.root/'mcp.zip').read_bytes(),self.body)
        self.assertEqual(self.calls[0][1]['Authorization'],'Bearer fixture-token');self.assertNotIn('Authorization',self.calls[1][1])
        retained=b''.join(p.read_bytes()for p in self.root.iterdir());self.assertNotIn(b'fixture-token',retained);self.assertNotIn(b'private-signed-query',retained)
        self.assertEqual((self.root/'mcp.zip').stat().st_mode&0o777,0o400)
    def test_third_party_redirect_is_rejected_before_any_external_request(self):
        self.storage='https://proxy.invalid/artifact'
        with self.assertRaisesRegex(t.Stop,'GITHUB_STORAGE_REDIRECT_REQUIRED'):t.download('mcp',self.descriptor,'fixture-token',self.root,self.opener)
        self.assertEqual(len(self.calls),1)
    def test_cleartext_or_userinfo_redirect_is_rejected(self):
        for url in('http://objects.githubusercontent.com/a','https://user:password@objects.githubusercontent.com/a','https://productionresultssa1.blob.core.windows.net:444/a'):
            with self.assertRaises(t.Stop):t.storage_url(url)
    def test_partial_or_changed_artifact_is_retained_and_cannot_be_replayed(self):
        self.descriptor['zipSha256']='0'*64
        with self.assertRaisesRegex(t.Stop,'PINNED_ARTIFACT_BYTES_REQUIRED'):t.download('mcp',self.descriptor,'fixture-token',self.root,self.opener)
        self.assertTrue((self.root/'mcp.zip.part').exists());self.assertFalse((self.root/'mcp.zip').exists())
        calls=len(self.calls)
        with self.assertRaisesRegex(t.Stop,'ARTIFACT_ALREADY_PRESENT_RECONCILE'):t.download('mcp',self.descriptor,'fixture-token',self.root,self.opener)
        self.assertEqual(calls,len(self.calls))
    def test_existing_archive_is_never_overwritten(self):
        (self.root/'mcp.zip').write_bytes(b'retained')
        with self.assertRaisesRegex(t.Stop,'ARTIFACT_ALREADY_PRESENT_RECONCILE'):t.download('mcp',self.descriptor,'fixture-token',self.root,self.opener)
        self.assertEqual((self.root/'mcp.zip').read_bytes(),b'retained');self.assertEqual(self.calls,[])
    def test_oversize_content_length_stops_before_partial_file(self):
        self.descriptor['zipBytes']=1
        with self.assertRaisesRegex(t.Stop,'PINNED_CONTENT_LENGTH_REQUIRED'):t.download('mcp',self.descriptor,'fixture-token',self.root,self.opener)
        self.assertFalse((self.root/'mcp.zip.part').exists())
    def test_missing_content_length_still_enforces_stream_size(self):
        self.descriptor['zipBytes']=1
        def opener(url,headers):
            if url.startswith('https://api.github.com/'):return Response(302,headers={'Location':self.storage})
            return Response(200,self.body)
        with self.assertRaisesRegex(t.Stop,'EXACT_ARTIFACT_SIZE_BOUND'):t.download('mcp',self.descriptor,'fixture-token',self.root,opener)
        self.assertFalse((self.root/'mcp.zip').exists())
    def test_wrong_api_status_has_no_storage_get_and_no_credentials_in_error(self):
        with self.assertRaisesRegex(t.Stop,'GITHUB_ARTIFACT_REDIRECT_STATUS_REQUIRED'):
            t.download('mcp',self.descriptor,'fixture-token',self.root,lambda *_:Response(403,b'private-token-error'))
    def test_storage_redirects_are_finite_and_never_receive_authorization(self):
        def opener(url,headers):
            self.calls.append((url,headers));return Response(302,headers={'Location':self.storage})
        with self.assertRaisesRegex(t.Stop,'FINITE_STORAGE_REDIRECTS_EXHAUSTED'):t.download('mcp',self.descriptor,'fixture-token',self.root,opener)
        self.assertEqual(len(self.calls),4);self.assertTrue(all('Authorization'not in headers for _,headers in self.calls[1:]))
    def test_case_or_token_drift_stops_before_claim_or_network(self):
        with self.assertRaisesRegex(t.Stop,'EXACT_STAGING_CASE_REQUIRED'):t.transport({},self.root,'fixture-token',self.opener)
        with self.assertRaisesRegex(t.Stop,'JOB_GITHUB_TOKEN_REQUIRED'):t.transport({},self.root,'',self.opener)
        self.assertEqual(self.calls,[])
    def test_production_case_replay_stops_before_requests(self):
        case=json.loads((SOURCE.parents[1]/'releases/acquisition-read-package-case-20261025.json').read_text())
        (self.root/('ouf-acquisition-read-transport-'+t.CASE_HASH[:16])).mkdir()
        with self.assertRaisesRegex(t.Stop,'TRANSPORT_SCOPE_EXISTS_NO_REPLAY'):t.transport(case,self.root,'fixture-token',self.opener)
        self.assertEqual(self.calls,[])
    def test_cli_reports_closed_failure_instead_of_traceback_or_environment(self):
        import subprocess,sys
        result=subprocess.run([sys.executable,str(SOURCE)],capture_output=True,text=True,env=dict(os.environ,GH_TOKEN='fixture-token'))
        self.assertEqual(result.returncode,2);self.assertEqual(json.loads(result.stdout)['status'],'STOP_RECONCILE');self.assertNotIn('fixture-token',result.stdout+result.stderr);self.assertNotIn('Traceback',result.stderr)
if __name__=='__main__':unittest.main()
