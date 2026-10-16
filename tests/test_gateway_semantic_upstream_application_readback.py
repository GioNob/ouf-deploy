import ast,copy,hashlib,http.server,importlib.util,json,os,socket,subprocess,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('upstream_apply',ROOT/'scripts/apply-chatbot-semantic-upstream-repair-20261016.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Application(unittest.TestCase):
    def fixture(self):
        before={'a':{'id':'a','upstream':{'nodes':{'old:8080':1}}},'untouched':{'id':'untouched'}}
        after=copy.deepcopy(before);after['a']['upstream']['nodes']={'127.0.0.1:8080':1}
        repair={'changes':[{'routeId':'a','before':before['a'],'after':after['a']}],'proposedRoutes':after}
        return before,after,repair
    def test_claim_durable_before_write_and_complete_map_preserved(self):
        before,after,repair=self.fixture();current=copy.deepcopy(before);records=[]
        def persist(value,exclusive):records.append(copy.deepcopy(value))
        def write(rid,row):
            self.assertEqual(records[-1]['effects'][-1]['state'],'CLAIMED');current[rid]=copy.deepcopy(row);return 'ack'
        with patch.object(r,'emit'):
            out=r.apply_route_changes(repair,before,lambda:current,write,lambda:None,persist)
        self.assertEqual(current,after);self.assertEqual(out['state'],'COMPLETE');self.assertEqual(out['nextStep'],1)
        self.assertEqual(records[-1]['effects'][0]['state'],'APPLIED')
    def test_ambiguous_write_keeps_claim_and_never_repeats(self):
        before,after,repair=self.fixture();records=[];calls=[]
        def write(rid,row):calls.append(rid);raise r.ReadDenied('AMBIGUOUS')
        with self.assertRaisesRegex(r.ReadDenied,'AMBIGUOUS'):
            r.apply_route_changes(repair,before,lambda:before,write,lambda:None,lambda value,exclusive:records.append(copy.deepcopy(value)))
        self.assertEqual(calls,['a']);self.assertEqual(records[-1]['effects'][-1]['state'],'CLAIMED')
    def test_unrelated_map_drift_blocks_before_write(self):
        before,after,repair=self.fixture();write=lambda *args:self.fail('must not write')
        with self.assertRaisesRegex(r.ReadDenied,'COMPLETE_MAP_BEFORE_DRIFT'):
            r.apply_route_changes(repair,before,lambda:{},write,lambda:None,lambda *args:None)
    def test_guard_revocation_after_claimed_write_does_not_mark_applied(self):
        before,after,repair=self.fixture();records=[];calls=iter([None,r.ReadDenied('REVOKED')]);current=copy.deepcopy(before)
        def guard():
            value=next(calls)
            if value:raise value
        def write(rid,row):current[rid]=row;return 'ack'
        with self.assertRaisesRegex(r.ReadDenied,'REVOKED'):
            r.apply_route_changes(repair,before,lambda:current,write,guard,lambda value,exclusive:records.append(copy.deepcopy(value)))
        self.assertEqual(records[-1]['effects'][-1]['state'],'CLAIMED')
    def test_exclusive_journal_refuses_existing_claim(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as tmp:
            path=Path(tmp)/'journal.json';r.atomic_record(path,{'state':'CLAIMED'},True)
            with self.assertRaises(FileExistsError):r.atomic_record(path,{'state':'NEW'},True)
            self.assertEqual(json.loads(path.read_text()),{'state':'CLAIMED'})
    def test_only_get_and_exact_route_put_no_delete_or_service_actions(self):
        for source in (r.GET_CHILD,r.PUT_CHILD):
            for node in ast.walk(ast.parse(source)):
                if isinstance(node,ast.Call)and isinstance(node.func,ast.Attribute)and node.func.attr=='request':
                    self.assertIn(ast.literal_eval(node.args[0]),('GET','PUT'))
        self.assertIn("'/apisix/admin/routes/'+rid",r.PUT_CHILD)
        main=next(x for x in ast.parse(Path(r.__file__).read_text()).body if isinstance(x,ast.FunctionDef)and x.name=='apply_main')
        text=ast.unparse(main);self.assertLess(text.index('terminal_repair_decision('),text.index('sign_and_verify('))
        self.assertLess(text.index('sign_and_verify('),text.index('apply_route_changes('))
    def test_native_ed25519_both_roles_and_tamper_denial(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as tmp:
            folder=Path(tmp);folder.chmod(0o700);private=folder/'private.pem'
            result=subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','Ed25519','-out',str(private)],capture_output=True)
            self.assertEqual(result.returncode,0);private.chmod(0o600)
            raw=private.read_bytes();public=subprocess.run(['/usr/bin/openssl','pkey','-in',str(private),'-pubout','-outform','DER'],capture_output=True,check=True).stdout[-32:]
            program={'path':'/usr/bin/openssl','sha256':hashlib.sha256(Path('/usr/bin/openssl').read_bytes()).hexdigest()}
            profile={'keyBindings':{'installer':{'path':str(private),'sha256':hashlib.sha256(raw).hexdigest()}}}
            key={'keyRef':'fixture-key','issuerRef':'fixture-installer','publicKey':public.hex()};authority={'scope':'exact-test','expiresAt':2000000000,'installationRef':'fixture-installation','entityRef':'fixture-entity'}
            signatures=r.sign_and_verify(authority,profile,key,program,folder);r.verify_signatures(authority,signatures,key,program,folder)
            self.assertEqual(len(signatures),2);bad=copy.deepcopy(authority);bad['scope']='tampered'
            with self.assertRaisesRegex(r.ReadDenied,'SIGNATURE_HEADER_REQUIRED'):r.verify_signatures(bad,signatures,key,program,folder)
    def test_native_namespace_put_sends_only_selected_route_and_checks_ack(self):
        try:info=os.stat('/proc/self/ns/net')
        except FileNotFoundError:
            if os.environ.get('OUF_NATIVE_NAMESPACES')=='1':raise
            self.skipTest('local namespace unavailable; CI forbids skip')
        row={'id':'selected','uri':'/fixed','upstream':{'nodes':{'127.0.0.1:8080':1}}};seen=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_PUT(self):
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));seen.append((self.path,body))
                raw=json.dumps({'value':body}).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def log_message(self,*args):pass
        server=http.server.HTTPServer(('127.0.0.1',9180),Handler);self.addCleanup(server.server_close)
        thread=threading.Thread(target=server.handle_request,daemon=True);thread.start()
        binding={'runtimeBinding':{'pid':os.getpid()},'networkNamespace':{'device':info.st_dev,'inode':info.st_ino},
            'pythonExecutable':{'path':'/usr/bin/python3'}}
        with patch.object(r,'gateway_check',return_value='fixture-admin-key-value'),patch.object(r,'executable',return_value='/usr/bin/python3'):
            ack=r.gateway_put({},binding,'selected',row)
        thread.join(3);self.assertFalse(thread.is_alive());self.assertEqual(seen,[('/apisix/admin/routes/selected',row)]);self.assertEqual(len(ack),64)
if __name__=='__main__':unittest.main()
