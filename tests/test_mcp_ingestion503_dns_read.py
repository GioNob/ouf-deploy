import ast,copy,importlib.util,os,socket,struct,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tests'))
SCRIPT=ROOT/'scripts/read-mcp-ingestion503-dns.py'
if not SCRIPT.exists():SCRIPT=Path(__file__).with_name('read.py')
spec=importlib.util.spec_from_file_location('qualified_dns_reader',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def packet(name='missing-service',addresses=('10.9.0.2',),flags=0x8180,ident=12,answer_name=None):
 question=m.dns_name(name)+struct.pack('!2H',1,1);answers=b''
 for address in addresses:
  owner=b'\xc0\x0c'if answer_name is None else m.dns_name(answer_name)
  answers+=owner+struct.pack('!2HIH',1,1,10,4)+socket.inet_aton(address)
 return struct.pack('!6H',ident,flags,1,len(addresses),0,0)+question+answers
class DNS(unittest.TestCase):
 def test_exact_question_compressed_ipv4_answer_and_bounded_request(self):
  result=m.dns_reply(packet(),12,'missing-service');self.assertEqual(result,{'status':'RESOLVED','addresses':{'10.9.0.2'}})
  self.assertEqual(m.dns_name('Service.Name'),b'\x07service\x04name\x00')
  for name in('https://caller.invalid','a'*64+'.name','name:53','a..b'):
   with self.assertRaises(Exception):m.dns_name(name)
 def test_nxdomain_or_unrelated_records_do_not_claim_owner_resolution(self):
  self.assertEqual(m.dns_reply(packet(addresses=(),flags=0x8183),12,'missing-service')['status'],'NXDOMAIN')
  result=m.dns_reply(packet(answer_name='unrelated'),12,'missing-service');self.assertEqual(result['status'],'NO_A_ANSWER');self.assertEqual(result['addresses'],set())
 def test_cname_chain_is_accepted_but_compression_loop_is_denied(self):
  name='logical';target='owner';question=m.dns_name(name)+struct.pack('!2H',1,1);encoded=m.dns_name(target)
  cname=b'\xc0\x0c'+struct.pack('!2HIH',5,1,10,len(encoded))+encoded
  answer=encoded+struct.pack('!2HIH',1,1,10,4)+socket.inet_aton('10.9.0.2')
  raw=struct.pack('!6H',12,0x8180,1,2,0,0)+question+cname+answer
  self.assertEqual(m.dns_reply(raw,12,name)['addresses'],{'10.9.0.2'})
  with self.assertRaises(Exception):m.decode_name(b'\xc0\x00',0)
 def test_wrong_id_question_malformed_or_truncated_response_fails_closed(self):
  for raw,ident,name in((packet(),13,'missing-service'),(packet(),12,'different'),(packet()[:-1],12,'missing-service'),(packet()+b'junk',12,'missing-service')):
   with self.assertRaises(Exception):m.dns_reply(raw,ident,name)
  self.assertEqual(m.dns_reply(packet(flags=0x8380),12,'missing-service'),{'status':'TRUNCATED','addresses':set()})
 def test_one_udp_request_no_retry_and_only_local_resolver(self):
  client=Mock();client.send.side_effect=lambda raw:len(raw);client.recv.return_value=packet()
  with patch.object(m.os,'urandom',return_value=b'\x00\x0c'),patch.object(m.socket,'socket',return_value=client):
   result=m.query_dns('missing-service','127.0.0.11')
  self.assertEqual(result['status'],'RESOLVED');client.send.assert_called_once();client.connect.assert_called_once_with(('127.0.0.11',53));client.close.assert_called_once()
  client.reset_mock();client.recv.side_effect=TimeoutError()
  with patch.object(m.os,'urandom',return_value=b'\x00\x0c'),patch.object(m.socket,'socket',return_value=client):self.assertEqual(m.query_dns('missing-service','127.0.0.11')['status'],'TIMEOUT')
  client.send.assert_called_once();client.close.assert_called_once()
  with self.assertRaises(Exception):m.query_dns('missing-service','8.8.8.8')
 def test_projection_never_prints_dns_names_addresses_or_credentials(self):
  result=m.project_dns('RETAINED_ROUTE_TARGET',{'status':'RESOLVED','addresses':{'10.9.0.2','10.9.0.3'}},{'10.9.0.2'})
  self.assertTrue(result['hasRetainedOwnerAddress']);self.assertTrue(result['hasOtherAddress']);self.assertFalse(result['allAnswersBelongToRetainedOwner'])
  self.assertNotIn('10.9.',m.encoded(result).decode())
 def test_owner_alias_requires_exact_one_shared_network_and_explicit_alias(self):
  gateway={'NetworkSettings':{'Networks':{'shared':{}}}};owner={'Name':'/owner','NetworkSettings':{'Networks':{'shared':{'Aliases':['owner'],'IPAddress':'10.9.0.2'}}}}
  self.assertEqual(m.owner_alias(gateway,owner),('owner',{'10.9.0.2'}))
  owner['NetworkSettings']['Networks']['shared']['Aliases']=[]
  with self.assertRaises(Exception):m.owner_alias(gateway,owner)
 def test_no_child_process_login_backend_probe_or_owner_write(self):
  calls=[ast.unparse(n.func)for n in ast.walk(ast.parse(SCRIPT.read_bytes()))if isinstance(n,ast.Call)]
  self.assertFalse(any(v.endswith(('.Popen','.execv','.login','.refresh_if_due','.write_text','.write_bytes','.migrate'))for v in calls));self.assertNotIn('entry.main',calls)
class KernelAndProfile(unittest.TestCase):
 def test_real_kernel_namespace_restored_even_after_exception(self):
  before=Path('/proc/self/ns/net').stat();binding={'device':before.st_dev,'inode':before.st_ino}
  class StopProbe(Exception):pass
  with self.assertRaises(StopProbe):
   with m.gateway_namespace(os.getpid(),binding):raise StopProbe()
  after=Path('/proc/self/ns/net').stat();self.assertEqual((after.st_dev,after.st_ino),(before.st_dev,before.st_ino))
 def test_approved_projection_actual_root_custody_default_and_explicit_binding(self):
  with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)))as directory:
   path=Path(directory)/'projection.json'
   for explicit in (False,True):
    target='owner'if explicit else'ouf-ingestion-runtime';value={'services':{'bindings':{'ouf-ingestion-runtime':target}if explicit else{}}}
    path.write_bytes(m.encoded(value));path.chmod(0o600);raw,pin=m.root_file(path)
    routes={mode:{'uri':'/internal/capabilities/v1/execute/ouf.ingestion.'+mode,'methods':['POST'],'upstream':{'scheme':'http','nodes':{target+':8080':1}},'plugins':{'serverless-post-function':{'functions':['local DELEGATION_KEY_ENV = "KEY"\n']}}}for mode in('status','history')}
    plan={'gateway':{'projectionBinding':{'path':str(path),'sha256':m.sha(raw),'metadata':pin},'afterRoutes':routes}}
    with patch.object(m,'PROFILE_PATH',str(path)):
     result,selected=m.profile_binding(plan);self.assertEqual(selected,target);self.assertEqual(result['explicitIngestionServiceBindingPresent'],explicit)
     path.write_bytes(b'changed')
     with self.assertRaises(Exception):m.profile_binding(plan)
# Exercise the same retained-history/custody tests against this new reader.
try:
 import test_mcp_ingestion503_topology_read as prior
 class RetainedHistory(prior.CompletedHistory):
  def setUp(self):
   p=patch.object(prior,'m',m);p.start();self.addCleanup(p.stop)
 class RetainedPrivateCustody(prior.Custody):
  def setUp(self):
   p=patch.object(prior,'m',m);p.start();self.addCleanup(p.stop)
except ImportError:pass
if __name__=='__main__':unittest.main()
