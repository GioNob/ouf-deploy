"""Backup proof and failure boundaries; no live database or runtime mutation."""
import copy,hashlib,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.linked_property_rollout import database as d
from tools.linked_property_rollout.owner import digest,UpdateDenied
class Backup(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  self.fact={'database':'ouf_udp','databaseOid':123,'role':'fixture_admin','migrations':[{'version':'34'}]}
  self.plan={'authorityDirectory':str(self.root),'engine':{'socketPath':'/fixture.sock'},'programs':{'docker':{'path':'/fixture/docker'}},
             'database':{'postgresRuntimeBinding':{'containerId':'a'*64},'before':{'udp':self.fact}}}
  self.db=d.Database(self.plan,{}, {'read':lambda p,*_:json.loads(Path(p).read_text())})
  self.db.guard=lambda:None;self.db.quiescent=lambda:None;self.db.verify_before=lambda:{'udp':copy.deepcopy(self.fact)}
  self.calls=[];self.payload=b'PGDMP'+b'x'*256
  def bounded(args,seconds,maximum,**kw):
   self.calls.append(args)
   if 'pg_dump' in args:
    kw['output_stream'].write(self.payload)
    return b'',{'customFormatHeader':True,'bytes':len(self.payload),'sha256':hashlib.sha256(self.payload).hexdigest()}
   self.assertIn('pg_restore',args);self.assertIn('--file=/dev/null',args)
   self.assertEqual(kw['input_stream'].read(),self.payload)
   if getattr(self,'parse_failure',False):raise RuntimeError('CORRUPT_BACKUP')
   return b'',{}
  for target,name,value in ((d,'command',lambda b:b['path']),(d,'bounded',bounded)):
   p=patch.object(target,name,value);p.start();self.addCleanup(p.stop)
 def test_full_payload_is_parsed_before_backup_evidence_is_published(self):
  proof=self.db.backup();self.assertTrue(proof['payloadParsed']);self.assertEqual(len(self.calls),2)
  self.assertIn('-i',self.calls[1]);self.assertNotIn('--list',self.calls[1]);self.assertFalse(proof['restorePerformed'])
  self.assertEqual((self.root/'udp.dump').read_bytes(),self.payload)
 def test_parse_failure_leaves_no_complete_backup_proof(self):
  self.parse_failure=True
  with self.assertRaises(RuntimeError):self.db.backup()
  self.assertFalse((self.root/'backup.json').exists());self.assertTrue((self.root/'udp.dump').exists())
 def test_existing_partial_archive_is_never_overwritten_or_retried(self):
  (self.root/'udp.dump').write_bytes(b'partial')
  with self.assertRaises(FileExistsError):self.db.backup()
  self.assertEqual(self.calls,[]);self.assertEqual((self.root/'udp.dump').read_bytes(),b'partial')
 def test_running_producer_blocks_before_dump(self):
  def not_quiescent():raise UpdateDenied('BOTH_APPLICATIONS_MUST_BE_STOPPED_FOR_BACKUP')
  self.db.quiescent=not_quiescent
  with self.assertRaises(UpdateDenied):self.db.backup()
  self.assertEqual(self.calls,[])
 def test_schema_drift_during_dump_leaves_no_success_proof(self):
  facts=iter([{'udp':self.fact},{'udp':{**self.fact,'migrations':[{'version':'35'}]}}])
  self.db.verify_before=lambda:next(facts)
  with self.assertRaises(UpdateDenied):self.db.backup()
  self.assertFalse((self.root/'backup.json').exists())
