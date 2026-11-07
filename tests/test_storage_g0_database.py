import copy,json,unittest
from unittest.mock import patch
from tools.storage_planning import g0_database as db
from tools.storage_planning.g0_reconciliation import reconcile,census,WRITERS
from tools.storage_planning.inventory_manifest import canonical,sha

def raw_export(profile,rows=None):
 rows=rows or {}
 data=[{'kind':'header','schema':'ouf.storage-g0-db-export.v1','profile':profile,'sourceSchemaCommit':db.SOURCES[profile],'readOnly':'on','isolation':'repeatable read','profileSchemaCompatible':True,'snapshot':'1:2:'}]
 for table in db.TABLES[profile]:
  data.append({'kind':'section','table':table,'tableOid':1,'columns':[{'name':c,'type':'text','notNull':False} for c in sorted(db.columns(profile,table))]})
  data.extend({'kind':'row','table':table,'value':dict.fromkeys(db.columns(profile,table))|r} for r in rows.get(table,[]))
 data.append({'kind':'footer','complete':True});return b'\n'.join(canonical(x) for x in data)+b'\n'
def fixture():
 h=sha(b'abc');asset='11111111-1111-1111-1111-111111111111';lake='22222222-2222-2222-2222-222222222222';ref='object://managed-files/'+asset;loc='lake/tenant/raw/'+h
 rows={'ouf_onboarding.managed_file_asset':[{'asset_id':asset,'tenant_id':'tenant','staging_ref':ref,'content_hash':'sha256:'+h,'size_bytes':3}], 'ouf_udp.lake_object':[{'lake_object_id':lake,'tenant_id':'tenant','locator':loc,'content_hash':'sha256:'+h,'logical_size_bytes':3,'state':'VERIFIED'}]}
 exports={p:db.parse_export(raw_export(p,rows),p) for p in ['onboarding','udp','ingestion']}
 collection={'schema':'ouf.storage-g0-body-collection.v1','complete':True,'sourceObservationsEqual':True,'runtimeAuthorityIssued':False,'installationRef':'fixture','objects':[{'bucket':'ouf-managed-files','key':ref[9:],'versionId':None,'bytes':3,'sha256':h,'etag':'"synthetic"'},{'bucket':'ouf-udp','key':loc,'versionId':None,'bytes':3,'sha256':h,'etag':'"synthetic"'}]}
 writers={'schema':'ouf.storage-g0-writer-census.v1','installationRef':'fixture','paths':[]}
 return collection,exports,{'onboarding':'ouf-managed-files','udp':'ouf-udp'},writers
class G0DatabaseTest(unittest.TestCase):
 def test_all_profiles_have_fixed_read_only_projection(self):
  for p in db.TABLES:
   self.assertEqual(len(db.parse_export(raw_export(p),p)['sections']),len(db.TABLES[p]));q=db.sql(p);self.assertIn('REPEATABLE READ READ ONLY',q);self.assertIn('row_security=off',q);self.assertNotIn('SELECT *',q)
 def test_incomplete_export_denied(self):
  raw=raw_export('udp');self.assertRaises(ValueError,db.parse_export,raw.rsplit(b'\n',2)[0],'udp')
 def test_duplicate_json_denied(self):self.assertRaises(ValueError,db.parse_export,b'{"kind":"header","kind":"header"}\n','udp')
 def test_wrong_schema_or_writable_export_denied(self):
  for old,new in [(b'"on"',b'"off"'),(b'"profileSchemaCompatible":true',b'"profileSchemaCompatible":false'),(db.SOURCES['udp'].encode(),b'0'*40)]:self.assertRaises(ValueError,db.parse_export,raw_export('udp').replace(old,new),'udp')
 def test_row_limit_is_not_silent_truncation(self):
  with patch.object(db,'MAX_ROWS',0):self.assertRaises(ValueError,db.parse_export,raw_export('udp',{'ouf_udp.lake_object':[{}]}),'udp')
 def test_body_join_is_never_admission(self):
  r=reconcile(*fixture());self.assertEqual(r['findingsCount'],0);self.assertEqual(r['classifiedBodies'],2);self.assertFalse(r['g0Complete']);self.assertFalse(r['writerCensus']['intakeComplete'])
 def test_missing_body_and_hash_and_size(self):
  for mode in ['missing','hash','size']:
   args=list(fixture())
   if mode=='missing':args[0]['objects'].pop()
   elif mode=='hash':args[0]['objects'][0]['sha256']='0'*64
   else:args[0]['objects'][0]['bytes']=4
   self.assertGreater(reconcile(*args)['findingsCount'],0)
 def test_duplicate_body_or_db_id_denied(self):
  args=list(fixture());args[0]['objects'].append(copy.deepcopy(args[0]['objects'][0]));self.assertRaises(ValueError,reconcile,*args)
  args=list(fixture());rows=args[1]['udp']['sections']['ouf_udp.lake_object']['rows'];rows.append(copy.deepcopy(rows[0]));self.assertRaises(ValueError,reconcile,*args)
 def test_compaction_does_not_compare_slice_hash_to_pack(self):
  args=list(fixture());args[1]['udp']['sections']['ouf_udp.lake_object']['rows'][0]['locator']='manifest://missing';r=reconcile(*args);self.assertIn('COMPACTED_SLICE_VERIFICATION_REQUIRED',[f['code'] for f in r['observationFindings']])
 def test_writer_unknown_is_not_absent_and_declaration_is_not_fence(self):
  c={'schema':'ouf.storage-g0-writer-census.v1','installationRef':'fixture','paths':[{'path':p,'presence':'ABSENT','provenance':'OPERATOR_DECLARATION','evidenceSha256':'0'*64,'capturedAt':'2026-11-05T00:00:00Z','ownerRef':'fixture-owner'} for p in WRITERS]};r=census(c,'fixture');self.assertTrue(r['intakeComplete']);self.assertFalse(r['writersQuiescentProven']);self.assertFalse(r['evidenceAuthenticityVerified']);c['paths'][0]['presence']='UNKNOWN';self.assertFalse(census(c,'fixture')['intakeComplete'])
 def test_watermark_requires_ack(self):
  args=list(fixture());sections=args[1]['ingestion']['sections'];sections['ouf_ingestion.handoff_outbox']['rows']=[{'handoff_id':'h','run_id':'r','lineage_id':'l','state':'READY','raw_object_ref':None,'partition_key':'p','sequence_no':1,'candidate_watermark_sha256':'a'}];sections['ouf_ingestion.ing_watermark']['rows']=[{'committed_handoff_id':'h','partition_key':'p','source_id':'s','watermark_sha256':'a'}];r=reconcile(*args);self.assertIn('WATERMARK_ACK_BINDING_MISMATCH',[f['code'] for f in r['observationFindings']])
 def test_unknown_body_not_treated_as_safe_orphan(self):
  args=list(fixture());p=copy.deepcopy(args[0]['objects'][0]);p['key']='unclassified';args[0]['objects'].append(p);r=reconcile(*args);self.assertIn('UNCLASSIFIED_BODY',[f['code'] for f in r['observationFindings']])
if __name__=='__main__':unittest.main()
