"""Readback queries against PostgreSQL fixtures, never the target installation."""
import importlib.util,json,os,subprocess,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('linked_reader',ROOT/'scripts/read-linked-property-post-rollout-20261017.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Metadata(unittest.TestCase):
 def test_history_drift_is_rejected(self):
  wanted=[dict(version='35',script='V35__linked_property_reconciliation.sql',checksum=-376865285,success=True)]
  r.validate_history({'migrations':wanted},wanted)
  with self.assertRaises(ValueError):r.validate_history({'migrations':[{**wanted[0],'success':False}]},wanted)
 def test_sql_bindings_reject_injection_and_unknown_modules(self):
  with self.assertRaises(ValueError):r.query('onboarding',"bad';COMMIT;--",'subject')
  with self.assertRaises(ValueError):r.query('unknown','tenant','subject')
  for module in('udp','onboarding'):
   sql=r.query(module,'tenant','subject');self.assertTrue(sql.startswith('BEGIN READ ONLY;'));self.assertTrue(sql.endswith('ROLLBACK;'))

@unittest.skipUnless(os.environ.get('OUF_TEST_POSTGRES_CONTAINER'),'Dedicated PostgreSQL fixture required')
class PostgresProjection(unittest.TestCase):
 @classmethod
 def sql(cls,query):
  out=subprocess.run(['docker','exec','-i',os.environ['OUF_TEST_POSTGRES_CONTAINER'],'psql','-U','postgres','-X','-q','-A','-t','-v','ON_ERROR_STOP=1'],input=query.encode(),capture_output=True,timeout=20)
  if out.returncode:raise AssertionError(out.stderr.decode())
  return out.stdout.decode().strip()
 @classmethod
 def setUpClass(cls):
  cls.sql('''create schema ouf_udp;create schema ouf_onboarding;
   create table ouf_udp.flyway_schema_history(installed_rank int,version text,script text,checksum int,success boolean);
   create table ouf_onboarding.flyway_schema_history(like ouf_udp.flyway_schema_history);
   insert into ouf_udp.flyway_schema_history values(35,'35','V35__linked_property_reconciliation.sql',-376865285,true);
   insert into ouf_onboarding.flyway_schema_history values(1,'1','V1__onboarding_core.sql',7,true);
   create table ouf_udp.handoff_property_profile(handoff_id text);
   create table ouf_udp.property_value(reconciliation_evidence jsonb);
   create table ouf_onboarding.source(source_id text,source_kind text,acquisition_mode text);
   create table ouf_onboarding.onboarding_version(onboarding_version_id uuid,source_id text,state text,configuration_hash text,configuration jsonb);
   create table ouf_onboarding.published_configuration(publication_id uuid,source_id text,onboarding_version_id uuid,bundle_version int,bundle jsonb,checksum text,active boolean);
   create table ouf_onboarding.managed_onboarding_review(onboarding_version_id uuid,source_id text,tenant_id text,subject_id text);''')
  property={'sourceField':'urn:field:name','propertyIri':'urn:field:name','datatype':'string','accessLabel':'RESTRICTED','authorityOrder':['source-a']}
  cls.config={'extractionProfile':{'runtime':{'udp':{'materialization':{'policyRef':'urn:materialize:v1','properties':[property]}}}},'syncProfile':{'incremental':'NONE'},'credential':'SECRET_MUST_NOT_APPEAR'}
  bundle={**cls.config,'triggerOnce':True}
  sid=r.literal(r.SOURCE);vid=r.literal(r.VERSION);conf="'"+json.dumps(cls.config)+"'::jsonb";b="'"+json.dumps(bundle)+"'::jsonb"
  cls.sql(f"insert into ouf_onboarding.source values({sid},'INTERNAL_MANAGED','MANAGED'); insert into ouf_onboarding.onboarding_version values({vid},{sid},'ACTIVE','sha256:fixture',{conf}); insert into ouf_onboarding.published_configuration values('11111111-1111-4111-8111-111111111111',{sid},{vid},1,{b},'sha256:fixture',true); insert into ouf_onboarding.managed_onboarding_review values({vid},{sid},'tenant','subject');")
 def test_v35_and_profile_projection_on_real_postgres(self):
  udp=json.loads(self.sql(r.query('udp','tenant','subject')))
  self.assertTrue(udp['transactionReadOnly']);self.assertTrue(udp['profileTablePresent']);self.assertTrue(udp['evidenceColumnPresent'])
  raw=self.sql(r.query('onboarding','tenant','subject'));self.assertNotIn('SECRET_MUST_NOT_APPEAR',raw)
  report=json.loads(raw);self.assertTrue(report['transactionReadOnly']);self.assertEqual(report['activePublicationCount'],1)
  profile=report['publications'][0]
  self.assertTrue(profile['selectedVersionMatches']);self.assertTrue(profile['ownedReviewMatches']);self.assertTrue(profile['profileMatchesApprovedConfiguration'])
  self.assertEqual(profile['propertyCount'],1);self.assertEqual(profile['properties'][0]['datatype'],'string');self.assertTrue(profile['triggerOnce'])
  other=json.loads(self.sql(r.query('onboarding','different-tenant','subject')))
  self.assertFalse(other['publications'][0]['ownedReviewMatches'])
