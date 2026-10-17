"""Reject ambiguous Spring, JDBC and external-file bindings before any stop."""
import copy,hashlib,json,sys,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.linked_property_rollout import configuration as c
class Configuration(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  self.raw=(ROOT/'releases/linked-property-udp-application.yml').read_bytes();self.sha=hashlib.sha256(self.raw).hexdigest()
  self.jar=self.root/'candidate.jar'
  with zipfile.ZipFile(self.jar,'w')as z:
   z.writestr('BOOT-INF/classes/application.yml',self.raw);z.writestr('BOOT-INF/lib/flyway-core-fixture.jar',b'fixture')
  self.candidate={'jar':{'path':str(self.jar),'sha256':hashlib.sha256(self.jar.read_bytes()).hexdigest()}}
  self.actual={'Config':{'Env':['JAVA_HOME=/opt/java','JAVA_VERSION=21','OUF_UDP_DB_URL=jdbc:postgresql://pg:5432/ouf_udp','OUF_UDP_DB_USER=ouf_udp','OUF_UDP_DB_PASSWORD=fixture-only'], 'Entrypoint':['java','-jar','/app/app.jar'],'Cmd':None,'WorkingDir':'/app'}}
  self.pg={'Name':'/pg','Config':{'Hostname':'pg'},'NetworkSettings':{'Networks':{}}}
  p=patch.object(c,'private_file');p.start();self.addCleanup(p.stop)
 def verify(self):return c.verify(self.actual,self.candidate,self.pg,self.sha,root=self.root)
 def test_qualified_default_binding_has_no_secret_output(self):
  result=self.verify();self.assertTrue(result['sameDatasourceAsApplication']);self.assertNotIn('fixture-only',json.dumps(result))
 def test_spring_java_json_and_loader_overrides_are_rejected(self):
  for value in ['SPRING_FLYWAY_ENABLED=false','SPRING_APPLICATION_JSON={"spring":{"flyway":{"enabled":false}}}','JAVA_TOOL_OPTIONS=-Dspring.flyway.user=admin','_JAVA_OPTIONS=-Dspring.config.location=/other','LOADER_PATH=/other','SPRING_PROFILES_ACTIVE=test']:
   with self.subTest(value=value):
    self.actual['Config']['Env'].append(value)
    with self.assertRaises(Exception):self.verify()
    self.actual['Config']['Env'].pop()
 def test_wrong_database_role_endpoint_and_jdbc_options_rejected(self):
  for key,value in [('OUF_UDP_DB_URL','jdbc:postgresql://elsewhere:5432/ouf_udp'),('OUF_UDP_DB_URL','jdbc:postgresql://pg:5432/other'),('OUF_UDP_DB_URL','jdbc:postgresql://pg:5432/ouf_udp?user=admin'),('OUF_UDP_DB_USER','admin')]:
   old=self.actual['Config']['Env'];self.actual['Config']['Env']=[v for v in old if not v.startswith(key+'=')]+[key+'='+value]
   with self.assertRaises(Exception):self.verify()
   self.actual['Config']['Env']=old
 def test_external_default_configuration_is_not_ignored(self):
  (self.root/'app/config').mkdir(parents=True);(self.root/'app/config/application.yml').write_text('spring.flyway.enabled: false')
  with self.assertRaises(Exception):self.verify()
 def test_jar_configuration_drift_is_rejected(self):
  with zipfile.ZipFile(self.jar,'w')as z:z.writestr('BOOT-INF/classes/application.yml',self.raw+b'\nspring.flyway.enabled: false\n')
  with self.assertRaises(Exception):self.verify()
 def test_unknown_profile_configuration_is_rejected(self):
  with zipfile.ZipFile(self.jar,'a')as z:z.writestr('BOOT-INF/classes/application-prod.yml','spring.flyway.enabled: false')
  with self.assertRaises(Exception):self.verify()
