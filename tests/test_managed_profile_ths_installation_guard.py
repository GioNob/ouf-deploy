"""Exercise the actual native verifier definitions sealed by owner update Context."""
import ast,hashlib,json,re,tempfile,unittest,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Denied(Exception):pass
def require(ok,code):
 if not ok:raise Denied(code)
class InstallationGuard(unittest.TestCase):
 def invoke(self,scopes,*,recovery=True,nested=False):
  raw=(ROOT/'tools/source_revision_update/configuration.py').read_text();names=('application_json_metadata','owner_json_overlay','overlay_text','additional_location','verify')
  nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name in names]
  namespace={'hashlib':hashlib,'json':json,'os':__import__('os'),'Path':Path,'re':re,'urlsplit':__import__('urllib.parse',fromlist=['urlsplit']).urlsplit,'zipfile':zipfile,'require':require,
             'env':lambda rows:dict(row.split('=',1)for row in rows),'private_file':lambda path,checksum,maximum:require(hashlib.sha256(Path(path).read_bytes()).hexdigest()==checksum,'JAR_DRIFT'),
             'private_config':lambda _:self.fail('unexpected config file read')}
  exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-native-configuration-definitions>','exec'),namespace)
  with tempfile.TemporaryDirectory()as directory:
   jar=Path(directory)/'owner.jar';yaml=b'fixture: true\n'
   with zipfile.ZipFile(jar,'w')as out:
    out.writestr('BOOT-INF/classes/application.yml',yaml);out.writestr('BOOT-INF/lib/flyway-core-fixture.jar',b'fixture')
    if recovery:out.writestr('BOOT-INF/classes/fixture/api/ManagedProfileRecoveryThs.class',b'package contract fixture only')
   obj={'spring.security.oauth2.client.registration.ouf-ths.scope':scopes}if not nested else{'spring':{'security':{'oauth2':{'client':{'registration':{'ouf-ths':{'scope':scopes}}}}}}}
   actual={'Config':{'Env':['OUF_ONB_DB_USER=fixture-runtime','OUF_ONB_DB_PASSWORD=PRIVATE_FIXTURE_ONLY','OUF_ONB_DB_URL=jdbc:postgresql://fixture-postgres:5432/fixture-db','SPRING_APPLICATION_JSON='+json.dumps(obj)],'WorkingDir':'/app','Entrypoint':['java'],'Cmd':['-jar','app.jar']},'Mounts':[]}
   postgres={'Name':'/fixture-postgres','Config':{'Hostname':'fixture-postgres'},'NetworkSettings':{'Networks':{}}}
   return namespace['verify'](actual,{'jar':{'path':str(jar),'sha256':hashlib.sha256(jar.read_bytes()).hexdigest()}},postgres,
      {'user':'fixture-runtime','database':'fixture-db','schema':'public'},5432,hashlib.sha256(yaml).hexdigest(),root=Path(directory)/'proc-root')
 def test_new_recovery_artifact_cannot_pass_native_preflight_with_old_request(self):
  with self.assertRaisesRegex(Denied,'RECOVERY_THS_REQUEST_SCOPE_CONTRACT_INCOMPLETE'):self.invoke(['openid','resolution.issue.read','resolution.match.approve'])
 def test_complete_contract_passes_actual_verifier_for_flat_and_nested_configuration(self):
  scopes=['openid','resolution.issue.read','ouf.managed-source.preview','ouf.managed-source.file.profile','ouf.onboarding.quarantine.release']
  for nested in (False,True):
   with self.subTest(nested=nested):self.assertTrue(self.invoke(scopes,nested=nested)['nativeFlywayEnabledByDefault'])
 def test_legacy_artifact_without_recovery_keeps_its_own_existing_contract(self):
  self.assertTrue(self.invoke(['openid','resolution.issue.read'],recovery=False)['nativeFlywayEnabledByDefault'])
if __name__=='__main__':unittest.main()
