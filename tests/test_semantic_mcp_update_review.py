"""Private-only preparation; real qualified image archive when supplied by CI."""
import copy,hashlib,importlib.util,io,json,os,stat,tempfile,time,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=module(ROOT/'scripts/prepare-chatbot-semantic-mcp-update-review-20261016.py','update_review')
r=module(ROOT/'scripts/read-chatbot-semantic-mcp-reprocessing-preflight-20261016.py','preflight')
c=module(ROOT/'tools/semantic_application_cutover/image_custody.py','image_custody')
class Preparation(unittest.TestCase):
 def test_closed_archive_shape_rejects_duplicate_missing_links_and_expansion(self):
  for fault in ('missing','duplicate','link','oversize'):
   with self.subTest(fault=fault):
    data=io.BytesIO()
    with zipfile.ZipFile(data,'w')as z:
     for name in sorted(m.MEMBERS):
      if fault=='missing'and name=='package/ouf-mcp':continue
      item=zipfile.ZipInfo(name);item.external_attr=((stat.S_IFLNK|0o777)if fault=='link'and name=='package/ouf-mcp'else(stat.S_IFREG|0o600))<<16
      z.writestr(item,b'x')
     if fault=='duplicate':z.writestr('package/ouf-mcp',b'x')
    data.seek(0)
    with zipfile.ZipFile(data)as z:
     if fault=='oversize':z.infolist()[0].file_size=134217729
     with self.assertRaises(m.PreparationDenied):m.validate_zip(z)
 def test_bounded_input_pin_no_symlink_and_wrong_digest(self):
  with tempfile.TemporaryDirectory(dir=ROOT)as temp:
   p=Path(temp)/'input';p.write_bytes(b'fixture');h=hashlib.sha256(b'fixture').hexdigest()
   self.assertEqual(m.bounded_input(p,h,10),b'fixture')
   for digest,limit in [('0'*64,10),(h,1)]:
    with self.assertRaises(m.PreparationDenied):m.bounded_input(p,digest,limit)
   q=Path(temp)/'link';q.symlink_to(p)
   with self.assertRaises(OSError):m.bounded_input(q,h,10)
 def fixtures(self):
  binding={'module':'mcp','database':'db_fixture','databaseOid':21560,'user':'app_fixture'}
  request={'User':'10005:10005','Image':'sha256:'+'a'*64,'Env':['MCP_DATABASE_URL=PRIVATE_FIXTURE_NOT_PUBLIC'],
   'HostConfig':{'NetworkMode':'fixture-backend'},'NetworkingConfig':{'EndpointsConfig':{'fixture-backend':{'NetworkID':'a'*64}}}}
  facts=json.loads((ROOT/'evidence/chatbot-semantic-mcp-binding-target-20261016.json').read_text())
  observed={'claimFacts':{'claimCount':1,'claims':[facts['claim']]},'rolePreflight':m.expected_roles(r),
   'runtimeBinding':{'containerId':facts['containerId']},'sourceReviewHash':r.REVIEW,'sourceAuthorityHash':r.AUTHORITY,
   'mcp':{'Config':{'Env':['PRIVATE_FIXTURE_NOT_PUBLIC']},'HostConfig':{},'Mounts':[],
    'NetworkSettings':{'Networks':{'fixture-backend':{'NetworkID':'a'*64}}}},
   'module':{'creationRequest':request},'programs':{},'prepared':{'engine':{},
   'databasePlan':{'modules':[binding],'mcpAuditRoleAdministration':{'admin':'admin_fixture'},'postgresRuntimeBinding':{}},
   'authorization':{'plan':{'selection':{'tenant':'fixture'}}}}}
  authorities={'installationRef':'fixture','entityRef':'fixture-entity','intentIssuerRef':'fixture-installer','approvalIssuerRef':'fixture-installer','attestorRef':'fixture-attestor'}
  profile={'schema':'ouf.semantic-existing-installation-authority-bindings.v1','policyBinding':m.POLICY,
   'authorities':authorities,'keyRefs':{'installer':'fixture-key'}}
  policy={'installationRef':'fixture','entityRef':'fixture-entity','keys':[{'keyRef':'fixture-key','issuerRef':'fixture-installer',
   'state':'ACTIVE','roles':['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'],'notBefore':0,'expiresAt':int(time.time())+3600}]}
  return observed,profile,policy
 def test_claim_or_privilege_drift_never_compiles_a_ready_plan(self):
  observed,profile,policy=self.fixtures()
  continuity={'before':r.EXPECTED_MIGRATIONS,'candidate':r.EXPECTED_MIGRATIONS+[{'version':13,'checksum':m.MIGRATION_SHA}]}
  for fault in ('claim','privilege'):
   o=copy.deepcopy(observed)
   if fault=='claim':o['claimFacts']['claims'][0]['actualToolCalls']=2
   else:o['rolePreflight']['applicationCanUseRetentionRole']=True
   with self.assertRaises(m.PreparationDenied):m.compile_plan(o,r,{}, {},continuity,Path('/fixture'),profile,policy)
  plan=m.compile_plan(observed,r,{}, {},continuity,Path('/fixture'),profile,policy)
  self.assertFalse(plan['readyForExecution']);self.assertFalse(plan['runtimeAuthorityIssued'])
  self.assertEqual(plan['temporaryPrivilege']['afterMembers'],0)
  self.assertFalse(plan['history']['tokenRenewalAuthorized'])
  self.assertTrue(plan['database']['freshBackupRequired'])
 def test_no_overwrite_of_a_private_review(self):
  with tempfile.TemporaryDirectory(dir=ROOT)as temp:
   p=Path(temp)/'review.json';m.write_new(p,b'first')
   with self.assertRaises(FileExistsError):m.write_new(p,b'second')
   self.assertEqual(p.read_bytes(),b'first');self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
 @unittest.skipUnless(os.environ.get('MCP_REPROCESSING_PACKAGE_DIRECTORY'),'actual CI package required')
 def test_actual_candidate_tagless_preparation_both_native_store_profiles(self):
  package=Path(os.environ['MCP_REPROCESSING_PACKAGE_DIRECTORY'])
  blob=io.BytesIO()
  with zipfile.ZipFile(blob,'w',compression=zipfile.ZIP_DEFLATED)as z:
   for name in sorted(m.MEMBERS):z.write(package/name,name)
  observed,profile,policy=self.fixtures()
  for containerd in (False,True):
   with self.subTest(containerd=containerd),tempfile.TemporaryDirectory(dir=ROOT)as temp:
    info={'Driver':'overlayfs'if containerd else'overlay2','DriverStatus':[['driver-type','io.containerd.snapshotter.v1']]if containerd else[],'ServerVersion':'fixture','CgroupDriver':'systemd'}
    with patch.object(r,'observe',return_value=copy.deepcopy(observed)),patch.object(r,'read',side_effect=lambda path,*a:profile if str(path)==m.PROFILE['path']else policy),patch.object(m.signal,'alarm'):
     plan=m.prepare(temp,blob.getvalue(),r,c,lambda engine:info)
    self.assertFalse(plan['readyForExecution']);self.assertFalse(plan['runtimeAuthorityIssued'])
    self.assertEqual(plan['imageAudit']['repositoryTags'],[])
    self.assertEqual(plan['imageAudit']['imageId'],m.IMAGE_SHA)
    self.assertEqual('nativeIdentity'in plan['imageAudit'],containerd)
    self.assertEqual(json.loads((Path(temp)/'review.json').read_bytes()),plan)
    self.assertIn('PRIVATE_FIXTURE_NOT_PUBLIC',(Path(temp)/'review.json').read_text())
    self.assertFalse(plan['installationAuthority']['privateKeysRead'])
if __name__=='__main__':unittest.main()
