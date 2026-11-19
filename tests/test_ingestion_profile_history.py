import base64,copy,hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;PKG=HERE
if not(PKG/'history.py').exists():PKG=ROOT/'tools/ingestion_profile_publication'
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('owner7_history',PKG/'history.py');loader=load('projection_history_loader',PKG/'runtime.py')
BUNDLE=ROOT/'ingestion_owner_recovery/delivery-bundle.json'
if not BUNDLE.exists():BUNDLE=ROOT/'releases/ingestion-owner-recovery-bundle-20261019.json'
class History(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=HERE);self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.context=self.root/'completed-owner';self.context.mkdir(mode=0o700);self.tr=self.root/'stopped';self.tr.mkdir(mode=0o700)
  self.bundle=json.loads(BUNDLE.read_bytes());self.files={n:base64.b64decode(v['base64'])for n,v in self.bundle['files'].items()}
  self.orig={'path':str(self.root/'original-selection'),'sha256':'a'*64};oldnames=loader.MODULES-{n for n in loader.MODULES if n.startswith(('tools.ingestion_owner_recovery.','tools.ingestion_profile_publication.'))}
  self.old={n:b'raise RuntimeError("DO_NOT_EXECUTE_HISTORY")\n'for n in oldnames}
  oldraw={'case.json':m.encoded({'originalBinding':self.orig}),'sources.json':m.encoded({n:base64.b64encode(v).decode()for n,v in self.old.items()}),
   'bootstrap.py':b'raise RuntimeError("OLD_BOOTSTRAP_FORBIDDEN")','runtime.py':b'raise RuntimeError("OLD_LOADER_FORBIDDEN")','reader.py':b'raise RuntimeError("OLD_READER_FORBIDDEN")'}
  oldpackage={'fileHashes':{n:m.sha(v)for n,v in oldraw.items()},'closure':{'declaration':{'sourceHashes':{n:m.sha(v)for n,v in self.old.items()}}}}
  for n,v in oldraw.items():m.write_new(self.tr/n,v)
  m.write_new(self.tr/'package.json',m.encoded(oldpackage));self.trhash=m.digest(oldpackage)
  self.sources={**self.old,**{'tools.ingestion_owner_recovery.'+n:self.files[n]for n in m.RECOVERY_HASHES}}
  self.sources['tools.chatbot_file_cohort.human_session']+=b'\n'+self.files['confirmation_patch']+b'\n'+self.files['human_extension']
  self.case={'originalBinding':self.orig}
  self.raw={'case.json':m.encoded(self.case),'sources.json':m.encoded({n:base64.b64encode(v).decode()for n,v in self.sources.items()}),
   'bootstrap.py':self.files['bootstrap'],'runtime.py':self.files['runtime'],'reader.py':oldraw['reader.py']}
  self.pins={'caseSha256':m.digest(self.case),'executorSha256':m.BOOTSTRAP_SHA256,'mode':'INGESTION_OWNER_REFERENCE_RECOVERY_APPLY'}
  self.decl={'moduleCount':238,'entryModule':'tools.ingestion_owner_recovery.entry','sourceHashes':{n:m.sha(v)for n,v in self.sources.items()},'bootstrapBindings':self.pins}
  self.package={'sourceCommit':m.SOURCE,'fileHashes':{n:m.sha(v)for n,v in self.raw.items()},'closure':{'declaration':self.decl},'executionPins':self.pins,'declarationHash':m.digest(self.decl)}
  self.install_package()
  self.human={'retryProfile':{'id':'ouf.human.ingestion-owner-recovery288.v7','maximumAttempts':288},'expiresAt':1792450664,'sessionDirectory':str(self.root/'NO_CREDENTIAL_JOURNAL_READ')}
  self.projection={'installationId':'fixture','revision':6,'checksum':'source','services':{'bindings':{}}}
  self.plan={'humanBinding':self.human,'bindingPlan':{'candidatePayloadChecksum':'c'*64},'sourceProjection':self.projection,'logicalRef':'d'*64}
  self.planhash=m.digest(self.plan)
  exported={**self.projection,'revision':7,'checksum':'c'*64};self.exporthash=m.digest(exported);m.write_new(self.context/'owner-active-projection.json',m.encoded(exported))
  self.result={'complete':True,'status':'OWNER_REFERENCE_ACTIVATED_AND_EXPORTED','planHash':self.planhash,'ownerPayloadReadbackProven':True,'ownerPosts':3,'projectionExports':1,
   'activeProjectionWrites':0,'gatewayWrites':0,'containerLifecycleOperations':0,'directDatabaseCalls':0,'oauthAttemptsAfter':276,'maximumCumulativeOAuthAttempts':288,
   'active':{'installationId':'fixture','revision':7,'generation':7,'checksum':'c'*64},'humanWindowExpiresAt':1792450664,
   'projectionBinding':{'path':str(self.context/'owner-active-projection.json'),'sha256':self.exporthash}}
  m.write_new(self.context/'execution-plan.json',m.encoded(self.plan));m.write_new(self.context/'update-result.json',m.encoded(self.result));self.resulthash=m.digest(self.result)
  receipt={'schema':'ouf.ingestion-owner-recovery-budget288-receipt.v1','directory':self.human['sessionDirectory'],'oauthAttemptsAfter':276,'maximumCumulativeOAuthAttempts':288,'expiresAt':1792450664,'budgetReset':False}
  m.write_new(self.context/'login-window-receipt.json',m.encoded(receipt));scope={'planHash':self.planhash};review={'scopes':{'ingestionOwnerReference':scope},'sourceClosureHash':m.digest(self.package['closure']),'authenticatedHuman':self.human}
  self.review=review;self.scope=scope
  decision={'schema':'ouf.semantic-scoped-terminal-decision.v1','state':'ACTIVE','decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','reviewHash':m.digest(review),'sourceClosureHash':review['sourceClosureHash'],'humanSessionHash':m.digest(self.human)}
  m.write_new(self.context/'review.json',m.encoded(review));m.write_new(self.context/'decision.json',m.encoded(decision))
  stages=['VERIFY_INPUTS','CREATE_REVISION','VALIDATE_ENVIRONMENT','ACTIVATE_EXPECTED','EXPORT_ACTIVE','VERIFY_FINAL']
  self.row={'scopeHash':m.digest(scope),'incidentState':'RECOVERED','nextStage':6,'authorityHash':'e'*64,'effects':[
   {'stage':s,'state':'APPLIED','intentHash':m.digest({'planHash':self.planhash,'stage':s}),'evidence':{'active':self.result['active']}if s=='ACTIVATE_EXPECTED'else{'projectionBinding':self.result['projectionBinding']}if s=='EXPORT_ACTIVE'else{'verified':True}}for s in stages]}
  m.write_new(self.context/'recovery.json',m.encoded(self.row));m.write_new(self.root/('ingestion-owner-reference-'+self.plan['logicalRef']+'.claim.json'),m.encoded({'context':str(self.context),'scopeHash':m.digest(scope),'authorityHash':'e'*64,'automaticReplayAllowed':False,'budgetReset':False}))
  for key,value in(('CONTEXT',self.context),('TR',self.tr),('TR_PACKAGE',self.trhash),('PLAN',self.planhash),('RESULT',self.resulthash),('EXPORT',self.exporthash)):
   p=patch.object(m,key,value);p.start();self.addCleanup(p.stop)
 def overwrite(self,path,raw):path.write_bytes(raw);path.chmod(0o600)
 def install_package(self):
  for n,v in self.raw.items():self.overwrite(self.context/n,v)
  self.overwrite(self.context/'package.json',m.encoded(self.package));self.overwrite(self.context/'runtime.claim.json',m.encoded({'packageHash':m.digest(self.package),'automaticReplayAllowed':False}))
 def test_verified_history_is_pure_file_read_and_preserves_consumed_claims(self):
  before={str(p):p.read_bytes()for p in self.root.rglob('*')if p.is_file()};completed=m.verified()
  self.assertEqual(completed['result'],self.result);self.assertEqual(len(completed['sources']),238)
  self.assertEqual(before,{str(p):p.read_bytes()for p in self.root.rglob('*')if p.is_file()});self.assertFalse(Path(self.human['sessionDirectory']).exists())
 def test_changed_result_plan_export_or_claim_blocks(self):
  path=self.context/'owner-active-projection.json';self.overwrite(path,b'changed')
  with self.assertRaises(Exception):m.verified()
 def test_claimed_or_incomplete_owner_stage_cannot_be_treated_as_complete(self):
  row=copy.deepcopy(self.row);row['effects'][3]['state']='CLAIMED';self.overwrite(self.context/'recovery.json',m.encoded(row))
  with self.assertRaisesRegex(ValueError,'EXACT_COMPLETED_OWNER_JOURNAL_REQUIRED'):m.verified()
 def test_self_consistent_tampered_human_source_is_rejected_by_pinned_prefix(self):
  h='tools.chatbot_file_cohort.human_session';self.sources[h]=b'# CHANGED\n'+self.sources[h]
  self.raw['sources.json']=m.encoded({n:base64.b64encode(v).decode()for n,v in self.sources.items()});self.decl['sourceHashes'][h]=m.sha(self.sources[h])
  self.package['fileHashes']['sources.json']=m.sha(self.raw['sources.json']);self.package['declarationHash']=m.digest(self.decl);self.install_package()
  with self.assertRaisesRegex(ValueError,'EXACT_QUALIFIED238_SOURCE_PROVENANCE_REQUIRED'):m.verified()
 def test_frozen_source_and_new_recovery_module_both_remain_pinned(self):
  name='tools.ingestion_owner_recovery.entry';self.sources[name]=b'pass\n';self.raw['sources.json']=m.encoded({n:base64.b64encode(v).decode()for n,v in self.sources.items()})
  self.decl['sourceHashes'][name]=m.sha(self.sources[name]);self.package['fileHashes']['sources.json']=m.sha(self.raw['sources.json']);self.package['declarationHash']=m.digest(self.decl);self.install_package()
  with self.assertRaisesRegex(ValueError,'EXACT_QUALIFIED238_SOURCE_PROVENANCE_REQUIRED'):m.verified()
if __name__=='__main__':unittest.main()
