import ast,base64,copy,hashlib,importlib.util,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;PKG=HERE
if not(PKG/'prepare.py').exists():PKG=ROOT/'tools/ingestion_read_owner_reference'
PREP=HERE/'prepare.py'
if not PREP.exists():PREP=ROOT/'scripts/prepare-ingestion-owner-reference.py'
spec=importlib.util.spec_from_file_location('owner_prepare',PREP);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
spec=importlib.util.spec_from_file_location('owner_closed_runtime',PKG/'runtime.py');loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(loader)
V5=ROOT/'installation_route_reconcile/human_extension.py'
if not V5.exists():V5=ROOT/'tools/installation_route_reconcile/human_extension.py'
class Preparation(unittest.TestCase):
 def test_byte_exact_frozen256_and_v5_prefix_preserved_and_any_drift_rejected(self):
  prefix=b'class HumanSession: pass\n';v5=V5.read_bytes();v6=(PKG/'human_extension.py').read_bytes()
  with patch.object(m,'FROZEN256',m.sha(prefix)):
   result=m.extend_human(prefix+b'\n'+v5,v5,v6);self.assertEqual(result,prefix+b'\n'+v5+b'\n'+v6)
   for changed in(prefix+b'# drift\n'+b'\n'+v5,prefix+b'\n'+v5+b' ',result):
    with self.subTest(changed=m.sha(changed)),self.assertRaises(Exception):m.extend_human(changed,v5,v6)
  self.assertEqual(m.FROZEN256,'305c7804b084b02f0bf7d6c1521c3c5a4f8e7f4e2fb0a15e27f5886a2a685dcc')
 def test_actual232_preparation_preserves_all_old_files_and_has_no_login_until_new_bootstrap(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   root=Path(d);first=root/'predecessor';draft=root/'draft';first.mkdir(mode=0o700);draft.mkdir(mode=0o700)
   names=loader.MODULES-{k for k in loader.MODULES if k.startswith('tools.ingestion_read_owner_reference.')}
   sources={n:b'pass\n'for n in names};prefix=b'class HumanSession: pass\n';v5=V5.read_bytes();sources['tools.chatbot_file_cohort.human_session']=prefix+b'\n'+v5
   sources_raw=m.encoded({n:base64.b64encode(v).decode()for n,v in sources.items()})
   members={'case.json':m.encoded({'originalBinding':{'path':str(root/'original'),'sha256':'0'*64}}),'bootstrap.py':b'raise RuntimeError("OLD_MAIN_FORBIDDEN")\n',
    'runtime.py':b'raise RuntimeError("OLD_RUNTIME_FORBIDDEN")\n','reader.py':b'raise RuntimeError("OLD_READER_FORBIDDEN")\n','sources.json':sources_raw}
   closure={'declaration':{'moduleCount':226,'sourceHashes':{n:m.sha(v)for n,v in sources.items()}}}
   package={'closure':closure,'sourcePins':{'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40,'ouf-mcp-server':'c'*40},'fileHashes':{n:m.sha(v)for n,v in members.items()}}
   for n,v in members.items():m.write_new(first/n,v)
   m.write_new(first/'package.json',m.encoded(package));m.write_new(first/'runtime.claim.json',m.encoded({'packageHash':m.digest(package),'automaticReplayAllowed':False}))
   m.write_new(first/'execution-plan.json',m.encoded({'humanBinding':{'sessionDirectory':str(root/'NO_HUMAN_READ'),'expiresAt':1792436155}}))
   proposal={'private':'draft'};dh=m.digest(proposal);m.write_new(draft/'draft-plan.json',m.encoded(proposal))
   m.write_new(draft/'preparation-result.json',m.encoded({'complete':True,'draftPlanHash':dh,'runtimeAuthorityIssued':False,'installedSqlResourceEqualityProven':True,'candidateRootfsByteCustodyProven':True}))
   before={p:p.read_bytes()for p in first.iterdir()};delivery={n:(PKG/(n+'.py')).read_bytes()for n in m.NAMES if n not in('prepare','predecessor_extension')};delivery.update(prepare=PREP.read_bytes(),predecessor_extension=v5)
   dispatched=[];flags=types.SimpleNamespace(isolated=True,no_site=True)
   with (patch.object(m,'FIRST',first),patch.object(m,'DRAFT',draft),patch.object(m,'DRAFT_HASH',dh),patch.object(m,'PACKAGE',m.digest(package)),patch.object(m,'CLOSURE',m.digest(closure)),
    patch.object(m,'FROZEN256',m.sha(prefix)),patch.object(m.sys,'flags',flags),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.os,'execv',side_effect=lambda *a:dispatched.append(a))):
    m.main(delivery,'a'*40)
    self.assertEqual(len(dispatched),1);self.assertTrue(all(p.read_bytes()==v for p,v in before.items()))
    claims=list(root.glob('ingestion-owner-reference-preparation-*.claim.json'));self.assertEqual(len(claims),1)
    context=Path(json.loads(claims[0].read_bytes())['context']);report=m.parsed(context/'preparation-result.json')
    self.assertEqual(report['sourceModuleCount'],232);self.assertEqual(report['oauthRequests'],0);self.assertFalse(report['budgetChangeAuthorized'])
    self.assertFalse((context/'runtime.claim.json').exists());self.assertFalse((context/'authority.json').exists());self.assertFalse((root/'NO_HUMAN_READ').exists())
    self.assertEqual(context.stat().st_mode&0o777,0o700)
    with self.assertRaisesRegex(ValueError,'OWNER_REFERENCE_ALREADY_PREPARED_NO_REPLAY'):m.main(delivery,'a'*40)
    self.assertEqual(len(dispatched),1)
   m.signal.alarm(0)
 def test_preparer_has_no_issuer_or_effect_primitives(self):
  calls={ast.unparse(n.func)for n in ast.walk(ast.parse(PREP.read_bytes()))if isinstance(n,ast.Call)}
  for suffix in('.login','.refresh_if_due','.token','.request','.setns','.Popen','.issue_action'):
   self.assertFalse(any(v.endswith(suffix)for v in calls))
if __name__=='__main__':unittest.main()
