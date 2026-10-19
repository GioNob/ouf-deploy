import ast,copy,hashlib,importlib.util,json,os,stat,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/read-ingestion-read-gateway-custody-stop.py'
if not SCRIPT.exists():SCRIPT=Path(__file__).with_name(SCRIPT.name)
spec=importlib.util.spec_from_file_location('custody_reader',SCRIPT);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Custody(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(SCRIPT.parent)));self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.path=self.root/'profile.json';self.path.write_bytes(b'{"PRIVATE":"NEVER_PRINT_THIS"}');self.path.chmod(0o440)
  info=self.path.lstat();self.binding={'path':str(self.path),'sha256':hashlib.sha256(self.path.read_bytes()).hexdigest(),'custody':{k:getattr(info,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size')}}
 def test_actual_approved0440_is_reported_unchanged_and_fails_legacy0600_predicate(self):
  result=r.custody_projection(self.binding);self.assertEqual(result['mode'],'0o440');self.assertTrue(result['hashMatchesApprovedBinding']);self.assertTrue(result['approvedCustodyMatches'])
  self.assertTrue(result['approvedPublic0440PredicateWouldPass']);self.assertFalse(result['legacyPrivate0600PredicateWouldPass']);self.assertNotIn('NEVER_PRINT_THIS',json.dumps(result))
  self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o440)
 def test_private0600_file_retains_distinct_predicate(self):
  self.path.chmod(0o600);binding={'path':str(self.path),'sha256':self.binding['sha256']}
  result=r.custody_projection(binding,private=True);self.assertTrue(result['legacyPrivate0600PredicateWouldPass']);self.assertFalse(result['approvedPublic0440PredicateWouldPass'])
 def test_custody_drift_does_not_become_approved_public_file(self):
  self.path.chmod(0o600);result=r.custody_projection(self.binding);self.assertFalse(result['approvedCustodyMatches']);self.assertFalse(result['approvedPublic0440PredicateWouldPass'])
 def test_symlink_and_hardlink_are_rejected_without_changes(self):
  link=self.root/'policy.json';link.symlink_to(self.path)
  with self.assertRaises(Exception):r.custody_projection({**self.binding,'path':str(link)})
  link.unlink();os.link(self.path,link)
  with self.assertRaises(Exception):r.custody_projection(self.binding)
class Journal(unittest.TestCase):
 def data(self):
  plan={'fixture':'plan'};scope={'profile':r.PROFILE,'planHash':r.digest(plan),'maximumGatewayWrites':2}
  review={'scopes':{'ingestionReadGatewayUpdate':scope}}
  journal={'schema':'ouf.ingestion-read-gateway-journal.v1','scopeHash':r.digest(scope),'budgetReset':False,'nextStage':0,'effects':[],'version':0,'incidentState':'OPEN','expiresAt':1792413300}
  return journal,review,plan
 def test_initial_empty_journal_proves_no_route_dispatch_by_this_qualified_action(self):
  row,review,plan=self.data();out=r.journal_projection(row,review,plan);self.assertTrue(out['zeroStageClaimsProven']);self.assertTrue(out['noGatewayDispatchByThisActionProven'])
 def test_route_claim_is_ambiguous_and_never_reported_as_no_dispatch(self):
  row,review,plan=self.data();row['nextStage']=1;row['version']=3
  row['effects']=[{'stage':stage,'state':state,'intentHash':r.digest({'planHash':r.digest(plan),'stage':stage})}for stage,state in(('VERIFY_INPUTS','APPLIED'),('GATEWAY_STATUS_ROUTE','CLAIMED'))]
  out=r.journal_projection(row,review,plan);self.assertFalse(out['zeroStageClaimsProven']);self.assertFalse(out['noGatewayDispatchByThisActionProven'])
 def test_wrong_scope_or_out_of_order_stage_denies(self):
  row,review,plan=self.data();row['nextStage']=3
  with self.assertRaises(Exception):r.journal_projection(row,review,plan)
  row,review,plan=self.data();review['scopes']['ingestionReadGatewayUpdate']['maximumGatewayWrites']=3
  with self.assertRaises(Exception):r.journal_projection(row,review,plan)
 def test_reader_has_no_target_exec_network_private_authority_or_write_surface(self):
  tree=ast.parse(SCRIPT.read_bytes());calls=[ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)]
  self.assertFalse(set(calls)&{'exec','eval','compile','os.chmod','os.chown','os.write','os.execv','subprocess.run','subprocess.Popen'})
  self.assertFalse(any(x.endswith(('.login','.refresh_if_due','.authenticate','.request','.write_bytes','.write_text'))for x in calls))
  for node in ast.walk(tree):
   if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='parse':
    self.assertNotIn('authority.json',ast.unparse(node))
if __name__=='__main__':unittest.main()
