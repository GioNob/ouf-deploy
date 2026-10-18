"""Deep candidate copy + migration readback in isolated root fixtures."""
import copy,hashlib,json,sys,tempfile,unittest,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from test_chat_recovery_root_custody import RootCustody
from tools.chat_recovery_update import preparation as p
class CandidateStaging(unittest.TestCase):
 def exercise(self,tamper=False):
  with tempfile.TemporaryDirectory(dir='/root') as temp:
   root=Path(temp);root.chmod(0o700)
   _,review=RootCustody().fixture(root)
   package=root/'package';package.mkdir(mode=0o700)
   jar=package/'application.jar'
   with zipfile.ZipFile(jar,'w') as z:
    z.writestr('BOOT-INF/classes/db/migration/V1__fixture.sql','select 1;\n')
   raw=(hashlib.sha256(jar.read_bytes()).hexdigest()+'  application.jar\n').encode()
   (package/'SHA256SUMS').write_bytes(raw)
   value=json.loads(review.read_bytes())
   case={'runnerImageReview':{'path':str(review),'sha256':hashlib.sha256(review.read_bytes()).hexdigest()},
      'candidateSourceCommits':{m:r['imageAudit']['sourceCommit'] for m,r in value['candidates'].items()},
      'package':{'directory':str(package),'manifestSha256':hashlib.sha256(raw).hexdigest(),'udpJarRelativePath':'application.jar'},
      'udpMigrations':p.migration_rows(jar)}
   target=root/'execution';target.mkdir(mode=0o700)
   if tamper:jar.write_bytes(b'changed after review')
   if tamper:
    with self.assertRaises(Exception):p.stage_candidates(case,target)
   else:
    candidates=p.stage_candidates(case,target)
    self.assertEqual(set(candidates),{'udp','mcp'})
    self.assertEqual(Path(candidates['udp']['jar']['path']).read_bytes(),jar.read_bytes())
    self.assertEqual((target/'application.jar').stat().st_mode&0o777,0o600)
    for m in ('udp','mcp'):
     self.assertEqual(candidates[m]['imageAudit'],value['candidates'][m]['imageAudit'])
    with self.assertRaises(FileExistsError):p.stage_candidates(case,target)
 def test_real_root_copy_deep_audit_and_jar_readback(self):self.exercise()
 def test_changed_jar_blocks_before_native_authority(self):self.exercise(True)
if __name__=='__main__':unittest.main()
