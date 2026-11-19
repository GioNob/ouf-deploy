"""Production-size custody regression; real signatures and exact sealed V2.

HUMAN/qualification are synthetic fixtures. No target activation or acceptance.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_authority as fixture
from tools.ingestion_readiness_patch_execution import member_io_v2 as io,authority_v2 as a,entry_v2 as e
from tools.ingestion_readiness_patch_execution import runtime_v2 as runtime,operator_delivery as carrier
from tools.semantic_policy_token_owner.producer import protected_directory
from iam_binding_candidate import read_member as historical_read_member

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual root metadata and role fixtures required')
class LargeReview(unittest.TestCase):
    def setUp(self):
        self.f=fixture.NativeIssuer();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.root=self.f.context
    def write(self,name,raw):
        p=self.root/name;p.write_bytes(raw);p.chmod(0o600);return p
    def test_exact_reported_sizes_pass_new_reader_and_legacy_limit_is_unchanged(self):
        for name,size in (('review.json',545058),('packet.json',1320265)):
            raw=b'{"fixture":"'+b'x'*(size-14)+b'"}'
            self.assertEqual(len(raw),size);json.loads(raw);self.write(name,raw)
            with protected_directory(self.root)as fd:
                with self.assertRaisesRegex(Exception,'PRIVATE_SNAPSHOT_CUSTODY_UNPROVEN'):historical_read_member(fd,name)
                self.assertEqual(io.read_member(fd,name),raw)
    def test_typed_limits_do_not_expand_other_members_or_accept_unknown_paths(self):
        with protected_directory(self.root)as fd:
            for name in ('../review.json','binding.json','other.json'):
                with self.assertRaises(Exception):io.read_member(fd,name)
            for name in ('review.json','packet.json','human.json','decision.json','authority.json'):
                self.write(name,b'x'*(io.LIMITS[name]+1))
                with self.assertRaisesRegex(Exception,'CUSTODY_UNPROVEN'):io.read_member(fd,name)
    def test_bad_modes_links_and_symlinks_still_fail(self):
        p=self.write('review.json',b'{}')
        with protected_directory(self.root)as fd:
            p.chmod(0o400)
            with self.assertRaises(Exception):io.read_member(fd,'review.json')
            p.chmod(0o600);link=self.root/'second-link';os.link(p,link)
            with self.assertRaises(Exception):io.read_member(fd,'review.json')
            link.unlink();p.unlink();p.symlink_to(self.root/'review-target')
            with self.assertRaises(Exception):io.read_member(fd,'review.json')
    def test_fd_path_or_bytes_changed_during_read_is_denied(self):
        self.write('review.json',b'x'*545058);actual=io.os.read;changed=[False]
        def read(fd,n):
            raw=actual(fd,n)
            if not changed[0]:
                changed[0]=True;p=self.root/'review.json';p.rename(self.root/'old-review');self.write('review.json',b'x'*545058)
            return raw
        with protected_directory(self.root)as fd,patch.object(io.os,'read',side_effect=read):
            with self.assertRaisesRegex(Exception,'MEMBER_CHANGED'):io.read_member(fd,'review.json')
    def review(self,padding=600000):
        bundle=copy.deepcopy(self.f.native_review['preparedInputs'])
        bundle['explicitSyntheticCapturedMetadata']='x'*padding
        native,packet=a.native_review.compile_review(bundle,{'path':str(self.root/'large-inputs.json'),'sha256':e.c.digest(bundle)},
            self.f.profile['expectedBinding'],str(self.root),human_read_profile=self.f.profile)
        closure=copy.deepcopy(self.f.closure);closure['declaration']['entryModule']=runtime.ENTRY
        reviewed=a.compile_action_review(native,packet,closure,self.f.issuer,self.f.qualification,210)
        decision=copy.deepcopy(self.f.decision);decision.update(reviewHash=e.c.digest(reviewed),
            sourceClosureHash=reviewed['sourceClosureHash'],humanSessionHash=e.c.digest(reviewed['authenticatedHuman']))
        return reviewed,packet,decision
    def test_large_valid_review_is_signed_and_loaded_through_the_new_reader(self):
        review,packet,decision=self.review();self.assertGreater(len(e.c.encoded(review)),524288)
        self.write('review.json',e.c.encoded(review))
        with patch.object(a,'verify_closure'):
            action=a.issue_action(review,decision,self.f.human,e.c.digest(decision))
            mandate=(self.root/'human.json').read_bytes()
            loaded=e.load_action(review,decision,self.f.human,e.c.digest(decision),hashlib.sha256(mandate).hexdigest())
        self.assertEqual(loaded.authority_hash,action.authority_hash)
        self.assertEqual(len(list(self.root.glob('*.DEPLOYMENT_INTENT.json'))),1)
        self.assertEqual(len(list(self.root.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'))),1)
        with patch.object(a,'verify_closure'),self.assertRaises(Exception):a.issue_action(review,decision,self.f.human,e.c.digest(decision))
    def test_oversized_review_blocks_during_compilation_before_issuance(self):
        with self.assertRaisesRegex(Exception,'REVIEW_EXCEEDS_TYPED'):self.review(2100000)
        self.assertFalse((self.root/'ingestion-readiness-patch-issuance.claim.json').exists())

class SealedV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path=ROOT/'tools/ingestion_readiness_patch_execution/runtime_v2.py'
        cls.sources={n:(ROOT/runtime.SOURCE_PATHS[n]).read_bytes()for n in runtime.MODULES}
    def test_all_original139_and_114_sources_are_byte_unchanged(self):
        payload,manifest=carrier.core(ROOT)
        for name,source in payload['sources'].items():self.assertEqual(self.sources[name],source.encode(),name)
        self.assertEqual(len(runtime.MODULES),142)
        self.assertEqual(len(set(runtime.MODULES)-set(payload['sources'])),3)
    def test_exact142_module_entry_loads_isolated_without_disk_fallback(self):
        source='''import importlib.util,json,sys
from pathlib import Path
p=Path(sys.argv[1]);root=Path(sys.argv[2]);s=importlib.util.spec_from_file_location('v2_loader',p)
r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
sources={n:(root/r.SOURCE_PATHS[n]).read_bytes()for n in r.MODULES}
pins={n:'1'*40 for n in ('ouf-deploy','ouf-onboarding','ouf-ingestion-runtime','ouf-api-gateway')}
declaration=r.declaration('1'*40,sources,p.read_bytes(),pins)
e,m=r.load_entry('1'*40,sources,p.read_bytes(),r.digest(declaration),pins)
assert e.__name__==r.ENTRY and m['moduleCount']==142
assert e.authority.__name__.endswith('authority_v2')
assert e.read_member.__module__.endswith('member_io_v2')
assert not any(getattr(sys.modules[n],'__file__',None)for n in r.MODULES if n in sys.modules)
print(json.dumps({'modules':142,'effects':0}))
'''
        value=subprocess.run([sys.executable,'-I','-B','-S','-c',source,str(self.path),str(ROOT)],capture_output=True,text=True,timeout=30)
        self.assertEqual(value.returncode,0,value.stderr);self.assertEqual(json.loads(value.stdout)['modules'],142)

if __name__=='__main__':unittest.main()
