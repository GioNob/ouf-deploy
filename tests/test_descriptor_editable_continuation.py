"""Synthetic owner policy. Only one remaining preview and one publish allowed."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('tty_continuation',ROOT/'scripts/continue-existing-descriptor-publication-editable-20261026.py')
f=module('old_residual_fixtures',ROOT/'tests/test_existing_descriptor_residual_publication.py')


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.owner=f.SyntheticOwner();self.candidate=copy.deepcopy(self.owner.draft['policy'])
        self.patch=patch.multiple(m,DRAFT_ID=self.owner.draft['id'],CANDIDATE_HASH=m.digest(self.candidate),BASE_RESPONSE=m.digest(self.owner.current))
        self.patch.start();self.j=m.Journal(Path(self.tmp.name)/'fixed-continuation')
        self.t=m.Transport('SYNTHETIC_TOKEN_CANARY',self.j);self.t.opener=self.owner
        self.preview={'draftId':m.DRAFT_ID,'revision':0,'baseActiveRef':m.BASE_REF,'activeHash':'sha256:'+m.BASE_HASH,
            'draftHash':'sha256:'+m.digest(self.candidate),'addedCapabilities':[m.registration(cap)['descriptor'] for cap in m.MISSING],
            'removedCapabilities':[],'grantChanges':[],'authoritative':False}
        self.j.row['retainedInitialPreview']=self.preview
        self.old={'baselineCapabilitiesHash':m.digest(self.owner.current['policy']['capabilities'])}
    def tearDown(self):self.patch.stop();self.tmp.cleanup()
    def prepare(self):return m.prepare(self.candidate,self.old,self.j,self.t,time.time()+150)
    def approve(self,plan,line=None):
        a,b=os.openpty();out=[]
        try:
            os.write(a,('APPROVO '+m.digest(plan)+'\n').encode() if line is None else line)
            m.approve(plan,self.j,self.t,fd=b,emit=out.append)
        finally:os.close(a);os.close(b)
        return out
    def test_complete_uses_one_new_preview_and_one_publish(self):
        plan=self.prepare();self.assertEqual(self.t.counts['previewPosts'],1)
        self.assertFalse(any(method=='POST' for method,_,_ in self.owner.calls))
        out=self.approve(plan);result=m.execute(plan,self.j,self.t)
        self.assertEqual(result['counts']['administrativeWrites'],7)
        self.assertEqual(result['counts']['previewPosts'],2)
        self.assertEqual(result['ttyInput'],{'state':'LINE_RECEIVED','receivedBytes':72,'enterReceived':True,'rejectedLines':0})
        self.assertTrue(any('APPROVAZIONE ACQUISITA' in s for s in out))
        self.assertEqual([p for method,p,_ in self.owner.calls if method=='POST'],['/policies/'+m.DRAFT_ID+':preview','/policies/'+m.DRAFT_ID+':publish'])
        with self.assertRaises(m.Stop):m.execute(plan,self.j,self.t)
    def test_cannot_run_initial_preview_or_publish_before_approval(self):
        self.prepare()
        for op in ('preview','publish'):
            with self.assertRaises(m.Stop):self.t.request('/policies/'+m.DRAFT_ID+':'+op,method='POST',revision=0)
        self.assertEqual(self.t.counts['previewPosts'],1)
        self.assertEqual(self.t.counts['administrativeWrites'],6)
    def test_old_review_hash_cannot_approve_new_review(self):
        plan=self.prepare();self.t.deadline=time.monotonic()+.25
        with self.assertRaises(m.Stop):self.approve(plan,('APPROVO '+m.FAILED_REVIEW_HASH+'\n').encode())
        self.assertNotIn('PUBLISH_DRAFT',self.j.row['effects'])
    def test_embedded_terminal_reader_exact_source(self):
        raw=(ROOT/'tools/human_terminal_line_review.py').read_bytes()
        self.assertEqual(m.TTY_CODE.encode(),raw)
        self.assertEqual(m.TTY_SHA256,hashlib.sha256(raw).hexdigest())
    def test_changed_retained_preview_stops_before_approval(self):
        self.j.row['retainedInitialPreview']=dict(self.preview,grantChanges=[{'grantId':'changed'}])
        with self.assertRaises(m.Stop):self.prepare()
        self.assertFalse(any(method=='POST' for method,_,_ in self.owner.calls))
    def test_no_enter_never_approves_and_restores_terminal(self):
        plan=self.prepare();self.t.deadline=time.monotonic()+.3
        with self.assertRaises(m.Stop):self.approve(plan,('APPROVO '+m.digest(plan)).encode())
        self.assertEqual(self.j.row['ttyInput']['state'],'WAITING_INPUT')
        self.assertFalse(self.j.row.get('humanReviewApproved',False))
        self.assertEqual(self.t.counts['previewPosts'],1)
    def test_register_create_and_wrong_uuid_still_closed(self):
        for method,path in [('POST','/policies'),('POST','/capabilities'),('GET','/policies/other')]:
            with self.assertRaises(m.Stop):self.t.request(path,method=method)
        self.assertFalse(self.owner.calls)


if __name__=='__main__':unittest.main()
