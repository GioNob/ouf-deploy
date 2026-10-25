"""Synthetic owner/IAM/history; real PTY approvals are CI-only synthetic reviews."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import urllib.error
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
m=module('residual_descriptor',ROOT/'scripts/publish-existing-descriptor-draft-20261025.py')
f=module('prior_synthetic_fixture',ROOT/'tests/test_acquisition_descriptor_publication.py')


class SyntheticOwner(f.SyntheticOwner):
    def __init__(self):
        super().__init__()
        first=self.current['policy']['grants'][0]
        self.current['policy']['grants']=[dict(first,grantId='ci-synthetic-'+str(i)) for i in range(105)]+[self.current['policy']['grants'][1]]
        for cap in m.MISSING:self.catalogue[cap]=m.registration(cap)
        candidate=copy.deepcopy(self.current['policy']);candidate.update(version=49,publishedAt='2026-10-25T12:00:00Z')
        candidate['capabilities'] += [m.registration(cap)['descriptor'] for cap in m.MISSING]
        self.draft={'id':'00000000-0000-4000-8000-000000000050','revision':0,'state':'DRAFT','baseActiveRef':m.BASE_REF,'policy':candidate}
    def open(self,request,**kwargs):
        reply=super().open(request,**kwargs)
        if request.full_url.endswith(':publish'):
            reply.headers['ETag']='"1"';self.current['contentHash']='f'*64
        if request.get_method()=='GET' and request.full_url.endswith('/policies/'+self.draft['id']):reply.headers['ETag']='"0"'
        return reply


class ResidualTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.owner=SyntheticOwner();self.candidate=copy.deepcopy(self.owner.draft['policy'])
        self.patches=patch.multiple(m,DRAFT_ID=self.owner.draft['id'],BASE_RESPONSE=m.digest(self.owner.current),CANDIDATE_HASH=m.digest(self.candidate))
        self.patches.start()
        self.j=m.Journal(Path(self.tmp.name)/'single-residual')
        self.t=m.Transport('SYNTHETIC_TOKEN_CANARY',self.j);self.t.opener=self.owner
        self.old_review={'baselineCapabilitiesHash':m.digest(self.owner.current['policy']['capabilities'])}
    def tearDown(self):self.patches.stop();self.tmp.cleanup()
    def prepare(self):
        return m.prepare(self.candidate,self.old_review,self.j,self.t,time.time()+200)
    def approve(self,plan,suffix=''):
        master,slave=os.openpty();out=[]
        try:
            os.write(master,('APPROVO '+m.digest(plan)+suffix+'\n').encode())
            m.approve(plan,self.j,self.t,fd=slave,emit=out.append)
        finally:os.close(master);os.close(slave)
        return out
    def test_success_preserves106grants_and_counters(self):
        plan=self.prepare();out=self.approve(plan);result=m.execute(plan,self.j,self.t)
        self.assertEqual(result['counts']['administrativeWrites'],7)
        self.assertEqual(result['counts']['previewPosts'],2)
        self.assertGreater(result['counts']['ownerGets'],9)
        self.assertEqual(result['candidateGrantCount'],106)
        self.assertTrue(result['allGrantsPreserved'])
        self.assertEqual(self.owner.current['policy']['grants'],self.candidate['grants'])
        self.assertTrue(any(s=='APPROVO '+m.digest(plan) for s in out))
        self.assertEqual([(method,path) for method,path,_ in self.owner.calls if method=='POST'],[
            ('POST','/policies/'+m.DRAFT_ID+':preview'),('POST','/policies/'+m.DRAFT_ID+':preview'),('POST','/policies/'+m.DRAFT_ID+':publish')])
    def test_create_register_update_delete_and_arbitrary_uuid_ports_closed(self):
        for method,path in [('POST','/policies'),('POST','/capabilities'),('PUT','/policies/'+m.DRAFT_ID),
                            ('DELETE','/policies/'+m.DRAFT_ID),('GET','/policies/other')]:
            with self.subTest(method=method,path=path):
                with self.assertRaises(m.Stop):self.t.request(path,method=method)
        self.assertFalse(self.owner.calls)
        with self.assertRaises(m.Stop):self.j.effect('CREATE_DRAFT',{})
    def test_publication_before_fresh_approval_denied(self):
        plan=self.prepare()
        with self.assertRaises(m.Stop):m.execute(plan,self.j,self.t)
        with self.assertRaises(m.Stop):self.t.request('/policies/'+m.DRAFT_ID+':publish',method='POST',revision=0)
        self.assertEqual(self.t.counts['administrativeWrites'],6)
    def test_approval_with_extra_phrase_is_denied(self):
        plan=self.prepare()
        with self.assertRaises(m.Stop):self.approve(plan,' per la sola revisione esatta.')
        self.assertEqual(self.t.counts['administrativeWrites'],6)
        self.assertNotIn('PUBLISH_DRAFT',self.j.row['effects'])
    def test_non_tty_and_expired_approval_are_denied(self):
        plan=self.prepare();read,write=os.pipe()
        try:
            with self.assertRaises(m.Stop):m.approve(plan,self.j,self.t,fd=read,emit=lambda _:None)
        finally:os.close(read);os.close(write)
        self.t.deadline=0
        with self.assertRaises(m.Stop):self.approve(plan)
    def test_scope_or_execution_cannot_replay(self):
        plan=self.prepare();self.approve(plan);m.execute(plan,self.j,self.t)
        with self.assertRaises(m.Stop):m.Journal(self.j.path)
        with self.assertRaises(m.Stop):m.execute(plan,self.j,self.t)
        self.assertEqual(sum(path.endswith(':publish') for _,path,_ in self.owner.calls),1)
    def test_stale_revision_zero_etag_and_base_guard(self):
        self.owner.draft['revision']=1
        with self.assertRaises(m.Stop):self.prepare()
        self.assertFalse(any(method=='POST' for method,_,_ in self.owner.calls))
    def test_wrong_candidate_any_grant_rejected_before_preview(self):
        self.candidate['grants'][0]['grantId']='changed'
        with self.assertRaises(m.Stop):self.prepare()
        self.assertFalse(any(method=='POST' for method,_,_ in self.owner.calls))
    def test_preview_grant_or_descriptor_changes_rejected(self):
        self.owner.preview_change=lambda p:dict(p,grantChanges=[{'grantId':'unexpected'}])
        with self.assertRaises(m.Stop):self.prepare()
        self.assertTrue((self.j.path/'initial-preview-response.json').exists())
        self.assertEqual(self.t.counts['previewPosts'],1)
    def test_changed_final_preview_blocks_publication(self):
        plan=self.prepare();self.approve(plan)
        self.owner.preview_change=lambda p:dict(p,draftHash='sha256:'+'a'*64)
        with self.assertRaises(m.Stop):m.execute(plan,self.j,self.t)
        self.assertEqual(self.t.counts['previewPosts'],2)
        self.assertEqual(self.t.counts['administrativeWrites'],6)
    def test_lost_publish_response_retains_claim_never_retries(self):
        plan=self.prepare();self.approve(plan)
        def after(method,path,body):
            if path.endswith(':publish'):raise TimeoutError('SYNTHETIC_LOST_RESPONSE')
        self.owner.after=after
        with self.assertRaises(m.Stop):m.execute(plan,self.j,self.t)
        self.assertEqual(self.j.row['effects']['PUBLISH_DRAFT']['state'],'CLAIMED')
        self.assertEqual(self.t.counts['administrativeWrites'],7)
        self.assertEqual(self.owner.current['policyRef'],'ouf-lab-authorization:49')
        with self.assertRaises(m.Stop):m.execute(plan,self.j,self.t)
        self.assertEqual(sum(path.endswith(':publish') for _,path,_ in self.owner.calls),1)
    def test_http500_publication_ack_is_retained_before_guard(self):
        plan=self.prepare();self.approve(plan);original=self.owner.open
        def opened(request,**kwargs):
            reply=original(request,**kwargs)
            if request.full_url.endswith(':publish'):
                import io
                raise urllib.error.HTTPError(request.full_url,500,'synthetic',{'ETag':'"1"'},io.BytesIO(reply.raw))
            return reply
        self.owner.open=opened
        with self.assertRaises(m.Stop):m.execute(plan,self.j,self.t)
        response=json.loads((self.j.path/'owner-publish-response.json').read_text())
        self.assertEqual(response['status'],500)
        self.assertEqual(json.loads(response['bodyUtf8'])['revision'],1)
        self.assertEqual(self.j.row['effects']['PUBLISH_DRAFT']['state'],'CLAIMED')
    def test_owner_denial_stops_without_second_path(self):
        def denied(method,path,body):raise urllib.error.HTTPError(m.ADMIN+path,403,'synthetic',{},None)
        self.owner.before=denied
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(len(self.owner.calls),1)
        self.assertEqual(self.t.counts['ownerGets'],10)
    def test_review_changed_on_disk_blocks_all_later_requests(self):
        plan=self.prepare();self.approve(plan)
        path=self.j.path/'review.json';value=json.loads(path.read_text());value['nonce']='tampered';path.write_text(json.dumps(value))
        with self.assertRaises(m.Stop):m.execute(plan,self.j,self.t)
        self.assertEqual(self.t.counts['administrativeWrites'],6)
    def test_postpublication_grant_drift_remains_claimed(self):
        plan=self.prepare();self.approve(plan);self.owner.grants_at_publish=[]
        with self.assertRaises(m.Stop):m.execute(plan,self.j,self.t)
        self.assertEqual(self.j.row['effects']['PUBLISH_DRAFT']['state'],'CLAIMED')


if __name__=='__main__':unittest.main()
