"""Actual root/nonroot filesystem and delivery custody; all histories synthetic."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import importlib.util

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('residual_protocol_fixtures',ROOT/'tests/test_existing_descriptor_residual_publication.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
spec_new=importlib.util.spec_from_file_location('tty_continuation_custody',ROOT/'scripts/continue-existing-descriptor-publication-editable-20261026.py')
m=importlib.util.module_from_spec(spec_new);spec_new.loader.exec_module(m)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        assert os.geteuid()==0,'actual root mandatory; no skips'
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('RESIDUAL_TEST_ROOT',str(ROOT)))
        self.base=Path(self.temp.name)
        self.owner=f.SyntheticOwner();self.candidate=copy.deepcopy(self.owner.draft['policy'])
        self.review={'candidatePolicy':self.candidate,'baselineGrantCount':106,
            'baselineGrantsHash':m.digest(self.candidate['grants']),
            'baselineCapabilitiesHash':m.digest(self.owner.current['policy']['capabilities'])}
        self.original=self.base/'original';self.original.mkdir(mode=0o700)
        self.lookup=self.base/'lookup';self.lookup.mkdir(mode=0o700)
        self.lookup_result={'complete':True,'draftId':self.owner.draft['id'],'draftRevision':0,
            'candidatePolicyHash':m.digest(self.candidate),'counts':m.LOOKUP_COUNTS,'continuationAuthorized':False,
            'publishRequests':0,'draftsCreated':0,'iamCounts':{'iamGets':1,'iamPosts':10,'ownerGets':0,'bytes':13166}}
        self.old={'reviewHash':m.digest(self.review),'humanReviewApproved':True,'state':'STOP_RECONCILE',
            'automaticReplayAllowed':False,'budgetReset':False,
            'counts':{'ownerGets':6,'administrativeWrites':6,'previewPosts':0,'bytes':346780},
            'iamCounts':{'iamGets':1,'iamPosts':7,'ownerGets':0,'bytes':13000},
            'effects':{'CREATE_DRAFT':{'state':'CLAIMED','bodyHash':m.digest(self.candidate)},
                       **{'REGISTER:'+cap:{'state':'APPLIED','bodyHash':'f'*64} for cap in m.MISSING}}}
        def write(path,value,owner):
            path.write_text(json.dumps(value));path.chmod(0o600);os.chown(path,owner,owner)
        write(self.original/'review.json',self.review,65534)
        write(self.original/'state.json',self.old,65534)
        os.chown(self.original,65534,65534)
        write(self.lookup/'result.json',self.lookup_result,0)
        write(self.lookup/'state.json',{'state':'COMPLETE','counts':m.LOOKUP_COUNTS,'draftId':self.owner.draft['id'],
              'nativeSqlSessionAttempts':1,'containerExecAttempts':1,'engineGets':2},0)
        write(self.lookup/'owner-draft-response.json',{'status':200,'etag':'"0"','bodyUtf8':json.dumps(self.owner.draft)},0)
        self.failed=self.base/'expired';self.failed.mkdir(mode=0o700)
        self.preview={'draftId':self.owner.draft['id'],'revision':0,'baseActiveRef':m.BASE_REF,
            'activeHash':'sha256:'+m.BASE_HASH,'draftHash':'sha256:'+m.digest(self.candidate),
            'addedCapabilities':[m.registration(cap)['descriptor'] for cap in m.MISSING],
            'removedCapabilities':[],'grantChanges':[],'authoritative':False}
        previous={'draftId':self.owner.draft['id'],'draftRevision':0,'candidatePolicy':self.candidate,
                  'countsAtReview':m.EXPIRED_COUNTS,'initialOwnerPreview':self.preview}
        write(self.failed/'review.json',previous,0)
        write(self.failed/'state.json',{'state':'STOP_RECONCILE','reasonCode':'FINITE_HUMAN_WINDOW_EXPIRED',
              'humanReviewApproved':False,'effects':{},'counts':m.EXPIRED_COUNTS,'reviewHash':m.digest(previous),
              'iamCounts':{'iamGets':1,'iamPosts':11,'ownerGets':0,'bytes':14000}},0)
        write(self.failed/'initial-preview-response.json',{'status':200,'truncated':False,'bodyUtf8':json.dumps(self.preview)},0)
        self.tty_failed=self.base/'tty-failed';self.tty_failed.mkdir(mode=0o700)
        tty_review=dict(previous,countsAtReview=m.INHERITED,inheritedCounts=m.EXPIRED_COUNTS)
        tty_state={'state':'STOP_RECONCILE','reasonCode':'EXACT_TERMINAL_REVIEW_LENGTH_EXCEEDED',
            'humanReviewApproved':False,'effects':{},'counts':m.INHERITED,'reviewHash':m.digest(tty_review),
            'automaticReplayAllowed':False,'budgetReset':False,'preflightComplete':True,
            'retainedInitialPreview':self.preview,
            'reads':{s:{'state':'COMPLETE','attempts':1} for s in ('baseline-active','baseline-registration:0','baseline-draft','baseline-verify')},
            'iamCounts':{'iamGets':1,'iamPosts':12,'ownerGets':0,'bytes':15000}}
        tty_result={'schema':'ouf.existing-descriptor-residual-publication-result.v1','status':'STOP_RECONCILE',
            'complete':False,'reasonCode':'EXACT_TERMINAL_REVIEW_LENGTH_EXCEEDED','automaticReplayAllowed':False,
            'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False,'counts':m.INHERITED,
            'contextPath':str(self.tty_failed),'publicationClaimed':False}
        write(self.tty_failed/'state.json',tty_state,0);write(self.tty_failed/'review.json',tty_review,0)
        write(self.tty_failed/'result.json',tty_result,0)
        self.patches=patch.multiple(m,TTY_FAILED_SCOPE=str(self.tty_failed),TTY_FAILED_REVIEW_HASH=m.digest(tty_review),FAILED_SCOPE=str(self.failed),FAILED_REVIEW_HASH=m.digest(previous),ORIGINAL=str(self.original),LOOKUP=str(self.lookup),
            ORIGINAL_REVIEW_HASH=m.digest(self.review),LOOKUP_RESULT_HASH=m.digest(self.lookup_result),
            DRAFT_ID=self.owner.draft['id'],CANDIDATE_HASH=m.digest(self.candidate))
        self.patches.start()
    def tearDown(self):self.patches.stop();self.temp.cleanup()
    def test_exact_retained_inputs_and_iam_histories(self):
        review,candidate,result,historical,preview=m.retained(65534)
        self.assertEqual(candidate,self.candidate)
        self.assertEqual(result['counts'],m.LOOKUP_COUNTS)
        self.assertEqual(preview,self.preview)
        self.assertEqual(historical['expiredResidualPublication']['iamPosts'],11)
        self.assertEqual(historical['lookup']['iamPosts'],10)
        self.assertEqual(historical['consumedTtyPublication']['iamPosts'],12)
        self.assertEqual(historical['originalPublication']['iamPosts'],7)
    def test_wrong_result_or_original_counters_denied(self):
        path=self.lookup/'result.json';value=json.loads(path.read_text());value['counts']['ownerGets']=0
        path.write_text(json.dumps(value))
        with self.assertRaises(m.Stop):m.retained(65534)
    def test_private_symlinks_and_modes_denied(self):
        path=self.lookup/'state.json';raw=path.read_bytes();path.unlink()
        target=self.lookup/'unrelated.json';target.write_bytes(raw);target.chmod(0o600);path.symlink_to(target)
        with self.assertRaises(OSError):m.retained(65534)
        path.unlink();path.write_bytes(raw);path.chmod(0o644)
        with self.assertRaises(m.Stop):m.retained(65534)
    def test_original_files_not_changed_and_no_scope_replay(self):
        paths=[self.original/'review.json',self.original/'state.json',self.lookup/'result.json',self.lookup/'state.json',self.lookup/'owner-draft-response.json',
               self.failed/'state.json',self.failed/'review.json',self.failed/'initial-preview-response.json',self.tty_failed/'state.json',self.tty_failed/'review.json',self.tty_failed/'result.json']
        before={str(p):(p.read_bytes(),p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in paths}
        m.retained(65534)
        self.assertEqual(before,{str(p):(p.read_bytes(),p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in paths})
        prior=os.umask(0o077)
        try:j=m.Journal(self.base/'one');j.write('result.json',{'private':True},exclusive=True)
        finally:os.umask(prior)
        self.assertEqual(j.path.stat().st_mode&0o777,0o700)
        self.assertEqual((j.path/'result.json').stat().st_mode&0o777,0o600)
        with self.assertRaises(m.Stop):m.Journal(j.path)
        denied=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(j.path/'result.json')],capture_output=True)
        self.assertNotEqual(denied.returncode,0)

    def test_tty_claim_counter_or_review_changes_denied(self):
        path=self.tty_failed/'state.json';initial=path.read_text()
        for field,value in [('effects',{'PUBLISH_DRAFT':{'state':'CLAIMED'}}),('counts',m.EXPIRED_COUNTS),('humanReviewApproved',True),('reviewHash','0'*64)]:
            row=json.loads(initial);row[field]=value;path.write_text(json.dumps(row))
            with self.assertRaises(m.Stop):m.retained(65534)
        path.write_text(initial)
        result=self.tty_failed/'result.json';row=json.loads(result.read_text());row['publicationClaimed']=True;result.write_text(json.dumps(row))
        with self.assertRaises(m.Stop):m.retained(65534)

    def test_actual_root077_protected_delivery_and_execution(self):
        wrapper=(ROOT/'releases/continue-existing-descriptor-publication-editable-20261026.sh').read_text()
        self.assertIn('sudo /usr/bin/python3 -I -S -B "$code"\n',wrapper)
        self.assertNotIn('sudo /usr/bin/python3 -I -S -B "$code" 2>&1 |',wrapper)
        marker="<<'PY' 2>&1 | tee -a \"$delivery_log\"\n"
        copier=wrapper.split(marker,1)[1].split('\nPY\n',1)[0]
        raw=(ROOT/'scripts/continue-existing-descriptor-publication-editable-20261026.py').read_bytes()
        expected=hashlib.sha256(raw).hexdigest()
        self.assertIn('code_sha='+expected,wrapper)
        source=self.base/'download.py';source.write_bytes(raw);source.chmod(0o600);os.chown(source,65534,65534)
        target=Path('/usr/local/lib/ouf-existing-descriptor-editable-continuation-'+expected[:16])
        self.assertFalse(target.exists())
        previous=os.umask(0o077)
        try:
            copied=subprocess.run(['/usr/bin/python3','-I','-S','-B','-',str(source),expected,'65534'],input=copier,text=True,capture_output=True)
            self.assertEqual(copied.returncode,0,copied.stdout+copied.stderr)
            code=target/'continue.py'
            self.assertEqual(target.stat().st_mode&0o777,0o700)
            self.assertEqual(code.stat().st_mode&0o777,0o400)
            self.assertEqual(hashlib.sha256(code.read_bytes()).hexdigest(),expected)
            denied=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(code)],capture_output=True)
            self.assertNotEqual(denied.returncode,0)
            execute=subprocess.run(['/usr/bin/python3','-I','-S','-B',str(code)],stdin=subprocess.DEVNULL,text=True,capture_output=True)
            self.assertEqual(execute.returncode,2)
            self.assertEqual(json.loads(execute.stdout)['reasonCode'],'ISOLATED_ROOT_OPERATOR_TTY_REQUIRED')
            replay=subprocess.run(['/usr/bin/python3','-I','-S','-B','-',str(source),expected,'65534'],input=copier,text=True,capture_output=True)
            self.assertNotEqual(replay.returncode,0)
            self.assertEqual(hashlib.sha256(code.read_bytes()).hexdigest(),expected)
        finally:
            os.umask(previous)
            if target.exists():shutil.rmtree(target)


if __name__=='__main__':unittest.main(verbosity=2)
