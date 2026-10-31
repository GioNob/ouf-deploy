"""Synthetic retained data; immutable historical public controller is never executed."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('retained_stop', ROOT/'scripts/read-descriptor-publication-stop-20261025.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class RetainedStopTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, 'root-owned historical code fixture requires root, no skips')
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'retained'
        self.path.mkdir(mode=0o700)
        self.code = Path(self.tmp.name)/'public-controller.py'
        self.code.write_bytes((ROOT/'tests/fixtures/acquisition-descriptor-publisher-3f0b407.py.txt').read_bytes())
        self.code.chmod(0o444)
        self.assertEqual(hashlib.sha256(self.code.read_bytes()).hexdigest(), m.CODE_HASH)
        grants = [{'grantId':str(n), 'validFrom':'2026-01-01T00:00:00Z', 'private':'CANARY_NEVER_PROJECT'} for n in range(106)]
        candidate = {'bundleId':'ouf-lab-authorization','version':49,'publishedAt':'2026-10-25T19:40:00Z','capabilities':[], 'grants':grants}
        self.review = {'candidatePolicy':candidate,'baselineGrantCount':106,'baselineGrantsHash':m.digest(grants),
                       'activatedDescriptorIds':list(m.CAPS),'newGrants':0,'roleCatalogueMutations':0}
        self.hash = m.digest(self.review)
        self.state = {'reviewHash':self.hash,'humanReviewApproved':True,'state':'STOP_RECONCILE',
                      'budgetReset':False,'automaticReplayAllowed':False,
                      'effects':{'REGISTER:'+cap:{'state':'APPLIED','bodyHash':'a'*64} for cap in m.CAPS},
                      'counts':{'ownerGets':5,'administrativeWrites':6,'previewPosts':0,'bytes':1000},
                      'reads':{'before-draft-active':{'state':'COMPLETE','attempts':1}}}
        self.state['effects']['CREATE_DRAFT'] = {'state':'CLAIMED','bodyHash':m.digest(candidate)}
        self.save()
    def tearDown(self): self.tmp.cleanup()
    def save(self):
        for name, data in (('review.json',self.review),('state.json',self.state)):
            path = self.path/name
            path.write_text(json.dumps(data))
            path.chmod(0o600)
    def observe(self):
        return m.observe(self.path, self.code, owner=0, expected_review=self.hash)

    def test_claimed_create_without_uuid_is_reported_without_inventing_receipt(self):
        before = {name:hashlib.sha256((self.path/name).read_bytes()).hexdigest() for name in ('review.json','state.json')}
        result = self.observe()
        self.assertTrue(result['allFiveRegistrationsAppliedInRetainedJournal'])
        self.assertTrue(result['createDispatchClaimed'])
        self.assertFalse(result['draftIdRetained'])
        self.assertFalse(result['publishDispatchRecorded'])
        self.assertFalse(result['originalControllerPersistsRawCreateResponse'])
        self.assertFalse(result['continuationAuthorized'])
        self.assertEqual(result['oldFilesWritten'], 0)
        self.assertNotIn('CANARY_NEVER_PROJECT', json.dumps(result))
        self.assertEqual(before, {name:hashlib.sha256((self.path/name).read_bytes()).hexdigest() for name in before})

    def test_existing_revision_zero_draft_id_is_retained_for_governed_read(self):
        ident = str(uuid.uuid4())
        self.state.update(draftId=ident,draftRevision=0)
        self.save()
        result = self.observe()
        self.assertEqual(result['draftId'], ident)
        self.assertEqual(result['draftRevision'], 0)
        self.assertFalse(result['continuationAuthorized'])

    def test_wrong_review_or_false_approval_blocks(self):
        self.state['humanReviewApproved'] = False
        self.save()
        with self.assertRaisesRegex(m.Stop,'EXACT_APPROVED_STOPPED_REVIEW_REQUIRED'): self.observe()

    def test_changed_candidate_body_is_not_adopted(self):
        self.state['effects']['CREATE_DRAFT']['bodyHash'] = 'b'*64
        self.save()
        with self.assertRaisesRegex(m.Stop,'RETAINED_CREATE_BODY_HASH_MISMATCH'): self.observe()

    def test_unexpected_effect_cannot_be_hidden(self):
        self.state['effects']['RETRY_ACQUISITION'] = {'state':'APPLIED','bodyHash':'a'*64}
        self.save()
        with self.assertRaisesRegex(m.Stop,'BOUNDED_RETAINED_EFFECTS_REQUIRED'): self.observe()

    def test_symlink_review_and_wrong_public_code_block(self):
        real = self.path/'review.json'
        real.rename(self.path/'original.json')
        real.symlink_to(self.path/'original.json')
        with self.assertRaises(OSError): self.observe()
        real.unlink(); (self.path/'original.json').rename(real)
        self.code.chmod(0o600)
        self.code.write_text('wrong code')
        self.code.chmod(0o444)
        with self.assertRaisesRegex(m.Stop,'EXACT_STOPPED_CONTROLLER_HASH_REQUIRED'): self.observe()

    def test_audit_guard_rejects_network_process_old_writes_and_enumeration(self):
        guard = m.audit_guard(self.path,self.code,self.path/'retained-draft-read-v1')
        cases = [('socket.__new__',()),('subprocess.Popen',()),('exec',()),('os.scandir',(str(self.path),)),
                 ('open',(str(self.path/'state.json'),'w',os.O_WRONLY)),
                 ('os.chmod',(str(self.path/'state.json'),0o777))]
        for event,args in cases:
            with self.assertRaises(m.Stop): guard(event,args)
        guard('open',(str(self.path/'review.json'),'r',os.O_RDONLY))
        guard('open',(str(self.path/'retained-draft-read-v1'/'result.json'),'w',os.O_WRONLY|os.O_CREAT))


if __name__ == '__main__': unittest.main()
