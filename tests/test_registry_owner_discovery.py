"""Real root metadata and kernel lock observation; no target or credential use."""
import fcntl,importlib.util,json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('owner_discovery',ROOT/'scripts/read-registry-token-owner-candidates-20261023.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Discovery(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.parent=self.root/'snapshots';self.parent.mkdir(mode=0o700)
        self.boot=(Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            if os.environ.get('OUF_NATIVE_LOCKS')=='1' else 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
        self.proc=self.root/'proc';(self.proc/'sys/kernel/random').mkdir(parents=True)
        (self.proc/'sys/kernel/random/boot_id').write_text(self.boot)
        (self.proc/'locks').write_text('')
    def write(self,path,value):
        path.write_text(json.dumps(value));path.chmod(0o600)
    def owner(self,name='fixture-action/worker',**changes):
        p=self.parent/name;p.mkdir(mode=0o700,parents=True)
        row={'schema':'ouf.bounded-recovery.v1','state':'ACTIVE','contextRef':'a'*64,'generationRef':'b'*64,
            'attempts':3,'controlledCumulativeGrantAttempts':10,'bootId':self.boot,
            'lastWall':time.time()-1,'lastMonotonic':time.monotonic()-1,
            'tokenExpiresWall':time.time()+300,'tokenExpiresMonotonic':time.monotonic()+300,**changes}
        marker={'schema':'ouf.policy-token-owner-admission.v1','ownerProfileHash':'c'*64,
            'contextRef':'a'*64,'generationRef':'b'*64,'state':'ACTIVE','tokenHash':'d'*64,
            'version':2,'blockedAttempt':None}
        self.write(p/'recovery.json',row);self.write(p/'owner-admission.json',marker)
        (p/'invocation.lock').write_bytes(b'');(p/'invocation.lock').chmod(0o600)
        return p
    def observe(self):return m.observe(self.parent,self.proc)

    def test_metadata_finds_journal_without_selecting_or_authenticating_it(self):
        p=self.owner();r=self.observe();self.assertEqual(r['candidateCount'],1)
        row=r['candidates'][0];self.assertEqual(row['journalPath'],str(p))
        self.assertTrue(row['sameCurrentBoot']);self.assertTrue(row['retainedTokenWindowAtLeast90Seconds'])
        self.assertFalse(row['currentOwnerIdentityEstablished']);self.assertFalse(r['candidateSelectionPerformed'])
        self.assertEqual(r['metadataReadOperations'],4);self.assertEqual(r['runtimeEffectsDispatched'],0)

    def test_missing_candidate_is_not_proof_that_no_owner_exists(self):
        r=self.observe();self.assertEqual(r['candidates'],[])
        self.assertTrue(r['absenceOfMatchDoesNotProveNoOwner']);self.assertTrue(r['otherOwnersNotExcluded'])

    def test_stale_boot_expired_and_parked_states_remain_distinct(self):
        self.owner('previous-boot/worker',bootId='11111111-2222-3333-4444-555555555555')
        self.owner('expired/worker',tokenExpiresWall=0)
        self.owner('parked/worker',state='PAUSED_EXHAUSTED')
        rows={Path(x['journalPath']).parent.name:x for x in self.observe()['candidates']}
        self.assertFalse(rows['previous-boot']['sameCurrentBoot'])
        self.assertFalse(rows['previous-boot']['retainedTokenWindowPositive'])
        self.assertFalse(rows['expired']['retainedTokenWindowPositive'])
        self.assertEqual(rows['parked']['recoveryState'],'PAUSED_EXHAUSTED')

    def test_token_secret_authority_and_status_files_are_never_opened_or_printed(self):
        p=self.owner();canary='PRIVATE_MATERIAL_MUST_NOT_APPEAR'
        for name in ('token.jwt','client-secret','authority.json','human.json','owner-status.json'):
            (p/name).write_text(canary)
        original=os.open;opened=[]
        def guarded(path,*args,**kwargs):
            opened.append(Path(path).name)
            self.assertNotIn(Path(path).name,('token.jwt','client-secret','authority.json','human.json','owner-status.json'))
            return original(path,*args,**kwargs)
        with patch.object(m.os,'open',side_effect=guarded):result=self.observe()
        self.assertNotIn(canary,json.dumps(result));self.assertEqual(result['credentialFilesOpened'],0)
        self.assertEqual(set(opened),{'locks','recovery.json','owner-admission.json'})

    @unittest.skipUnless(os.environ.get('OUF_NATIVE_LOCKS')=='1','Native kernel observation is mandatory in hosted CI')
    def test_real_existing_exclusive_invocation_lock_is_observed_without_acquiring_it(self):
        p=self.owner();fd=os.open(p/'invocation.lock',os.O_RDWR)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            r=m.observe(self.parent,Path('/proc'))
            self.assertTrue(r['candidates'][0]['invocationExclusiveLockObserved'])
        finally:os.close(fd)

    def test_duplicate_json_and_writable_metadata_stop(self):
        p=self.owner();(p/'owner-admission.json').write_text('{"schema":1,"schema":2}')
        with self.assertRaisesRegex(m.Stop,'DUPLICATE_METADATA_KEY'):self.observe()
        self.owner('another/worker');(p/'owner-admission.json').chmod(0o666)
        with self.assertRaisesRegex(m.Stop,'BOUNDED_ROOT_METADATA'):self.observe()

    def test_symlinks_are_not_followed_and_depth_limits_are_explicit(self):
        (self.parent/'link').symlink_to(self.root,target_is_directory=True)
        p=self.parent/'a/b/c/hidden';p.mkdir(parents=True)
        r=self.observe();self.assertEqual(r['symlinksNotFollowed'],1)
        self.assertEqual(r['subdirectoriesOutsideScope'],1);self.assertEqual(r['candidateCount'],0)

    def test_candidate_and_directory_limits_stop_without_fallback(self):
        self.owner()
        with patch.object(m,'MAX_CANDIDATES',0):
            with self.assertRaisesRegex(m.Stop,'OWNER_CANDIDATE_BOUND'):self.observe()
        with patch.object(m,'MAX_DIRECTORIES',1):
            with self.assertRaisesRegex(m.Stop,'DISCOVERY_DIRECTORY_BOUND'):self.observe()

    def test_lock_parser_distinguishes_waiters_read_locks_and_unsupported_format(self):
        raw=b'1: FLOCK ADVISORY WRITE 123 00:ab:45 0 EOF\n2: -> FLOCK ADVISORY WRITE 456 00:ab:45 0 EOF\n3: FLOCK ADVISORY READ 1 00:ab:46 0 EOF\n'
        self.assertEqual(m.locks(raw),{(0,171,45):123})
        with self.assertRaisesRegex(m.Stop,'FLOCK_FORMAT'):m.locks(b'1: FLOCK UNKNOWN 123\n')

if __name__=='__main__':unittest.main()
