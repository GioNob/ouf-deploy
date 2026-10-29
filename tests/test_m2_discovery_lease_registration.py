"""Actual files/claims/signatures, synthetic manager and application admission.

Only this protocol fixture substitutes a private directory for the two allowed
native systemd unit directories. The production path allowlist is unchanged.
"""
import copy,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_lease_file_installation as files
from tools.m2_discovery_installation_profile import lease_registration as m


class Registration(unittest.TestCase):
    def fixture(self):
        f=files.Files();installation,intent,auth,material,_=f.fixture();self.addCleanup(f.doCleanups)
        for name in ('registration','manager-units'):(auth.root/name).mkdir(mode=0o700)
        units=str(auth.root/'manager-units')
        allowed=patch.object(m,'UNIT_DIRECTORIES',frozenset((units,)));allowed.start();self.addCleanup(allowed.stop)
        base=installation.start
        scope=m.registration_scope(base.template,base.scope,unit_directory=units,journal_directory=str(auth.root/'registration'))
        auth.review['components']['operationalLeaseInstallation']=m.registered_component(base.template,base.installation_component,scope)
        parent=auth.fixture()
        start=files.starts.m.LeaseStartAdapter(parent=parent,authority=base.authority,authority_raw=base.authority_raw,
            transition=base.transition,store=base.store,node_owner=base.node_owner,template=base.template,proposal=base.proposal,
            scope=base.scope,intent=intent,publication_directory=base.publication_directory,registration_scope=scope)
        installation=files.m.LeaseFileInstallation(start,material,verifier=installation.verifier,probe=installation.probe)
        installation.apply(intent)
        state={'LoadState':'loaded','ActiveState':'inactive','SubState':'dead','MainPID':'0',
            'FragmentPath':start.proposal['configuration']['serviceUnitPath'],'DropInPaths':'','NeedDaemonReload':'no'}
        calls=[]
        def manager(args):
            calls.append(args)
            if args==['daemon-reload']:return b''
            self.assertEqual(args[:2],['show',start.scope['unitName']])
            return ('\n'.join(k+'='+v for k,v in state.items())+'\n').encode()
        start.manager=manager
        return m.LeaseRegistration(installation),intent,auth,calls,state

    def test_one_reload_and_owned_link_no_start_or_enable(self):
        owner,intent,auth,calls,state=self.fixture();owner.apply(intent)
        self.assertEqual(owner.observe(intent)[0],'APPLIED')
        self.assertEqual(calls.count(['daemon-reload']),1)
        self.assertEqual(owner.link.readlink(),Path(owner.start.proposal['configuration']['serviceUnitPath']))
        self.assertFalse(any(v[0] in ('start','enable','restart') for v in calls))
        with self.assertRaises(FileExistsError):owner.apply(intent)
        self.assertEqual(calls.count(['daemon-reload']),1)

    def test_lost_reload_reply_reconciles_without_second_reload(self):
        owner,intent,auth,calls,state=self.fixture();real=owner.start.manager
        def lost(args):
            result=real(args)
            if args==['daemon-reload']:raise TimeoutError('SYNTHETIC_REPLY_LOST_AFTER_RELOAD')
            return result
        with patch.object(owner.start,'manager',side_effect=lost),self.assertRaises(TimeoutError):owner.apply(intent)
        self.assertEqual(owner.observe(intent)[0],'APPLIED');self.assertEqual(calls.count(['daemon-reload']),1)

    def test_claim_without_reload_dispatch_is_consumed_and_unknown(self):
        owner,intent,auth,calls,state=self.fixture()
        with m.directory(owner.root) as fd:m.new_file(fd,'claim.json',m.encoded(owner.claim()))
        self.assertEqual(owner.observe(intent)[0],'UNKNOWN')
        with self.assertRaises(FileExistsError):owner.apply(intent)
        self.assertEqual(calls,[])

    def test_preexisting_unit_is_preserved_without_reload(self):
        owner,intent,auth,calls,state=self.fixture();auth.write(owner.link,b'PRESERVE_EXISTING_UNIT')
        with self.assertRaises(FileExistsError):owner.apply(intent)
        self.assertEqual(owner.link.read_bytes(),b'PRESERVE_EXISTING_UNIT');self.assertEqual(calls,[])
        self.assertTrue((owner.root/'claim.json').exists())

    def test_lost_complete_marker_is_read_only_reconciled(self):
        owner,intent,auth,calls,state=self.fixture();real=m.new_file
        def lost(fd,name,raw,mode=0o600):
            if name=='complete.json':raise TimeoutError('SYNTHETIC_REPLY_LOST_AFTER_MANAGER_READ')
            return real(fd,name,raw,mode)
        with patch.object(m,'new_file',side_effect=lost),self.assertRaises(TimeoutError):owner.apply(intent)
        with patch.object(m,'new_file',side_effect=AssertionError('NO_OBSERVATION_WRITES')):
            self.assertEqual(owner.observe(intent)[0],'APPLIED')

    def test_dropin_or_wrong_fragment_or_pending_reload_cannot_claim_registration(self):
        for key,value in (('DropInPaths','unreviewed.conf'),('FragmentPath','/other.service'),('NeedDaemonReload','yes')):
            owner,intent,auth,calls,state=self.fixture();state[key]=value
            with self.assertRaisesRegex(ValueError,'EXACT_RELOADED'):owner.apply(intent)
            self.assertFalse((owner.root/'complete.json').exists());self.assertEqual(calls.count(['daemon-reload']),1)

    def test_replaced_link_with_same_target_is_not_adopted(self):
        owner,intent,auth,calls,state=self.fixture();owner.apply(intent)
        replacement=owner.link.with_name('replacement.service');replacement.symlink_to(owner.link.readlink());replacement.replace(owner.link)
        with self.assertRaisesRegex(ValueError,'LINK_INODE_DRIFT'):owner.observe(intent)

    def test_changed_parent_before_reload_preserves_link_and_claim(self):
        owner,intent,auth,calls,state=self.fixture();real=owner.link_proof
        def revoked():
            proof=real();(auth.signatures/(owner.start.parent.sha+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink();return proof
        with patch.object(owner,'link_proof',side_effect=revoked),self.assertRaises(FileNotFoundError):owner.apply(intent)
        self.assertTrue(owner.link.is_symlink());self.assertEqual(calls,[])

    def test_active_registration_is_not_reported_as_worker_or_application_readiness(self):
        owner,intent,auth,calls,state=self.fixture();owner.apply(intent)
        state.update(ActiveState='active',SubState='running',MainPID='123')
        outcome,evidence=owner.observe(intent)
        self.assertEqual(outcome,'APPLIED');self.assertFalse(evidence['serviceStartPerformed'])
        self.assertFalse(evidence['applicationE2EProven'])

    def test_native_scope_does_not_accept_caller_selected_unit_directory(self):
        owner,intent,auth,calls,state=self.fixture()
        with patch.object(m,'UNIT_DIRECTORIES',frozenset(('/etc/systemd/system','/run/systemd/system'))):
            with self.assertRaisesRegex(ValueError,'EXPLICIT_LOCAL_SYSTEM_MANAGER'):
                m.registration_scope(owner.start.template,owner.start.scope,unit_directory=str(auth.root/'arbitrary'),
                    journal_directory=str(owner.root))


if __name__=='__main__':unittest.main()
