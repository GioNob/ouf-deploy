"""Actual journal/flock and production worker failure path; kernel is modeled."""
import copy,json,os,sys,threading,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_policy_token_owner')]
import test_m2_discovery_lease_worker as fixture
from tools.m2_discovery_installation_profile import lease_worker as worker_module
from tools.m2_discovery_installation_profile.lease_service import existing_kernel_lock
from recovery_journal import Journal,encoded
from tools.m2_discovery_installation_profile.lease_observation_inputs import RecoverySnapshot,build_observed
from tools.m2_discovery_installation_profile import lease_observation,lease_start_owner,lease_service


class ReaderContention(unittest.TestCase):
    def fixture(self):
        case=fixture.Worker();self.addCleanup(case.doCleanups)
        c,j,p,s,o,calls=case.fixture('ACTIVE')
        before=j.read();j.compare_and_save(before,{**before,'attempts':1,'publicationCount':16})
        worker=worker_module.build_worker(c,j,p,s,**o);worker.active_here=True
        self.retained_scope=copy.deepcopy(s)
        c.owner.backend.active_deadline=None
        kernel=j.root/'kernel.lock';kernel.write_bytes(b'');kernel.chmod(0o600)
        info=kernel.stat();pin=[info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink]
        c.hold_lock=lambda:existing_kernel_lock(kernel,pin)
        coordination={'state':'LEASE_READY','leaseAuthorized':True};effects=[]
        c.journal=lambda:copy.deepcopy(coordination)
        c.sets=lambda:[['1.1.1.1']] if coordination['leaseAuthorized'] else [[]]
        def quiesce():
            with c.hold_lock():
                effects.append('KERNEL_REVOKED');coordination.update(state='QUIESCED',leaseAuthorized=False)
        c.quiesce=quiesce
        return worker,c,j,coordination,effects,calls

    def test_exclusive_host_journal_read_reproduces_active16_quiesced_and_parked_worker(self):
        worker,c,j,coordination,effects,calls=self.fixture();before=j.record.read_bytes()
        host=Journal(j.root);read=host.private_read;messages=[];seen=[];stop=threading.Event()
        def wait(seconds):
            seen.append((json.loads(j.record.read_bytes()),copy.deepcopy(coordination),seconds))
            stop.set();return True
        stop.wait=wait
        reporter=worker_module.LeaseReporter(j,messages.append)
        def read_while_worker_runs():
            worker_module._serve_claimed(worker,stop,reporter)
            return read()
        with patch.object(host,'private_read',side_effect=read_while_worker_runs):observed=host.read()
        self.assertEqual(observed['state'],'ACTIVE');self.assertEqual(observed['publicationCount'],16)
        self.assertEqual(coordination,{'state':'QUIESCED','leaseAuthorized':False})
        self.assertEqual(effects,['KERNEL_REVOKED']);self.assertEqual(j.record.read_bytes(),before)
        self.assertEqual(seen[0][0]['attempts'],1);self.assertEqual(seen[0][2],1)
        self.assertTrue(any('STATUS_UNAVAILABLE' in message for message in messages))
        self.assertFalse(worker.active_here);self.assertTrue(all(v[0]=='custody' for v in calls))

    def test_snapshot_does_not_acquire_the_existing_transaction_lock(self):
        worker,c,j,coordination,effects,calls=self.fixture();scope=self.retained_scope
        reader=RecoverySnapshot(j.root,scope,worker.r.policy);before=j.read()
        with j.transaction():
            self.assertEqual(reader.read(),before)
        self.assertEqual(effects,[]);self.assertEqual(coordination['state'],'LEASE_READY')

    def test_atomic_writer_can_commit_during_snapshot_without_revocation_or_reset(self):
        worker,c,j,coordination,effects,calls=self.fixture();reader=RecoverySnapshot(j.root,self.retained_scope,worker.r.policy)
        before=j.read();read=os.read;replaced=[]
        def concurrent(fd,size):
            if not replaced:
                replaced.append(True);j.compare_and_save(before,{**before,'publicationCount':17})
            return read(fd,size)
        with patch.object(os,'read',side_effect=concurrent),self.assertRaises(BlockingIOError):reader.read()
        self.assertEqual(reader.read()['publicationCount'],17);self.assertEqual(j.read()['attempts'],1)
        self.assertEqual(j.read()['startedMonotonic'],before['startedMonotonic'])
        self.assertEqual(coordination['state'],'LEASE_READY');self.assertEqual(effects,[])

    def test_snapshot_allows_a_live_worker_tick_without_forcing_pause(self):
        worker,c,j,coordination,effects,calls=self.fixture();reader=RecoverySnapshot(j.root,self.retained_scope,worker.r.policy)
        read=os.read;ticks=[]
        def concurrent(fd,size):
            if not ticks:
                ticks.append(True)
                with patch('continuous_supervisor.window',return_value={'waitSeconds':1,'deadlineMonotonic':60}):
                    self.assertEqual(worker.tick()['state'],'ACTIVE')
            return read(fd,size)
        with patch.object(os,'read',side_effect=concurrent):self.assertEqual(reader.read()['state'],'ACTIVE')
        self.assertTrue(worker.active_here);self.assertEqual(coordination['state'],'LEASE_READY')
        self.assertEqual(effects,[]);self.assertEqual(j.read()['publicationCount'],16)

    def test_atomic_drift_consumes_only_original_three_observations_and_one_deadline(self):
        worker,c,j,coordination,effects,calls=self.fixture();reader=RecoverySnapshot(j.root,self.retained_scope,worker.r.policy)
        attempts=[];waits=[]
        def changed(*args,**kwargs):
            attempts.append(kwargs['deadline']);raise BlockingIOError('DISCOVERY_RECOVERY_CHANGED_DURING_READ')
        with patch.object(lease_observation,'_observe',side_effect=changed),patch.object(lease_observation.time,'sleep',side_effect=waits.append):
            with self.assertRaises(BlockingIOError):lease_observation.observe('unused','unused',unit_name='unused',systemctl={})
        self.assertEqual(len(attempts),3);self.assertEqual(len(set(attempts)),1);self.assertEqual(waits,[.02,.04])
        self.assertEqual(effects,[])

    def test_snapshot_rejects_bad_custody_scope_accounting_and_counter_records(self):
        worker,c,j,coordination,effects,calls=self.fixture();reader=RecoverySnapshot(j.root,self.retained_scope,worker.r.policy)
        before=j.record.read_bytes()
        for case in ('mode','hardlink','symlink','context','generation','policy','scope','accounting','state','counter','duplicate','oversize'):
            j.record.write_bytes(before);j.record.chmod(0o600);alias=j.root/'alias'
            value=json.loads(before)
            if case=='mode':j.record.chmod(0o644)
            elif case=='hardlink':os.link(j.record,alias)
            elif case=='symlink':j.record.rename(alias);j.record.symlink_to(alias)
            elif case in ('context','generation','policy','scope'):
                key={'context':'contextRef','generation':'generationRef','policy':'policyHash','scope':'discoveryLeaseScopeHash'}[case]
                value[key]='f'*64;j.record.write_bytes(encoded(value))
            elif case=='accounting':value['healthyWallSeconds']=-1;j.record.write_bytes(encoded(value))
            elif case=='state':value['state']='NATIVE_READY';j.record.write_bytes(encoded(value))
            elif case=='counter':value['attempts']=True;j.record.write_bytes(encoded(value))
            elif case=='duplicate':j.record.write_bytes(b'{"state":"ACTIVE","state":"ACTIVE"}')
            else:j.record.write_bytes(b'x'*65537)
            with self.subTest(case=case),self.assertRaises((ValueError,RuntimeError,OSError)):reader.read()
            if case=='symlink':j.record.unlink();alias.rename(j.record)
            elif alias.exists():alias.unlink()
        self.assertEqual(effects,[])


class HostComposition(unittest.TestCase):
    def test_signed_installed_inputs_match_original_factory_without_any_recovery_lock(self):
        import test_m2_discovery_lease_file_installation as files
        case=files.Files();self.addCleanup(case.doCleanups);owner,intent,auth,material,calls=case.fixture()
        owner.apply(intent);lease_observation.preload_runtime()
        path=owner.start.configuration_path;anchor=material['proposal']['serviceUnit']['configurationAnchor']
        original,old_guard,old_scope=lease_service.build_installed(path,anchor)
        with patch.object(Journal,'read',side_effect=AssertionError('HOST_OBSERVER_TOOK_WORKER_LOCK')):
            observed,guard,scope=build_observed(path,anchor)
            row=observed.r.journal.read()
            with patch.object(lease_start_owner,'boot_id',return_value=material['generation']['bootId']):
                owner.start.installed(before_start=False)
        self.assertEqual(scope,old_scope);self.assertEqual(guard.configuration,old_guard.configuration)
        self.assertEqual(observed.c.configuration,original.c.configuration)
        self.assertEqual(observed.c.binding,original.c.binding)
        self.assertEqual(observed.c.dns_profile,original.c.dns_profile)
        self.assertEqual(row,original.r.journal.read())
        self.assertFalse(hasattr(observed,'tick'));self.assertFalse(hasattr(observed.r,'adapter'))
        for operation in (observed.c.hold_lock,observed.c.write):
            with self.assertRaises(ValueError):operation()
        self.assertEqual(calls,[])

    def test_both_host_entrypoints_use_observation_factory_and_frozen_worker_factory_stays_separate(self):
        self.assertIs(lease_start_owner.build_installed,build_observed)
        self.assertIs(lease_observation.build_installed,build_observed)
        self.assertIsNot(lease_service.build_installed,build_observed)


if __name__=='__main__':unittest.main()
