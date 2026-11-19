import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('volume_crash33', ROOT / 'scripts/run-storage-generation33-lateral-isolation.py')
lab = importlib.util.module_from_spec(spec); spec.loader.exec_module(lab)


class VolumeCrashTests(unittest.TestCase):
    def snapshots(self):
        before = {r: {'Id': r, 'RestartCount': 0, 'State': {'Running': True, 'StartedAt': 'initial',
                    'OOMKilled': False, 'Error': '', 'ExitCode': 0}} for r in lab.ROLES}
        killed = copy.deepcopy(before['volume']); killed['State'].update(Running=False, ExitCode=137)
        return before, killed

    def test_only_exact_non_oom_sigkill_passes(self):
        before, killed = self.snapshots(); lab.validate_killed_volume(before['volume'], killed)
        for field, value in [('ExitCode',0),('ExitCode',143),('OOMKilled',True),('Running',True),('Error','failed')]:
            changed = copy.deepcopy(killed); changed['State'][field] = value
            with self.subTest(field=field,value=value), self.assertRaises(ValueError):
                lab.validate_killed_volume(before['volume'],changed)
        killed['Id']='wrong'
        with self.assertRaises(ValueError):lab.validate_killed_volume(before['volume'],killed)

    def test_other_roles_cannot_restart_or_change_identity(self):
        before,_=self.snapshots();after=copy.deepcopy(before);after['volume']['Id']='replacement'
        lab.validate_retained_roles(before,after)
        for role in ('master','filer','s3','client'):
            for mutation in ('Id','RestartCount','StartedAt'):
                bad=copy.deepcopy(after)
                if mutation=='StartedAt':bad[role]['State'][mutation]='restarted'
                else:bad[role][mutation]='different' if mutation=='Id' else 1
                with self.subTest(role=role,mutation=mutation),self.assertRaises(ValueError):
                    lab.validate_retained_roles(before,bad)

    def test_fresh_gate_keeps_same_data_image_and_capability_limits(self):
        data=Path('/fixture');base=(data,data/'config',Path('/network-gate'))
        old=lab.container_argv('sha256:fixture','old','net',*base,'volume',data/'gate-volume')
        new=lab.container_argv('sha256:fixture','new','net',*base,'volume',data/'gate-volume-recovered')
        self.assertIn('type=bind,src=/fixture/volume,dst=/data',old)
        self.assertIn('type=bind,src=/fixture/volume,dst=/data',new)
        self.assertIn('type=bind,src=/fixture/gate-volume-recovered,dst=/gate,readonly',new)
        self.assertIn('--read-only',new);self.assertIn('--cap-drop',new);self.assertNotIn('--privileged',new)
        self.assertEqual(old[old.index('sha256:fixture'):],new[new.index('sha256:fixture'):])

    def test_response_byte_counter_covers_established_volume_stream(self):
        rules=lab.nft_rules('volume')
        position=rules.index('tcp sport 18080 counter name volume_http_response_bytes')
        self.assertLess(position,rules.index('ct state established,related accept'))
        self.assertNotIn('volume_http_response_bytes',lab.nft_rules('client'))

    def test_deterministic_large_fixture_exceeds_small_object_path(self):
        body=lab.volume_body();self.assertEqual(8*1024*1024+257,len(body))
        self.assertEqual(body,lab.volume_body())
        self.assertEqual(256,len(set(body[:16384])))

    def test_dat_prefix_survives_append_without_synthesizing_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'1.dat';path.write_bytes(b'original durable fixture')
            before=lab.volume_inventory(root)
            path.write_bytes(path.read_bytes()+b'new background log')
            self.assertEqual(before,lab.volume_inventory(root,before))

    def test_truncated_or_changed_dat_prefix_fails(self):
        for payload in (b'short',b'altered original bytes'):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);path=root/'1.dat';path.write_bytes(b'original durable data')
                before=lab.volume_inventory(root);path.write_bytes(payload)
                with self.assertRaises(ValueError):lab.volume_inventory(root,before)

    def test_missing_or_symlink_dat_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'1.dat';path.write_bytes(b'original')
            before=lab.volume_inventory(root);path.unlink()
            with self.assertRaises(ValueError):lab.volume_inventory(root,before)
            (root/'other').write_bytes(b'original');path.symlink_to(root/'other')
            with self.assertRaises(ValueError):lab.volume_inventory(root,before)

    def test_seed_records_ack_without_priming_body_cache(self):
        with patch.object(lab,'s3_request',return_value={'status':200}) as request:
            result=lab.client('seed-volume',Path('/fixture'))
        self.assertEqual(['PUT','PUT'],[c.args[3] for c in request.call_args_list])
        self.assertEqual(0,result['bodyReadsBeforeCrash'])
        self.assertEqual(200,result['putStatus'])
        self.assertEqual(lab.VOLUME_BYTES,result['acknowledgedObject']['bytes'])

    def test_only_explicit_transient_http_can_return_retry_decision(self):
        with patch.object(lab,'s3_request',return_value={'status':503}) as request:
            result=lab.client('read-volume',Path('/fixture'))
        self.assertEqual({'status':'TRANSIENT_READ_FAILURE','httpStatus':503,'mutatingRequests':0},result)
        self.assertEqual(['GET'],[c.args[3] for c in request.call_args_list])
        with patch.object(lab,'s3_request',return_value={'status':403}):
            with self.assertRaises(ValueError):lab.client('read-volume',Path('/fixture'))


if __name__=='__main__':unittest.main()
