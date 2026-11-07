"""Exact private file, deadline and cleanup protocol; native nft is separate."""
import os,stat,sys,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_lease_recovery'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.m2_discovery_installation_profile.discovery_nft_backend import DiscoveryNftBackend
from tools.m2_discovery_installation_profile import discovery_nft_backend as m


class Backend(unittest.TestCase):
    def setUp(self):
        # The native job tests the real private /tmp. Unit tests redirect only
        # storage so they also run in a restricted workspace with no /tmp.
        original=m.tempfile.TemporaryDirectory
        def directory(*,prefix,dir):
            self.assertEqual(dir,'/tmp');return original(prefix=prefix,dir=ROOT)
        patch=mock.patch.object(m.tempfile,'TemporaryDirectory',directory)
        patch.start();self.addCleanup(patch.stop)

    def backend(self,clock=lambda:10):
        self.assertEqual(os.geteuid(),0);b=object.__new__(DiscoveryNftBackend)
        b.clock=clock;b.budget=5;return b

    def test_one_private_input_keeps_exact_bytes_and_is_removed(self):
        b=self.backend();seen=[];transaction='flush set inet owned provider_0\nflush set bridge owned provider_0\n'
        def run(args,raw=None,timeout=None):
            self.assertEqual(args[0],'-f');self.assertNotEqual(args[1],'-');self.assertIsNone(raw)
            p=Path(args[1]);seen.append(p)
            self.assertEqual(p.read_bytes(),transaction.encode());self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
            self.assertEqual(stat.S_IMODE(p.parent.stat().st_mode),0o700);self.assertEqual(p.stat().st_nlink,1)
            self.assertEqual(timeout,2)
        b.run=run;b.apply(transaction,12)
        self.assertEqual(len(seen),1);self.assertFalse(seen[0].exists());self.assertFalse(seen[0].parent.exists())

    def test_file_preparation_time_consumes_the_original_deadline(self):
        times=iter((10,13));b=self.backend(lambda:next(times));b.run=mock.Mock()
        with self.assertRaisesRegex(RuntimeError,'DEADLINE_MISSED'):b.apply('flush set inet owned provider_0\n',12)
        b.run.assert_not_called()

    def test_failed_native_command_is_not_retried_and_input_is_removed(self):
        b=self.backend();seen=[]
        def fail(args,**kw):seen.append(Path(args[1]));raise RuntimeError('SYNTHETIC_NATIVE_FAILURE')
        b.run=fail
        with self.assertRaisesRegex(RuntimeError,'SYNTHETIC_NATIVE_FAILURE'):b.apply('flush set inet owned provider_0\n',12)
        self.assertEqual(len(seen),1);self.assertFalse(seen[0].parent.exists())

    def test_empty_nul_or_unbounded_input_is_denied_without_command(self):
        b=self.backend();b.run=mock.Mock()
        for raw in ('','bad\0input','x'*1048577):
            with self.assertRaisesRegex(ValueError,'BOUNDED_DISCOVERY'):b.apply(raw,12)
        b.run.assert_not_called()

if __name__=='__main__':unittest.main()
