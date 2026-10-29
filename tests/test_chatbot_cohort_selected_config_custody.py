"""The selected live bind owners differ from root without widening other reads."""
import stat
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_chatbot_cohort_gateway import g, ROOT


def metadata(uid, gid, mode):
    return SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode)


class SelectedConfigCustody(unittest.TestCase):
    def test_exact_existing_projection_and_ths(self):
        fixtures = (
            ('/opt/ouf/installation/active-projection.json',
             (('/opt/ouf',1000,1000,0o750),('/opt/ouf/installation',0,0,0o700)),
             (0,0,0o600)),
            ('/opt/ouf/secrets/onboarding-ths.yaml',
             (('/opt/ouf',1000,1000,0o750),('/opt/ouf/secrets',1000,1000,0o700)),
             (10003,10003,0o400)),
            ('/opt/ouf/secrets/apisix-admin-key',
             (('/opt/ouf',1000,1000,0o750),('/opt/ouf/secrets',1000,1000,0o700)),
             (1000,None,0o600)),
            ('/etc/ouf/deploy-snapshots/consultation-human-read-20261002-1153/prepared/apisix-config.yaml',
             (('/etc/ouf',0,0,0o755),), (636,636,0o400)),
        )
        for path, parents, file_owner in fixtures:
            with self.subTest(path=path):
                exception=g._EXISTING_CONFIG_CUSTODY[path]
                for directory,uid,gid,mode in parents:
                    self.assertTrue(g.selected_directory_custody(metadata(uid,gid,stat.S_IFDIR|mode),
                                                                  directory,exception))
                    self.assertFalse(g.selected_directory_custody(metadata(uid+1,gid,stat.S_IFDIR|mode),
                                                                   directory,exception))
                    self.assertFalse(g.selected_directory_custody(metadata(uid,gid,stat.S_IFDIR|mode|0o020),
                                                                   directory,exception))
                uid,gid,mode=file_owner
                observed_gid=gid if gid is not None else 1234
                self.assertTrue(g.selected_file_custody(metadata(uid,observed_gid,stat.S_IFREG|mode),exception))
                self.assertFalse(g.selected_file_custody(metadata(uid+1,observed_gid,stat.S_IFREG|mode),exception))
                if gid is not None:
                    self.assertFalse(g.selected_file_custody(metadata(uid,gid+1,stat.S_IFREG|mode),exception))
                self.assertFalse(g.selected_file_custody(metadata(uid,observed_gid,stat.S_IFREG|mode|0o020),exception))

    def test_no_wildcard_for_other_configurations(self):
        self.assertFalse(g.selected_directory_custody(metadata(1000,1000,stat.S_IFDIR|0o750),
                                                       '/opt/ouf',None))
        self.assertFalse(g.selected_file_custody(metadata(636,636,stat.S_IFREG|0o400),None))
        self.assertTrue(g.selected_file_custody(metadata(0,0,stat.S_IFREG|0o600),None))

    @unittest.skipUnless(os.geteuid()==0, 'native cross-owner file fixture requires root')
    def test_descriptor_read_accepts_named_owner_and_fences_drift(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            parent=Path(directory)/'selected';parent.mkdir(mode=0o700)
            try: os.chown(parent,1000,1000)
            except OSError: self.skipTest('sandbox cannot assign target host owners')
            leaf=parent/'mounted.yaml';leaf.write_bytes(b'selected configuration fixture')
            os.chown(leaf,10003,10003);leaf.chmod(0o400)
            exception={'parents':{str(parent):(1000,1000,0o700)},'file':(10003,10003,0o400)}
            with patch.dict(g._EXISTING_CONFIG_CUSTODY,{str(leaf):exception}):
                raw,binding=g.private_config(leaf)
                self.assertEqual(raw,b'selected configuration fixture')
                self.assertEqual(g.private_config(leaf,binding)[0],raw)
                os.chown(parent,1001,1000)
                with self.assertRaisesRegex(ValueError,'APISIX_CONFIG_ANCESTRY_NOT_CUSTODIED'):
                    g.private_config(leaf,binding)


if __name__ == '__main__': unittest.main()
