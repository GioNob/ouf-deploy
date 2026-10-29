import ast
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'scripts/reconcile-ingestion-rollout-packet-20261020.py'
spec=importlib.util.spec_from_file_location('packet_reconciliation',PATH)
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class ReconciliationBoundaries(unittest.TestCase):
    def test_only_selected_native_archive_and_no_replay_download_or_reenvelope(self):
        source=PATH.read_text();tree=ast.parse(source)
        calls={ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)}
        self.assertFalse({'subprocess.run','os.execv','os.unlink','os.rename','os.replace','package.inventory',
                          'package.copy_member','custody.tagless_archive','authenticate_candidate'}&calls)
        self.assertIn("ingestion-rollout-packet-kkj_njiz",source)
        self.assertIn('EXACT_RETAINED_PREDECESSOR_CLAIM_REQUIRED',source)
        self.assertIn('EXACT_STOP_BEFORE_CONFIG_STAGING_REQUIRED',source)
        self.assertIn('PACKET_RECONCILIATION_ALREADY_CLAIMED_NO_REPLAY',source)
        self.assertEqual(r.NATIVE_SHA,'a3e26164c58dc40a6a0cd8b13e7ab91b7ea2a2e6094b49623a7d537ec7e8af95')
        requests=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and ast.unparse(n.func)=='connection.request']
        self.assertEqual(len(requests),2);self.assertTrue(all(ast.literal_eval(n.args[0])=='GET'for n in requests))

    def test_staging_uses_exact_bound_metadata_without_historical_uid_predicate(self):
        function=next(n for n in ast.parse(PATH.read_text()).body if isinstance(n,ast.FunctionDef)and n.name=='stage_gateway_config')
        source=ast.unparse(function)
        self.assertNotIn('636',source);self.assertIn('os.fchown(fd, uid, gid)',source)
        self.assertIn('EXACT_STAGED_CONFIG_BYTES_AND_METADATA_REQUIRED',source)

    def test_delivery_immutable_no_artifact_download_and_retained_stop_log(self):
        launcher=ROOT/'scripts/launch-ingestion-rollout-packet-reconcile-20261020.sh';source=launcher.read_text();raw=PATH.read_bytes()
        self.assertIn(hashlib.sha256(raw).hexdigest(),source)
        self.assertIn(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),source)
        self.assertNotIn('actions/artifacts',source);self.assertNotIn('candidate.zip',source)
        self.assertIn('trap ouf_report_log EXIT',source)
        self.assertLess(source.index('ouf-gh-2.102.0.PNoFbF'),source.index('command -v gh'))
        self.assertLess(source.index('sha256sum -c -'),source.index('sudo /usr/bin/python3'))
        subprocess.run(['bash','-n',str(launcher)],check=True)

if 'OUF_TEST_ROOT'in os.environ:
    class ExactConfigCustody(unittest.TestCase):
        def test_preserve_root_private_root_readable_and_historical_nonroot_metadata(self):
            for uid,gid,mode in [(0,0,0o600),(0,0,0o644),(636,636,0o400)]:
                with self.subTest(uid=uid,mode=mode),tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])as root:
                    root=Path(root);old=root/'old.yaml';old.write_bytes(b'nginx_config:\n  envs:\n  - KEEP\n')
                    os.chown(old,uid,gid);old.chmod(mode)
                    r.gateway._EXISTING_CONFIG_CUSTODY[str(old)]={'parents':{},'file':(uid,gid,mode)}
                    raw,binding=r.gateway.private_config(old);proposed=r.frames.expose_owner_environment(raw)
                    context=root/'new';context.mkdir(mode=0o700)
                    path,result=r.stage_gateway_config(proposed,binding,context)
                    self.assertEqual(result['metadata'][2:5],binding['metadata'][2:5])
                    self.assertEqual(path.read_bytes(),proposed)
                    self.assertEqual(r.gateway.private_config(old,binding)[0],raw)
                    with self.assertRaises(FileExistsError):r.stage_gateway_config(proposed,binding,context)

        def test_retained_context_and_archive_reject_extra_files_symlinks_and_nonprivate_mode(self):
            for state in ('extra','symlink','mode'):
                with self.subTest(state=state),tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])as root:
                    root=Path(root);path=root/'image.native-tagless.docker.tar';path.write_bytes(b'fixture');path.chmod(0o600)
                    (root/'image.original.docker.tar').write_bytes(b'fixture')
                    if state=='extra':(root/'packet-plan.json').write_bytes(b'{}')
                    if state=='symlink':path.unlink();path.symlink_to('/unread')
                    if state=='mode':path.chmod(0o644)
                    with patch.object(r,'RETAINED',root),self.assertRaises((r.Denied,OSError)):
                        with r.RetainedArchive(path):pass

        def test_new_claim_and_plan_are_exclusive_and_old_context_remains_unchanged(self):
            with tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])as root:
                root=Path(root);path=root/'claim.json';r.write_new(path,{'retained':True});before=r.read(path)
                with self.assertRaises(FileExistsError):r.write_new(path,{'reset':True})
                self.assertEqual(r.read(path),before)

if __name__=='__main__':unittest.main()
