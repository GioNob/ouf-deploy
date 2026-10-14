"""Real source TAR and isolated root-body execution; explicit fixture target only.

The production /etc/ouf/deploy-snapshots literal is replaced only in this test's
copy of ROOT_BODY. Synthetic entry code reports its arguments/custody; it cannot
deploy. GitHub and sudo transports are never called. No real package acceptance,
HUMAN approval, installation authority or target mutation is represented here.
"""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cohort_delivery_launcher', ROOT/'scripts/deliver-chatbot-file-cohort.py')
launcher = importlib.util.module_from_spec(spec); spec.loader.exec_module(launcher)
COMMIT = 'd'*40
ENTRY = 'scripts/install-chatbot-file-cohort.py'
ENTRY_BYTES = b'''import argparse,hashlib,json,os,stat,sys
from pathlib import Path
p=argparse.ArgumentParser()
for name in ("source-directory","package-archive","staging-directory","source-commit","preparation-source-hash"):
    p.add_argument("--"+name,required=True)
a=p.parse_args();source=Path(a.source_directory);stage=Path(a.staging_directory)
members={str(v.relative_to(stage)):{"mode":oct(stat.S_IMODE(v.stat().st_mode)),
    "uid":v.stat().st_uid,"gid":v.stat().st_gid,"sha256":hashlib.sha256(v.read_bytes()).hexdigest()}
    for v in stage.rglob("*") if v.is_file()}
print(json.dumps({"status":"SYNTHETIC_ENTRY_ONLY","isolated":sys.flags.isolated,
    "noSite":sys.flags.no_site,"noBytecode":sys.dont_write_bytecode,"uid":os.geteuid(),
    "arguments":vars(a),"files":members,"targetApplyAuthorized":False},sort_keys=True))
'''


def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class DeliveryLauncherTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual((os.geteuid(), os.getegid()), (0, 0), 'native root-custody fixture required')
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT, prefix='launcher-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.base = self.root/'explicit-synthetic-snapshots'; self.base.mkdir(mode=0o700)
        self.files = {ENTRY:ENTRY_BYTES, 'tools/fixture/helper.py':b'FIXTURE_ONLY = True\n',
                      'docs/fixture.txt':b'Not a real installation source capsule.\n'}
        self.manifest = {'schema':'ouf.chatbot-file-preparation-capsule.v1',
                         'files':{name:sha(raw) for name, raw in self.files.items()}}
        self.manifest_raw = encoded(self.manifest); self.expected = sha(self.manifest_raw)
        self.package = self.root/'fixture-cohort.zip'; self.package.write_bytes(b'SYNTHETIC-NOT-A-COHORT')
        self.real_run = subprocess.run

    def archive(self, rows=None):
        rows = rows if rows is not None else [('GioNob-ouf-deploy-fixture/'+name, raw, tarfile.REGTYPE)
                                              for name, raw in self.files.items()]
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz', format=tarfile.PAX_FORMAT) as archive:
            for name, raw, kind in rows:
                member = tarfile.TarInfo(name); member.type = kind
                member.size = len(raw) if kind == tarfile.REGTYPE else 0
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE): member.linkname = '../outside'
                archive.addfile(member, io.BytesIO(raw) if member.isfile() else None)
        return output.getvalue()

    def select(self, raw=None, manifest=None):
        path = self.root/'selected-source.tar.gz'; path.write_bytes(raw or self.archive())
        return launcher.selected_sources(path, manifest or self.manifest)

    def payload(self, files=None, manifest_raw=None):
        return encoded({'manifest':base64.b64encode(manifest_raw or self.manifest_raw).decode(),
            'files':{name:base64.b64encode(raw).decode() for name, raw in
                     (self.files if files is None else files).items()}})

    def root_body(self):
        selected = "base=Path('/etc/ouf/deploy-snapshots')"
        self.assertEqual(launcher.ROOT_BODY.count(selected), 1)
        return launcher.ROOT_BODY.replace(selected, 'base=Path('+repr(str(self.base))+')')

    def run_root(self, payload=None, expected=None, flags=('-I', '-B', '-S')):
        return self.real_run([sys.executable, *flags, '-c',
            'EXPECTED='+repr(expected or self.expected)+'\n'+self.root_body(), COMMIT, str(self.package)],
            input=self.payload() if payload is None else payload, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=15)

    def assert_denied(self, result, reason):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(reason.encode(), result.stderr)
        self.assertNotIn(b'SYNTHETIC_ENTRY_ONLY', result.stdout)

    def test_selected_real_gzip_tar_has_exact_hash_closure_without_extracting_unselected_files(self):
        rows = [('GioNob-ouf-deploy-fixture/', b'', tarfile.DIRTYPE)]
        rows += [('GioNob-ouf-deploy-fixture/'+name, raw, tarfile.REGTYPE) for name, raw in self.files.items()]
        rows += [('GioNob-ouf-deploy-fixture/unselected.py', b'raise RuntimeError("NEVER EXECUTE")', tarfile.REGTYPE)]
        self.assertEqual(self.select(self.archive(rows)), self.files)
        self.assertFalse((self.root/'unselected.py').exists())

    def test_missing_changed_duplicate_and_linked_selected_tar_members_deny(self):
        rows = [('repo/'+name, raw, tarfile.REGTYPE) for name, raw in self.files.items()]
        variants = [(rows[1:], 'CLOSURE_INCOMPLETE'),
            ([(rows[0][0], b'changed', tarfile.REGTYPE), *rows[1:]], 'SOURCE_HASH_MISMATCH'),
            (rows+[rows[0]], 'REGULAR_UNIQUE_SOURCE_MEMBER'),
            ([(rows[0][0], b'', tarfile.SYMTYPE), *rows[1:]], 'REGULAR_UNIQUE_SOURCE_MEMBER'),
            ([(rows[0][0], b'', tarfile.LNKTYPE), *rows[1:]], 'REGULAR_UNIQUE_SOURCE_MEMBER')]
        for entries, reason in variants:
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                self.select(self.archive(entries))

    def test_manifest_traversal_and_archive_root_changes_cannot_select_executable_bytes(self):
        for name in ('../outside', '/outside', 'tools/../outside', './outside', 'tools//outside'):
            with self.subTest(name=name):
                manifest = copy.deepcopy(self.manifest); manifest['files'][name] = sha(b'bad')
                with self.assertRaisesRegex(ValueError, 'EXACT_SOURCE_MEMBER_AND_DIGEST'):
                    self.select(manifest=manifest)
        rows = [('repo/'+name, raw, tarfile.REGTYPE) for name, raw in self.files.items()]
        rows[0] = ('repo/../'+ENTRY, ENTRY_BYTES, tarfile.REGTYPE)
        with self.assertRaisesRegex(ValueError, 'CLOSURE_INCOMPLETE'): self.select(self.archive(rows))
        rows[0] = ('different/'+ENTRY, ENTRY_BYTES, tarfile.REGTYPE)
        with self.assertRaisesRegex(ValueError, 'ONE_SOURCE_ARCHIVE_ROOT'): self.select(self.archive(rows))

    def test_root_subprocess_executes_exact_entry_with_isolation_private_custody_and_forwarded_bindings(self):
        result = self.run_root(); self.assertEqual(result.returncode, 0, result.stderr.decode())
        receipt = json.loads(result.stdout); stage = self.base/('chatbot-file-intake-'+self.expected)
        attempt = Path(receipt['arguments']['staging_directory'])
        self.assertEqual(attempt.parent, stage)
        self.assertRegex(attempt.name, r'^attempt-[0-9a-f]{24}$')
        self.assertEqual(receipt['status'], 'SYNTHETIC_ENTRY_ONLY')
        self.assertEqual((receipt['isolated'], receipt['noSite'], receipt['noBytecode'], receipt['uid']), (1, 1, True, 0))
        self.assertEqual(receipt['arguments'], {'source_directory':str(stage/'source'),
            'package_archive':str(self.package), 'staging_directory':str(attempt),
            'source_commit':COMMIT, 'preparation_source_hash':self.expected})
        self.assertFalse(receipt['targetApplyAuthorized'])
        self.assertEqual(set(receipt['files']), {'preparation-manifest.json'})
        for name, value in receipt['files'].items():
            self.assertEqual((value['uid'], value['gid'], value['mode']), (0, 0, '0o600'))
            self.assertEqual(value['sha256'], sha(self.manifest_raw))
        for name, raw in self.files.items():
            source = stage/'source'/name
            self.assertEqual(sha(source.read_bytes()), sha(raw))
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
        for path in (stage, *(p for p in stage.rglob('*') if p.is_dir())):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        self.assertEqual(list(stage.rglob('*.pyc')), [])

    def test_root_hash_complete_set_and_source_bytes_are_rechecked_before_any_entry(self):
        self.assert_denied(self.run_root(expected='0'*64), 'ROOT_CAPSULE_MANIFEST_HASH_MISMATCH')
        missing = dict(self.files); missing.pop(ENTRY)
        self.assert_denied(self.run_root(self.payload(files=missing)), 'ROOT_COMPLETE_SOURCE_SET_REQUIRED')
        changed = {**self.files, ENTRY:ENTRY_BYTES+b'# drift\n'}
        self.assert_denied(self.run_root(self.payload(files=changed)), 'ROOT_SOURCE_MEMBER_HASH_MISMATCH')
        self.assertEqual(list(self.base.iterdir()), [])

    def test_root_duplicate_json_traversal_and_nonisolated_launch_are_denied(self):
        payload = self.payload().decode()
        self.assert_denied(self.run_root(('{"manifest":"duplicate",'+payload[1:]).encode()), 'DUPLICATE_CAPSULE_KEY')
        files = {**self.files, '../outside':b'not allowed'}
        manifest = {'schema':self.manifest['schema'], 'files':{name:sha(raw) for name, raw in files.items()}}
        raw = encoded(manifest)
        self.assert_denied(self.run_root(self.payload(files, raw), sha(raw)), 'ROOT_SOURCE_MEMBER_HASH_MISMATCH')
        self.assert_denied(self.run_root(flags=('-B', '-S')), 'ISOLATED_ROOT_DELIVERY_REQUIRED')
        self.assertEqual(list(self.base.iterdir()), [])

    def test_root_reentry_retains_exact_bytes_and_rejects_byte_or_mode_drift(self):
        first = self.run_root(); self.assertEqual(first.returncode, 0, first.stderr.decode())
        stage = self.base/('chatbot-file-intake-'+self.expected); entry = stage/'source'/ENTRY
        identity = (entry.stat().st_dev, entry.stat().st_ino)
        first_attempt=Path(json.loads(first.stdout)['arguments']['staging_directory'])
        marker=first_attempt/'retained-marker';marker.write_bytes(b'PRIOR_ATTEMPT_UNCHANGED')
        again = self.run_root(); self.assertEqual(again.returncode, 0, again.stderr.decode())
        second_attempt=Path(json.loads(again.stdout)['arguments']['staging_directory'])
        self.assertNotEqual(first_attempt,second_attempt)
        self.assertEqual(marker.read_bytes(),b'PRIOR_ATTEMPT_UNCHANGED')
        self.assertEqual(identity, (entry.stat().st_dev, entry.stat().st_ino))
        entry.write_bytes(ENTRY_BYTES.replace(b'SYNTHETIC_ENTRY_ONLY', b'SYNTHETIC_ENTRY_EVIL'))
        self.assert_denied(self.run_root(), 'ROOT_EXISTING_SOURCE_BYTES_DRIFT')
        entry.write_bytes(ENTRY_BYTES); entry.chmod(0o644)
        self.assert_denied(self.run_root(), 'ROOT_EXISTING_SOURCE_CUSTODY_DRIFT')

    def test_root_parent_and_stage_custody_drift_block_before_entry(self):
        self.base.chmod(0o770)
        self.assert_denied(self.run_root(), 'ROOT_STAGING_PARENT_CUSTODY_REQUIRED')
        self.base.chmod(0o700)
        stage = self.base/('chatbot-file-intake-'+self.expected); stage.mkdir(mode=0o755)
        self.assert_denied(self.run_root(), 'ROOT_PRIVATE_STAGE_REQUIRED')

    def test_complete_outer_command_with_fixture_transport_reaches_real_isolated_root_entry(self):
        home = self.root/'operator-home'; home.mkdir(mode=0o700)
        archive = self.archive(); calls = []; root_receipts = []
        downloader = b'''import argparse
from pathlib import Path
def main():
    p=argparse.ArgumentParser();p.add_argument("--run");p.add_argument("--producer-commit");p.add_argument("--output")
    a=p.parse_args();d=Path(a.output);d.mkdir(mode=0o700)
    (d/"cohort.zip").write_bytes(b"SYNTHETIC-NOT-A-COHORT")
'''
        def transport(argv, **kwargs):
            calls.append(argv)
            if argv[0] == 'fixture-gh':
                endpoint = argv[2]
                if '/contents/'+launcher.CAPSULE_PATH+'?ref='+COMMIT in endpoint:
                    raw = self.manifest_raw
                elif '/contents/scripts/download-file-cohort.py?ref='+launcher.PACKAGE_COMMIT in endpoint:
                    raw = downloader
                else:
                    self.assertEqual(endpoint, 'repos/'+launcher.REPOSITORY+'/tarball/'+COMMIT)
                    kwargs['stdout'].write(archive)
                    return subprocess.CompletedProcess(argv, 0)
                return subprocess.CompletedProcess(argv, 0, stdout=base64.b64encode(raw))
            self.assertEqual(argv[:3], ['sudo', '--', '/usr/bin/python3'])
            self.assertEqual(argv[3:7], ['-I', '-B', '-S', '-c'])
            code = argv[7].replace("base=Path('/etc/ouf/deploy-snapshots')", 'base=Path('+repr(str(self.base))+')')
            child = self.real_run([sys.executable, *argv[3:7], code, *argv[8:]], input=kwargs['input'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            self.assertEqual(child.returncode, 0, child.stderr.decode()); root_receipts.append(json.loads(child.stdout))
            return child
        with patch.object(launcher.Path, 'home', return_value=home), patch.object(launcher.shutil, 'which', return_value='fixture-gh'), \
             patch.object(launcher, 'CAPSULE_SHA256', self.expected), patch.object(launcher, 'DOWNLOADER_SHA256', sha(downloader)), \
             patch.object(launcher, 'PACKAGE_SHA256', sha(self.package.read_bytes())), \
             patch.object(launcher.sys, 'argv', ['fixture-launcher', '--source-commit', COMMIT]), \
             patch.object(launcher.subprocess, 'run', side_effect=transport), patch('builtins.print'):
            self.assertEqual(launcher.main(), 0)
        self.assertEqual(len(calls), 4)
        self.assertEqual(len(root_receipts), 1)
        self.assertEqual(root_receipts[0]['arguments']['source_commit'], COMMIT)

    def test_existing_exact_archive_is_reused_with_new_capsule_and_old_partial_stage_untouched(self):
        home=self.root/'operator-home';home.mkdir(mode=0o700)
        previous='e'*64
        previous_output=home/('ouf-chatbot-file-delivery-'+previous[:24])
        previous_cohort=previous_output/'cohort';previous_cohort.mkdir(mode=0o700,parents=True)
        existing=previous_cohort/'cohort.zip';existing.write_bytes(self.package.read_bytes())
        old_stage=self.base/('chatbot-file-intake-'+previous)
        old_partial=old_stage/'package';old_partial.mkdir(mode=0o700,parents=True)
        marker=old_partial/'partial-evidence';marker.write_bytes(b'RETAINED-NOT-REPLAYED')
        original=(existing.stat().st_ino,marker.stat().st_ino,marker.read_bytes())
        calls=[];receipts=[];archive=self.archive()
        def transport(argv,**kwargs):
            calls.append(argv)
            if argv[0]=='fixture-gh':
                endpoint=argv[2]
                if '/contents/'+launcher.CAPSULE_PATH+'?ref='+COMMIT in endpoint:
                    return subprocess.CompletedProcess(argv,0,stdout=base64.b64encode(self.manifest_raw))
                self.assertEqual(endpoint,'repos/'+launcher.REPOSITORY+'/tarball/'+COMMIT)
                kwargs['stdout'].write(archive);return subprocess.CompletedProcess(argv,0)
            self.assertEqual(argv[:3],['sudo','--','/usr/bin/python3'])
            self.assertEqual(argv[-1],str(existing))
            code=argv[7].replace("base=Path('/etc/ouf/deploy-snapshots')",'base=Path('+repr(str(self.base))+')')
            result=self.real_run([sys.executable,*argv[3:7],code,*argv[8:]],input=kwargs['input'],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr.decode());receipts.append(json.loads(result.stdout))
            return result
        with patch.object(launcher.Path,'home',return_value=home), \
             patch.object(launcher.shutil,'which',return_value='fixture-gh'), \
             patch.object(launcher,'CAPSULE_SHA256',self.expected), \
             patch.object(launcher,'PACKAGE_SHA256',sha(self.package.read_bytes())), \
             patch.object(launcher.sys,'argv',['fixture-launcher','--source-commit',COMMIT,'--package-archive',str(existing)]), \
             patch.object(launcher.subprocess,'run',side_effect=transport),patch('builtins.print'):
            self.assertEqual(launcher.main(),0)
        self.assertEqual(len(calls),3) # manifest, small source TAR, isolated root entry; no package downloader
        self.assertEqual(len(receipts),1)
        self.assertEqual(Path(receipts[0]['arguments']['staging_directory']).parent,
                         self.base/('chatbot-file-intake-'+self.expected))
        self.assertNotEqual(receipts[0]['arguments']['staging_directory'],str(old_stage))
        self.assertEqual((existing.stat().st_ino,marker.stat().st_ino,marker.read_bytes()),original)
        self.assertFalse((home/('ouf-chatbot-file-delivery-'+self.expected[:24])/'cohort').exists())

    def test_reused_archive_tamper_link_and_nonregular_file_are_denied(self):
        with patch.object(launcher,'PACKAGE_SHA256',sha(self.package.read_bytes())):
            self.assertEqual(launcher.verified_package(self.package),self.package)
            with self.assertRaisesRegex(ValueError,'EXACT_DELIVERED_ARCHIVE_PATH_REQUIRED'):
                launcher.verified_package('relative/cohort.zip')
            link=self.root/'linked.zip';link.symlink_to(self.package)
            with self.assertRaises(OSError):launcher.verified_package(link)
            hardlink=self.root/'hardlink.zip';os.link(self.package,hardlink)
            with self.assertRaisesRegex(ValueError,'REGULAR_PRIVATE_OPERATOR_ARCHIVE_REQUIRED'):
                launcher.verified_package(hardlink)
            hardlink.unlink()
            with self.assertRaisesRegex(ValueError,'REGULAR_PRIVATE_OPERATOR_ARCHIVE_REQUIRED'):
                launcher.verified_package(self.root)
            self.package.write_bytes(b'CHANGED')
            with self.assertRaisesRegex(ValueError,'EXACT_COHORT_ARCHIVE_REQUIRED'):
                launcher.verified_package(self.package)

    def test_mismatched_explicit_archive_stops_before_source_tar_or_sudo_without_downloading(self):
        home=self.root/'operator-home';home.mkdir(mode=0o700);calls=[]
        def transport(argv,**kwargs):
            calls.append(argv)
            self.assertEqual(argv[0],'fixture-gh')
            self.assertIn('/contents/'+launcher.CAPSULE_PATH+'?ref='+COMMIT,argv[2])
            return subprocess.CompletedProcess(argv,0,stdout=base64.b64encode(self.manifest_raw))
        with patch.object(launcher.Path,'home',return_value=home), \
             patch.object(launcher.shutil,'which',return_value='fixture-gh'), \
             patch.object(launcher,'CAPSULE_SHA256',self.expected), \
             patch.object(launcher,'PACKAGE_SHA256','0'*64), \
             patch.object(launcher.sys,'argv',['fixture-launcher','--source-commit',COMMIT,'--package-archive',str(self.package)]), \
             patch.object(launcher.subprocess,'run',side_effect=transport),patch('builtins.print'):
            with self.assertRaisesRegex(ValueError,'EXACT_COHORT_ARCHIVE_REQUIRED'):launcher.main()
        self.assertEqual(len(calls),1)
        self.assertEqual(list(self.base.iterdir()),[])


if __name__ == '__main__':
    unittest.main()
