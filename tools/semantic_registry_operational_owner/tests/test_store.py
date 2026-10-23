import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from tools.semantic_registry_operational_owner import core as c
from tools.semantic_registry_operational_owner.store import Store


POLICY=c.RenewalPolicy(60,90,15,60,3,30,(5,15,60,300))


class Filesystem(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'ledger';self.root.mkdir(mode=0o700)
        row=c.initial('a'*64,'b'*64,321,POLICY,'fixture-boot',(10000,1000))
        for name,raw in [('state.json',c.encoded(row)),('invocation.lock',b''),('cas.lock',b'')]:
            path=self.root/name;path.write_bytes(raw);path.chmod(0o600)
        self.store=Store(self.root);self.addCleanup(self.store.close)
    def test_real_file_cas_requires_live_invocation_and_preserves_history(self):
        row=self.store.read();following=dict(row,version=1,reason='CHECKED')
        with self.assertRaises(c.Denied):self.store.cas(row,following)
        with self.store.invocation():self.store.cas(row,following)
        self.assertEqual(self.store.read(),following);self.assertEqual((self.root/'state.json').stat().st_mode&0o777,0o600)
    def test_second_process_cannot_take_same_invocation(self):
        source='''import sys
from tools.semantic_registry_operational_owner.store import Store
from tools.semantic_registry_operational_owner.core import Denied
s=Store(sys.argv[1])
try:
 with s.invocation():raise SystemExit(3)
except Denied:print("CONCURRENT_REFUSED")
finally:s.close()
'''
        with self.store.invocation():
            result=subprocess.run([sys.executable,'-B','-c',source,str(self.root)],cwd=ROOT,
                                  capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout.strip(),'CONCURRENT_REFUSED')
    def test_replaced_invocation_file_cannot_keep_cached_ownership(self):
        with self.store.invocation():
            path=self.root/'invocation.lock';path.unlink();path.write_bytes(b'');path.chmod(0o600)
            with self.assertRaisesRegex(c.Denied,'INVOCATION_LOCK_CHANGED'):self.store.assert_invocation()
    def test_directory_replacement_refused_by_held_ancestry(self):
        old=self.root.with_name('old');self.root.rename(old);self.root.mkdir(mode=0o700)
        with self.assertRaisesRegex(c.Denied,'ANCESTRY_CHANGED'):self.store.read()
    def test_symlink_or_hardlink_ledger_refused(self):
        path=self.root/'state.json';saved=path.with_name('saved');path.rename(saved);path.symlink_to(saved)
        with self.assertRaises(OSError):self.store.read()
        path.unlink();os.link(saved,path)
        with self.assertRaisesRegex(c.Denied,'PRIVATE_OPERATIONAL_STORE_FILE'):self.store.read()
    def test_stale_cas_cannot_overwrite_a_later_transition(self):
        with self.store.invocation():
            row=self.store.read();next_row=dict(row,version=1,reason='FIRST');self.store.cas(row,next_row)
            with self.assertRaisesRegex(c.Denied,'CAS_CONFLICT'):self.store.cas(row,dict(row,version=1,reason='STALE'))
            self.assertEqual(self.store.read(),next_row)
    def test_counter_or_predecessor_rewrite_refused_without_touching_file(self):
        row=self.store.read();before=(self.root/'state.json').read_bytes()
        with self.store.invocation():
            for changes in ({'cumulativeAttempts':320},{'priorControlledAttempts':0},{'policyHash':'c'*64}):
                with self.assertRaisesRegex(c.Denied,'CANNOT_RESET_HISTORY'):self.store.cas(row,dict(row,version=1,**changes))
        self.assertEqual((self.root/'state.json').read_bytes(),before)
    def test_no_initializer_or_implicit_lock_creation(self):
        (self.root/'cas.lock').unlink()
        with self.store.invocation():
            row=self.store.read()
            with self.assertRaises(FileNotFoundError):self.store.cas(row,dict(row,version=1))
        self.assertFalse((self.root/'cas.lock').exists())

if __name__=='__main__':unittest.main()
