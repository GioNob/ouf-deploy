"""Real private publication and unchanged nft/owner CLI; systemd is simulated."""
import importlib.util
from pathlib import Path
import types
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
b=load('boot_fixture',Path(__file__).with_name('test_discovery_boot_activation.py'))
n=load('successor_native',Path(__file__).with_name('native_discovery_coordinator_successor.py'))
m=b.m


class NativeBoot(unittest.TestCase):
    setUp=n.NativeSuccessor.setUp
    tearDown=n.NativeSuccessor.tearDown
    stage=n.NativeSuccessor.stage
    cli=n.NativeSuccessor.cli

    def fixture(self):
        stage,files,owner,_,current,_=self.stage();root=Path(self.tmp.name)
        c=types.SimpleNamespace(p=n.q.load_helper('reconcile-discovery-placeholder-20261109.py'))
        oldcmd='old-command';newcmd=m.command_for(stage,n.m.digest(files['boot-profile.json']))
        old={'guard.service':b'[Service]\nExecStart=old-command\n','docker-drop-in.conf':b'[Service]\nExecStartPre=old-command\n'}
        new,_=m.unit_plan(old,oldcmd,newcmd,b.metadata(oldcmd),stage=stage)
        entries=[]
        for key in old:
            path=root/key;c.p.save(path,old[key]);entries.append({'path':path,'old':old[key],'new':new[key]})
        pointer=root/'pointer.json';c.p.save(pointer,b'old-pointer')
        return stage,files,owner,current,c,entries,pointer

    def test_publish_then_pointer_keeps_native_structure_and_historical_owner(self):
        stage,files,owner,current,c,entries,pointer=self.fixture();before=Path(owner['journalFile']).read_bytes();events=[]
        def verify():
            self.assertEqual(b'old-pointer',pointer.read_bytes());self.assertEqual(0,self.cli(stage,files).returncode)
            for e in entries:self.assertEqual(e['new'],e['path'].read_bytes())
            events.append('verified')
        m.publish(c,entries,lambda:events.append('reload'),verify)
        self.assertEqual(['reload','verified'],events)
        m.replace(c,pointer,b'old-pointer',b'new-pointer');self.assertEqual(b'new-pointer',pointer.read_bytes())
        self.assertEqual(before,Path(owner['journalFile']).read_bytes())
        self.assertEqual(current,self.core.semantic_provider_lease_nft.structure_hash(self.coordinator.owner.backend.tables()))

    def test_foreign_unit_prevents_all_publication_and_preserves_pointer(self):
        stage,files,owner,current,c,entries,pointer=self.fixture()
        m.replace(c,entries[1]['path'],entries[1]['old'],b'foreign')
        with self.assertRaisesRegex(RuntimeError,'PUBLICATION_INPUT_CHANGED'):
            m.publish(c,entries,lambda:self.fail('reload'),lambda:self.fail('verify'))
        self.assertEqual(entries[0]['old'],entries[0]['path'].read_bytes());self.assertEqual(b'foreign',entries[1]['path'].read_bytes())
        self.assertEqual(b'old-pointer',pointer.read_bytes());self.assertEqual(0,self.cli(stage,files).returncode)

    def test_failed_loaded_verification_keeps_pointer_old_and_partial_files(self):
        stage,files,owner,current,c,entries,pointer=self.fixture()
        def failed():raise RuntimeError('LOADED_READBACK_FAILED')
        with self.assertRaisesRegex(RuntimeError,'LOADED_READBACK_FAILED'):m.publish(c,entries,lambda:None,failed)
        self.assertEqual(b'old-pointer',pointer.read_bytes())
        for e in entries:self.assertEqual(e['new'],e['path'].read_bytes())
        self.assertEqual(0,self.cli(stage,files).returncode)


if __name__=='__main__':unittest.main(verbosity=2)
