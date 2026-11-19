import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('boot_activation', ROOT/'scripts/activate-discovery-coordinator-boot-20261109.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def metadata(command):
    result = {}
    for unit in ('ouf-semantic-boot-guard.service','docker.service'):
        row = dict.fromkeys(m.PROPERTIES, '')
        row.update(LoadState='loaded',ActiveState='active',SubState='exited',MainPID='0',ControlPID='0',
                   NeedDaemonReload='no',PrivateNetwork='no',PrivateUsers='no',ProtectSystem='strict',ReadWritePaths='/etc/ouf')
        prop = 'ExecStart' if unit.startswith('ouf-') else 'ExecStartPre'
        row[prop] = '{ path=/usr/bin/python3 ; argv[]='+command+' ; ignore_errors=no ; }'
        if unit == 'docker.service':
            row.update(SubState='running',MainPID='333',DropInPaths=str(m.UNITS['docker-drop-in.conf']))
        else: row['FragmentPath'] = str(m.UNITS['guard.service'])
        result[unit] = row
    return result


def loader(rows):
    return lambda args: '\n'.join(k+'='+v for k,v in rows[args[1]].items())+'\n'


class BootActivation(unittest.TestCase):
    def test_continuation_binds_exact_preserved_prepublication_hold(self):
        receipt=json.loads((ROOT/'evidence/discovery-successor-boot-held-operator-20261109.json').read_bytes())
        raw=m.encoded(receipt)+b'\n'; self.assertEqual(1195,len(raw));m.verify_prepublication_hold(raw)
        receipt['publicationAttempted']=True
        with self.assertRaisesRegex(RuntimeError,'EXACT_PREPUBLICATION_HOLD_REQUIRED'):
            m.verify_prepublication_hold(m.encoded(receipt)+b'\n')

    def test_exact_complete_staged_receipt_uses_producer_serialization(self):
        receipt = json.loads((ROOT/'evidence/discovery-coordinator-staged-operator-20261109.json').read_bytes())
        raw = m.encoded(receipt)+b'\n'; self.assertEqual(1646,len(raw)); m.verify_receipt(raw)
        receipt.pop('reviewedReceiptSha256')
        with self.assertRaisesRegex(RuntimeError,'EXACT_STAGED_RECEIPT_REQUIRED'): m.verify_receipt(m.encoded(receipt)+b'\n')

    def test_full_dependency_closure_can_load_from_installed_observer_layout(self):
        c=m.dependency(); pins=m.helper_pins(c); self.assertEqual(13,len(pins))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'helpers/core').mkdir(parents=True)
            for name,digest in pins.items():
                raw=(ROOT/'scripts'/name).read_bytes();self.assertEqual(digest,m.sha(raw));(root/'helpers'/name).write_bytes(raw)
            with patch.object(m,'__file__',str(root/'transition-source.py')):
                installed=m.dependency();self.assertEqual(pins,m.helper_pins(installed))

    def test_only_two_commands_change_with_existing_write_scope(self):
        oldcmd='/usr/bin/python3 -I -B /old/guard.py';newcmd='/usr/bin/python3 -I -B /new/guard.py'
        old={'guard.service':('[Unit]\nAfter=network.target\n[Service]\nExecStart='+oldcmd+'\nProtectSystem=strict\n').encode(),
             'docker-drop-in.conf':('[Service]\nExecStartPre='+oldcmd+'\n').encode()}
        before=copy.deepcopy(old);new,added=m.unit_plan(old,oldcmd,newcmd,metadata(oldcmd))
        self.assertFalse(added);self.assertEqual(before,old)
        for key in old:self.assertEqual(old[key],new[key].replace(newcmd.encode(),oldcmd.encode()))

    def test_strict_sandbox_gets_only_exact_successor_directory(self):
        rows=metadata('old');rows['ouf-semantic-boot-guard.service']['ReadWritePaths']='/run/ouf /old'
        old={'guard.service':b'[Service]\nExecStart=old\nProtectSystem=strict\n','docker-drop-in.conf':b'[Service]\nExecStartPre=old\n'}
        new,added=m.unit_plan(old,'old','new',rows);self.assertTrue(added)
        self.assertIn(('ReadWritePaths='+str(m.STAGED)+'\n').encode(),new['guard.service'])
        after=copy.deepcopy(rows);after['ouf-semantic-boot-guard.service']['ReadWritePaths']+=' '+str(m.STAGED)
        m.verify_loaded_delta(rows,after,'new',True)
        after['ouf-semantic-boot-guard.service']['ReadWritePaths']+=' /'
        with self.assertRaisesRegex(RuntimeError,'BOOT_WRITE_SCOPE_CHANGED'):m.verify_loaded_delta(rows,after,'new',True)

    def test_duplicate_commands_and_inaccessible_stage_refused(self):
        with self.assertRaisesRegex(RuntimeError,'EXACT_PREVIOUS_UNIT_COMMAND_REQUIRED'):
            m.rewrite(b'[Service]\nExecStart=old\nExecStart=foreign\n','ExecStart','old','new')
        rows=metadata('old');rows['ouf-semantic-boot-guard.service']['InaccessiblePaths']='/etc/ouf'
        with self.assertRaisesRegex(RuntimeError,'STAGED_BOOT_PATH_INACCESSIBLE'):
            m.unit_plan({'guard.service':b'[Service]\nExecStart=old\n','docker-drop-in.conf':b'ExecStartPre=old\n'},'old','new',rows)

    def test_loaded_commands_are_exact_not_substring_matches(self):
        rows=metadata('exact');self.assertEqual(rows,m.loaded('exact',loader(rows)))
        rows['docker.service']['ExecStartPre']=rows['docker.service']['ExecStartPre'].replace('argv[]=exact','argv[]=exact --foreign')
        with self.assertRaisesRegex(RuntimeError,'EXACT_LOADED_BOOT_COMMAND_REQUIRED'):m.loaded('exact',loader(rows))

    def test_pending_reload_or_control_process_refused(self):
        for key,value in [('NeedDaemonReload','yes'),('ControlPID','123')]:
            rows=metadata('exact');rows['docker.service'][key]=value
            with self.subTest(key=key),self.assertRaisesRegex(RuntimeError,'SETTLED_LOADED_SYSTEMD_UNITS_REQUIRED'):
                m.loaded('exact',loader(rows))

    def test_observed_guard_omission_requires_typed_empty_proof(self):
        rows=metadata('exact'); del rows['ouf-semantic-boot-guard.service']['ExecStartPre']; calls=[]
        result=m.loaded('exact',loader(rows),lambda:calls.append('typed-read'))
        self.assertEqual(['typed-read'],calls)
        self.assertEqual('',result['ouf-semantic-boot-guard.service']['ExecStartPre'])
        def denied(): raise RuntimeError('EMPTY_GUARD_PRESTART_NOT_PROVEN')
        with self.assertRaisesRegex(RuntimeError,'EMPTY_GUARD_PRESTART_NOT_PROVEN'):
            m.loaded('exact',loader(rows),denied)

    def test_other_omissions_are_not_defaulted(self):
        for unit in metadata('exact'):
            for key in m.PROPERTIES:
                if unit.startswith('ouf-') and key == 'ExecStartPre': continue
                rows=metadata('exact'); del rows[unit][key]
                with self.subTest(unit=unit,key=key),self.assertRaisesRegex(RuntimeError,'SETTLED_LOADED_SYSTEMD_UNITS_REQUIRED'):
                    m.loaded('exact',loader(rows),lambda:self.fail('unexpected fallback'))

    def test_typed_empty_proof_requires_exact_signature_and_zero_elements(self):
        def call(raw, code=0):
            def fake(args, **kw):
                self.assertEqual(['/usr/bin/busctl','--system','--no-pager','get-property',
                    'org.freedesktop.systemd1',
                    '/org/freedesktop/systemd1/unit/ouf_2dsemantic_2dboot_2dguard_2eservice',
                    'org.freedesktop.systemd1.Service','ExecStartPre'],args)
                self.assertEqual(15,kw['timeout']); kw['stdout'].write(raw)
                return types.SimpleNamespace(returncode=code)
            with patch.object(m.subprocess,'run',fake): m.empty_guard_prestart()
        call(b'a(sasbttttuii) 0\n')
        for raw,code in [(b'',0),(b'as 0\n',0),(b'a(sasbttttuii) 1 "foreign"\n',0),
                         (b'a(sasbttttuii) 0\n',1),(b'a(sasbttttuii) 0\nextra\n',0)]:
            with self.subTest(raw=raw,code=code),self.assertRaisesRegex(RuntimeError,'EMPTY_GUARD_PRESTART_NOT_PROVEN'):
                call(raw,code)

    def test_prestart_proof_preserves_metadata_comparison_and_reload_denial(self):
        before=metadata('old'); after=metadata('new')
        del before['ouf-semantic-boot-guard.service']['ExecStartPre']
        del after['ouf-semantic-boot-guard.service']['ExecStartPre']
        before=m.loaded('old',loader(before),lambda:None)
        after=m.loaded('new',loader(after),lambda:None)
        m.verify_loaded_delta(before,after,'new',False)
        after['ouf-semantic-boot-guard.service']['ExecStartPre']='foreign'
        with self.assertRaisesRegex(RuntimeError,'UNRELATED_LOADED_UNIT_METADATA_CHANGED'):
            m.verify_loaded_delta(before,after,'new',False)
        rows=metadata('old'); del rows['ouf-semantic-boot-guard.service']['ExecStartPre']
        rows['ouf-semantic-boot-guard.service']['NeedDaemonReload']='yes'
        with self.assertRaisesRegex(RuntimeError,'SETTLED_LOADED_SYSTEMD_UNITS_REQUIRED'):
            m.loaded('old',loader(rows),lambda:None)

    def test_pid_and_unrelated_metadata_changes_refused(self):
        before=metadata('old');after=metadata('new');m.verify_loaded_delta(before,after,'new',False)
        after['docker.service']['MainPID']='444'
        with self.assertRaisesRegex(RuntimeError,'DOCKER_PID_CHANGED'):m.verify_loaded_delta(before,after,'new',False)
        after=metadata('new');after['docker.service']['DropInPaths']+=' /foreign.conf'
        with self.assertRaisesRegex(RuntimeError,'UNRELATED_LOADED_UNIT_METADATA_CHANGED'):m.verify_loaded_delta(before,after,'new',False)

    def test_only_systemd_read_and_reload_are_supported(self):
        for args in (['restart','docker'],['start','ouf-semantic-boot-guard.service'],['stop','docker'],['show','foreign','--property=ExecStart','--no-pager']):
            with self.subTest(args=args),self.assertRaisesRegex(RuntimeError,'BOUNDED_SYSTEMD_COMMAND_REQUIRED'):m.systemctl(args)


if __name__=='__main__':unittest.main()
