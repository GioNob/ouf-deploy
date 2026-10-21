import importlib.util
from pathlib import Path
import types
import unittest

PATH=Path(__file__).resolve().parents[1]/'scripts/read-r11-guard-diagnosis.py'
spec=importlib.util.spec_from_file_location('guard_diagnosis',PATH)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
    def test_masks_private_exception_messages_and_paths(self):
        value=m.safe_error(PermissionError(13,'private-secret','/private/secret'))
        self.assertEqual(value['errno'],13)
        self.assertEqual(value['reason'],'READ_UNPROVEN')
        self.assertNotIn('secret',str(value))

    def test_preserves_specific_check_hidden_by_outer_guard(self):
        def require(ok,code):
            if not ok:raise ValueError(code)
        entry=types.SimpleNamespace(require=require)
        reader=types.SimpleNamespace(**{n:(lambda *a,**kw:None) for n in ('private','generation','run','native_read')})
        facts=m.instrument(entry,reader)
        def guard():
            try:entry.require(False,'CURRENT_ROLE_GENERATION_CHANGED')
            except Exception:raise RuntimeError('GENERATION_CHANGED') from None
        value=m.probe(entry,reader,types.SimpleNamespace(guard=guard),False)
        self.assertEqual(value['reason'],'GENERATION_CHANGED')
        self.assertEqual(facts['check'],'CURRENT_ROLE_GENERATION_CHANGED')
        self.assertEqual(value['innerFailure']['check'],'CURRENT_ROLE_GENERATION_CHANGED')

    def test_retains_safe_operation_and_errno_for_generation_denial(self):
        def denied(*args):raise PermissionError(13,'private process')
        entry=types.SimpleNamespace(require=lambda ok,code:None)
        reader=types.SimpleNamespace(**{n:denied for n in ('private','generation','run','native_read')})
        facts=m.instrument(entry,reader)
        with self.assertRaises(PermissionError):reader.generation(123)
        self.assertEqual(facts['operation'],'generation')
        self.assertEqual(facts['errno'],13)

    def test_never_invokes_activation_or_budget_initialization(self):
        source=PATH.read_text()
        for forbidden in ('entry.apply(','.initialize(','.quiesce(','.publish(','.serve(','.step(','.create('):
            self.assertNotIn(forbidden,source)

if __name__=='__main__':unittest.main()
