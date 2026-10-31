"""Operator dispatch/redaction units, not native recovery qualification."""
import ast
import hashlib
import json
from pathlib import Path
import types
import unittest
from unittest.mock import Mock

SOURCE = Path(__file__).resolve().parents[1] / 'postboot_entry.py'


def subject():
    tree = ast.parse(SOURCE.read_text())
    tree.body = [n for n in tree.body if not isinstance(n, ast.ImportFrom)
                 or not (n.level or n.module == 'file_only_profile')]
    module = types.ModuleType('entry_units')
    def require(ok, reason):
        if not ok:
            raise RuntimeError(reason)
    def encoded(v):
        return json.dumps(v, sort_keys=True, separators=(',', ':')).encode()
    module.__dict__.update(require=require, encoded=encoded,
        digest=lambda v: hashlib.sha256(encoded(v)).hexdigest(),
        hashed=lambda v: type(v) is str and len(v) == 64 and set(v) <= set('0123456789abcdef'))
    exec(compile(tree, str(SOURCE), 'exec'), module.__dict__)
    return module


class EntryUnits(unittest.TestCase):
    def setUp(self):
        self.m = subject(); self.root = Path('/exact/prepared')
        self.case = {'schema': self.m.SCHEMA, 'preparation': {'fixed': 'fixture'}}
        self.proof = {'sourceClosureHash': 'a'*64, 'engineGets': 12, 'adminGets': 1,
            'frozenConfigurationGets': 1, 'originalServiceBearerUsed': True}
        self.prepared = {'privatePreparationPath': str(self.root / 'prepared.json'),
            'privatePreparationHash': 'b'*64, 'preparationProof': self.proof,
            'nativeContext': {'private': 'NOT-PUBLIC'}, 'ownerContext': {'credential': 'NOT-PUBLIC'}}
        self.preparer = types.SimpleNamespace(prepared_root=Mock(return_value=self.root),
            read_prepared=Mock(return_value=self.prepared), prepare=Mock(return_value=self.prepared))
        self.m.postboot_prepare = self.preparer
        self.authority = types.SimpleNamespace(issue=Mock(return_value={'issued': True}),
            load_runtime=Mock(return_value=('gate', b'raw', 'verifier', 'signer')))
        self.m.postboot_authority = self.authority
        self.controllers = types.SimpleNamespace(bootstrap_gate=Mock(return_value={'gate': True}),
            install_owner=Mock(return_value={'owner': True}), continue_recovery=Mock(return_value={'finite': True}))
        self.m.postboot_controller = self.controllers
        self.m.review_binding = Mock(return_value=({}, {'path': str(self.root / 'review.json'), 'sha256': 'c'*64}))
        self.manifest, self.sources = {'closure': 'fixture'}, {'module': b'fixture'}

    def execute(self, argv):
        return self.m.execute(self.case, self.manifest, self.sources, argv)

    def test_prepare_projects_no_private_context_or_credentials(self):
        result = self.execute(['prepare'])
        self.assertEqual(result['engineGets'], 12)
        self.assertNotIn('NOT-PUBLIC', json.dumps(result))
        self.assertFalse(result['targetApplyAuthorized'])
        self.assertFalse(result['serviceReadinessEstablished'])
        self.preparer.read_prepared.assert_not_called()
        self.authority.issue.assert_not_called()
        self.authority.load_runtime.assert_not_called()

    def test_no_default_arbitrary_mode_or_path(self):
        for argv in ([], ['recover'], ['prepare', '/tmp/replacement'], ['issue'],
                     ['issue', 'c'*64, 'extra'], ['continue', '/tmp/authority.json']):
            with self.subTest(argv=argv), self.assertRaises(RuntimeError):
                self.execute(argv)
        self.preparer.prepare.assert_not_called()
        self.authority.load_runtime.assert_not_called()

    def test_changed_review_hash_stops_before_issuer_or_runtime(self):
        for mode in self.m.SIGNED_MODES:
            with self.subTest(mode=mode), self.assertRaisesRegex(RuntimeError, 'EXPLICIT_PUBLISHED'):
                self.execute([mode, 'd'*64])
        self.authority.issue.assert_not_called()
        self.authority.load_runtime.assert_not_called()

    def test_issue_does_not_dispatch_lifecycle(self):
        self.assertEqual(self.execute(['issue', 'c'*64]), {'issued': True})
        self.authority.issue.assert_called_once()
        self.authority.load_runtime.assert_not_called()
        for fn in vars(self.controllers).values():
            fn.assert_not_called()

    def test_each_explicit_runtime_mode_dispatches_only_its_owner(self):
        expected = {'bootstrap': 'bootstrap_gate', 'owner': 'install_owner', 'continue': 'continue_recovery'}
        for mode, name in expected.items():
            for fn in vars(self.controllers).values():
                fn.reset_mock()
            self.execute([mode, 'c'*64])
            for key, fn in vars(self.controllers).items():
                self.assertEqual(fn.call_count, int(key == name))
        self.controllers.continue_recovery.assert_called_with(self.prepared['nativeContext'],
            self.prepared['ownerContext'], 'gate', b'raw', 'verifier', 'signer', self.m.emit)

    def test_prepared_path_cannot_switch(self):
        self.prepared['privatePreparationPath'] = '/different/prepared.json'
        with self.assertRaisesRegex(RuntimeError, 'SAME_DETERMINISTIC'):
            self.execute(['issue', 'c'*64])
        self.authority.issue.assert_not_called()


if __name__ == '__main__':
    unittest.main()
