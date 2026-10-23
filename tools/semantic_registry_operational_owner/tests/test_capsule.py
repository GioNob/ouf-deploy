"""Source declaration and immutable legacy dependency packaging, no execution."""
import ast
import base64
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
import tempfile

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('operational_capsule_builder',ROOT/'scripts/build-registry-operational-owner-capsule.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)


class Capsule(unittest.TestCase):
    def reader(self):
        import stat
        nodes=[n for n in ast.parse(builder.BOOTSTRAP).body if isinstance(n,ast.FunctionDef)]
        namespace={'os':os,'stat':stat,'hashlib':hashlib}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'bootstrap-reader-fixture','exec'),namespace)
        return namespace['bound_input']

    def test_rebinding_reads_only_root_owned_exact_bounded_metadata(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path=Path(directory)/'inputs.json';path.write_bytes(b'{"fixture":true}');path.chmod(0o400)
            raw=path.read_bytes();reader=self.reader()
            self.assertEqual(reader(str(path),1024,hashlib.sha256(raw).hexdigest()),raw)
            with self.assertRaisesRegex(ValueError,'INPUT_OR_HASH_CHANGED'):reader(str(path),1024,'f'*64)
            with self.assertRaisesRegex(ValueError,'CUSTODIED_BOOTSTRAP_INPUT'):reader(str(path),1,hashlib.sha256(raw).hexdigest())

    def test_rebinding_rejects_symlink_or_writable_parent_without_execution(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root=Path(directory);path=root/'inputs.json';path.write_bytes(b'{}');path.chmod(0o400)
            link=root/'link';link.symlink_to(path);reader=self.reader();expected=hashlib.sha256(b'{}').hexdigest()
            with self.assertRaises(OSError):reader(str(link),1024,expected)
            root.chmod(0o777)
            with self.assertRaisesRegex(ValueError,'ROOT_BOOTSTRAP_INPUT_ANCESTRY'):reader(str(path),1024,expected)
            root.chmod(0o700)

    def test_reproducible_capsule_binds_all_eight_sources_and_unchanged_142_dependencies(self):
        raw,delivery=builder.build('a'*40)
        self.assertEqual(builder.build('a'*40),(raw,delivery))
        values={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(raw).body
                if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
        self.assertEqual(hashlib.sha256(values['BOOTSTRAP'].encode()).hexdigest(),delivery['sourceManifest']['bootstrapHash'])
        payload=gzip.decompress(base64.b64decode(values['PACKED'],validate=True))
        self.assertEqual(hashlib.sha256(payload).hexdigest(),delivery['payloadHash'])
        parsed=json.loads(payload);self.assertEqual(len(parsed['dependency']['sources']),142)
        self.assertEqual(len(parsed['sources']),8)
        for name,value in parsed['sources'].items():
            self.assertEqual(hashlib.sha256(value.encode()).hexdigest(),delivery['sourceManifest']['sourceHashes'][name])
        for name,value in parsed['dependency']['sources'].items():
            self.assertEqual(hashlib.sha256(value.encode()).hexdigest(),delivery['dependencyDeclaration']['sourceHashes'][name])


if __name__=='__main__':unittest.main()
