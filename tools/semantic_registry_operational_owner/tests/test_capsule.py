"""Source declaration and immutable legacy dependency packaging, no execution."""
import ast
import base64
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('operational_capsule_builder',ROOT/'scripts/build-registry-operational-owner-capsule.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)


class Capsule(unittest.TestCase):
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
