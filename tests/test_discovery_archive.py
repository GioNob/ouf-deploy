import ast
import gzip
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path("verification-source").resolve()))
from tools import verify_semantic_image_archive as archive

node = next(n for n in ast.parse(Path("scripts/scan-discovery-candidate.py").read_text()).body
            if isinstance(n, ast.FunctionDef) and n.name == "verify_general_image")
scope = dict(archive=archive, gzip=gzip, hashlib=hashlib, tarfile=tarfile)
exec(compile(ast.Module(body=[node], type_ignores=[]), "archive-verifier", "exec"), scope)
verify = scope["verify_general_image"]

def fixture(path, *, compressed=False, bad_diff=False, bad_path=False, oci=False):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as layer:
        data = b"a" * 200000
        entry = tarfile.TarInfo("var/lib/dpkg/status")
        entry.size = len(data)
        layer.addfile(entry, io.BytesIO(data))
    raw = buffer.getvalue()
    stored = gzip.compress(raw, mtime=0) if compressed else raw
    diff = "sha256:" + hashlib.sha256(raw).hexdigest()
    if bad_diff:
        diff = "sha256:" + "0" * 64
    config = json.dumps({"os":"linux", "architecture":"amd64", "rootfs":{"type":"layers", "diff_ids":[diff]}}).encode()
    sha = hashlib.sha256(config).hexdigest()
    config_name = "blobs/sha256/" + sha if oci else sha + ".json"
    layer_name = "blobs/sha256/" + hashlib.sha256(stored).hexdigest() if oci else "layer.tar"
    manifest = json.dumps([{"Config":config_name, "Layers":[layer_name]}]).encode()
    files = [(config_name,config), (layer_name,stored), ("manifest.json",manifest)]
    identity = "sha256:" + sha
    if oci:
        document = {"schemaVersion":2, "mediaType":"application/vnd.oci.image.manifest.v1+json",
                    "config":{"mediaType":"application/vnd.oci.image.config.v1+json", "digest":"sha256:"+sha, "size":len(config)},
                    "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip" if compressed else "application/vnd.oci.image.layer.v1.tar",
                               "digest":"sha256:"+hashlib.sha256(stored).hexdigest(), "size":len(stored)}]}
        payload = json.dumps(document).encode()
        identity = "sha256:" + hashlib.sha256(payload).hexdigest()
        files.append(("blobs/sha256/" + identity[7:],payload))
    if bad_path:
        files.append(("../escape",b"x"))
    with tarfile.open(path, "w") as bundle:
        for name, data in files:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            bundle.addfile(entry, io.BytesIO(data))
    return identity

class ArchiveChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "image.tar"

    def test_large_package_metadata_raw_and_gzip(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                identity = fixture(self.path, compressed=compressed)
                self.assertEqual(verify(self.path,identity)["imageIdentityBindingKind"],"CONFIG")

    def test_oci_manifest_identity_is_bound_to_config_and_layers(self):
        identity = fixture(self.path, compressed=True, oci=True)
        self.assertEqual(verify(self.path,identity)["imageIdentityBindingKind"],"MANIFEST")

    def test_changed_layer_is_rejected(self):
        identity = fixture(self.path, bad_diff=True)
        with self.assertRaises((AssertionError,archive.Blocked)):
            verify(self.path,identity)

    def test_path_escape_is_rejected(self):
        identity = fixture(self.path, bad_path=True)
        with self.assertRaises((AssertionError,archive.Blocked)):
            verify(self.path,identity)

    def test_wrong_image_identity_is_rejected(self):
        fixture(self.path)
        with self.assertRaises((AssertionError,archive.Blocked)):
            verify(self.path,"sha256:"+"1"*64)
