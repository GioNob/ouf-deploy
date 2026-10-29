"""Bounded archive provenance checks without extraction or runtime calls."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from prepare_provider_image_rootfs import Budget,Denied,spool_stream,verify_layout,OCI_MANIFEST,OCI_CONFIG,DOCKER_MANIFEST,DOCKER_CONFIG,DOCKER_LAYER

def digest(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def image_fixture(changed_diff=False,extra=None,docker=False):
    plain=io.BytesIO()
    with tarfile.open(fileobj=plain,mode='w') as archive:
        entry=tarfile.TarInfo('data');entry.size=4;archive.addfile(entry,io.BytesIO(b'good'))
    layer=plain.getvalue();compressed=gzip.compress(layer,mtime=0)
    config=encoded({'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':[digest(b'wrong') if changed_diff else digest(layer)]},'config':{}})
    manifest=encoded({'schemaVersion':2,'mediaType':DOCKER_MANIFEST if docker else OCI_MANIFEST,'config':{'mediaType':DOCKER_CONFIG if docker else OCI_CONFIG,'digest':digest(config),'size':len(config)},
        'layers':[{'mediaType':DOCKER_LAYER if docker else 'application/vnd.oci.image.layer.v1.tar+gzip','digest':digest(compressed),'size':len(compressed)}]})
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w') as archive:
        values={'oci-layout':encoded({'imageLayoutVersion':'1.0.0'})}
        values.update({'blobs/sha256/'+digest(raw)[7:]:raw for raw in (compressed,config,manifest)})
        for name,raw in values.items():
            item=tarfile.TarInfo(name);item.size=len(raw);archive.addfile(item,io.BytesIO(raw))
        if extra:
            item=tarfile.TarInfo(extra[0]);item.type=extra[1];item.linkname='/etc/passwd';archive.addfile(item)
    return gzip.compress(stream.getvalue(),mtime=0),digest(manifest),digest(config)

class ArchiveTest(unittest.TestCase):
    def inspect(self,raw,manifest,config):
        with tempfile.TemporaryDirectory() as directory:
            layout=Path(directory)/'layout';budget=Budget();blobs=spool_stream(io.BytesIO(raw),layout,budget)
            return verify_layout(layout,manifest,config,blobs,budget)
    def test_valid_ordered_content_and_diff_ids(self):
        self.assertEqual(len(self.inspect(*image_fixture())),1)
    def test_docker_descriptor_view_retains_original_content(self):
        raw,manifest,config=image_fixture(docker=True)
        with tempfile.TemporaryDirectory() as directory:
            layout=Path(directory)/'layout';budget=Budget();blobs=spool_stream(io.BytesIO(raw),layout,budget)
            original=(layout/'blobs/sha256'/manifest[7:]).read_bytes()
            self.assertEqual(len(verify_layout(layout,manifest,config,blobs,budget)),1)
            self.assertEqual((layout/'blobs/sha256'/manifest[7:]).read_bytes(),original)
            view_digest=json.loads((layout/'index.json').read_bytes())['manifests'][0]['digest']
            view=json.loads((layout/'blobs/sha256'/view_digest[7:]).read_bytes())
            self.assertNotEqual(view_digest,manifest);self.assertEqual(view['config']['digest'],config)
            self.assertEqual(view['layers'][0]['digest'],json.loads(original)['layers'][0]['digest'])
    def test_rejects_config_substitution(self):
        raw,manifest,config=image_fixture()
        with self.assertRaisesRegex(Denied,'OCI_CONFIG_BINDING_DRIFT'):self.inspect(raw,manifest,'sha256:'+'0'*64)
    def test_rejects_wrong_uncompressed_layer_hash(self):
        with self.assertRaisesRegex(Denied,'OCI_LAYER_DIFF_ID_DRIFT'):self.inspect(*image_fixture(changed_diff=True))
    def test_rejects_outer_symlink(self):
        with self.assertRaisesRegex(Denied,'OUTER_ARCHIVE_ENTRY_DENIED'):self.inspect(*image_fixture(extra=('link',tarfile.SYMTYPE)))
    def test_rejects_parent_traversal(self):
        with self.assertRaisesRegex(Denied,'ARCHIVE_PATH_REQUIRED'):self.inspect(*image_fixture(extra=('../escape',tarfile.REGTYPE)))
    def test_rejects_duplicate_blob(self):
        raw,manifest,config=image_fixture()
        contents=gzip.decompress(raw);rows=[]
        with tarfile.open(fileobj=io.BytesIO(contents)) as source:
            for item in source:rows.append((item,source.extractfile(item).read()))
        duplicate=io.BytesIO()
        with tarfile.open(fileobj=duplicate,mode='w') as target:
            for item,data in rows+[rows[-1]]:target.addfile(item,io.BytesIO(data))
        with self.assertRaisesRegex(Denied,'DUPLICATE_ARCHIVE_ENTRY'):self.inspect(gzip.compress(duplicate.getvalue()),manifest,config)
if __name__=='__main__':unittest.main()
