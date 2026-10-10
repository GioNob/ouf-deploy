import hashlib,io,json,tarfile,tempfile,unittest
from pathlib import Path
import candidate_roots as roots
class Archive(unittest.TestCase):
    def archive(self,d,whiteout=False,private_link=False):
        layer=io.BytesIO()
        with tarfile.open(fileobj=layer,mode='w') as t:
            i=tarfile.TarInfo('etc/ssl/certs/java/cacerts');v=b'public-baseline-store';i.size=len(v);t.addfile(i,io.BytesIO(v))
            i=tarfile.TarInfo('opt/java/openjdk/lib/security/cacerts');i.type=tarfile.SYMTYPE;i.linkname='/etc/private.key' if private_link else '/etc/ssl/certs/java/cacerts';t.addfile(i)
            if whiteout:t.addfile(tarfile.TarInfo('etc/ssl/certs/java/.wh.cacerts'))
        config=json.dumps({'config':{'Env':['JAVA_HOME=/opt/java/openjdk']}}).encode();identity='sha256:'+hashlib.sha256(config).hexdigest();p=Path(d)/'image.tar.gz'
        with tarfile.open(p,mode='w:gz') as t:
            for name,v in [('config.json',config),('layer.tar',layer.getvalue()),('manifest.json',json.dumps([{'Config':'config.json','Layers':['layer.tar']}]).encode())]:
                i=tarfile.TarInfo(name);i.size=len(v);t.addfile(i,io.BytesIO(v))
        return p,hashlib.sha256(p.read_bytes()).hexdigest(),identity
    def test_exact_archive_config_and_public_store_link(self):
        with tempfile.TemporaryDirectory() as d:
            p,h,i=self.archive(d);raw,receipt=roots.roots(p,h,i);self.assertEqual(raw,b'public-baseline-store');self.assertEqual(receipt['sourcePath'],'etc/ssl/certs/java/cacerts')
    def test_archive_or_image_tamper_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p,h,i=self.archive(d)
            for digest,image in [('0'*64,i),(h,'sha256:'+'0'*64)]:
                with self.assertRaises(ValueError):roots.roots(p,digest,image)
    def test_final_whiteout_cannot_return_older_store(self):
        with tempfile.TemporaryDirectory() as d:
            p,h,i=self.archive(d,whiteout=True)
            with self.assertRaises(ValueError):roots.roots(p,h,i)
    def test_link_cannot_select_a_private_or_unbound_file(self):
        with tempfile.TemporaryDirectory() as d:
            p,h,i=self.archive(d,private_link=True)
            with self.assertRaises(ValueError):roots.roots(p,h,i)
if __name__=='__main__':unittest.main()
