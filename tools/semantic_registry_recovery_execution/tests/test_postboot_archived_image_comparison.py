"""Real tar/layer hashing and protected file IO; no Docker or extraction."""
import ast
import copy
import hashlib
import gzip
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch
import test_postboot_root_binding_metadata as f

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('archived_image_comparison',ROOT/'scripts/compare-registry-archived-image-20261023.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
REAL_PRIMITIVE=m.image_primitive


def primitive():
    raw=(ROOT/'releases/semantic-registry-postboot-byte-20261023.py').read_bytes()
    values={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(raw).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
    return REAL_PRIMITIVE(values)


def layer(rows):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w') as tar:
        for name,kind,data in rows:
            row=tarfile.TarInfo(name);row.mode=0o755 if kind=='dir' else 0o644
            if kind=='file':row.size=len(data);tar.addfile(row,io.BytesIO(data))
            else:
                row.type={'dir':tarfile.DIRTYPE,'link':tarfile.LNKTYPE,'sym':tarfile.SYMTYPE}[kind]
                if kind in ('link','sym'):row.linkname=data
                tar.addfile(row)
    return output.getvalue()


def image(layers):
    source='c'*40
    config=json.dumps({'os':'linux','architecture':'amd64','config':{'Labels':{'org.opencontainers.image.revision':source}},
        'rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(gzip.decompress(v) if v.startswith(b'\x1f\x8b') else v).hexdigest() for v in layers]}},sort_keys=True).encode()
    config_hash=hashlib.sha256(config).hexdigest();names=[str(n)+'/layer.tar' for n in range(len(layers))]
    manifest=json.dumps([{'Config':config_hash+'.json','RepoTags':None,'Layers':names}]).encode()
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w') as tar:
        for name,data in [('manifest.json',manifest),(config_hash+'.json',config),*zip(names,layers)]:
            row=tarfile.TarInfo(name);row.size=len(data);tar.addfile(row,io.BytesIO(data))
    raw=output.getvalue();audit=primitive()(io.BytesIO(raw),hashlib.sha256(raw).hexdigest(),'sha256:'+config_hash,source)
    return raw,audit


class Archive(unittest.TestCase):
    def test_real_sealed_archive_primitive_and_layers_match_exact_content_without_extract(self):
        raw,audit=image([layer([('app','file',b'payload'),('run','dir',b'')])])
        with patch.object(tarfile.TarFile,'extract',side_effect=AssertionError('no extract')),patch.object(tarfile.TarFile,'extractall',side_effect=AssertionError('no extract')):
            rows,reports=m.namespace(m.Counted(io.BytesIO(raw),m.Work()),audit,m.Work())
        observed=[{'path':p,**v} for p,v in rows.items()]
        observed.extend({'path':'extra'+str(n),'kind':'directory','mode':0o755,'uid':0,'gid':0} for n in range(6))
        result=m.compare(rows,observed)
        self.assertEqual(len(result['extraEntries']),6);self.assertEqual(result['differences'],[]);self.assertEqual(result['missingEntries'],[])
        self.assertFalse(result['xattrsCompared']);self.assertFalse(result['nlinkCompared'])
        observed[0]['sha256']='0'*64
        self.assertIn('sha256',m.compare(rows,observed)['differences'][0]['fields'])

    def test_compressed_layer_actual_byte_audit_and_streaming_content(self):
        raw,audit=image([gzip.compress(layer([('app','file',b'compressed payload')]),mtime=0)])
        work=m.Work();rows,_=m.namespace(m.Counted(io.BytesIO(raw),work),audit,work)
        self.assertEqual(rows['app']['sha256'],hashlib.sha256(b'compressed payload').hexdigest())
        self.assertGreater(work.readBytes,0)

    def test_whiteouts_opaque_and_same_layer_entries_preserved_regardless_marker_order(self):
        raw,audit=image([layer([('old','file',b'old'),('dir','dir',b''),('dir/old','file',b'x')]),
            layer([('dir/new','file',b'new'),('dir/.wh..wh..opq','file',b''),('.wh.old','file',b'')])])
        rows,_=m.namespace(io.BytesIO(raw),audit,m.Work())
        self.assertNotIn('old',rows);self.assertNotIn('dir/old',rows);self.assertEqual(rows['dir/new']['size'],3)
        raw,audit=image([layer([('old','file',b'old')]),layer([('.wh..wh..opq','file',b''),('new','file',b'new')])])
        rows,_=m.namespace(io.BytesIO(raw),audit,m.Work());self.assertNotIn('old',rows);self.assertIn('new',rows)

    def test_ordered_hardlink_content_survives_later_target_overwrite_metadata_marked_unproven(self):
        raw,audit=image([layer([('a','file',b'old'),('b','link','a'),('a','file',b'new')])])
        rows,_=m.namespace(io.BytesIO(raw),audit,m.Work())
        self.assertEqual(rows['b']['sha256'],hashlib.sha256(b'old').hexdigest())
        self.assertEqual(rows['a']['sha256'],hashlib.sha256(b'new').hexdigest())
        self.assertTrue(rows['b']['hardlinkMetadataUnproven'])

    def test_parent_symlink_forward_link_and_path_escape_are_not_silently_interpreted(self):
        for data,reason in [([('a','sym','elsewhere'),('a/file','file',b'x')],'LAYER_PARENT_SYMLINK'),
            ([('b','link','not-yet')],'FORWARD_OR_NONFILE_HARDLINK'),([('../escape','file',b'x')],'SAFE_CANONICAL_LAYER_PATH')]:
            raw,audit=image([layer(data)])
            with self.assertRaisesRegex(ValueError,reason):m.namespace(io.BytesIO(raw),audit,m.Work())

    def test_archive_read_time_and_pax_metadata_bounds(self):
        work=m.Work();work.until=-1
        with self.assertRaisesRegex(ValueError,'ARCHIVE_COMPARISON_DEADLINE'):m.Counted(io.BytesIO(b'x'),work).read(1)
        with patch.object(m,'MAX_READ_BYTES',1),self.assertRaisesRegex(ValueError,'ARCHIVE_READ_BYTE_BUDGET'):
            m.Counted(io.BytesIO(b'xx'),m.Work()).read(2)
        info=m.BoundedTarInfo('pax');info.size=1048577
        with self.assertRaisesRegex(ValueError,'BOUNDED_LAYER_PAX_METADATA_REQUIRED'):info._proc_pax(None)


class Metadata(unittest.TestCase):
    write=f.RootBinding.write
    refresh=f.RootBinding.refresh
    def setUp(self):
        f.RootBinding.setUp(self)
        self.raw,self.audit=image([layer([('app','file',b'payload')])]);self.archive=self.root/'semantic.tagless.tar';self.archive.write_bytes(self.raw);self.archive.chmod(0o600)
        prepared=json.loads((self.prep/'prepared.json').read_bytes())
        prepared['registryInputs']['imageAudit']=self.audit
        prepared['nativeContext']['nodeRecipe']['imageConfigurationHash']=self.audit['configSha256']
        registry=copy.deepcopy(prepared['registryInputs'])
        original={'registry':registry,'imagePlan':{'images':[{'module':'semantic','archivePath':str(self.archive),'audit':self.audit}]}}
        bundle={'prepared':original};bundle_path=self.root/'bundle.json';self.write(bundle_path,bundle)
        historical={'scopes':{'finiteActionProcess':{'bundle':{'path':str(bundle_path),'sha256':self.b.digest(bundle)}}},
            'privateInputHashes':{'preparedInputs':self.b.digest(original)}}
        hist=self.root/'historical.json';self.write(hist,historical)
        case={'preparation':{'historicalReview':{'path':str(hist),'sha256':self.b.digest(historical)},'lineageReceipt':{'historicalBundleHash':self.b.digest(bundle)}}}
        cap=Path(self.b.CAPSULE);values={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(cap.read_bytes()).body if isinstance(n,ast.Assign)}
        values['CASE']=case;values['DELIVERY']['caseHash']=self.b.digest(case);values['DELIVERY_HASH']=self.b.digest(values['DELIVERY'])
        cap.write_text(''.join(k+'='+repr(v)+'\n' for k,v in values.items()));cap.chmod(0o600)
        self.write(self.prep/'prepared.json',prepared)
        review=json.loads((self.prep/'review.json').read_bytes());review['currentContext']=prepared['nativeContext'];self.write(self.prep/'review.json',review)
        receipt=json.loads((self.prep/'authority/receipt.json').read_bytes());receipt['reviewHash']=self.b.digest(review);self.write(self.prep/'authority/receipt.json',receipt)
        manifest={'authorityHash':self.b.AUTHORITY_HASH,'expectedRootfsSeal':prepared['nativeContext']['nodeRecipe']['expectedRootfsSeal'],
            'entries':[{'path':'app','kind':'file','mode':0o644,'uid':0,'gid':0,'size':7,'sha256':hashlib.sha256(b'payload').hexdigest()}]}
        root=self.root/'complete';root.mkdir();self.write(root/'rootfs-manifest.json',manifest)
        analysis={'searchComplete':True,'matchingVariants':[],'testedVariants':226}
        aroot=self.root/'analysis';aroot.mkdir();self.write(aroot/'analysis.json',analysis)
        for name,value in {'PREPARATION_HASH':self.b.digest(prepared),'REVIEW_HASH':self.b.digest(review),
            'CAPSULE_HASH':hashlib.sha256(cap.read_bytes()).hexdigest(),'DECLARATION_HASH':self.b.digest(values['DELIVERY'])}.items():
            p=patch.object(self.b,name,value);p.start();self.addCleanup(p.stop)
        real=Path
        for name,value in {'base_module':lambda:self.b,'MANIFEST_ROOT':'complete','MANIFEST_HASH':self.b.digest(manifest),
            'ANALYSIS_ROOT':'analysis','ANALYSIS_HASH':self.b.digest(analysis),
            'image_primitive':lambda values:primitive(), # Actual137source extraction tested independently above; metadata capsule fixture is explicit.
            'Path':lambda v:self.bootfile if v=='/proc/sys/kernel/random/boot_id' else real(v)}.items():
            p=patch.object(m,name,value);p.start();self.addCleanup(p.stop)

    def test_exact_retained_chain_real_archive_and_private_comparison_no_runtime_or_replay(self):
        paths=list(self.root.rglob('*.json'))+[self.archive];before={p:p.read_bytes() for p in paths}
        v=m.inspect();self.assertEqual(v['status'],'ARCHIVED_IMAGE_COMPARED');self.assertEqual(v['engineGets'],0)
        self.assertEqual(v['contentDifferenceCount'],0);self.assertEqual(v['extraEntryCount'],0)
        self.assertTrue(v['archiveBytesReaudited']);self.assertTrue(v['layerBytesReaudited']);self.assertFalse(v['nativeSealEqualityProven'])
        self.assertEqual(self.calls,[]);self.assertEqual(before,{p:p.read_bytes() for p in paths})
        path=Path(v['privateComparisonPath']);self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),v['privateComparisonHash'])
        self.assertNotIn(str(self.archive),json.dumps(v))
        with self.assertRaisesRegex(ValueError,'ARCHIVE_COMPARISON_ALREADY_CONSUMED'):m.inspect()

    def test_archive_tamper_refused_without_docker(self):
        raw=bytearray(self.raw);raw[7000]^=1;self.archive.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'AUTHENTICATED_ARCHIVE_BYTES_CHANGED'):m.inspect()
        self.assertEqual(self.calls,[])


if __name__=='__main__':unittest.main()
