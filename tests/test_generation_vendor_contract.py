import copy
import importlib.util
import json
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vendor_contract', ROOT/'tools/storage_security/generation_vendor_contract.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

class VendorContractTests(unittest.TestCase):
    def setUp(self):
        self.parent_bytes=(ROOT/'releases/seaweedfs-452-generation32-build-manifest-20261103.json').read_bytes()
        self.parent=json.loads(self.parent_bytes)
        self.graph=('\n'.join(sorted(['github.com/apache/iceberg-go/config','github.com/apache/iceberg-go/table','go.yaml.in/yaml/v3']))+'\n').encode()
        self.info='unit-fixture: go1.27.3\n\tdep\tgithub.com/apache/iceberg-go\tv0.7.0\t\n\tdep\tgo.yaml.in/yaml/v3\tv3.0.5\t\n'
        self.materials={name:c.canonical({'explicitSyntheticUnitFixture':name}) for name in c.MATERIAL_NAMES}
        self.manifest={'schema':'ouf.seaweedfs-generation-vendor-build-manifest.v1','generation':33,
            'status':'VENDOR_SOURCE_REVIEWED_BUILD_PINNED_NOT_ADMITTED','sourcePatchCount':32,'dependencyPatchCount':1,
            'orderedSourcePatches':copy.deepcopy(self.parent['orderedPatches']),
            'orderedDependencyPatches':[dict(c.DEPENDENCY_PATCH)],'parentManifestSha256':c.PARENT_MANIFEST_SHA256,
            'rootSourceGitTree':self.parent['build']['patchedSourceTree'],
            'rootLockfilesSha256':dict(self.parent['build']['rootLockfilesSha256']),
            'vendor':{'beforeTreeSha256':'1'*64,'afterTreeSha256':'2'*64,'modulesTxtSha256':'3'*64,'fileCount':1},
            'materialsSha256':{k:c.sha(v)for k,v in self.materials.items()},
            'build':{'go':'1.27.3','os':'linux','arch':'amd64','cgo':False,'tags':[],'trimpath':True,'moduleMode':'vendor',
                'binarySha256':c.sha(b'explicit synthetic unit binary'),'compiledPackagesSha256':c.sha(self.graph),
                'compiledPackages':3,'binaryDependencyModules':2,
                'binaryModuleRowsSha256':c.sha(('\n'.join(l for l in self.info.splitlines() if l.startswith('\tdep\t'))+'\n').encode())},
            'maintenance':{'status':'OPEN','technicalOwner':None,'reviewCadence':'EACH_CANDIDATE_AND_WEEKLY_WHILE_PATCH_ACTIVE'},
            'allDependenciesMaintained':False,'releaseAdmitted':False,'runtimeAuthorityIssued':False,'targetOperations':0}
        self.execution={'effectiveGOFLAGS':'','effectiveGOWORK':'off','rootCommands':[
            {'role':'build','args':['build','-mod=vendor','-trimpath','./weed']},
            {'role':'production-deps','args':['list','-mod=vendor','-deps','./weed']},
            {'role':'regression','args':['test','-mod=vendor','./weed/filer']},
            {'role':'race','args':['test','-mod=vendor','-race','./weed/util/httpdown']},
            {'role':'excluded-profile','args':['build','-mod=vendor','-tags=gcs','./weed']}],
            'goModVerifyBefore':True,'goModVerifyAfter':True,'baselineVendorFilesMatchOriginalArchives':True}
    def origins(self,identities):
        return {'moduleCount':len(identities),'moduleCacheMutated':False,'modules':[
            {'module':m,'version':v,'inputZipSha256':'a'*64,'inputGoModSha256':'b'*64,
             'inputZipH1':'h1:'+'A'*43+'=','inputGoModH1':'h1:'+'B'*43+'=',
             'checksumsDescribeOriginalInputsOnly':True}for m,v in identities]}
    def coverage(self, baseline, compiled, txt, info):
        identities=sorted(c.parse_vendor_modules(txt))
        enumeration=('vendor/modules.txt original-input enumeration; NOT binary build-info\n'+''.join('\tdep\t'+m+'\t'+v+'\t\n'for m,v in identities)).encode()
        baseline.setdefault('buildInfoSha256',c.sha(enumeration));compiled.setdefault('buildInfoSha256',c.sha(info.encode()))
        baseline.setdefault('rootGoSumSha256','c'*64);compiled.setdefault('rootGoSumSha256','c'*64)
        return c.verify_origin_coverage(baseline,compiled,txt,info,enumeration,'c'*64)
    def inventories(self):
        before={c.PATCHED_CONFIG:c.ORIGINAL_CONFIG_SHA256,'modules.txt':'a'*64,'github.com/apache/iceberg-go/LICENSE':'b'*64}
        after=dict(before);after[c.PATCHED_CONFIG]=c.PATCHED_CONFIG_SHA256
        m=copy.deepcopy(self.manifest);m['vendor']={'beforeTreeSha256':c.inventory_tree(before),'afterTreeSha256':c.inventory_tree(after),'modulesTxtSha256':'a'*64,'fileCount':3}
        origins={'filesAuthenticatedAgainstOriginalZip':2,'modulesTxtGeneratedByGo':True,'modulesTxtSha256':'a'*64,'vendorTreeSha256':c.inventory_tree(before)}
        return m,before,after,origins
    def test_separate_patch_domains_and_frozen_parent(self):
        c.validate_manifest(self.manifest,self.parent_bytes)
        self.assertEqual(self.parent['build']['patchedSourceTree'], '80632ef3a54debb04531c1913860d2f94d2b418d')
        for field,value in [('sourcePatchCount',33),('dependencyPatchCount',0),('dependencyPatchCount',True),('orderedPatches',self.parent['orderedPatches']),
                             ('rootSourceGitTree','0'*40),('parentManifestSha256','0'*64)]:
            m=copy.deepcopy(self.manifest);m[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):c.validate_manifest(m,self.parent_bytes)
    def test_source_prefix_and_dependency_patch_cannot_be_relabelled(self):
        for field in ('orderedSourcePatches','orderedDependencyPatches'):
            m=copy.deepcopy(self.manifest);m[field][0]['sha256']='0'*64
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'DOMAINS'):c.validate_manifest(m,self.parent_bytes)
    def test_missing_real_vendor_binding_denied(self):
        for field in ('beforeTreeSha256','afterTreeSha256','modulesTxtSha256'):
            m=copy.deepcopy(self.manifest);m['vendor'][field]=None
            with self.subTest(field=field),self.assertRaises(ValueError):c.validate_manifest(m,self.parent_bytes)
    def test_missing_material_and_changed_bytes_denied(self):
        c.verify_material_digests(self.manifest,self.materials)
        missing=dict(self.materials);missing.pop('baseline-vendor-origins.json')
        with self.assertRaisesRegex(ValueError,'MATERIAL_SET'):c.verify_material_digests(self.manifest,missing)
        changed=dict(self.materials);changed['compiled-module-origins.json']=b'changed'
        with self.assertRaisesRegex(ValueError,'MATERIAL_CHANGED'):c.verify_material_digests(self.manifest,changed)
    def test_vendor_build_mode_not_metadata_only(self):
        m=copy.deepcopy(self.manifest);m['build']['moduleMode']='mod'
        with self.assertRaisesRegex(ValueError,'VENDOR_BUILD_FACTS'):c.validate_manifest(m,self.parent_bytes)
        c.verify_execution(self.execution)
        for args in (['build','-mod=mod'],['build','-mod=vendor','-modfile=other.mod'],
                     ['build','-mod=vendor','-overlay=other.json'],['build','-mod=vendor','-mod=vendor']):
            e=copy.deepcopy(self.execution);e['rootCommands'][0]['args']=args
            with self.subTest(args=args),self.assertRaises(ValueError):c.verify_execution(e)
    def test_unverified_cache_or_vendor_bytes_denied(self):
        for key in ('goModVerifyBefore','goModVerifyAfter','baselineVendorFilesMatchOriginalArchives'):
            e=copy.deepcopy(self.execution);e[key]=False
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'AUTHENTIC_BASE_VENDOR'):c.verify_execution(e)
    def test_vendor_no_h1_is_valid_but_original_h1_cannot_be_forged_into_it(self):
        self.assertEqual(len(c.parse_module_rows(self.info)),2)
        bad=self.info.replace('v0.7.0\t\n','v0.7.0\th1:'+'A'*43+'=\n')
        with self.assertRaisesRegex(ValueError,'MUST_NOT_INVENT_H1'):c.parse_module_rows(bad)
    def test_replacement_and_duplicate_module_denied(self):
        with self.assertRaisesRegex(ValueError,'REPLACEMENT'):c.parse_module_rows(self.info+'\t=>\tlocal/module\t(devel)\n')
        with self.assertRaisesRegex(ValueError,'UNIQUE_VERSIONED'):c.parse_module_rows(self.info+self.info.splitlines()[1]+'\n')
    def test_all_vendor_origins_and_compiled_subset_are_distinct(self):
        binary=sorted(c.parse_module_rows(self.info));full=binary+[('gopkg.in/yaml.v3','v3.0.1')]
        txt=''.join('# '+m+' '+v+'\n## explicit\n'for m,v in full).encode()
        result=self.coverage(self.origins(full),self.origins(binary),txt,self.info)
        self.assertEqual(result['allVendorModules'],3);self.assertEqual(result['compiledModules'],2)
        with self.assertRaisesRegex(ValueError,'ALL_VENDORED'):self.coverage(self.origins(binary),self.origins(binary),txt,self.info)
        with self.assertRaisesRegex(ValueError,'EXACT_COMPILED'):self.coverage(self.origins(full),self.origins(binary[:1]),txt,self.info)
    def test_divergent_input_checksum_between_vendor_and_binary_denied(self):
        ids=sorted(c.parse_module_rows(self.info));txt=''.join('# '+m+' '+v+'\n'for m,v in ids).encode()
        a=self.origins(ids);b=self.origins(ids);b['modules'][0]['inputZipSha256']='c'*64
        with self.assertRaisesRegex(ValueError,'ORIGIN_DIVERGENCE'):self.coverage(a,b,txt,self.info)
    def test_legacy_yaml_and_previous_compiled_exclusions_denied(self):
        c.verify_compiled(self.manifest,self.parent,self.graph,self.info)
        for module in ('gopkg.in/yaml.v3','go.opencensus.io','go.mongodb.org/mongo-driver/mongo'):
            graph=('\n'.join(sorted(self.graph.decode().splitlines()+[module]))+'\n').encode()
            m=copy.deepcopy(self.manifest);m['build']['compiledPackages']=4;m['build']['compiledPackagesSha256']=c.sha(graph)
            with self.subTest(module=module),self.assertRaisesRegex(ValueError,'EXCLUDED_COMPILED'):c.verify_compiled(m,self.parent,graph,self.info)
    def test_no_all_maintained_or_authority_inference(self):
        for field,value in [('allDependenciesMaintained',True),('releaseAdmitted',True),('runtimeAuthorityIssued',True),('targetOperations',1)]:
            m=copy.deepcopy(self.manifest);m[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):c.validate_manifest(m,self.parent_bytes)
    def test_only_reviewed_vendor_file_can_change(self):
        m,before,after,origins=self.inventories();c.verify_vendor_inventories(m,before,after,origins)
        after['github.com/apache/iceberg-go/LICENSE']='c'*64;m['vendor']['afterTreeSha256']=c.inventory_tree(after)
        with self.assertRaisesRegex(ValueError,'ONLY_REVIEWED'):c.verify_vendor_inventories(m,before,after,origins)
    def test_vendor_tree_digest_divergence_denied(self):
        m,before,after,origins=self.inventories();m['vendor']['afterTreeSha256']='f'*64
        with self.assertRaisesRegex(ValueError,'EXACT_VENDOR_FILE_TREES'):c.verify_vendor_inventories(m,before,after,origins)
    def test_missing_original_file_authentication_denied(self):
        m,before,after,origins=self.inventories();origins['filesAuthenticatedAgainstOriginalZip']=1
        with self.assertRaisesRegex(ValueError,'EVERY_BASE_VENDOR_FILE'):c.verify_vendor_inventories(m,before,after,origins)
    def test_origins_cannot_be_transferred_from_other_binary(self):
        ids=sorted(c.parse_module_rows(self.info));txt=''.join('# '+m+' '+v+'\n'for m,v in ids).encode()
        a=self.origins(ids);b=self.origins(ids);b['buildInfoSha256']='0'*64
        with self.assertRaisesRegex(ValueError,'DISTINCT_ENUMERATION_AND_ACTUAL_BUILD'):self.coverage(a,b,txt,self.info)
    def test_inventory_paths_cannot_escape_vendor(self):
        for path in ('../escape','/absolute','module/../file','module\\file','module\nfile'):
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,'SAFE_HASHED'):c.inventory_tree({path:'a'*64})
    def test_canonical_module_versions_cannot_be_relabelled(self):
        info=self.info.replace('v0.7.0','v0.7.1')
        m=copy.deepcopy(self.manifest);m['build']['binaryModuleRowsSha256']=c.sha(('\n'.join(l for l in info.splitlines()if l.startswith('\tdep\t'))+'\n').encode())
        with self.assertRaisesRegex(ValueError,'EXACT_CANONICAL_DEPENDENCY_VERSIONS'):c.verify_compiled(m,self.parent,self.graph,info)
    def test_original_parent_bytes_are_required(self):
        with self.assertRaisesRegex(ValueError,'EXACT_GENERATION32'):c.validate_manifest(self.manifest,self.parent_bytes+b' ')

if __name__=='__main__':unittest.main()
