import contextlib,importlib.util,io,json,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
usage=load('source_usage','scripts/read-retained-v11-source-usage.py')
fixture=load('usage_fixture','tests/test_retained_v11_source_expectations.py')
planner_raw=(ROOT/'scripts/prepare-retained-v11-source-expectations.py').read_bytes()
atomic_raw=(ROOT/'tools/semantic_application_cutover/atomic_review_intake.py').read_bytes()
class Usage(unittest.TestCase):
    def test_reference_names_only_no_paths_values_or_writer_inference(self):
        old=[{'binding':{'Type':'bind','Destination':'/private-dir'},'sourceMetadata':[{'kind':'directory'},{'path':'PRIVATE_MEMBER.pem'}]},
             {'binding':{'Type':'bind','Destination':'/private-file'},'sourceMetadata':[{'kind':'file'}]}]
        req={'Env':['OUF_DIR=configtree:/private-dir/','OUF_MEMBER=file:/private-dir/PRIVATE_MEMBER.pem','OUF_FILE=/private-file','CREDENTIAL=SECRET_VALUE']}
        rows=usage.references(req,old);raw=json.dumps(rows)
        self.assertEqual([v['environmentKey'] for v in rows[0]['environmentReferences']],['OUF_DIR','OUF_MEMBER'])
        self.assertEqual(rows[1]['referenceCount'],1)
        for value in ('/private','PRIVATE_MEMBER.pem','SECRET_VALUE'):self.assertNotIn(value,raw)
        self.assertTrue(all(v['writerIdentityProven'] is False for v in rows))
    def test_ambiguous_or_unbounded_environment_denied(self):
        for env in (['A=x','A=y'],['bad-name=x'],['A='+'x'*65536],['A=x']*257):
            with self.assertRaises(usage.Denied):usage.references({'Env':env},[])
    def test_selected_private_parent_integrity_and_no_source_read_or_write(self):
        f=fixture.Expectations();f.setUp();self.addCleanup(f.doCleanups)
        bindings,files=f.fixture(mixed=True);p=usage.planner(planner_raw)
        for k,v in bindings.items():
            if k!='sys':setattr(p,k,v)
        atomic=p.atomic_source(atomic_raw)
        before={q.name:q.read_bytes() for q in p.PARENT.iterdir()}
        original=usage.os.open
        def blocked(path,*args,**kwargs):
            if str(path) in (str(f.directory),str(f.file),f.directory.name,f.file.name):raise AssertionError('MOUNTED_SOURCE_OPENED')
            return original(path,*args,**kwargs)
        with patch.object(usage.os,'open',side_effect=blocked):report=usage.collect(p,atomic)
        self.assertEqual(report['requestMountShape']['totalMountCount'],6)
        self.assertEqual(before,{q.name:q.read_bytes() for q in p.PARENT.iterdir()})
        self.assertEqual(len(list(p.BASE.iterdir())),1)
        (p.PARENT/p.NAMES[0]).write_bytes(files[p.NAMES[0]]+b' ')
        with self.assertRaises(p.Denied):usage.collect(p,atomic)
    def test_dependency_pinning_and_unknown_exception_redaction(self):
        with self.assertRaises(usage.Denied):usage.planner(planner_raw+b'\n')
        p=usage.planner(planner_raw);scoped=types.SimpleNamespace(flags=types.SimpleNamespace(isolated=1),dont_write_bytecode=True,argv=['fixture'])
        out=io.StringIO()
        with patch.object(usage,'sys',scoped),patch.object(usage,'planner',return_value=p),patch.dict(usage.__dict__,{'__atomic_source__':atomic_raw}),\
             patch.object(usage,'collect',side_effect=RuntimeError('SECRET_UNKNOWN_ERROR')),contextlib.redirect_stdout(out):
            self.assertEqual(usage.main(),1)
        self.assertNotIn('SECRET_UNKNOWN_ERROR',out.getvalue());self.assertIn('SOURCE_USAGE_UNPROVEN',out.getvalue())
if __name__=='__main__':unittest.main()
