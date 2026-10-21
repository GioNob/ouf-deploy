import ast
import base64
from contextlib import redirect_stdout
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/semantic_policy_token_owner'))
import iam_binding_candidate as guard
spec=importlib.util.spec_from_file_location('consumer_delivery',ROOT/'scripts/observe-policy-token-consumers.py')
delivery=importlib.util.module_from_spec(spec);spec.loader.exec_module(delivery)

def load():
    tree=ast.parse(delivery.ROOT_BODY)
    nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))
        or isinstance(n,ast.Assign) and not any(isinstance(t,ast.Name)and t.id=='report'for t in n.targets)]
    namespace={'guard':guard}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'consumer-observer-test','exec'),namespace)
    return namespace

class ConsumerReviewTest(unittest.TestCase):
    def setUp(self):
        self.n=load();self.report={'systemctlReadAttempts':0,'sourceFilesRead':0,'configurationFilesRead':0}
        self.calls=[];self.reads=[]
        self.selected='fixture-semantic';self.issuer='https://auth.example/realms/fixture'
        self.sources={path:('CLIENT="'+('fixture-semantic'if 'refresh-policy-token.py'in path else 'fixture-other')+'"\n').encode()
            for path in self.n['WRITERS'].values()}
        self.metadata={'rootControlledAncestryAndFile':True,'executionCustodyAccepted':False}
    def command_runner(self,args,report,deadline):
        self.calls.append(args);report['systemctlReadAttempts']+=1
        if args[0]=='list-unit-files':return '\n'.join(unit+' static -'for unit in self.n['WRITERS'])+'\nouf-policy-token@.service static -\n'
        unit=args[1]
        if unit.endswith('.timer'):return 'Id='+unit+'\nLoadState=loaded\nActiveState=active\nSubState=waiting\nUnitFileState=enabled\n'
        path=self.n['WRITERS'][unit]
        return ('Id='+unit+'\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=static\n'
            +'ExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 '+path+' --secret PRIVATE_VALUE ; }\n'
            +'Environment=PRIVATE_PASSWORD=PRIVATE_VALUE\nTriggeredBy='+unit[:-8]+'.timer\n')
    def read(self,path,limit):
        self.reads.append(path)
        return self.sources[path],self.metadata
    def test_complete_four_layouts_and_timers_without_source_execution_or_private_output(self):
        onboard=list(self.sources)[-1]
        self.sources[onboard]=b'CLIENT="fixture-onboarding"\nraise RuntimeError("SOURCE_MUST_NOT_EXECUTE")\n'
        result=self.n['collect'](self.selected,self.issuer,self.report,self.read,self.command_runner)
        self.assertEqual(len(self.calls),9);self.assertEqual(len(result['writers']),4)
        self.assertEqual(result['sourceFilesRead'],4)
        self.assertEqual(result['staticSelectedClientWriterCount'],1)
        self.assertIn('/var/lib/ouf-r4a-identity/r4a_onboarding_token_runtime.py',self.reads)
        self.assertTrue(all(r['expectedTimerAssociationObserved']for r in result['writers']))
        self.assertTrue(all(r['timer']['ActiveState']=='active'for r in result['writers']))
        for private in ('PRIVATE_VALUE','SOURCE_MUST_NOT_EXECUTE','fixture-other','fixture-semantic','fixture-onboarding'):
            self.assertNotIn(private,json.dumps(result))
        self.assertFalse(result['credentialConsumerScopeProven']);self.assertFalse(result['allConsumerDiscoveryProven'])
    def test_one_unknown_source_does_not_hide_other_sources_or_timers(self):
        self.sources[list(self.sources)[1]]=b'not valid Python !!! PRIVATE_VALUE'
        result=self.n['collect'](self.selected,self.issuer,self.report,self.read,self.command_runner)
        self.assertEqual(len(self.calls),9)
        self.assertIn('SOURCE_SyntaxError',result['writers'][1]['findings'])
        self.assertIn('staticSource',result['writers'][2])
        self.assertTrue(result['observationHasFindings']);self.assertNotIn('PRIVATE_VALUE',json.dumps(result))
    def test_source_selected_configuration_is_read_but_secret_reference_is_not(self):
        path=list(self.sources)[0]
        self.sources[path]=b'CONFIG="/etc/ouf/policy-token/semantic.conf"\nSECRET="/private/credential"\nform={"client_id":required("OUF_POLICY_TOKEN_CLIENT_ID")}\n'
        self.sources['/etc/ouf/policy-token/semantic.conf']=b'OUF_POLICY_TOKEN_CLIENT_ID=fixture-semantic\nOUF_POLICY_TOKEN_SECRET_FILE=/private/credential\n'
        result=self.n['collect'](self.selected,self.issuer,self.report,self.read,self.command_runner)
        self.assertEqual(result['configurationFilesRead'],1)
        self.assertTrue(result['writers'][0]['staticSource']['selectedClientIdentifierObserved'])
        self.assertNotIn('/private/credential',self.reads);self.assertNotIn('/private/credential',json.dumps(result))
    def test_conflicting_configuration_is_not_silently_resolved(self):
        path=list(self.sources)[0]
        self.sources[path]=b'A="/etc/ouf/policy-token/a.conf"\nB="/etc/ouf/policy-token/b.conf"\nform={"client_id":required("OUF_POLICY_TOKEN_CLIENT_ID")}\n'
        self.sources['/etc/ouf/policy-token/a.conf']=b'OUF_POLICY_TOKEN_CLIENT_ID=fixture-semantic\n'
        self.sources['/etc/ouf/policy-token/b.conf']=b'OUF_POLICY_TOKEN_CLIENT_ID=fixture-other\n'
        result=self.n['collect'](self.selected,self.issuer,self.report,self.read,self.command_runner)
        first=result['writers'][0]
        self.assertIn('CONFIGURATION_VALUE_CONFLICT_REQUIRES_REVIEW',first['findings'])
        self.assertFalse(first['staticSource']['selectedClientIdentifierObserved'])
        self.assertEqual(first['staticSource']['unresolvedClientIdExpressionCount'],1)
    def test_outside_configuration_layout_and_duplicate_environment_files(self):
        parsed=self.n['properties']('Id=fixture\nEnvironmentFiles=/a (ignore_errors=no)\nEnvironmentFiles=/b (ignore_errors=no)\n',
            'fixture',('Id','EnvironmentFiles'))
        self.assertIn('/a',parsed['EnvironmentFiles']);self.assertIn('/b',parsed['EnvironmentFiles'])
        self.assertFalse(self.n['config_path']('/etc/ouf/policy-token/../secret.conf'))
        self.assertFalse(self.n['config_path']('/etc/ouf/credentials/secret.conf'))
        def run(args,report,deadline):
            raw=self.command_runner(args,report,deadline)
            return raw+'EnvironmentFiles=/private/credential (ignore_errors=no)\n'if args[1].endswith('.service')else raw
        result=self.n['collect'](self.selected,self.issuer,self.report,self.read,run)
        self.assertIn('ENVIRONMENT_FILE_OUTSIDE_REVIEWED_LAYOUT',result['writers'][0]['findings'])
        self.assertNotIn('/private/credential',self.reads)
    def test_static_dynamic_and_redefined_names_remain_unproven(self):
        raw=b'CLIENT="fixture-semantic"\nCLIENT=load_from_private_file()\nform={"client_id":CLIENT}\n'
        facts,refs=self.n['source_facts'](raw,{},self.selected,self.issuer)
        self.assertFalse(facts['selectedClientIdentifierObserved']);self.assertGreater(facts['unresolvedClientIdExpressionCount'],0)
        self.assertFalse(facts['effectiveDataFlowProven'])
    def test_bounded_command_failure_and_no_retry(self):
        calls=[]
        def fail(argv,**kwargs):
            calls.append(argv);kwargs['stderr'].write(b'PRIVATE_TOKEN permission denied')
            return subprocess.CompletedProcess(argv,7)
        with self.assertRaisesRegex(guard.CandidateDenied,'SYSTEMCTL_READ_FAILED_EXIT_7'):
            self.n['command'](['show','fixture'],self.report,time.monotonic()+10,fail)
        self.assertEqual(len(calls),1);self.assertNotIn('PRIVATE_TOKEN',json.dumps(self.report))
        self.report['systemctlReadAttempts']=9
        with self.assertRaisesRegex(guard.CandidateDenied,'BUDGET_EXHAUSTED'):
            self.n['command'](['show','fixture'],self.report,time.monotonic()+10,fail)
        self.assertEqual(len(calls),1)
    def test_native_regular_file_read_rejects_symlink_and_size(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as temp:
            path=Path(temp)/'source.py';path.write_text('CLIENT="fixture"\n');path.chmod(0o600)
            raw,metadata=self.n['file_read'](str(path),65536)
            self.assertEqual(raw,path.read_bytes());self.assertFalse(metadata['executionCustodyAccepted'])
            link=Path(temp)/'link.py';link.symlink_to(path)
            with self.assertRaises(guard.CandidateDenied):self.n['file_read'](str(link),65536)
            with self.assertRaises(guard.CandidateDenied):self.n['file_read'](str(path),2)
    def test_portable_existing_gh_and_isolated_hashed_root_delivery(self):
        raw=(ROOT/'tools/semantic_policy_token_owner/iam_binding_candidate.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),delivery.GUARD_SHA)
        with tempfile.TemporaryDirectory(dir=ROOT)as temp:
            home=Path(temp);gh=home/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh';gh.parent.mkdir(parents=True)
            gh.write_text('fixture');gh.chmod(0o700);calls=[]
            def run(argv,**kwargs):
                calls.append(argv)
                if argv[0]=='sudo':
                    self.assertEqual(kwargs['input'],raw);self.assertEqual(argv[:6],['sudo','--','/usr/bin/python3','-I','-B','-S'])
                    return subprocess.CompletedProcess(argv,0)
                self.assertEqual(argv[0],str(gh));return subprocess.CompletedProcess(argv,0,stdout=base64.b64encode(raw))
            with patch.object(delivery.Path,'home',return_value=home),patch.object(delivery.shutil,'which',return_value=None),\
                patch.object(delivery.subprocess,'run',side_effect=run):self.assertEqual(delivery.main(),0)
            self.assertEqual(len(calls),2)
    def test_complete_isolated_root_body_retains_private_redacted_evidence(self):
        self.assertEqual(os.geteuid(),0)
        self.assertTrue(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
        with tempfile.TemporaryDirectory(dir=ROOT)as temp:
            directory=Path(temp);directory.chmod(0o700)
            executable=Path('/usr/bin/systemctl').resolve(strict=True)
            host={'executables':{'systemctl':{'path':str(executable),'sha256':hashlib.sha256(executable.read_bytes()).hexdigest()}}}
            policy={'schema':'ouf.policy-token-client-policy-observation.v1','clientCore':{'clientId':self.selected}}
            raw_host,raw_policy=guard.encoded(host),guard.encoded(policy)
            host_hash,policy_hash=guard.sha(raw_host),guard.sha(raw_policy)
            for name,raw in [('policy-token-migration-host-inputs-'+host_hash+'.private.json',raw_host),
                ('policy-token-client-policies-'+policy_hash+'.private.json',raw_policy)]:
                file=directory/name;file.write_bytes(raw);file.chmod(0o600)
            writers={}
            for i,unit in enumerate(self.n['WRITERS']):
                path=directory/('source'+str(i)+'.py');path.write_text('CLIENT="fixture-semantic"\n');path.chmod(0o600)
                writers[unit]=str(path)
            tree=ast.parse(delivery.ROOT_BODY)
            replacements={'HOST_HASH':host_hash,'POLICY_HASH':policy_hash,'WRITERS':writers}
            for node in tree.body:
                if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
                    key=node.targets[0].id
                    if key in replacements:node.value=ast.parse(repr(replacements[key]),mode='eval').body
            ast.fix_missing_locations(tree)
            def runner(argv,**kwargs):
                raw=self.command_runner(argv[1:],{'systemctlReadAttempts':0},time.monotonic()+30)
                kwargs['stdout'].write(raw.encode());return subprocess.CompletedProcess(argv,0)
            output=io.StringIO()
            with patch.object(guard,'PARENT',directory),patch.object(subprocess,'run',side_effect=runner),redirect_stdout(output):
                with self.assertRaises(SystemExit)as done:exec(compile(tree,'root-review-fixture','exec'),{'guard':guard,'sys':sys})
            self.assertEqual(done.exception.code,0)
            report=json.loads(output.getvalue())
            self.assertEqual(report['systemctlReadAttempts'],9);self.assertEqual(report['privateEvidenceWrites'],1)
            retained=Path(report['privateEvidencePath'])
            self.assertEqual(guard.sha(retained.read_bytes()),report['privateEvidenceHash'])
            self.assertEqual(retained.stat().st_mode&0o777,0o600)
            self.assertFalse(report['productionApplyReady'])
            self.assertNotIn('PRIVATE_VALUE',output.getvalue());self.assertNotIn(self.selected,retained.read_text())

if __name__=='__main__':unittest.main()
