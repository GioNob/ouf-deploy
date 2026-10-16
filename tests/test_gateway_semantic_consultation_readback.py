"""Read-only diagnosis while the existing finite acceptance process remains live."""
import ast,contextlib,copy,hashlib,importlib.util,io,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('semantic_consultation_reader',ROOT/'scripts/read-chatbot-semantic-consultation-20261016.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class SemanticConsultation(unittest.TestCase):
    def full(self,drift=False,expose=True):
        with tempfile.TemporaryDirectory(dir=ROOT)as tmp:
            root=Path(tmp);root.chmod(0o700)
            def write(path,value):
                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(r.encoded(value));path.chmod(0o600)
                return r.digest(value)
            functions=['local DELEGATION_KEY_ENV = "DELEGATION_KEY"\nlocal OWNER_KEY_ENV = "SEMANTIC_KEY"\n']
            routes={name:{'id':name,'uri':'/internal/capabilities/v1/execute/semantic/'+name,
                'plugins':{'serverless-post-function':{'functions':functions}}}for name in ('search','get')}
            gateway={'proposedRoutes':routes,'changes':[{'id':'change-'+str(i)}for i in range(28)]}
            p={'engine':{},'gatewayPlan':gateway}
            bundle={'declaration':{'sourceCommit':r.SOURCE},'prepared':p};bh=write(root/'bundle.json',bundle)
            process={'unit':r.UNIT,'authorityDirectory':str(root),'directoryPlan':{'gateway':str(root/'gateway')},
                'bundle':{'path':str(root/'bundle.json'),'sha256':bh}}
            scopes={'finiteActionProcess':process};authority={**scopes,'expiresAt':2000000000,'issuedAt':1700000000}
            ah=write(root/'authority.json',authority)
            program=Path('/usr/bin/true');binding={'path':str(program),'sha256':hashlib.sha256(program.read_bytes()).hexdigest()}
            review={'sourceClosure':{'declaration':bundle['declaration'],'executables':{'systemctl':binding,'docker':binding}},
                'scopes':scopes,'privateInputHashes':{'preparedInputs':r.digest(p)}};rh=write(root/'review.json',review)
            write(root/'delivery-status.json',{'authorityHash':ah,'phase':'ACTUAL_CSV_OWNER_ACCEPTANCE_OBSERVED'})
            journal={'schema':'ouf.chatbot-file-cohort.gateway-publication.v1','authorityHash':ah,'planHash':r.digest(gateway),
                'budgetReset':False,'nextStep':28,'effects':[{'state':'APPLIED','routeId':c['id'],'intentHash':r.digest(c)}for c in gateway['changes']]}
            write(root/'gateway/recovery.json',journal)
            def native(cid):return {'Id':cid,'Image':'sha256:'+'b'*64,'Name':'/fixture','Config':{'Env':[]},
                'HostConfig':{},'Mounts':[],'NetworkSettings':{},'RestartCount':0,'State':{'Status':'running',
                'Running':True,'Paused':False,'Restarting':False,'Dead':False,'Pid':1234,'ExitCode':0,'StartedAt':'2026-10-16T09:00:00Z'}}
            gateway_actual=native('a'*64);gateway_actual['Config']['Env']=['DELEGATION_KEY='+'1'*64,'SEMANTIC_KEY='+'2'*64]
            registry_id='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
            natives={'a'*64:gateway_actual,registry_id:native(registry_id)}
            transport={'runtimeBinding':{'containerId':'a'*64},'configBinding':{'path':str(root/'selected.yaml')}}
            nginx=b'nginx_config:\n  envs:\n  - DELEGATION_KEY\n'+(b'  - SEMANTIC_KEY\n'if expose else b'')+b'deployment:\n'
            log=b'PRIVATE_SENTINEL "POST /internal/capabilities/v1/execute/semantic/search HTTP/1.1" 503 12\n'
            def read_routes(*args):
                if drift:write(root/'gateway/recovery.json',{**journal,'version':99})
                return routes
            out=io.StringIO()
            with patch.object(r,'CONTEXT',root),patch.object(r,'AUTHORITY',ah),patch.object(r,'REVIEW',rh),\
                patch.object(r.sys,'flags',type('Flags',(),{'isolated':1})()),patch.object(r.signal,'alarm'),\
                patch.object(r,'live_process')as live,patch.object(r,'transport_binding',return_value=transport),\
                patch.object(r,'gateway_read',side_effect=read_routes)as gets,patch.object(r,'gateway_check'),\
                patch.object(r,'private_config',return_value=(nginx,{})),\
                patch.object(r,'engine_get',side_effect=lambda engine,kind,cid:copy.deepcopy(natives[cid])),\
                patch.object(r,'bounded',return_value=(0,log,b'PRIVATE_SENTINEL',len(log)))as logs,\
                contextlib.redirect_stdout(out):r.main()
            self.assertEqual(gets.call_count,2);self.assertEqual(logs.call_count,2);self.assertEqual(live.call_count,2)
            self.assertNotIn('PRIVATE_SENTINEL',out.getvalue());self.assertNotIn('1'*64,out.getvalue());self.assertNotIn('2'*64,out.getvalue())
            return [json.loads(v)for v in out.getvalue().splitlines()]
    def test_complete_live_diagnosis_does_not_stop_or_write_and_redacts_keys(self):
        rows=self.full();end=rows[-1];self.assertTrue(end['complete'])
        for k in ('databaseCalls','backupArchiveReads','dumpProbes','grantRequests','iamCalls','mcpCalls','gatewayWrites','serviceMutations'):
            self.assertEqual(end[k],0)
        keys=[v for v in rows if v['check']=='GATEWAY_SIGNING_CONFIGURATION'];self.assertEqual(len(keys),4)
        self.assertTrue(all(v['referencePresent']and v['hex64']and v['exposedByNginxConfiguration']for v in keys))
    def test_unexposed_owner_key_is_reported_without_repairing_configuration(self):
        rows=self.full(expose=False);keys=[v for v in rows if v['check']=='GATEWAY_SIGNING_CONFIGURATION']
        self.assertTrue(all(not v['exposedByNginxConfiguration']for v in keys if v['keyRole']=='owner'))
        self.assertTrue(all(v['exposedByNginxConfiguration']for v in keys if v['keyRole']=='delegation'))
    def test_midread_completed_journal_change_blocks(self):
        with self.assertRaisesRegex(r.ReadDenied,'RETAINED_JOURNAL_DRIFT'):self.full(drift=True)
    def test_logs_publish_only_fixed_statuses_and_fixed_markers(self):
        raw=b'PRIVATE_SENTINEL connect() failed (111: Connection refused) while connecting to upstream\n"POST /api/internal/v1/semantic/consultation/search HTTP/1.1" 503 12\n'
        v=r.log_metadata(raw);self.assertEqual(v['httpStatusCounts'],{'ownerSemanticSearch:503':1})
        self.assertEqual(v['classifiedMarkerCounts']['UPSTREAM_CONNECTION_REFUSED'],1)
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(v))
    def test_closed_environment_references_and_allowlist(self):
        with self.assertRaises(r.ReadDenied):r.nginx_environment(b'nginx_config:\n  envs:\n  - KEY\n  - KEY\n')
        with self.assertRaises(r.ReadDenied):r.lua_constant({'plugins':{}},'OWNER_KEY_ENV')
    def test_live_observer_checks_exact_unit_and_pid_without_mutating(self):
        with patch.object(r,'executable',return_value='/usr/bin/systemctl'),patch.object(r,'bounded',return_value=(0,b'ActiveState=active\nMainPID=3733354\nJob=\n',b'',0))as call:
            r.live_process({});self.assertEqual(call.call_args.args[0][1],'show')
        with patch.object(r,'executable',return_value='/usr/bin/systemctl'),patch.object(r,'bounded',return_value=(0,b'ActiveState=inactive\nMainPID=0\nJob=\n',b'',0)):
            with self.assertRaises(r.ReadDenied):r.live_process({})
    def test_all_http_calls_are_get_and_native_helpers_match_prior_qualification(self):
        source=Path(r.__file__).read_text()
        for text in (source,r.GET_CHILD):
            for node in ast.walk(ast.parse(text)):
                if isinstance(node,ast.Call)and isinstance(node.func,ast.Attribute)and node.func.attr=='request':
                    self.assertEqual(ast.literal_eval(node.args[0]),'GET')
        old=ast.parse((ROOT/'scripts/read-chatbot-ingestion-start-20261016.py').read_text());new=ast.parse(source)
        for name in ('engine_get','gateway_read','gateway_check','transport_binding','private_config','selected_admin_key'):
            a=next(x for x in old.body if isinstance(x,ast.FunctionDef)and x.name==name)
            b=next(x for x in new.body if isinstance(x,ast.FunctionDef)and x.name==name)
            self.assertEqual(ast.dump(a,include_attributes=False),ast.dump(b,include_attributes=False))
if __name__=='__main__':unittest.main()
