"""Incident-bound diagnostic: private custody, exact generation and safe log fields."""
import contextlib,copy,importlib.util,io,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('authorization_reader',ROOT/'scripts/read-chatbot-gateway-authorization-20261016.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class AuthorizationReader(unittest.TestCase):
    def test_logs_publish_only_fixed_route_category_and_status_counts(self):
        raw=b'private-address - - [time] "POST /mcp HTTP/1.1" 429 42 "PRIVATE_SENTINEL"\n'
        raw+=b'x "GET /api/trusted-human/v1/authorization/policies/active HTTP/1.1" 200 4\n'
        raw+=b'x "POST /private-secret-path HTTP/1.1" 403 4 PRIVATE_SENTINEL\n'
        v=r.http_log_summary(raw)
        self.assertEqual(v['httpStatusCounts'],{'mcp:429':1,'authorizationAdmin:200':1})
        self.assertNotIn('PRIVATE',json.dumps(v));self.assertFalse(v['historicalExceptionReasonProven'])
        self.assertEqual(r.http_log_summary(b'PRIVATE_SENTINEL')['coverage'],'NO_MATCHING_ACCESS_RECORDS')

    def test_mount_identity_ignores_order_but_no_native_fields(self):
        actual={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Pid':123,'StartedAt':'synthetic'},
            'Config':{},'HostConfig':{},'NetworkSettings':{},
            'Mounts':[{'Destination':'/a','Source':'private-a','RW':False},{'Destination':'/b','Source':'private-b','RW':False}]}
        pin=r.runtime_pin(actual);changed=copy.deepcopy(actual);changed['Mounts'].reverse()
        self.assertEqual(r.runtime_pin(changed),pin)
        changed['Mounts'][0]['RW']=True;self.assertNotEqual(r.runtime_pin(changed),pin)
        changed=copy.deepcopy(actual);changed['Mounts'].append(changed['Mounts'][0])
        with self.assertRaisesRegex(r.ReadDenied,'DUPLICATE'):r.runtime_pin(changed)

    def full(self,drift=False):
        with tempfile.TemporaryDirectory(dir=ROOT)as tmp:
            root=Path(tmp);root.chmod(0o700)
            def write(path,value):
                path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                path.write_bytes(r.encoded(value));path.chmod(0o600);return r.digest(value)
            routes={'private':{'id':'private','uri':'PRIVATE_SENTINEL'}}
            plan={'previousRoutes':routes,'proposedRoutes':{},'changes':[{}]*28}
            p={'gatewayPlan':plan,'authorization':{'plan':{}},'engine':{},'postGrantWorkerDirectory':str(root/'owner'),
                'cohortPlan':{'gatewayPlanHash':r.digest(plan)}}
            declaration={'sourceCommit':r.SOURCE};bundle={'prepared':p,'declaration':declaration}
            bh=write(root/'bundle.json',bundle)
            dirs={name:str(root/name)for name in ('gatewayRuntime','authorization')}
            process={'unit':r.UNIT,'authorityDirectory':str(root),'directoryPlan':dirs,
                'bundle':{'path':str(root/'bundle.json'),'sha256':bh}}
            scopes={'finiteActionProcess':process,'policyTokenOwnerInstallation':{'journalPath':str(root/'owner')}}
            authority={**scopes,'expiresAt':1792135583};ah=write(root/'authority.json',authority)
            review={'sourceClosure':{'declaration':declaration,'executables':{'systemctl':{},'docker':{}}},
                'scopes':scopes,'privateInputHashes':{'preparedInputs':r.digest(p)}}
            rh=write(root/'review.json',review)
            write(root/'delivery-status.json',{'authorityHash':ah,'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'AuthorizationPaused'})
            auth={'planHash':r.digest({}),'authorityHash':ah,'effects':{},'budgetReset':False}
            write(root/'authorization/recovery.json',auth)
            write(root/'gatewayRuntime/recovery.json',{'nextStep':8})
            actual={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Pid':123,'StartedAt':'synthetic','Running':True,'Paused':False},
                'Config':{},'HostConfig':{},'NetworkSettings':{},'Mounts':[],'RestartCount':0}
            def gateway(*args):
                if drift:write(root/'authorization/recovery.json',{**auth,'effects':{'unexpected':{}}})
                return routes
            output=io.StringIO()
            with patch.object(r,'CONTEXT',root),patch.object(r,'REVIEW',rh),patch.object(r,'AUTHORITY',ah),\
                patch.object(r.sys,'flags',type('Flags',(),{'isolated':1})()),patch.object(r.signal,'alarm'),patch.object(r,'stopped'),\
                patch.object(r,'transport_binding',return_value={'runtimeBinding':{'containerId':actual['Id']}}),\
                patch.object(r,'gateway_check'),patch.object(r,'gateway_read',side_effect=gateway)as reads,\
                patch.object(r,'engine_get',return_value=actual),patch.object(r,'executable',return_value='/synthetic/docker'),\
                patch.object(r,'bounded',return_value=(0,b'x "POST /mcp HTTP/1.1" 502 4',b'',32))as logs,\
                contextlib.redirect_stdout(output):r.main()
            self.assertEqual(reads.call_count,2);self.assertEqual(logs.call_count,1)
            self.assertEqual(logs.call_args.args[0][1],'logs');self.assertNotIn('PRIVATE_SENTINEL',output.getvalue())
            return [json.loads(line)for line in output.getvalue().splitlines()]

    def test_full_readback_has_no_mcp_iam_database_or_mutation_calls(self):
        rows=self.full();last=rows[-1];self.assertTrue(last['complete'])
        for key in ('mcpCalls','iamCalls','grantRequests','databaseCalls','gatewayWrites','serviceMutations'):
            self.assertEqual(last[key],0)
        self.assertEqual(next(x for x in rows if x['check']=='GATEWAY_ACCESS_LOG_METADATA')['httpStatusCounts'],{'mcp:502':1})

    def test_retained_record_drift_blocks_completion(self):
        with self.assertRaisesRegex(r.ReadDenied,'RETAINED_RECORD_CHANGED'):self.full(drift=True)

if __name__=='__main__':unittest.main()
