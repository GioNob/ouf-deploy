"""Exact post-Gateway diagnostic, real private files and redacted observations."""
import ast,contextlib,copy,importlib.util,io,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ingestion_start_reader',ROOT/'scripts/read-chatbot-ingestion-start-20261016.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

def row(module,index):
    return {'module':module,'name':'fixture-'+module,'oldRuntimeBinding':{'containerId':str(index)*64},
        'creationRequest':{'Image':'sha256:'+'a'*64,'User':'10001','Env':['SERVICE=PRIVATE_SENTINEL'],
            'Labels':{'fixture':'PRIVATE_SENTINEL'},'HostConfig':{'RestartPolicy':{'Name':'no'}},
            'NetworkingConfig':{}}}

def journal(plan,n,authority):
    effects=[]
    for step in [m+'.'+s for m in r.MODULES for s in r.STAGES][:n+1]:
        module,stage=step.split('.');item=next(x for x in plan['replacements']if x['module']==module)
        e={'step':step,'state':'APPLIED'if len(effects)<n else'CLAIMED',
            'intentHash':r.digest({'modulePlan':item,'stage':stage})}
        if e['state']=='APPLIED':e.update(evidence={},evidenceHash=r.digest({}))
        effects.append(e)
    return {'schema':'ouf.chatbot-cohort-container-journal.v1','planHash':r.digest(plan),
        'authorityHash':authority,'budgetReset':False,'nextStep':n,'effects':effects,
        'gates':{'gateway':{'scopeHash':plan['gatewayPlanHash'],'evidenceHash':'c'*64}}}

class IngestionStartReader(unittest.TestCase):
    def full(self,n=12,drift=False):
        with tempfile.TemporaryDirectory(dir=ROOT)as tmp:
            root=Path(tmp);root.chmod(0o700)
            def write(path,value):
                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                path.write_bytes(r.encoded(value));path.chmod(0o600);return r.digest(value)
            routes={'existing':{'id':'existing','uri':'PRIVATE_SENTINEL'}}
            changes=[{'id':'route-'+str(i),'after':{'id':'route-'+str(i)},'before':None}for i in range(28)]
            gateway={'previousRoutes':routes,'proposedRoutes':routes,'changes':changes}
            plan={'gatewayPlanHash':r.digest(gateway),'replacements':[row(m,i+1)for i,m in enumerate(r.MODULES)]}
            p={'cohortPlan':plan,'gatewayPlan':gateway,'databasePlan':{},'engine':{},'postGrantWorkerDirectory':str(root/'owner')}
            declaration={'sourceCommit':r.SOURCE};bundle={'prepared':p,'declaration':declaration};bh=write(root/'bundle.json',bundle)
            dirs={k:str(root/k)for k in ('containers','databases','gateway','gatewayRuntime')}
            process={'unit':r.UNIT,'authorityDirectory':str(root),'directoryPlan':dirs,
                'bundle':{'path':str(root/'bundle.json'),'sha256':bh}}
            scopes={'finiteActionProcess':process,'applicationCohortInstallation':{'planHash':r.digest(plan)},
                'policyTokenOwnerInstallation':{'journalPath':str(root/'owner')}}
            authority={**scopes,'expiresAt':1792142704};ah=write(root/'authority.json',authority)
            review={'sourceClosure':{'declaration':declaration,'executables':{'systemctl':{}}},
                'sourceClosureHash':'d'*64,'scopes':scopes,'privateInputHashes':{'preparedInputs':r.digest(p)}}
            rh=write(root/'review.json',review)
            write(root/'decision.json',{'approvedReviewHash':rh,'approvedSourceClosureHash':'d'*64,'expiresAt':authority['expiresAt']})
            write(root/'delivery-status.json',{'authorityHash':ah,'phase':'PAUSED_REQUIRES_RECONCILIATION',
                'reason':'COHORT_START_REQUIRES_RECONCILIATION'})
            write(root/'containers/recovery.json',journal(plan,n,ah))
            for name,value in [('recovery.json',{'state':'CANCELLED','controlledCumulativeGrantAttempts':10}),
                ('owner-session.json',{'predecessorGrantAttempts':8}),('owner-admission.json',{'state':'BLOCKED'})]:
                write(root/'owner'/name,value)
            write(root/'databases/recovery.json',{'authorityHash':ah,'planHash':r.digest({}),
                'mcpMigration':{'state':'COMPLETE'},'mcpAuditRole':{'state':'CLEAN'},
                'backups':{m:{'state':'COMPLETE'}for m in r.MODULES}})
            write(root/'gateway/recovery.json',{'schema':'ouf.chatbot-file-cohort.gateway-publication.v1',
                'authorityHash':ah,'planHash':r.digest(gateway),'budgetReset':False,'nextStep':28,
                'effects':[{'routeId':c['id'],'state':'APPLIED','intentHash':r.digest(c)}for c in changes]})
            natives={}
            for i,item in enumerate(plan['replacements']):
                config={k:copy.deepcopy(v)for k,v in item['creationRequest'].items()if k not in ('HostConfig','NetworkingConfig')}
                config['Env']=['PATH=PRIVATE_SENTINEL',*config['Env']]
                natives[item['name']]={'Id':str(i+5)*64 if i<3 or n>=15 else item['oldRuntimeBinding']['containerId'],
                    'Image':config['Image'],'Config':config,'HostConfig':item['creationRequest']['HostConfig'],
                    'Mounts':[],'NetworkSettings':{},'RestartCount':0,
                    'State':{'Status':'created','Running':False,'Paused':False,'Restarting':False,'Dead':False,
                        'Pid':0,'ExitCode':0,'StartedAt':'0001-01-01T00:00:00Z'}}
            item=next(x for x in plan['replacements']if x['module']=='ingestion')
            actual=natives[item['name']];actual['Id']=r.CREATED
            actual['State']['Error']='OCI runtime create failed: mount PRIVATE_SENTINEL: permission denied'
            j=journal(plan,n,ah)
            if n>=12:
                created=j['effects'][11];created['evidence']={'containerId':r.CREATED,
                    'imageId':actual['Image'],'configHash':r.digest(actual['Config']),
                    'mountsHash':r.digest(actual['Mounts'])}
                created['evidenceHash']=r.digest(created['evidence'])
            write(root/'containers/recovery.json',j)
            image={'Id':'sha256:'+'a'*64,'Config':{'Env':['PATH=PRIVATE_SENTINEL'],'Labels':{}}}
            calls=[]
            def get(engine,kind,reference):
                calls.append((kind,reference));return copy.deepcopy(image if kind=='images'else natives[reference])
            def gateway_get(*args):
                if drift:write(root/'owner/recovery.json',{'state':'ACTIVE'})
                return routes
            out=io.StringIO()
            with patch.object(r,'CONTEXT',root),patch.object(r,'REVIEW',rh),patch.object(r,'AUTHORITY',ah),\
                patch.object(r.sys,'flags',type('Flags',(),{'isolated':1})()),patch.object(r.signal,'alarm'),\
                patch.object(r,'stopped'),patch.object(r,'transport_binding',return_value={}),\
                patch.object(r,'gateway_check'),patch.object(r,'gateway_read',side_effect=gateway_get)as reads,\
                patch.object(r,'engine_get',side_effect=get),contextlib.redirect_stdout(out):r.main()
            self.assertEqual(reads.call_count,2);self.assertNotIn('PRIVATE_SENTINEL',out.getvalue())
            return [json.loads(line)for line in out.getvalue().splitlines()]

    def test_full_diagnosis_identifies_ingestion_and_proves_completed_gateway_without_mutations(self):
        rows=self.full();end=rows[-1];self.assertEqual(end['technicalPhase'],6)
        self.assertTrue(end['technicalPhase5Verified'])
        check=next(x for x in rows if x['check']=='CONTAINER_CHECKPOINT')
        self.assertEqual(check['pendingStep'],'ingestion.start');self.assertTrue(check['claimed'])
        native=next(x for x in rows if x['check']=='MODULE_CONFIG_COMPARISON'and x['module']=='ingestion')
        self.assertEqual(native['differingFields'],['Env']);self.assertTrue(native['environmentMatchesImageDefaultsAndRequest'])
        self.assertFalse(native['originalProcessPredicateMatches'])
        self.assertEqual(next(x for x in rows if x['check']=='WORKER')['controlledCumulativeGrantAttempts'],10)
        for k in ('grantRequests','iamCalls','mcpCalls','databaseCalls','databaseMutations','gatewayWrites','dumpProbes','serviceMutations','backupArchiveReads'):
            self.assertEqual(end[k],0)
    def test_other_boundary_cannot_be_mistaken_for_this_failed_start(self):
        with self.assertRaisesRegex(r.ReadDenied,'EXACT_INGESTION_START_BOUNDARY'):
            self.full(n=11)
    def test_retained_error_is_redacted_and_categories_are_bounded(self):
        rows=self.full();error=next(x for x in rows if x['check']=='INGESTION_RETAINED_START_ERROR')
        self.assertEqual(error['categories'],['MOUNT_FAILURE','OCI_RUNTIME_FAILURE','PERMISSION_DENIED'])
        self.assertFalse(error['rawErrorPrinted'])
        self.assertFalse(error['historicalStartHttpStatusAvailable'])
        self.assertEqual(r.start_error_metadata({'State':{'Error':''}})['categories'],[])
        self.assertTrue(r.start_error_metadata({'State':{'Error':'PRIVATE_SENTINEL'}})['unclassifiedError'])
    def test_midread_record_drift_blocks_completion(self):
        with self.assertRaisesRegex(r.ReadDenied,'RETAINED_RECORD_CHANGED'):self.full(drift=True)
    def test_same_name_is_not_enough_to_reconcile_start_generation(self):
        actual={'Id':r.CREATED,'Image':'sha256:'+'a'*64,'Config':{'User':'10002'},'Mounts':[]}
        created={'state':'APPLIED','step':'ingestion.create','evidenceHash':'b'*64,
            'evidence':{'containerId':r.CREATED,'imageId':actual['Image'],
                'configHash':r.digest(actual['Config']),'mountsHash':r.digest([])}}
        claimed={'state':'CLAIMED','step':'ingestion.start','intentHash':'c'*64}
        j={'effects':[created,claimed]}
        self.assertTrue(r.start_generation({},actual,j)['sameCreatedContainer'])
        wrong=copy.deepcopy(actual);wrong['Id']='0'*64
        with self.assertRaisesRegex(r.ReadDenied,'EXACT_CREATED_INGESTION'):r.start_generation({},wrong,j)
        wrong=copy.deepcopy(actual);wrong['Config']['User']='0'
        with self.assertRaisesRegex(r.ReadDenied,'INGESTION_CREATED_EVIDENCE'):r.start_generation({},wrong,j)
    def test_configuration_diffs_redact_unknown_keys_and_reject_incorrect_image(self):
        item=row('ingestion',1);item['creationRequest']['PRIVATE_UNKNOWN']='PRIVATE_SENTINEL'
        image={'Id':item['creationRequest']['Image'],'Config':{'Env':['PATH=PRIVATE_SENTINEL']}}
        actual={'Config':{'Env':['SERVICE=CHANGED','EXTRA=PRIVATE_SENTINEL'],'Labels':{}},'HostConfig':{}}
        result=r.configuration_projection(item,actual,image)
        self.assertNotIn('PRIVATE',json.dumps(result));self.assertEqual(result['differingUnknownFieldCount'],1)
        self.assertEqual(result['environmentUnexpectedKeyCount'],1);self.assertEqual(result['environmentChangedValueCount'],1)
        with self.assertRaisesRegex(r.ReadDenied,'EXACT_REQUEST_IMAGE'):r.configuration_projection(item,actual,{'Id':'wrong'})
    def test_tampered_claim_and_evidence_are_rejected(self):
        plan={'replacements':[row(m,i+1)for i,m in enumerate(r.MODULES)],'gatewayPlanHash':'a'*64}
        good=journal(plan,11,r.AUTHORITY)
        for field in ('intentHash','evidenceHash'):
            bad=copy.deepcopy(good);bad['effects'][0][field]='0'*64
            with self.assertRaises(r.ReadDenied):r.container_checkpoint(plan,bad)
    def test_all_http_requests_are_literal_get_and_helpers_match_qualified_reader(self):
        source=Path(r.__file__).read_text()
        for text in (source,r.GET_CHILD):
            for node in ast.walk(ast.parse(text)):
                if isinstance(node,ast.Call)and isinstance(node.func,ast.Attribute)and node.func.attr=='request':
                    self.assertEqual(ast.literal_eval(node.args[0]),'GET')
        old=ast.parse((ROOT/'scripts/read-chatbot-gateway-authorization-20261016.py').read_text());new=ast.parse(source)
        for name in ('engine_get','gateway_read','gateway_check','transport_binding','private_config','selected_admin_key'):
            a=next(x for x in old.body if isinstance(x,ast.FunctionDef)and x.name==name)
            b=next(x for x in new.body if isinstance(x,ast.FunctionDef)and x.name==name)
            self.assertEqual(ast.dump(a,include_attributes=False),ast.dump(b,include_attributes=False))

if __name__=='__main__':unittest.main()
