"""Target schema-only reader: real custody fixture, redaction and no mutations."""
import ast,contextlib,copy,importlib.util,io,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/('read-chatbot-gateway-'+name+'-20261016.py'))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
r=module('schema');previous=module('state')

def schema():
    return {'type':'object','properties':{'Arguments':{'properties':{'expectedVersion':{'maximum':9007199254740991},
        'executionProposal':{'$id':'urn:ouf:managed-file-execution-proposal:lexical-csv:v1','type':'object','description':'PRIVATE_SENTINEL'}}}}}
def plan():
    before={'legacy':{'id':'legacy','uri':'PRIVATE_SENTINEL'}};after=copy.deepcopy(before)
    for name in ('mcp-managed-file-review-prepare','semantic-proposal-review','semantic-proposal-validate'):
        s=schema() if name.startswith('mcp') else {'properties':{'Arguments':{'properties':{'expectedRowVersion':{'maximum':9007199254740991}}}}}
        after[name]={'id':name,'uri':'PRIVATE_SENTINEL','plugins':{'request-validation':{'body_schema':s}}}
    return {'schema':'ouf.chatbot-file-cohort.gateway-publication.v1','previousRoutes':before,'proposedRoutes':after,
        'previousRuntimeHash':r.digest(before),'proposedRuntimeHash':r.digest(after),'changes':[{'id':n,'before':None,'after':after[n]} for n in sorted(after) if n!='legacy'],
        'transportBinding':{'runtimeBinding':{'imageId':'sha256:'+'a'*64}}}

class SchemaReader(unittest.TestCase):
    def test_metadata_projection_preserves_plan_and_redacts_unknown_values(self):
        p=plan();before=copy.deepcopy(p);facts=r.schema_projection(p)
        self.assertEqual(p,before);self.assertTrue(facts['knownNestedIdentifierPresent'])
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(facts))
        self.assertTrue(all(x['maximumMatchesSafeIntegerContract'] for x in facts['numericLimits']))
        p['proposedRoutes']['mcp-managed-file-review-prepare']['plugins']['request-validation']['body_schema']['$ref']='PRIVATE_SENTINEL'
        facts=r.schema_projection(p);self.assertEqual(facts['referenceKeywordCount'],1)
        self.assertEqual(facts['bodySchemaHash'],facts['metadataOnlyProjectionHash'])
    def full(self,mutate=False):
        with tempfile.TemporaryDirectory(dir=ROOT)as tmp:
            root=Path(tmp);root.chmod(0o700)
            def write(path,v):
                path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);path.write_bytes(r.encoded(v));path.chmod(0o600);return r.digest(v)
            p={'gatewayPlan':plan(),'gatewayRuntimePlan':None,'engine':{},'postGrantWorkerDirectory':str(root/'owner')}
            p['cohortPlan']={'gatewayPlanHash':r.digest(p['gatewayPlan'])}
            declaration={'sourceCommit':r.SOURCE};bundle={'prepared':p,'declaration':declaration}
            bh=write(root/'bundle.json',bundle)
            process={'unit':r.UNIT,'authorityDirectory':str(root),'directoryPlan':{'gateway':str(root/'gateway')},'bundle':{'path':str(root/'bundle.json'),'sha256':bh}}
            scopes={'finiteActionProcess':process,'policyTokenOwnerInstallation':{'journalPath':str(root/'owner')}}
            ah=write(root/'authority.json',scopes)
            review={'sourceClosure':{'declaration':declaration,'executables':{'systemctl':{}}},'scopes':scopes,'privateInputHashes':{'preparedInputs':r.digest(p)}}
            rh=write(root/'review.json',review)
            write(root/'delivery-status.json',{'authorityHash':ah,'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'GATEWAY_WRITE_OUTCOME_UNPROVEN_NO_REPLAY'})
            change=p['gatewayPlan']['changes'][0]
            j={'planHash':r.digest(p['gatewayPlan']),'authorityHash':ah,'budgetReset':False,'nextStep':0,'effects':[{'routeId':change['id'],'intentHash':r.digest(change),'state':'CLAIMED'}]}
            jh=write(root/'gateway/recovery.json',j)
            write(root/'owner/recovery.json',{'state':'CANCELLED','controlledCumulativeGrantAttempts':8})
            write(root/'owner/owner-admission.json',{'state':'BLOCKED'})
            def get(*args):
                if mutate:write(root/'owner/recovery.json',{'state':'ACTIVE'})
                return p['gatewayPlan']['previousRoutes']
            output=io.StringIO()
            with patch.object(r,'CONTEXT',root),patch.object(r,'REVIEW',rh),patch.object(r,'AUTHORITY',ah),patch.object(r,'EXPECTED_JOURNAL',jh),\
                patch.object(r.sys,'flags',type('Flags',(),{'isolated':1})()),patch.object(r.signal,'alarm'),patch.object(r,'stopped'),\
                patch.object(r,'gateway_check'),patch.object(r,'engine_get',return_value={'Id':'sha256:'+'a'*64})as engine,\
                patch.object(r,'gateway_read',side_effect=get)as reads,contextlib.redirect_stdout(output):r.main()
            self.assertEqual(reads.call_count,2);self.assertTrue(all(c.args[1]=='images' for c in engine.call_args_list))
            self.assertNotIn('PRIVATE_SENTINEL',output.getvalue());return [json.loads(x) for x in output.getvalue().splitlines()]
    def test_complete_reader_gets_schema_image_and_stable_claim_without_backups_or_database(self):
        rows=self.full();self.assertTrue(rows[-1]['complete']);self.assertEqual(rows[-1]['databaseCalls'],0)
        self.assertEqual(rows[-1]['backupArchiveReads'],0);self.assertEqual(rows[-1]['gatewayWrites'],0)
        self.assertIn('facts',next(x for x in rows if x['check']=='PLANNED_SCHEMA_COMPATIBILITY'))
    def test_concurrent_record_change_blocks_completion(self):
        with self.assertRaisesRegex(r.ReadDenied,'RETAINED_RECORD_CHANGED'):self.full(mutate=True)
    def test_transport_and_custody_are_exact_qualified_get_only_helpers(self):
        def defs(name):
            tree=ast.parse((ROOT/'scripts'/('read-chatbot-gateway-'+name+'-20261016.py')).read_text())
            return {n.name:ast.dump(n,include_attributes=False) for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        new,old=defs('schema'),defs('state')
        for name in set(new)-{'schema_projection','main','emit'}:self.assertEqual(new[name],old[name],name)
        self.assertEqual(r.GET_CHILD,previous.GET_CHILD)
        self.assertNotIn('sql_read',new);self.assertNotIn('archive',new)

if __name__=='__main__':unittest.main()
