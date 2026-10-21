import ast,copy,importlib.util,json,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('reader',Path(__file__).with_name('read_terminal_maintenance_denial.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
    def test_consumed_claim_and_unknown_lifecycle_remain_unknown(self):
        result={'schema':'ouf.semantic-terminal-task-cleanup.v1','status':'BLOCKED','reason':'TERMINAL_TASK_DELETE_UNPROVEN','taskDeleteRequests':1,'doNotRerunApply':True,'wrapperRestored':True,'evidenceDirectory':str(m.EVIDENCE),'dockerStartRequests':0,'startAuthorized':False,'phase':'DELETE_EXACT_STOPPED_TASKS_WITHOUT_FORCE','priorJournalsPreserved':False,'containerLifecycleOperations':None}
        claim={'approvalRef':m.APPROVAL,'approvedAt':1791552018,'evidenceDirectory':str(m.EVIDENCE),'tasks':{m.A:{},m.S:{}}}
        value=m.retained_summary(result,claim)
        self.assertIsNone(value['containerLifecycleOperations']);self.assertFalse(value['priorJournalsPreserved'])
        changed=copy.deepcopy(result);changed['wrapperRestored']=False
        with self.assertRaises(m.Denied):m.retained_summary(changed,claim)
        changed=copy.deepcopy(claim);changed['approvalRef']='OTHER'
        with self.assertRaises(m.Denied):m.retained_summary(result,changed)
    def test_task_absence_and_partial_presence_are_reported_separately(self):
        rows=m.task_inventory(('TASK PID STATUS\n'+m.A+' 123 STOPPED\n').encode())
        self.assertTrue(rows[m.A]['present']);self.assertFalse(rows[m.S]['present'])
        self.assertEqual(rows[m.A]['status'],'STOPPED')
        with self.assertRaises(m.Denied):m.task_inventory(('TASK PID STATUS\n'+m.A+' 123 STOPPED\n'+m.A+' 123 STOPPED\n').encode())
    def test_log_paths_tokens_unknown_words_and_fake_reasons_are_not_disclosed(self):
        raw='failed delete /etc/private/credential KEY=TOPSECRET UNKNOWNSECRET ABC_UNREVIEWED_REASON OUF_TERMINAL_DELETE_GATE=DENIED REASON=ROOT_GATE_FILE_REQUIRED exit status 1'
        value=m.safe_text(raw);out=json.dumps(value)
        for secret in ('/etc/private/credential','TOPSECRET','UNKNOWNSECRET','ABC_UNREVIEWED_REASON'):self.assertNotIn(secret,out)
        self.assertEqual(value['gateReasons'],['ROOT_GATE_FILE_REQUIRED']);self.assertFalse(value['rawLogPrinted'])
    def test_gate_reason_requires_exact_symbol_boundary(self):
        self.assertEqual(m.safe_text('PREFIX_ROOT_GATE_FILE_REQUIRED_SUFFIX')['gateReasons'],[])
        self.assertEqual(m.safe_text('ROOT_GATE_FILE_REQUIRED')['gateReasons'],['ROOT_GATE_FILE_REQUIRED'])
    def test_no_mutating_file_or_subprocess_entrypoint(self):
        tree=ast.parse(Path(m.__file__).read_text())
        attrs={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
        self.assertFalse(attrs & {'write_bytes','write_text','chmod','mkdir','unlink','replace','rename','acknowledge','publish','kill','terminate','Popen'})
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='command']
        self.assertEqual(len(calls),4)
        flattened=[ast.unparse(n) for n in calls]
        self.assertTrue(any("['tasks', 'list']" in v for v in flattened))
        self.assertTrue(any("['containers', 'info', cid]" in v for v in flattened))
        self.assertTrue(any("'list', '--format', 'json'" in v for v in flattened))
        self.assertTrue(any("'--lines=500'" in v for v in flattened))
        for value in flattened:
            for forbidden in ("'delete'","'kill'","'start'","'create'","'exec'"):self.assertNotIn(forbidden,value)
if __name__=='__main__':unittest.main()
