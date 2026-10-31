"""Actual isolated reader over root-protected synthetic retained files.

These fixtures qualify filesystem/retained comparison, not VPS state or recovery.
Only installation path/hash constants differ from the delivered program.
"""
import hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path

REPO=Path(__file__).resolve().parents[1]
SOURCE=REPO/'scripts/read-onboarding-v35-created-config-20261024.py'
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def write(path,value,mode=0o400):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.exists():path.chmod(0o600) # Only mutate disposable fixture evidence.
    path.write_bytes(encoded(value));path.chmod(mode)

class RetainedReaderTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual((os.geteuid(),os.getegid()),(0,0),'Root filesystem qualification must run, never skip')
        self.temp=tempfile.TemporaryDirectory(prefix='retained-fixture-',dir=REPO)
        self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name);self.parent=self.base/'snapshots';self.parent.mkdir(mode=0o700)
        self.logical='1'*64;self.cid='2'*64;self.old='3'*64;self.image='sha256:'+'4'*64
        self.root=self.parent/('onboarding-v35-apply-'+self.logical);self.root.mkdir(mode=0o700)
        self.frozen={'logicalOperationRef':self.logical,'proposedAuthorityDirectory':str(self.root)}
        self.mac='02:00:00:00:00:03' # disposable fixture only
        self.request={'Image':self.image,'Hostname':'fixture-name','Domainname':'','User':'10003:10003','Cmd':None,'Entrypoint':['java','-jar','/app/application.jar'],'WorkingDir':'/app','Env':['A=SECRET_ENV_VALUE'],'Labels':{'org.example.owner':'SECRET_LABEL_VALUE'},'MacAddress':self.mac,'HostConfig':{'RestartPolicy':{'Name':'no'}},'NetworkingConfig':{'EndpointsConfig':{}}}
        self.config={k:v for k,v in self.request.items()if k not in('HostConfig','NetworkingConfig')};self.config['MacAddress']=''
        self.plan={'replacement':{'request':self.request,'name':'fixture-onboarding','oldRuntimeBinding':{'containerId':self.old},'network':{'mac':self.mac}},'runtimeLabelProjection':{'expectedLabels':self.request['Labels']}}
        self.review={'frozenPlanHash':digest(self.frozen),'executionRoot':str(self.root),'logicalOperationRef':self.logical,'nativePlan':self.plan}
        self.authority={'scope':{'reviewHash':digest(self.review),'nativePlanHash':digest(self.plan)},'expiresAt':1}
        spec=importlib.util.spec_from_file_location('retained_fixture',SOURCE);self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        self.journal={'schema':'ouf.onboarding-v35-native-journal.v1','reviewHash':digest(self.review),'authorityHash':digest(self.authority),'nextStage':7,'createdId':self.cid,'createdConfigurationVerified':False,'createdGeneration':None,'automaticReplayAllowed':False,'budgetReset':False,'counts':{k:0 for k in self.module.LIMITS},'effects':[{'stage':stage,'state':'APPLIED'if i<7 else'CLAIMED','intentHash':digest({'reviewHash':digest(self.review),'stage':stage})}for i,stage in enumerate(self.module.STAGES)]}
        self.frozen_path=self.parent/'frozen/execution-plan.json';self.code=self.base/'reader';self.code.mkdir(mode=0o700)
    def stage(self):
        write(self.frozen_path,self.frozen);write(self.root/'review.json',self.review);write(self.root/'authority/authority.json',self.authority);write(self.root/'recovery.json',self.journal,0o600)
        old_config={**self.config,'MacAddress':self.mac}
        for number,status,body in [(1,200,{'Id':self.old,'Config':old_config}),(2,200,{'Id':self.image,'Config':{'MacAddress':''}}),(3,201,{'Id':self.cid,'Warnings':[]}),(4,200,{'Id':self.cid,'Name':'/fixture-onboarding','Image':self.image,'Config':self.config,'State':{'Running':False,'Pid':0}})]:write(self.root/('engine-response-%03d.json'%number),{'status':status,'body':body})
        text=SOURCE.read_text()
        replacements={'PARENT':repr(str(self.parent)),'FROZEN':repr(str(self.frozen_path)),'FROZEN_HASH':repr(digest(self.frozen)),'REVIEW_HASH':repr(digest(self.review)),'AUTHORITY_HASH':repr(digest(self.authority))}
        lines=text.splitlines()
        for key,value in replacements.items():
            indexes=[i for i,line in enumerate(lines)if line.startswith(key+'=')];self.assertEqual(len(indexes),1);lines[indexes[0]]=key+'='+value
        self.entry=self.code/'read.py';self.entry.write_text('\n'.join(lines)+'\n');self.entry.chmod(0o400)
    def run_entry(self):
        result=subprocess.run([sys.executable,'-I','-B','-S',str(self.entry)],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.stderr,'');self.assertNotIn('SECRET_',result.stdout);self.assertNotIn(self.mac,result.stdout);self.assertNotIn(self.cid,result.stdout)
        return result,json.loads(result.stdout)
    def snapshot(self):return {str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in self.root.rglob('*')if p.is_file()}
    def test_actual_entry_identifies_mac_difference_with_no_existing_file_changes(self):
        self.stage();before=self.snapshot();result,row=self.run_entry();self.assertEqual(result.returncode,0);self.assertEqual(before,self.snapshot())
        delta=row['retainedCandidateConfigDifferences'];self.assertEqual(len(delta),1);self.assertEqual(delta[0]['field'],'MacAddress');self.assertTrue(delta[0]['expectedMatchesReviewedEndpointMac']);self.assertTrue(delta[0]['observedEmpty'])
        self.assertEqual(row['retainedCumulativeCounts'],self.journal['counts']);self.assertFalse(row['currentRuntimeStateObserved']);self.assertFalse(row['historicalAuthorityReused']);self.assertEqual(row['retainedEffectStates'],['APPLIED']*7+['CLAIMED'])
        for key in ('engineGetAttempts','sqlSessionAttempts','containerExecAttempts','privateSigningKeysRead','credentialContentReads','oldJournalWrites'):self.assertEqual(row[key],0)
        first_claim=(self.code/'reader-claim.json').read_bytes();result,row=self.run_entry();self.assertEqual(result.returncode,2);self.assertEqual(row['status'],'STOP_RECONCILE');self.assertEqual(before,self.snapshot());self.assertEqual(first_claim,(self.code/'reader-claim.json').read_bytes())
    def test_actual_entry_null_empty_and_sensitive_env_order(self):
        self.config['Cmd']=[];self.config['Env']=['B=SECRET_OTHER','A=SECRET_ENV_VALUE'];self.request['Env']=['A=SECRET_ENV_VALUE','B=SECRET_OTHER'];self.plan['replacement']['request']=self.request
        self.review['nativePlan']=self.plan;self.authority['scope'].update(reviewHash=digest(self.review),nativePlanHash=digest(self.plan));self.journal.update(reviewHash=digest(self.review),authorityHash=digest(self.authority))
        for effect in self.journal['effects']:effect['intentHash']=digest({'reviewHash':digest(self.review),'stage':effect['stage']})
        self.stage();result,row=self.run_entry();self.assertEqual(result.returncode,0)
        by_field={d['field']:d for d in row['retainedCandidateConfigDifferences']};self.assertTrue(by_field['Cmd']['expectedNull']);self.assertTrue(by_field['Cmd']['observedEmpty']);self.assertTrue(by_field['Env']['equalIgnoringSequenceOrder'])
    def test_actual_entry_rejects_tampered_review_without_traceback(self):
        self.stage();write(self.root/'review.json',{'bad':'SECRET_TAMPER'});result,row=self.run_entry();self.assertEqual(result.returncode,2);self.assertEqual(row['reasonCode'],'EXACT_RETAINED_EVIDENCE_HASH_REQUIRED')
    def test_actual_entry_rejects_advanced_or_ambiguous_claim(self):
        self.journal['nextStage']=8;self.stage();result,row=self.run_entry();self.assertEqual(result.returncode,2);self.assertEqual(row['reasonCode'],'EXACT_PRESTART_CLAIMED_CREATE_REQUIRED')
    def test_actual_entry_rejects_symlink_evidence(self):
        self.stage();path=self.root/'recovery.json';target=self.root/'other.json';path.rename(target);path.symlink_to(target);result,row=self.run_entry();self.assertEqual(result.returncode,2);self.assertEqual(row['status'],'STOP_RECONCILE')
    def test_private_reader_detects_changed_bytes_and_wrong_permissions(self):
        self.stage();evidence=self.module.Evidence();path=self.root/'recovery.json';evidence.read(path);write(path,{**self.journal,'nextStage':8},0o600)
        with self.assertRaises(self.module.Stop):evidence.stable()
        path.chmod(0o644)
        with self.assertRaises(self.module.Stop):self.module.Evidence().read(path)
    def test_actual_entry_rejects_missing_create_evidence(self):
        self.stage();(self.root/'engine-response-003.json').unlink();result,row=self.run_entry();self.assertEqual(result.returncode,2);self.assertEqual(row['reasonCode'],'EXACT_RETAINED_CREATE_AND_INSPECT_REQUIRED')

if __name__=='__main__':unittest.main()
