import hashlib,importlib.util,json,os,re,shutil,subprocess,tempfile,time,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
bundle=module('bundle',BASE/'tools/acquisition_read_native/bundle.py')
@unittest.skipUnless(os.environ.get('OUF_APPLY_ROOT_FIXTURE')=='1','root crypto fixture requires dedicated CI')
class Protocol(unittest.TestCase):
    def setUp(self):
        import sys
        for name in list(sys.modules):
            if name=='tools'or name.startswith('tools.')or name.startswith('sealed_acquisition_'):del sys.modules[name]
        self.tmp=tempfile.TemporaryDirectory(dir='/var/lib');self.root=Path(self.tmp.name);self.code=self.root/'code';bundle.stage(BASE,self.code);self.entry=module('entry_'+str(time.time_ns()),self.code/'apply.py');saved=self.entry.Context;self.entry.Context=lambda parts,auth,sign,journal,closure:(parts,auth,sign,journal,closure)
        try:self.parts,self.auth,self.sign,self.journal,self.closure=self.entry.bootstrap()
        finally:self.entry.Context=saved
        self.core=self.parts['protocol'];self.p=self.parts['plan_helper'];self.execution_root=self.root/'execution';self.execution_root.mkdir(mode=0o700);self.policy_path=self.root/'policy';self.context={'installationRef':'ci-installation','entityRef':'ci-entity','intentIssuerRef':'ci-installer','approvalIssuerRef':'ci-installer','attestorRef':'ci-attestor'};self.profile={'keyBindings':{},'keyRefs':{}}
        keys=[];now=int(time.time())
        for role,issuer,roles in(('installer','ci-installer',['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),('attestor','ci-attestor',['CREATION_ATTESTATION'])):
            key=self.root/(role+'.key');subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);key.chmod(0o600);der=subprocess.check_output(['/usr/bin/openssl','pkey','-in',str(key),'-pubout','-outform','DER']);self.profile['keyBindings'][role]={'path':str(key),'sha256':hashlib.sha256(key.read_bytes()).hexdigest()};self.profile['keyRefs'][role]='ci-key-'+role;keys.append({'keyRef':'ci-key-'+role,'issuerRef':issuer,'roles':roles,'publicKey':der[-32:].hex(),'notBefore':now-5,'expiresAt':now+3600,'state':'ACTIVE'})
        policy={'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':'ci-installation','entityRef':'ci-entity','keys':keys};self.policy_path.write_bytes(self.core.encoded(policy));self.policy_path.chmod(0o600);openssl=Path('/usr/bin/openssl').resolve();version=re.match(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b',subprocess.check_output([str(openssl),'version']))[1].decode();self.verification={'trustPolicy':{'path':str(self.policy_path),'sha256':hashlib.sha256(self.policy_path.read_bytes()).hexdigest()},'openssl':{'path':str(openssl),'sha256':hashlib.sha256(openssl.read_bytes()).hexdigest(),'version':version},'context':self.context}
        plan={'frozenPlanHash':'a'*64};self.review={'schema':'ouf.acquisition-read-native-review.v1','executionRoot':str(self.execution_root),'frozenPlanHash':'a'*64,'nativePlan':plan,'nativePlanHash':self.core.digest(plan),'sourceClosure':self.closure,'sourceClosureHash':self.core.digest(self.closure),'logicalOperationRef':'b'*64,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'maximumSeconds':900,'maximums':self.core.LIMITS,'stages':list(self.core.STAGES),'negativeCleanup':{'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':3,'disableCandidateRestartFirst':True},'preflightCounts':{k:0 for k in self.core.LIMITS},'verification':self.verification,'databaseRestoreAuthorized':False,'humanBudgetOrSourceActivationAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    def tearDown(self):self.tmp.cleanup()
    def write(self,root,name,value):self.p.put(Path(root)/name,value)
    def read(self,path,expected):return self.p.decode(self.p.protected(Path(path),expected))
    def issue(self):return self.core.issue(self.review,self.execution_root,self.profile,{'reviewHash':self.core.digest(self.review),'decision':self.core.DECISION,'approvedAt':int(time.time())},self.write,self.read)
    def ports(self,fail=False):
        outer=self
        class Ports:
            root=outer.execution_root
            ctx=type('C',(),{'counts':{k:0 for k in outer.core.LIMITS}})()
            def guard(self,stage):pass
            def execute(self,stage):
                self.execution.reserve('engineGets')
                if fail:raise outer.core.Stop('AMBIGUOUS_CI_EFFECT')
                return {'closedFixtureEffect':True}
            def final_result(self):return {'complete':True}
        return Ports()
    def test_real_dual_signatures_and_ordered_protocol(self):
        gate=self.issue();ports=self.ports();execution=self.core.Execution(gate,self.journal.Journal(self.execution_root),ports);execution.initialize();self.assertTrue(execution.run()['complete']);row=execution.journal.read();self.assertEqual(row['state'],'COMPLETE');self.assertEqual(len(row['effects']),23);self.assertEqual(row['counts']['engineGets'],23)
    def test_ambiguous_effect_is_durably_claimed_and_never_replayed(self):
        gate=self.issue();ports=self.ports(True);e=self.core.Execution(gate,self.journal.Journal(self.execution_root),ports);e.initialize()
        with self.assertRaisesRegex(self.core.Stop,'AMBIGUOUS_CI_EFFECT'):e.run()
        before=e.journal.read()
        with self.assertRaisesRegex(self.core.Stop,'NO_REPLAY'):e.run()
        self.assertEqual(before,e.journal.read());self.assertEqual(before['effects'][0]['state'],'CLAIMED')
    def test_live_policy_revocation_blocks_positive_execution(self):
        gate=self.issue();self.policy_path.chmod(0o600);self.policy_path.write_bytes(b'{}')
        with self.assertRaises(Exception):gate.check()
    def test_forged_or_stale_terminal_decision_does_not_sign(self):
        for decision in({'reviewHash':'0'*64,'decision':self.core.DECISION,'approvedAt':int(time.time())},{'reviewHash':self.core.digest(self.review),'decision':self.core.DECISION,'approvedAt':int(time.time())-121}):
            with self.assertRaises(self.core.Stop):self.core.issue(self.review,self.execution_root,self.profile,decision,self.write,self.read)
        self.assertFalse((self.execution_root/'authority').exists())
    def test_negative_scope_signature_survives_live_policy_removal(self):
        gate=self.issue();snapshot=self.execution_root/'authority/issued-trust-policy.json';v=self.auth.DetachedAuthenticator({'path':str(snapshot),'sha256':self.verification['trustPolicy']['sha256']},str(snapshot.parent),self.verification['openssl']);self.policy_path.unlink();c=self.context
        for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):self.assertTrue(v(gate.raw,role,c[key],c['installationRef'],c['entityRef']))
    def test_bounded_journal_contention_retries_no_effect(self):
        gate=self.issue();ports=self.ports();e=self.core.Execution(gate,self.journal.Journal(self.execution_root),ports);e.initialize();original=e.journal.read;attempts=[]
        def busy():
            attempts.append(1)
            if len(attempts)==1:raise BlockingIOError()
            return original()
        e.journal.read=busy;row=e.record();self.assertEqual(row['effects'],[]);self.assertEqual(row['counts']['engineWrites'],0);self.assertEqual(len(attempts),2)
    def test_monitor_retries_only_proven_atomic_unlink_race(self):
        from unittest.mock import patch
        journal=self.journal.Journal(self.execution_root);journal.initialize({'version':0,'counts':{'unchanged':9}})
        real_fstat=os.fstat;old_inode=journal.record.stat().st_ino;replaced=[]
        def replace_during_fstat(fd):
            s=real_fstat(fd)
            if s.st_ino==old_inode and not replaced:
                replaced.append(True);path=self.execution_root/'next-record';journal.create(path,self.core.encoded({'version':1,'counts':{'unchanged':9}}));os.replace(path,journal.record);journal.sync();return real_fstat(fd)
            return s
        with patch.object(self.journal.os,'fstat',replace_during_fstat):self.assertEqual(journal.published_snapshot(),{'version':1,'counts':{'unchanged':9}})
        self.assertEqual(replaced,[True]);os.link(journal.record,self.execution_root/'hardlink')
        with self.assertRaisesRegex(ValueError,'CUSTODY'):journal.published_snapshot()
    def test_legacy_monitor_race_reproduced_with_real_filesystem(self):
        from unittest.mock import patch
        journal=self.journal.Journal(self.execution_root);journal.initialize({'version':0});real_fstat=os.fstat;old_inode=journal.record.stat().st_ino;replaced=[]
        def replace_during_fstat(fd):
            s=real_fstat(fd)
            if s.st_ino==old_inode and not replaced:
                replaced.append(True);path=self.execution_root/'next-record';journal.create(path,self.core.encoded({'version':1}));os.replace(path,journal.record);return real_fstat(fd)
            return s
        with patch.object(self.journal.os,'fstat',replace_during_fstat):
            with self.assertRaisesRegex(ValueError,'RECOVERY_FILE_CUSTODY_REQUIRED'):journal.private_read()
    def test_monitor_read_replacement_race_is_bounded(self):
        from unittest.mock import patch
        journal=self.journal.Journal(self.execution_root);journal.initialize({'version':0});real_fstat=os.fstat;replaced=[]
        def replace_during_fstat(fd):
            s=real_fstat(fd)
            if s.st_ino==journal.record.stat().st_ino:
                replaced.append(True);path=self.execution_root/('next-record-'+str(len(replaced)));journal.create(path,self.core.encoded({'version':len(replaced)}));os.replace(path,journal.record);return real_fstat(fd)
            return s
        with patch.object(self.journal.os,'fstat',replace_during_fstat):
            with self.assertRaisesRegex(ValueError,'CONTENTION_EXHAUSTED'):journal.published_snapshot()
        self.assertEqual(len(replaced),8)
    def test_runtime_monitor_short_transaction_blocks_publisher_unlink(self):
        from unittest.mock import patch
        import select
        journal=self.journal.Journal(self.execution_root);journal.initialize({'version':0,'counts':{'retained':128}})
        go_r,go_w=os.pipe();ack_r,ack_w=os.pipe();child=os.fork()
        if child==0:
            try:
                os.close(go_w);os.close(ack_r);os.read(go_r,1)
                old={'version':0,'counts':{'retained':128}};following={'version':1,'counts':{'retained':129}}
                try:journal.compare_and_save(old,following);os._exit(3)
                except BlockingIOError:os.write(ack_w,b'LOCKED')
                for _ in range(100):
                    try:journal.compare_and_save(old,following);os._exit(0)
                    except BlockingIOError:time.sleep(.01)
                os._exit(4)
            except BaseException:os._exit(5)
        os.close(go_r);os.close(ack_w);real_fstat=os.fstat;record_inode=journal.record.stat().st_ino;checked=[]
        def observe_lock(fd):
            s=real_fstat(fd)
            if s.st_ino==record_inode and not checked:
                checked.append(True);os.write(go_w,b'G');self.assertTrue(select.select([ack_r],[],[],2)[0]);self.assertEqual(os.read(ack_r,16),b'LOCKED')
            return s
        try:
            with patch.object(self.journal.os,'fstat',observe_lock):row=self.parts['quarantine'].read(journal)
            self.assertEqual(row,{'version':0,'counts':{'retained':128}});_,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),0);self.assertEqual(self.parts['quarantine'].read(journal)['version'],1)
            os.link(journal.record,self.execution_root/'forbidden-hardlink')
            with self.assertRaisesRegex(ValueError,'CUSTODY'):self.parts['quarantine'].read(journal)
        finally:
            os.close(go_w);os.close(ack_r)
            try:os.kill(child,9);os.waitpid(child,0)
            except (ProcessLookupError,ChildProcessError):pass
    def test_runtime_monitor_and_publisher_stress_retains_exact_counts(self):
        journal=self.journal.Journal(self.execution_root);journal.initialize({'version':0,'counts':{'retained':128}});child=os.fork()
        if child==0:
            try:
                for n in range(200):
                    old={'version':n,'counts':{'retained':128+n}};following={'version':n+1,'counts':{'retained':129+n}}
                    for attempt in range(128):
                        try:journal.compare_and_save(old,following);time.sleep(.005);break
                        except BlockingIOError:time.sleep(.001)
                    else:os._exit(3)
                os._exit(0)
            except BaseException:os._exit(4)
        try:
            seen=[];deadline=time.monotonic()+10
            while True:
                row=self.parts['quarantine'].read(journal);seen.append(row['version']);self.assertEqual(row['counts']['retained'],128+row['version'])
                if row['version']==200:break
                self.assertLess(time.monotonic(),deadline)
                time.sleep(.002)
            _,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),0);self.assertEqual(seen,sorted(seen))
        finally:
            try:os.kill(child,9);os.waitpid(child,0)
            except (ProcessLookupError,ChildProcessError):pass
    def test_oom_enabled_default_never_allows_disabling_oom(self):
        match=self.parts['engine_creation'].requested_host_config_matches
        self.assertTrue(match({'Memory':536870912,'OomKillDisable':None},{'Memory':536870912,'OomKillDisable':False},started=True))
        self.assertFalse(match({'Memory':536870912,'OomKillDisable':None},{'Memory':536870912,'OomKillDisable':True},started=True))
        self.assertFalse(match({'Memory':536870912,'OomKillDisable':None},{'Memory':1073741824,'OomKillDisable':False},started=True))
    def mac_guard_fixture(self):
        import copy,types
        before={'Id':'a'*64,'Image':'sha256:'+'b'*64,'Name':'/fixture-mcp','Config':{'MacAddress':'02:42:ac:44:01:07','Hostname':'fixture','Env':['PRIVATE=not-output']},'Mounts':[],'HostConfig':{'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0}},'State':{'Running':True,'Pid':123,'StartedAt':'generation'},'NetworkSettings':{'Networks':{'fixture':{'MacAddress':'02:42:ac:44:01:07'}}}}
        after=copy.deepcopy(before);del after['Config']['MacAddress'];after['HostConfig']['RestartPolicy']={'Name':'no','MaximumRetryCount':0};after['State'].update(Running=False,Pid=0);after['NetworkSettings']['Networks']={}
        binding={'containerId':before['Id'],'imageId':before['Image'],'configHash':self.core.digest(before['Config']),'mountsHash':self.core.digest([]),'startedAt':'generation'}
        old={'oldBinding':binding,'oldNativeHostConfig':before['HostConfig'],'name':'fixture-mcp','retiredName':'fixture-retained','network':{'id':'c'*64,'name':'fixture'}};plan={'mcpReplacement':old,'existingApplications':{'mcp':binding}}
        self.review['nativePlan']['proposal']=plan;self.review['nativePlan']['legacyConfigMacDetachPolicy']=self.parts['retained_mac'].policy(before);self.review['nativePlanHash']=self.core.digest(self.review['nativePlan'])
        ctx=types.SimpleNamespace(root=self.execution_root,core=self.core,mac=self.parts['retained_mac'],inputs={'currentObservations':{'mcp':{'path':'bound-original','sha256':self.core.digest(before)}}},read=lambda path,h:copy.deepcopy(before),evidence=lambda *a:None)
        ports=self.parts['ports'].NativePorts(ctx,self.review,None);ports.container=lambda cid:copy.deepcopy(after);ports.network=lambda role:{'Containers':{}}
        effects=[{'stage':s,'state':'APPLIED','proof':{'oldStopped':True,'oldDetached':True}}for s in self.core.STAGES];ports.execution=types.SimpleNamespace(record=lambda:{'effects':effects})
        return ports,after,effects
    def test_old_guard_mac_transition_requires_signed_policy_and_applied_detach(self):
        ports,after,effects=self.mac_guard_fixture();ports.old_guard('RENAME_OLD_MCP')
        self.review['nativePlan']['legacyConfigMacDetachPolicy']=None
        with self.assertRaisesRegex(self.core.Stop,'SIGNED_LEGACY_MAC'):ports.old_guard('RENAME_OLD_MCP')
        self.review['nativePlan']['legacyConfigMacDetachPolicy']=ports.ctx.mac.policy(ports.ctx.read('bound-original','unused'))
        effects[self.core.STAGES.index('DETACH_OLD_MCP')]['state']='CLAIMED'
        with self.assertRaisesRegex(self.core.Stop,'PROVEN_STOP_DETACH'):ports.old_guard('RENAME_OLD_MCP')
    def test_old_guard_rejects_mac_absence_before_detach_and_any_extra_config_change(self):
        ports,after,_=self.mac_guard_fixture()
        with self.assertRaisesRegex(self.core.Stop,'OLD_MCP_CONFIG_GENERATION'):ports.old_guard('DETACH_OLD_MCP')
        after['Config']['Hostname']='other'
        with self.assertRaisesRegex(self.core.Stop,'ONLY_PROVEN_LEGACY_MAC'):ports.old_guard('RENAME_OLD_MCP')
    def continuation_review(self):
        root=self.execution_root;child=root/'terminal-continuation-v1';child.mkdir(mode=0o700)
        c={'originalExecutionRoot':str(root),'originalReviewHash':'c'*64,'reconciliationReceiptHash':'d'*64,'retainedPreflightCounts':self.core.RETAINED_COUNTS,'retainedMaximums':self.core.LIMITS,'maximumAdditionalCredentialFileReads':1,'cumulativeCredentialReadMaximum':2,'noOriginalScopeReplay':True,'preConsentUsesRetainedRouteSnapshot':True,'freshRoutesRequiredBeforeFirstMutation':True}
        self.review.update(schema='ouf.acquisition-read-continuation-review.v1',executionRoot=str(child),continuation=c,maximums=self.core.CONTINUATION_LIMITS,stages=['LOAD_EXISTING_ADMIN_KEY',*self.core.STAGES],preflightCounts=self.core.RETAINED_COUNTS)
        self.review['nativePlan']['continuation']=c;self.review['nativePlanHash']=self.core.digest(self.review['nativePlan']);self.execution_root=child
    def test_continuation_preserves_cumulative_counts_and_only_one_extra_read(self):
        self.continuation_review();gate=self.issue();ports=self.ports();ports.root=self.execution_root;ports.ctx.counts=copy_counts=dict(self.core.RETAINED_COUNTS);execution=self.core.Execution(gate,self.journal.Journal(self.execution_root),ports);execution.initialize()
        self.assertEqual(execution.record()['counts'],copy_counts);execution.reserve('serviceCredentialFileReads');self.assertEqual(execution.record()['counts']['serviceCredentialFileReads'],2)
        with self.assertRaisesRegex(self.core.Stop,'BUDGET_EXHAUSTED'):execution.reserve('serviceCredentialFileReads')
        row=execution.record();execution.save(row,counts={**row['counts'],'engineGets':0})
        with self.assertRaisesRegex(self.core.Stop,'DURABLE_ACQUISITION_BUDGET'):execution.record()
    def test_unreviewed_credential_ceiling_increase_is_denied(self):
        self.continuation_review();self.review['maximums']={**self.core.CONTINUATION_LIMITS,'serviceCredentialFileReads':3}
        with self.assertRaisesRegex(self.core.Stop,'EXACT_FINITE'):self.core.validate_review(self.review)
    def test_continuation_tty_discloses_extra_read_and_separate_exact_command(self):
        self.continuation_review();self.test_tty_requires_the_exact_current_review_hash()
    def test_tty_requires_the_exact_current_review_hash(self):
        import pty,select
        exact='APPROVO '+self.core.digest(self.review)
        for answer,expected_status in(('APPROVO '+'0'*64,2),(exact+' per la sola revisione esatta.',2),(exact,0)):
            pid,fd=pty.fork()
            if pid==0:
                try:
                    decision=self.core.terminal_decision(self.review,self.execution_root/'review.json');print(json.dumps(decision),flush=True);os._exit(0)
                except self.core.Stop as error:print('DENIED='+str(error),flush=True);os._exit(2)
            try:
                buffer=b'';deadline=time.monotonic()+10
                while b'> 'not in buffer:
                    self.assertLess(time.monotonic(),deadline);ready,_,_=select.select([fd],[],[],1)
                    if ready:buffer+=os.read(fd,65536)
                lines=buffer.decode().replace('\r\n','\n').splitlines()
                commands=[line for line in lines if line.startswith('APPROVO ')]
                self.assertEqual(commands,[exact])
                self.assertIn('Non aggiungere parole o punteggiatura',buffer.decode())
                if'continuation'in self.review:
                    self.assertIn('Limite cumulativo letture credenziale:2',buffer.decode())
                    self.assertIn('SOLO dopo questa approvazione',buffer.decode())
                if'recovery'in self.review:
                    self.assertIn('writes22->28',buffer.decode());self.assertIn('fileadmin2->3',buffer.decode())
                    self.assertIn('Nessun import, CREATE dei READ, STOP/DETACH',buffer.decode())
                    self.assertIn('solo dopo APPROVO/firme/claim',buffer.decode())
                os.write(fd,(answer+'\n').encode())
                while True:
                    ready,_,_=select.select([fd],[],[],1)
                    if not ready:
                        done,status=os.waitpid(pid,os.WNOHANG)
                        if done:break
                    else:
                        try:buffer+=os.read(fd,65536)
                        except OSError:done,status=os.waitpid(pid,0);break
                self.assertEqual(os.waitstatus_to_exitcode(status),expected_status)
            finally:os.close(fd)
    def test_unclaimed_and_wrong_stage_writes_never_dispatch(self):
        import types
        cid='c'*64;self.review['nativePlan']['proposal']={'mcpReplacement':{'oldBinding':{'containerId':cid}}};self.review['nativePlanHash']=self.core.digest(self.review['nativePlan']);gate=self.issue();ctx=types.SimpleNamespace(root=self.execution_root,core=self.core,counts={k:0 for k in self.core.LIMITS});ports=self.parts['ports'].NativePorts(ctx,self.review,gate);e=self.core.Execution(gate,self.journal.Journal(self.execution_root),ports);e.initialize()
        with self.assertRaisesRegex(self.core.Stop,'CLAIMED_SIGNED_STAGE'):ports.request('POST','/v1.44/containers/'+cid+'/stop?t=10')
        row=e.record();stage=self.core.STAGES[0];e.save(row,effects=[{'stage':stage,'state':'CLAIMED','intentHash':self.core.digest({'reviewHash':self.core.digest(self.review),'stage':stage})}])
        with self.assertRaisesRegex(self.core.Stop,'EXACT_SIGNED_STAGE_COMMAND'):ports.request('POST','/v1.44/containers/'+cid+'/stop?t=10')
        self.assertEqual(e.record()['counts']['engineWrites'],0)
    def test_entrypoint_and_namespace_child_fail_closed(self):
        result=subprocess.run([os.sys.executable,str(self.code/'apply.py')],capture_output=True,text=True);self.assertEqual(result.returncode,2);self.assertEqual(json.loads(result.stdout)['reasonCode'],'ONE_ISOLATED_ROOT_ACQUISITION_APPLY_REQUIRED');compile(self.parts['transport'].CHILD,'namespace-child','exec')
if __name__=='__main__':unittest.main()
