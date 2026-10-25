#!/usr/bin/env python3
"""Installation-specific residual recovery; original13APPLIED stages never replayed."""
import copy,hashlib,json,os,re,signal,stat,sys,types
from pathlib import Path
NATIVE_HASH='5fa62e4f6869a6f40fb512878dcf65dcb6ffaf941be487e4189826f418046591'
ORIGINAL=Path('/etc/ouf/deploy-snapshots/acquisition-read-apply-'+NATIVE_HASH+'/terminal-continuation-v1')
REVIEW_HASH='7fcbce1f43fd99b4add8db9913b3dc2fe215836f16eecd8e8191f9e344e54aa9'
JOURNAL_HASH='1fb1159ada9d78123d1a90985e8c6ba23a18648bd3b3f621406c43dc9f57817d'
RECEIPT_HASH='7db79ea88e7f4ecf72dec889a8753afb40a53890573615bcebbf0b2fbc67e0f9'
EVIDENCE_HASH='e6b8642e1c04f510eabdddc6d038a87c9575e65be060928bf9981bd631eb4af2'
COUNTS={'adminGets':2,'adminPuts':0,'engineGets':128,'engineWrites':14,'imageLoadAttempts':3,'ownerConfigurationReads':42,'quarantineStops':2,'readinessGets':2,'serviceCredentialFileReads':2}
CHILD='detached-mcp-recovery-v1'
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def source(path):
    require(path.is_absolute()and path.resolve()==path,'CANONICAL_CONTINUATION_SOURCE_REQUIRED')
    for p in path.parents:
        s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_CONTINUATION_SOURCE_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);frame=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and 0<s.st_size<=131072,'ROOT_IMMUTABLE_CONTINUATION_SOURCE_REQUIRED');raw=os.read(fd,s.st_size+1)
        require(len(raw)==s.st_size and frame(s)==frame(os.fstat(fd))==frame(path.lstat()),'CONTINUATION_SOURCE_CHANGED');return raw
    finally:os.close(fd)
def base_module(code):
    manifest=json.loads(source(code/'sources.json'));require('recovery.py'in manifest and hashlib.sha256(source(Path(__file__).resolve())).hexdigest()==manifest['recovery.py'],'EXACT_RECOVERY_ENTRY_SOURCE_REQUIRED')
    raw=source(code/'apply.py');require(hashlib.sha256(raw).hexdigest()==manifest['apply.py'],'EXACT_RECOVERY_BASE_SOURCE_REQUIRED')
    m=types.ModuleType('sealed_detached_recovery_base');m.__file__=str(code/'apply.py');sys.modules[m.__name__]=m;exec(compile(raw,m.__file__,'exec'),m.__dict__);return m
def context_class(base):
    class Context(base.Context):
        def __init__(self,parts,auth,sign,journal,closure,*,original=ORIGINAL,review_hash=REVIEW_HASH,journal_hash=JOURNAL_HASH,receipt_hash=RECEIPT_HASH,evidence_hash=EVIDENCE_HASH,expected_counts=COUNTS,native_path=base.NATIVE,native_hash=NATIVE_HASH):
            self.core,self.http,self.ports_module,self.watch,self.engine_helpers,self.p,self.images,self.preparer=[parts[k]for k in('protocol','transport','ports','quarantine','engine_creation','plan_helper','image_custody','native_prepare')];self.mac=parts['retained_mac'];self.runtime=parts['runtime'];self.auth,self.sign,self.journal_module=auth,sign,journal;self.closure=copy.deepcopy(closure);self.original=Path(original);self.root=self.original/CHILD;self.native_path=Path(native_path);self.NATIVE_HASH=native_hash;self.serial=0;self.key=None;self.execution=None;self.limits=self.core.RECOVERY_LIMITS
            self.p.ancestry(self.original);require(not os.path.lexists(self.root),'DETACHED_RECOVERY_SCOPE_CONSUMED_NO_REPLAY')
            self.old_review=self.read(self.original/'review.json',review_hash);self.history=self.read(self.original/'recovery.json',journal_hash);self.receipt=self.read(self.original/'retained-old-mcp-guard-v1/complete.json',receipt_hash);evidence=self.read(self.original/'retained-old-mcp-guard-v1/private-evidence.json',evidence_hash)
            r=self.receipt;h=self.history
            require(r['status']=='RETAINED_OLD_MCP_GUARD_DIFFERENCE_OBSERVED'and r['complete']is True and r['reviewHash']==review_hash and r['journalHash']==journal_hash and r['privateEvidenceHash']==evidence_hash and r['recordedCounts']==expected_counts and r['guardChecks']=={'image':True,'config':False,'mounts':True,'startedAt':True}and r['negativeJournalState']=='APPLIED'and r['negativeCandidateStopsProvenInRetainedJournal']==['ingestion','udp']and r['renameClaimed']is False and r['newMcpCreated']is False,'EXACT_OBSERVED_DETACHED_MAC_RECEIPT_REQUIRED')
            require(h['reviewHash']==review_hash and h['counts']==expected_counts and h['nextStage']==13 and h['state']=='STOP_RECONCILE'and len(h['effects'])==13 and h['quarantine']['state']=='APPLIED'and set(h['candidates'])=={'ingestion','udp'}and self.old_review['maximums']==self.core.CONTINUATION_LIMITS and self.old_review['executionRoot']==str(self.original)and self.old_review['logicalOperationRef']==native_hash and h['authorityHash']==r['authorityHash'],'EXACT_STOPPED_PREFIX_AND_NEGATIVE_REQUIRED')
            for i,e in enumerate(h['effects']):require(e['stage']==self.old_review['stages'][i]and e['state']=='APPLIED'and e['intentHash']==self.core.digest({'reviewHash':review_hash,'stage':e['stage']}),'EXACT_RETAINED_APPLIED_INTENTS_REQUIRED')
            require(h['effects'][-1]['proof'].get('oldDetached')is True and h['effects'][-2]['proof'].get('oldStopped')is True,'PROVEN_OLD_STOP_DETACH_REQUIRED')
            self.seals={}
            for path,digest in evidence['fileHashes'].items():
                raw=self.p.protected(Path(path),digest);self.seals[path]=list(self.p.frame(Path(path).lstat()))
            for path,digest in self.old_review['sourceClosure'].items():self.p.protected(Path(path),digest);self.closure[path]=digest
            for path in(self.original/'review.json',self.original/'recovery.json',self.original/'retained-old-mcp-guard-v1/complete.json',self.original/'retained-old-mcp-guard-v1/private-evidence.json'):self.seals[str(path)]=list(self.p.frame(path.lstat()))
            self.counts=copy.deepcopy(expected_counts);self.native=self.read(self.native_path,native_hash);require(self.native['schema']=='ouf.acquisition-native-execution-inputs.v1'and self.p.digest(self.native['nativeProposal'])==self.native['nativeProposalHash']and self.native['frozenPlanHash']==self.preparer.PLAN_HASH,'EXACT_NATIVE_RECOVERY_IMAGE_INPUT_REQUIRED');self.proposal=copy.deepcopy(self.old_review['nativePlan']['proposal']);self.inputs=self.read(self.p.INPUTS,self.proposal['capturedInputsHash'])
            ref=self.inputs['currentObservations']['mcp'];self.original_mcp=self.read(ref['path'],ref['sha256']);self.mac_policy=self.mac.policy(self.original_mcp);self.read_started={}
            selected=sorted((p for p in evidence['fileHashes']if Path(p).parent==self.original and re.fullmatch('engine-response-[0-9]{4}.json',Path(p).name)),key=lambda p:int(Path(p).name[-9:-5]))
            for path in selected:
                value=self.read(path,evidence['fileHashes'][path]);body=value.get('body')
                if value.get('status')!=200 or type(body)is not dict:continue
                for role,candidate in h['candidates'].items():
                    if body.get('Id')==candidate['id']:self.read_started[role]=body['State']['StartedAt']
            require(set(self.read_started)=={'ingestion','udp'},'RETAINED_READ_GENERATIONS_REQUIRED');self.adopted={}
            for role,candidate in h['candidates'].items():
                created=next(e for e in h['effects']if e['stage']=='CREATE_'+role.upper()+'_READ');q=h['quarantine']['candidates'][role]
                require(created['proof']['createdId']==candidate['id']==q['id']and candidate['configurationVerified']is True and candidate['readinessProven']is True and q['stopped']is True and q['restartDisabled']is True and candidate['id']not in{v['containerId']for v in self.proposal['existingApplications'].values()},'ONLY_PREVIOUSLY_CREATED_AND_QUARANTINED_READ_ADOPTION')
                self.adopted[role]={'id':candidate['id'],'configurationVerified':True,'generation':None,'readinessProven':False,'retainedGeneration':candidate.get('generation'),'retainedReadinessProven':True,'originJournalHash':journal_hash}
            self.recovery={'originalExecutionRoot':str(self.original),'originalReviewHash':review_hash,'journalHash':journal_hash,'diagnosticReceiptHash':receipt_hash,'privateEvidenceHash':evidence_hash,'retainedCounts':copy.deepcopy(expected_counts),'retainedMaximums':copy.deepcopy(self.core.CONTINUATION_LIMITS),'retainedAppliedStages':13,'retainedQuarantineApplied':True,'adoptedIds':{k:v['id']for k,v in self.adopted.items()},'legacyMacPolicy':self.mac_policy,'newPositiveWritesMaximum':8,'newNegativeWritesMaximum':6,'additionalCredentialFileReadsMaximum':1,'noOriginalStageReplay':True}
            self.old_names={p.name for p in self.original.iterdir()};require(len(self.old_names)<=1024,'BOUNDED_CONSUMED_HISTORY_REQUIRED');self.root.mkdir(mode=0o700);fd=os.open(self.original,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
            self.write(self.root,'preparation-claim.json',{'schema':'ouf.detached-mcp-residual-recovery-claim.v1','recovery':self.recovery,'proposedMaximums':self.limits,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False});self.write(self.root,'retained-history.json',h)
            self.engine=self.http.Engine(self.p,self.proposal['engineBinding']);self.refresh_authority();self.openssl=self.executable();self.runtime_binding=self.runtime_snapshot();self.check_sources()
        def check_sources(self):
            base.Context.check_sources(self)
            require({p.name for p in self.original.iterdir()}==self.old_names|{CHILD},'CONSUMED_HISTORY_ENTRY_SET_CHANGED')
            for path,metadata in self.seals.items():require(list(self.p.frame(Path(path).lstat()))==metadata,'CONSUMED_HISTORY_OR_DIAGNOSTIC_CHANGED')
        def reserve(self,kind):
            if self.execution is not None:self.watch.ensure_alive(self);return self.execution.reserve(kind)
            require(kind in('engineGets','ownerConfigurationReads')and self.counts[kind]<self.core.CONTINUATION_LIMITS[kind],'NO_NEW_BUDGET_OR_CREDENTIAL_BEFORE_TERMINAL_MANDATE');self.counts[kind]+=1;self.evidence('preflight-claim',{'kind':kind,'attempt':self.counts[kind],'previousCountsRetained':True})
        def current(self):
            from urllib.parse import quote
            for role,b in self.proposal['existingApplications'].items():
                s,v=self.preflight_get('/v1.44/containers/'+b['containerId']+'/json');require(s==200,'EXACT_RETAINED_OWNER_INSPECT_REQUIRED')
                if role=='mcp':self.mac.verify_detached(self.original_mcp,v,expected_name='/'+self.proposal['mcpReplacement']['name'])
                else:require(v['State']['Running']is True and self.p.stable_binding(v)==b and self.p.process_pin(v['State']['Pid'])==self.inputs['currentProcessPins'][role],'EXACT_UNCHANGED_ORIGINAL_WORKER_REQUIRED')
            for role,c in self.adopted.items():
                s,v=self.preflight_get('/v1.44/containers/'+c['id']+'/json');require(s==200 and v['State']['StartedAt']==self.read_started[role]and v['RestartCount']==0,'SAME_STOPPED_OWNED_READ_REQUIRED');self.candidate_configuration(role,v,False,False)
            s,_=self.preflight_get('/v1.44/containers/'+self.proposal['mcpReplacement']['retiredName']+'/json');require(s==404,'RETAINED_NAME_ALREADY_TAKEN')
            s,info=self.preflight_get('/v1.44/info');require(s==200 and self.preparer.identity_profile(info)==self.native['imageIdentityProfile'],'SAME_CURRENT_RECOVERY_ENGINE_IMAGE_PROFILE_REQUIRED')
            for fact in self.native['candidateFacts'].values():
                s,v=self.preflight_get('/v1.44/images/'+quote(fact['nativeImageId'],safe='')+'/json');require(s==200,'ALREADY_IMPORTED_NATIVE_IMAGE_REQUIRED_NO_REIMPORT');self.images.loaded(fact['audit'],v)
            self.check_sources();self.check_owner_configuration(self.reserve);self.admission()
        def load_admin_key(self):
            require(self.execution is not None and self.key is None,'SIGNED_RECOVERY_REQUIRED_BEFORE_CREDENTIAL_READ');row=self.execution.record();require(row['nextStage']==0 and row['effects'][0]['stage']=='LOAD_EXISTING_ADMIN_KEY'and row['effects'][0]['state']=='CLAIMED','CLAIMED_RECOVERY_CREDENTIAL_READ_REQUIRED');base.Context.load_admin_key(self)
        def admin(self,method,path,body=None):
            require(self.execution is not None and self.key is not None,'NO_ADMIN_BEFORE_SIGNED_RECOVERY');self.execution.gate.check();return base.Context.admin(self,method,path,body)
    return Context
def ports_class(base_ports):
    class Ports(base_ports.NativePorts):
        def initial_candidates(self):
            self.require({k:v['id']for k,v in self.ctx.adopted.items()}==self.review['recovery']['adoptedIds'],'SIGNED_OWNED_ADOPTION_REQUIRED');return copy.deepcopy(self.ctx.adopted)
        def old_guard(self,stage):
            old=self.plan['mcpReplacement'];v=self.container(old['oldBinding']['containerId']);name=old['name']if self.stages.index(stage)<=self.stages.index('RENAME_OLD_MCP')else old['retiredName'];self.ctx.mac.verify_detached(self.ctx.original_mcp,v,expected_name='/'+name);self.require(v['Id']not in(self.network('mcp').get('Containers')or{}),'OLD_ENDPOINT_REMAINS_DETACHED');return v
        def candidate_guard(self,role,stage=None,started=None,restored=None,actual=None):
            row=self.execution.record()['candidates'][role];v=actual or self.container(row['id']);self.require(role=='mcp'or row['id']==self.review['recovery']['adoptedIds'][role],'EXACT_SIGNED_ADOPTED_CID_REQUIRED');i=self.stages.index(stage)if stage else -1
            if started is None:started=i>self.stages.index('START_MCP'if role=='mcp'else'RESTART_'+role.upper()+'_READ')
            if restored is None:restored=i>self.stages.index('RESTORE_'+role.upper()+'_RESTART')
            self.ctx.candidate_configuration(role,v,started,restored)
            if role!='mcp'and not started:self.require(v['State']['StartedAt']==self.ctx.read_started[role]and v['RestartCount']==0,'UNCHANGED_STOPPED_OWNED_READ_GENERATION_REQUIRED')
            if started:
                pin=self.ctx.p.process_pin(v['State']['Pid']);self.require(row.get('generation')is None or pin==row['generation'],'RECOVERED_OWNED_GENERATION_CHANGED')
                if row.get('generation')is None:self.execution.candidate(role,generation=pin)
            return v
        def assert_write(self,path,body):
            row=self.execution.record();i=row['nextStage'];stage=self.stages[i]
            if stage.startswith('RESTART_'):
                self.require(len(row['effects'])==i+1 and row['effects'][-1]['state']=='CLAIMED','CLAIMED_OWNED_RESTART_REQUIRED');role=stage.split('_')[1].lower();self.require(path=='/v1.44/containers/'+self.review['recovery']['adoptedIds'][role]+'/start'and body is None,'ONLY_SIGNED_ADOPTED_READ_RESTART_ALLOWED');return
            return super().assert_write(path,body)
        def execute(self,stage):
            row=self.execution.record();self.require(self.stages[row['nextStage']]==stage and len(row['effects'])==row['nextStage']+1 and row['effects'][-1]['state']=='CLAIMED','SIGNED_CLAIMED_RESIDUAL_STAGE_REQUIRED')
            if stage=='LOAD_EXISTING_ADMIN_KEY':self.ctx.load_admin_key();return{'cumulativeCredentialReads':self.execution.record()['counts']['serviceCredentialFileReads']}
            if stage=='VERIFY_RESIDUAL_ADMISSION':self.ctx.admission();return self.routes(0)
            if stage.startswith('RESTART_'):return self.start(stage.split('_')[1].lower())
            if stage=='VERIFY_RESTARTED_READ_REPLICAS':return{r:self.healthy(r)for r in('ingestion','udp')}
            return super().execute(stage)
        def final_result(self):return{**super().final_result(),'retainedAppliedStages':13,'restartedOwnQuarantinedReads':2,'retainedJournalHash':self.review['recovery']['journalHash'],'originalScopeUnchanged':True}
    return Ports
def prepare_review(ctx):
    ctx.current();c=ctx.core;plan={'frozenPlanHash':ctx.native['frozenPlanHash'],'nativeInputsHash':ctx.NATIVE_HASH,'runtimeBinding':ctx.runtime_binding,'runtimeBindingHash':c.digest(ctx.runtime_binding),'proposal':ctx.proposal,'recovery':ctx.recovery,'legacyConfigMacDetachPolicy':ctx.mac_policy}
    review=copy.deepcopy(ctx.old_review);review.pop('continuation',None);review.update(schema='ouf.acquisition-detached-mcp-recovery-review.v1',executionRoot=str(ctx.root),nativePlan=plan,nativePlanHash=c.digest(plan),recovery=ctx.recovery,maximums=copy.deepcopy(ctx.limits),stages=list(c.RECOVERY_STAGES),preflightCounts=copy.deepcopy(ctx.counts),sourceClosure=ctx.closure,sourceClosureHash=c.digest(ctx.closure),verification={'trustPolicy':ctx.native['publicAuthority']['trustPolicy'],'openssl':ctx.openssl,'context':ctx.native['publicAuthority']['context']});c.validate_review(review);ctx.write(ctx.root,'review.json',review);return review
def operator(base,ctx):
    c=ctx.core;review=prepare_review(ctx);decision=c.terminal_decision(review,ctx.root/'review.json');ctx.read(ctx.root/'review.json',c.digest(review));ctx.current();ctx.refresh_authority();gate=c.issue(review,ctx.root,ctx.profile,decision,ctx.write,ctx.read);ports=ports_class(ctx.ports_module)(ctx,review,gate);execution=c.Execution(gate,ctx.journal_module.Journal(ctx.root),ports);execution.initialize();ctx.execution=execution
    print(c.encoded({'schema':'ouf.acquisition-detached-recovery-issued.v1','reviewHash':c.digest(review),'authorityHash':c.sha(gate.raw),'runtimeAuthorityIssued':True,'runtimeEffectsDispatched':0,'retainedAppliedStages':13,'automaticReplayAllowed':False,'budgetReset':False}).decode(),flush=True)
    try:ctx.watch.launch(ctx,review,gate,execution.journal);result=execution.run()
    except BaseException:
        try:ctx.watch.negative(ctx,review,gate.raw,execution.journal,'RESIDUAL_RECOVERY_STOPPED')
        except BaseException:ctx.write(ctx.root,'quarantine-unproven.json',{'status':'STOP_RECONCILE','negativeEffectMayBePartial':True,'automaticReplayAllowed':False})
        raise
    return base.finalize(ctx,review,gate,result)
def main():
    ctx=None
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ONE_ISOLATED_ROOT_RESIDUAL_RECOVERY_REQUIRED')
        def interrupted(*_):raise Stop('RESIDUAL_RECOVERY_INTERRUPTED_RECONCILE_ONLY')
        for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
        base=base_module(Path(__file__).resolve().parent);ctx=context_class(base)(*base.components());result=operator(base,ctx)
    except Exception as error:
        reason=str(error)if re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'RESIDUAL_RECOVERY_UNPROVEN';result={'schema':'ouf.acquisition-read-native-result.v1','status':'STOP_RECONCILE','reasonCode':reason,'complete':False,'contextPath':str(ctx.root)if ctx else None,'runtimeEffectsMayBePartial':True,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False,'credentialValuesPrinted':False,'addressesPrinted':False,'humanBudgetsGranted':0,'sourceActivations':0}
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True);return 0 if result.get('complete')else 2
if __name__=='__main__':raise SystemExit(main())
