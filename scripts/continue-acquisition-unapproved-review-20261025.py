#!/usr/bin/env python3
"""Continue only a reconciled unapproved deployment; no original Context replay."""
import copy,hashlib,json,os,re,signal,stat,sys,types
from pathlib import Path
NATIVE_HASH='5fa62e4f6869a6f40fb512878dcf65dcb6ffaf941be487e4189826f418046591'
ORIGINAL=Path('/etc/ouf/deploy-snapshots/acquisition-read-apply-'+NATIVE_HASH)
REVIEW_HASH='4cdc8631745c00589e89c4763b34f57451032be714d168447df998dbbd1da328'
RECEIPT_HASH='4ba97a80d257743d05b0423328e34cc699358056b829e70142e1347f7599c158'
CHILD='terminal-continuation-v1'
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
    manifest=json.loads(source(code/'sources.json'));require('continuation.py'in manifest and hashlib.sha256(source(Path(__file__).resolve())).hexdigest()==manifest['continuation.py'],'EXACT_CONTINUATION_SOURCE_MANIFEST_REQUIRED')
    raw=source(code/'apply.py');require(hashlib.sha256(raw).hexdigest()==manifest['apply.py'],'EXACT_BASE_DEFINITIONS_REQUIRED');m=types.ModuleType('sealed_continuation_base');m.__file__=str(code/'apply.py');sys.modules[m.__name__]=m;exec(compile(raw,m.__file__,'exec'),m.__dict__);return m
def context_class(base):
    class Context(base.Context):
        def __init__(self,parts,auth,sign,journal,closure,*,original=ORIGINAL,review_hash=REVIEW_HASH,receipt_hash=RECEIPT_HASH,native_path=base.NATIVE,native_hash=NATIVE_HASH):
            self.core,self.http,self.ports_module,self.watch,self.engine_helpers,self.p,self.images,self.preparer=[parts[k]for k in('protocol','transport','ports','quarantine','engine_creation','plan_helper','image_custody','native_prepare')]
            self.auth,self.sign,self.journal_module=auth,sign,journal;self.closure=copy.deepcopy(closure);self.runtime=parts['runtime'];self.original=Path(original);self.root=self.original/CHILD;self.NATIVE_HASH=native_hash;self.native_path=Path(native_path);self.serial=0;self.key=None;self.execution=None;self.limits=self.core.CONTINUATION_LIMITS
            self.p.ancestry(self.original);require(not os.path.lexists(self.root),'CONTINUATION_SCOPE_CONSUMED_NO_REPLAY')
            self.old_names=self.old_inventory(False);self.old_review=self.read(self.original/'review.json',review_hash)
            receipt_path=self.original/'unapproved-review-reconciliation-v1/complete.json';receipt=self.read(receipt_path,receipt_hash)
            require(receipt['schema']=='ouf.acquisition-unapproved-review-reconciliation.v1'and receipt['status']=='UNAPPROVED_ACQUISITION_REVIEW_RECONCILED_NO_AUTHORITY'and receipt['complete']is True and receipt['reviewHash']==review_hash and receipt['nativeInputsHash']==native_hash and receipt['originalAuthorityAndJournalAbsent']is True and receipt['retainedClaimsProveNoRuntimeEffectsDispatched']is True and receipt['originalScopeConsumed']is True and receipt['continuationAuthorized']is False and receipt['retainedPreflightCounts']==self.core.RETAINED_COUNTS and receipt['retainedMaximums']==self.core.LIMITS,'EXACT_UNAPPROVED_REVIEW_RECEIPT_REQUIRED')
            require(self.old_review['schema']=='ouf.acquisition-read-native-review.v1'and self.old_review['executionRoot']==str(self.original)and self.old_review['logicalOperationRef']==native_hash and self.old_review['preflightCounts']==receipt['retainedPreflightCounts']and self.old_review['maximums']==self.core.LIMITS,'EXACT_ORIGINAL_REVIEW_AND_COUNTS_REQUIRED')
            for path,h in self.old_review['sourceClosure'].items():source_raw=source(Path(path));require(hashlib.sha256(source_raw).hexdigest()==h,'ORIGINAL_SOURCE_CLOSURE_CHANGED');self.closure[path]=h
            self.retained_files={str(self.original/name):list(self.p.frame((self.original/name).lstat()))for name in self.old_names if name!='unapproved-review-reconciliation-v1'}
            self.retained_files[str(receipt_path)]=list(self.p.frame(receipt_path.lstat()))
            self.continuation={'originalExecutionRoot':str(self.original),'originalReviewHash':review_hash,'reconciliationReceiptHash':receipt_hash,'retainedPreflightCounts':copy.deepcopy(receipt['retainedPreflightCounts']),'retainedMaximums':copy.deepcopy(self.core.LIMITS),'maximumAdditionalCredentialFileReads':1,'cumulativeCredentialReadMaximum':2,'noOriginalScopeReplay':True,'preConsentUsesRetainedRouteSnapshot':True,'freshRoutesRequiredBeforeFirstMutation':True}
            self.counts=copy.deepcopy(receipt['retainedPreflightCounts']);self.native=self.p.decode(self.p.protected(self.native_path,native_hash));require(self.native['schema']=='ouf.acquisition-native-execution-inputs.v1'and self.native['frozenPlanHash']==self.preparer.PLAN_HASH and self.p.digest(self.native['nativeProposal'])==self.native['nativeProposalHash']and self.native['executionEntryQualified']is False and self.native['targetApplyAuthorized']is False,'EXACT_CONTINUATION_NATIVE_INPUT_REQUIRED')
            self.proposal=copy.deepcopy(self.native['nativeProposal']);require(self.proposal['mcpReplacement']['oldNativeHostConfig'].get('AutoRemove')is False,'OLD_MCP_MUST_NOT_AUTOREMOVE');self.inputs=self.p.decode(self.p.protected(self.p.INPUTS,self.proposal['capturedInputsHash']))
            for proposal in [*self.proposal['readComponents'].values(),self.proposal['mcpReplacement']]:
                host=proposal['request']['HostConfig']
                if host.get('OomKillDisable')is None:proposal['runtimeHostProjection']={'profile':'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1','requestedOomKillDisable':None,'materializedOomKillDisable':False,'positiveMemoryBytes':host['Memory']}
            require(self.proposal==self.old_review['nativePlan']['proposal'],'FROZEN_REVIEW_PROPOSAL_MUST_REMAIN_IDENTICAL')
            self.root.mkdir(mode=0o700);fd=os.open(self.original,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
            self.write(self.root,'preparation-claim.json',{'schema':'ouf.acquisition-unapproved-continuation-claim.v1','continuation':self.continuation,'initialCumulativeCounts':self.counts,'proposedMaximums':self.limits,'runtimeEffectsDispatched':0,'approvalRequiredBeforeAdditionalCredentialRead':True,'automaticReplayAllowed':False,'budgetReset':False})
            self.engine=self.http.Engine(self.p,self.proposal['engineBinding']);self.refresh_authority();self.openssl=self.executable();self.runtime_binding=self.runtime_snapshot();self.check_sources()
        def old_inventory(self,child_exists):
            names={p.name for p in self.original.iterdir()};require(len(names)<=64,'BOUNDED_ORIGINAL_SCOPE_REQUIRED');expected={'review.json','preparation-claim.json','unapproved-review-reconciliation-v1'}
            require(expected<=names and all(n in expected or n==CHILD and child_exists or re.fullmatch(r'preflight-(claim|engine-response|admin)-[0-9]{4}\.json',n)for n in names),'ORIGINAL_SCOPE_HAS_POST_REVIEW_STATE_STOP')
            if child_exists:require(CHILD in names,'CONTINUATION_EXCLUSIVE_CLAIM_REQUIRED');names.remove(CHILD)
            return names
        def check_sources(self):
            base.Context.check_sources(self)
            require(self.old_inventory(True)==self.old_names,'ORIGINAL_SCOPE_ENTRY_SET_CHANGED')
            for path,metadata in self.retained_files.items():require(list(self.p.frame(Path(path).lstat()))==metadata,'ORIGINAL_RETAINED_FILE_CHANGED')
        def reserve(self,kind):
            if self.execution is not None:
                self.watch.ensure_alive(self);return self.execution.reserve(kind)
            require(kind!='serviceCredentialFileReads','TERMINAL_AUTHORITY_REQUIRED_BEFORE_CREDENTIAL_READ')
            require(self.counts[kind]<self.limits[kind],'CUMULATIVE_PREFLIGHT_BUDGET_EXHAUSTED');self.counts[kind]+=1;self.evidence('preflight-claim',{'kind':kind,'attempt':self.counts[kind],'attemptNotCompletion':True,'previousCountsRetained':True})
        def load_admin_key(self):
            require(self.execution is not None and self.key is None,'APPROVED_EXECUTION_REQUIRED_BEFORE_CREDENTIAL_READ');self.execution.gate.check();row=self.execution.record();require(row['nextStage']==0 and row['effects']and row['effects'][0]['stage']=='LOAD_EXISTING_ADMIN_KEY'and row['effects'][0]['state']=='CLAIMED','CLAIMED_ADDITIONAL_CREDENTIAL_READ_REQUIRED');base.Context.load_admin_key(self)
        def admin(self,method,path,body=None):
            require(self.execution is not None and self.key is not None,'NO_ADMIN_REQUEST_BEFORE_SIGNED_CREDENTIAL_STAGE');self.execution.gate.check();return base.Context.admin(self,method,path,body)
    return Context
def prepare_review(ctx):
    c=ctx.core;ctx.current()
    for fact in ctx.native['candidateFacts'].values():
        h=hashlib.sha256()
        with Path(fact['nativeArchive']['path']).open('rb')as stream:
            for block in iter(lambda:stream.read(1048576),b''):h.update(block)
        require(h.hexdigest()==fact['nativeArchive']['sha256'],'EXACT_PRE_REVIEW_NATIVE_ARCHIVE_BYTES_REQUIRED')
    plan={'frozenPlanHash':ctx.native['frozenPlanHash'],'nativeInputsHash':ctx.NATIVE_HASH,'runtimeBinding':ctx.runtime_binding,'runtimeBindingHash':c.digest(ctx.runtime_binding),'proposal':ctx.proposal,'continuation':ctx.continuation}
    review={**copy.deepcopy(ctx.old_review),'schema':'ouf.acquisition-read-continuation-review.v1','executionRoot':str(ctx.root),'nativePlan':plan,'nativePlanHash':c.digest(plan),'sourceClosure':ctx.closure,'sourceClosureHash':c.digest(ctx.closure),'continuation':ctx.continuation,'maximums':copy.deepcopy(ctx.limits),'stages':['LOAD_EXISTING_ADMIN_KEY',*c.STAGES],'preflightCounts':copy.deepcopy(ctx.counts),'verification':{'trustPolicy':ctx.native['publicAuthority']['trustPolicy'],'openssl':ctx.openssl,'context':ctx.native['publicAuthority']['context']}}
    c.validate_review(review);ctx.write(ctx.root,'review.json',review);return review
def operator(base,ctx):
    c=ctx.core;review=prepare_review(ctx);decision=c.terminal_decision(review,ctx.root/'review.json');ctx.read(ctx.root/'review.json',c.digest(review));ctx.current();ctx.refresh_authority();gate=c.issue(review,ctx.root,ctx.profile,decision,ctx.write,ctx.read)
    print(c.encoded({'schema':'ouf.acquisition-read-native-issued.v1','reviewHash':c.digest(review),'authorityHash':c.sha(gate.raw),'runtimeAuthorityIssued':True,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False,'additionalCredentialReadNotYetDispatched':True}).decode(),flush=True)
    ports=ctx.ports_module.NativePorts(ctx,review,gate);execution=c.Execution(gate,ctx.journal_module.Journal(ctx.root),ports);execution.initialize();ctx.execution=execution
    try:ctx.watch.launch(ctx,review,gate,execution.journal);result=execution.run()
    except BaseException:
        try:ctx.watch.negative(ctx,review,gate.raw,execution.journal,'CONTINUATION_CONTROLLER_STOPPED')
        except BaseException:ctx.write(ctx.root,'quarantine-unproven.json',{'status':'STOP_RECONCILE','negativeEffectMayBePartial':True,'automaticReplayAllowed':False})
        raise
    return base.finalize(ctx,review,gate,result)
def main():
    ctx=None
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ONE_ISOLATED_ROOT_CONTINUATION_REQUIRED')
        def interrupted(*_):raise Stop('CONTINUATION_INTERRUPTED_RECONCILE_ONLY')
        for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
        base=base_module(Path(__file__).resolve().parent);ctx=context_class(base)(*base.components());result=operator(base,ctx)
    except Exception as error:
        reason=str(error)if re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'ACQUISITION_CONTINUATION_UNPROVEN'
        result={'schema':'ouf.acquisition-read-native-result.v1','status':'STOP_RECONCILE','reasonCode':reason,'complete':False,'contextPath':str(ctx.root)if ctx else None,'runtimeEffectsMayBePartial':True,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False,'credentialValuesPrinted':False,'addressesPrinted':False,'humanBudgetsGranted':0,'sourceActivations':0}
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True);return 0 if result.get('complete')else 2
if __name__=='__main__':raise SystemExit(main())
