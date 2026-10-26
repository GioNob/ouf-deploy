#!/usr/bin/env python3
"""New signed MCP-only intent; deployment requires its qualified sealed delivery."""
import ast,copy,hashlib,json,os,re,signal,stat,sys,sysconfig,time,types
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
def require(ok,code):
    if not ok:raise RuntimeError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def source(path):
    path=Path(path);require(path.is_absolute()and path.resolve()==path,'CANONICAL_EXECUTOR_SOURCE_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_EXECUTOR_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o400 and 0<before.st_size<=131072,'ROOT400_EXECUTOR_SOURCE_REQUIRED')
        raw=os.read(fd,131073);frame=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        require(len(raw)==before.st_size and frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'EXECUTOR_SOURCE_CHANGED');return raw
    finally:os.close(fd)
def load(name,path,closure):
    raw=source(path);closure[str(path)]=sha(raw);m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m
def selected(name,path,names,environment,closure):
    raw=source(path);closure[str(path)]=sha(raw);nodes=[n for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names]
    require({n.name for n in nodes}==set(names),'CLOSED_VENDOR_DEFINITIONS_REQUIRED');m=types.ModuleType(name);m.__dict__.update(environment);sys.modules[name]=m;exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),m.__dict__);return m
def package(name):m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m
def components():
    folder=Path(__file__).resolve().parent;raw=source(folder/'sources.json');mapping=json.loads(raw)
    required={'entry.py','authority.py','context.py','transport.py','ports.py','quarantine.py','recovery_journal.py','engine_creation.py','plan_helper.py','image_custody.py','retained_mac.py','terminal.py','authentication.py','signing.py','auth_protocol.py','auth_preexec.py','auth_producer.py','runtime_binding.py'}
    require(type(mapping)is dict and set(mapping)==required,'EXACT_MCP_ONLY_SOURCE_CLOSURE_REQUIRED');closure={str(folder/'sources.json'):sha(raw)}
    for name,digest in mapping.items():require(re.fullmatch('[a-f0-9]{64}',digest)is not None and sha(source(folder/name))==digest,'EXACT_MCP_EXECUTOR_SOURCE_DIGEST_REQUIRED')
    require('tools'not in sys.modules,'ISOLATED_ROLE_VERIFIER_NAMESPACE_REQUIRED');package('tools');package('tools.semantic_lease_recovery')
    selected('tools.semantic_provider_preexec',folder/'auth_preexec.py',('PreexecDenied',),{},closure)
    selected('tools.semantic_provider_deployment_protocol',folder/'auth_protocol.py',('identity','hashed'),{'re':re},closure)
    selected('tools.semantic_provider_deployment_producer',folder/'auth_producer.py',('encoded',),{'json':json},closure)
    auth=load('tools.semantic_provider_deployment_authentication',folder/'authentication.py',closure);sign=load('tools.semantic_provider_deployment_signing',folder/'signing.py',closure)
    journal=load('tools.semantic_lease_recovery.recovery_journal',folder/'recovery_journal.py',closure)
    parts={name:load('sealed_mcp_update_'+name,folder/(name+'.py'),closure)for name in('authority','context','transport','ports','quarantine','engine_creation','plan_helper','image_custody','retained_mac','terminal')}
    runtime=selected('sealed_mcp_update_runtime',folder/'runtime_binding.py',('stdlib_binding',),{'Path':Path,'sysconfig':sysconfig,'sys':sys,'os':os,'stat':stat,'hashlib':hashlib,'re':re,'binding':types.SimpleNamespace(require=require,identity=parts['plan_helper'].frame,CandidateDenied=RuntimeError)},closure)
    closure[str(Path(__file__).resolve())]=mapping['entry.py'];return parts,auth,sign,journal,closure,runtime
def review(ctx):
    c=ctx.core;ctx.current();ctx.verify_archive();native={'frozenPlanHash':ctx.case['frozenPlanHash'],'preparedNativePlanHash':ctx.case['nativePlanHash'],'proposal':ctx.proposal,'networkBaseline':ctx.network_baseline,'imageAuditHash':c.digest(ctx.native['imageAudit']),'runtimeBinding':ctx.runtime_binding,'runtimeBindingHash':c.digest(ctx.runtime_binding)}
    value={'schema':'ouf.mcp-diagnostic-update-review.v1','executionRoot':str(ctx.root),'frozenPlanHash':ctx.case['frozenPlanHash'],'nativePlan':native,'nativePlanHash':c.digest(native),
           'sourceClosure':ctx.closure,'sourceClosureHash':c.digest(ctx.closure),'logicalOperationRef':ctx.case['nativePlanHash'],'bootId':ctx.inputs['bootId'],
           'maximumSeconds':900,'maximums':copy.deepcopy(c.LIMITS),'stages':list(c.STAGES),'negativeCleanup':{'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':1,'disableCandidateRestartFirst':True},
           'preflightCounts':copy.deepcopy(ctx.counts),'verification':{'trustPolicy':ctx.authority_metadata['trustPolicy'],'openssl':ctx.openssl,'context':ctx.authority_metadata['context']},
           'retainedInstallationCounts':ctx.proposal['retainedInstallationCounts'],'retainedCaptureCounts':ctx.proposal['retainedCaptureCounts'],
           'retainedImagePreparationCounts':{'privateMetadataReads':2,'ciZipReads':1,'nativeArchivesPrepared':1,'engineGets':0,'containerWrites':0,'imageImports':0},
           'maximumSigningOperations':3,'maximumSigningKeyReadDispatches':15,'maximumRawEngineReceiptBytesTwoPublishers':134217728,'databaseRestoreAuthorized':False,'humanBudgetOrSourceActivationAuthorized':False,
           'acquisitionCallsAuthorized':False,'gatewayMutationAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    c.validate_review(value);ctx.write(ctx.root,'review.json',value);return value
def terminal(ctx,value):
    c=ctx.core;reviewed=c.digest(value);deadline=time.monotonic()+900;wall=time.time()+900
    print('Revisione privata: '+str(ctx.root/'review.json'),flush=True)
    print('SOLA sostituzione del MCP con immagine diagnostica qualificata. Breve indisponibilita MCP; vecchio fermo/scollegato/trattenuto, MAC/IP e porte pubblicate correnti conservati, nessun rollback.',flush=True)
    print('Se STOP dopo il suo arresto, il MCP puo restare indisponibile fino a riconciliazione autorizzata. Il vecchio NON viene riavviato automaticamente.',flush=True)
    print('Sei componenti esistenti, Registry e Gateway intatti. Nessuna rotta, migrazione, grant, fonte o acquisizione.',flush=True)
    print('Include schema HUMAN CAPABILITIES e motivo/versione dei dinieghi sulle sole due READ. Normale bootstrap OAuth e aggiornamento catalogo manifest del nuovo MCP possono avvenire.',flush=True)
    print('Due chiavi installazione esistenti: tre firme dopo consenso (verifiche ripetute, massimo15 aperture chiave). Nessuna credenziale applicativa letta dal repair.',flush=True)
    print('Esecuzione900secondi+30 di sola quarantena del proprio nuovo MCP non committed. Stop ambiguo conserva CLAIMED; nessun rilancio o reset.',flush=True)
    print('Massimi: '+json.dumps(c.LIMITS,sort_keys=True),flush=True)
    print('I grant READ50 sono scaduti; questa revisione non li rinnova e non autorizza chiamate acquisition o accettazione E2E/release.',flush=True)
    print('Scadenza concreta della review: '+datetime.fromtimestamp(wall,ZoneInfo('Europe/Rome')).isoformat()+' (Europe/Rome)',flush=True)
    print('Tempo per inserire la review:900secondi. La riga errata resta correggibile entro la stessa scadenza. Inserisci ESCLUSIVAMENTE la riga seguente e premi Invio:',flush=True)
    print('APPROVO '+reviewed,flush=True)
    def guard():
        require(time.monotonic()<deadline and time.time()<wall,'FINITE_MCP_HUMAN_WINDOW_EXPIRED');ctx.check_sources()
    ctx.terminal.read_exact(reviewed,guard,emit=lambda s:print(s,flush=True),progress=lambda state:ctx.evidence('tty-progress',state))
    ctx.read(ctx.root/'review.json',reviewed)
    return {'schema':'ouf.mcp-diagnostic-terminal-decision.v1','reviewHash':reviewed,'decision':c.DECISION,'approvedAt':int(time.time())}
def execute_approved(ctx,value,decision):
    c=ctx.core;ctx.current();ctx.refresh_authority();gate=c.issue(value,ctx.root,ctx.profile,decision,ctx.write,ctx.read)
    print(c.encoded({'schema':'ouf.mcp-diagnostic-update-issued.v1','reviewHash':c.digest(value),'authorityHash':c.sha(gate.raw),'runtimeAuthorityIssued':True,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False}).decode(),flush=True)
    ports=ctx.ports_module.NativePorts(ctx,value,gate);ctx.ports=ports;ctx.review=value;ctx.gate=gate;execution=c.Execution(gate,ctx.journal_module.Journal(ctx.root),ports);execution.initialize();ctx.execution=execution
    try:
        ctx.watch.launch(ctx,value,gate,execution.journal);result=execution.run()
        return result
    except BaseException:
        try:ctx.watch.negative(ctx,value,gate.raw,execution.journal,'CONTROLLER_STOPPED')
        except BaseException:ctx.write(ctx.root,'quarantine-unproven.json',{'status':'STOP_RECONCILE','automaticReplayAllowed':False,'negativeEffectMayBePartial':True})
        raise
class Logger:
    def __init__(self,path):
        self.original=sys.stdout;fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);os.fchmod(fd,0o600);self.file=os.fdopen(fd,'w',buffering=1)
    def write(self,s):
        self.file.write(s);self.file.flush();os.fsync(self.file.fileno());self.original.write(s);return len(s)
    def flush(self):self.file.flush();os.fsync(self.file.fileno());self.original.flush()
    def fileno(self):return self.original.fileno()
    def isatty(self):return self.original.isatty()
def main():
    ctx=None
    try:
        require(os.geteuid()==os.getegid()==0 and len(sys.argv)==1 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ONE_ISOLATED_ROOT_MCP_UPDATE_REQUIRED')
        require(os.isatty(0)and os.isatty(1),'DIRECT_INTERACTIVE_SUDO_NO_PIPE_REQUIRED')
        tty=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
        try:require(os.tcgetpgrp(tty)==os.getpgrp(),'FOREGROUND_MCP_REVIEW_TERMINAL_REQUIRED')
        finally:os.close(tty)
        parts,auth,sign,journal,closure,runtime=components();log=Path(__file__).resolve().parent/'operator.log';sys.stdout=Logger(log)
        def cancelled(*_):raise RuntimeError('MCP_CONTROLLER_INTERRUPTED_RECONCILE_ONLY')
        for sig in(signal.SIGHUP,signal.SIGINT,signal.SIGTERM):signal.signal(sig,cancelled)
        ctx=parts['context'].Context(parts,auth,sign,journal,closure,runtime=runtime);value=review(ctx);decision=terminal(ctx,value);result=execute_approved(ctx,value,decision)
    except Exception as e:
        reason=str(e)if re.fullmatch('[A-Z0-9_]{1,120}',str(e))else'MCP_DIAGNOSTIC_UPDATE_UNPROVEN'
        result={'schema':'ouf.mcp-diagnostic-update-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,'contextPath':str(ctx.root)if ctx else None,'runtimeEffectsMayBePartial':True,'automaticReplayAllowed':False,'automaticRollbackPerformed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True);return 0 if result.get('complete')else 2
if __name__=='__main__':raise SystemExit(main())
