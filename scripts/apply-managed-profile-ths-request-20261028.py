#!/usr/bin/env python3
"""New signed same-image Onboarding request configuration; requires qualified sealed delivery."""
import ast,copy,hashlib,json,os,pwd,re,signal,stat,sys,sysconfig,time,types
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
    required={'entry.py','base_authority.py','control_context.py','control_ports.py','authority.py','context.py','ports.py','base_context.py','base_ports.py','onb_context.py','database.py','base_database.py','state_fence.py','base_state_fence.py','backup.py','transport.py','mcp_transport.py','quarantine.py','recovery_journal.py','engine_creation.py','plan_helper.py','image_custody.py','retained_mac.py','terminal.py','configuration.py','authentication.py','signing.py','auth_protocol.py','auth_preexec.py','auth_producer.py','runtime_binding.py'}
    require(type(mapping)is dict and set(mapping)==required,'EXACT_CONTROL_SOURCE_CLOSURE_REQUIRED');closure={str(folder/'sources.json'):sha(raw)}
    for name,digest in mapping.items():require(re.fullmatch('[a-f0-9]{64}',digest)is not None and sha(source(folder/name))==digest,'EXACT_CONTROL_SOURCE_DIGEST_REQUIRED')
    require('tools'not in sys.modules,'ISOLATED_ROLE_VERIFIER_NAMESPACE_REQUIRED');package('tools');package('tools.semantic_lease_recovery')
    selected('tools.semantic_provider_preexec',folder/'auth_preexec.py',('PreexecDenied',),{},closure)
    selected('tools.semantic_provider_deployment_protocol',folder/'auth_protocol.py',('identity','hashed'),{'re':re},closure)
    selected('tools.semantic_provider_deployment_producer',folder/'auth_producer.py',('encoded',),{'json':json},closure)
    auth=load('tools.semantic_provider_deployment_authentication',folder/'authentication.py',closure);sign=load('tools.semantic_provider_deployment_signing',folder/'signing.py',closure)
    journal=load('tools.semantic_lease_recovery.recovery_journal',folder/'recovery_journal.py',closure)
    names=('base_authority','authority','base_context','base_ports','onb_context','base_database','base_state_fence','backup','transport','mcp_transport','quarantine','engine_creation','plan_helper','image_custody','retained_mac','terminal','control_context','control_ports','context','ports','database','state_fence')
    parts={name:load('sealed_control_update_'+name,folder/(name+'.py'),closure)for name in names}
    parts['authority']=parts['authority'].bind(parts['base_authority'])
    parts['control_context'].Context=parts['control_context'].bind(parts['base_context'])
    parts['context'].Context=parts['context'].bind(parts['control_context'])
    parts['control_ports'].NativePorts=parts['control_ports'].bind(parts['base_ports'])
    parts['ports'].NativePorts=parts['ports'].bind(parts['control_ports'])
    parts['database']=parts['database'].bind(parts['base_database'])
    parts['state_fence']=parts['state_fence'].bind(parts['base_state_fence'])
    parts['configuration_raw']=source(folder/'configuration.py');closure[str(folder/'configuration.py')]=sha(parts['configuration_raw'])
    runtime=selected('sealed_control_update_runtime',folder/'runtime_binding.py',('stdlib_binding',),{'Path':Path,'sysconfig':sysconfig,'sys':sys,'os':os,'stat':stat,'hashlib':hashlib,'re':re,'binding':types.SimpleNamespace(require=require,identity=parts['plan_helper'].frame,CandidateDenied=RuntimeError)},closure)
    closure[str(Path(__file__).resolve())]=mapping['entry.py'];return parts,auth,sign,journal,closure,runtime
def review(ctx):
    c=ctx.core;ctx.current();ctx.verify_archive();frozen=c.digest(ctx.proposal)
    native={'frozenPlanHash':frozen,'executionInputsHash':ctx.case['executionInputsHash'],'conditionalNativePlanHash':ctx.case['conditionalPlanHash'],
            'proposal':copy.deepcopy(ctx.proposal),'networkBaseline':copy.deepcopy(ctx.network_baseline),
            'imageAuditHashes':{r:c.digest(v['audit'])for r,v in ctx.facts.items()},
            'runtimeBinding':ctx.runtime_binding,'runtimeBindingHash':c.digest(ctx.runtime_binding)}
    value={'schema':'ouf.ths-owner-request-update-review.v1','executionRoot':str(ctx.root),'frozenPlanHash':frozen,
           'nativePlan':native,'nativePlanHash':c.digest(native),'sourceClosure':ctx.closure,'sourceClosureHash':c.digest(ctx.closure),
           'logicalOperationRef':ctx.case['executionInputsHash'],'bootId':ctx.inputs['bootId'],'maximumSeconds':900,
           'maximums':copy.deepcopy(c.LIMITS),'stages':list(c.STAGES),
           'negativeCleanup':{'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':1,'disableCandidateRestartFirst':True},
           'preflightCounts':copy.deepcopy(ctx.counts),'verification':{'trustPolicy':ctx.authority_metadata['trustPolicy'],'openssl':ctx.openssl,'context':ctx.authority_metadata['context']},
           'retainedCaptureAccounting':{'nativePlanPreparationCounts':ctx.case['preparationCounts'],'oldScopesRemainConsumed':True},'retainedImagePreparationCounts':ctx.case['preparationCounts'],
           'retainedTransportCompatibility':ctx.transport_compatibility,'existingOwnerConfigurationBinding':ctx.owner_overlay_binding,
           'targetRoles':['onboarding'],'sameNativeImageRequired':True,'imageImportAuthorized':False,'iamMutationAuthorized':False,
           'configurationProfileHash':ctx.case['configurationProfileHash'],'maintenanceSqlAuthorized':True,'operationalSqlHash':ctx.proposal['operationalSqlHash'],
           'databaseMigrationAuthorized':False,'databaseMigration':{'from':36,'to':36,'newMigrations':0},
           'maximumBackupBytes':268435456,'maximumBackupSeconds':90,
           'maximumSigningOperations':3,'maximumSigningKeyReadDispatches':15,'maximumRawEngineReceiptBytesTwoPublishers':134217728,
           'databaseRestoreAuthorized':False,'humanBudgetOrSourceActivationAuthorized':False,'acquisitionCallsAuthorized':False,
           'gatewayMutationAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    c.validate_review(value);ctx.write(ctx.root,'review.json',value);return value
def terminal(ctx,value):
    c=ctx.core;reviewed=c.digest(value);deadline=time.monotonic()+900;wall=time.time()+900
    print('Revisione privata: '+str(ctx.root/'review.json'),flush=True)
    print('Nuova manutenzione SOLO Onboarding, stessa immagine9890b318/c512c247 e piano9c961982/e22a443d. Nessun import o migrazione, MCP e Registry intatti;12peer invariati.',flush=True)
    print('Unico delta: aggiunge preview/file.profile/quarantine.release alla richiesta THS, preservando5scope precedenti e ogni altra proprieta. Binding IAM e Policy58 gia acquisiti, nessun login/grant nuovo.',flush=True)
    print('Configurazione owner proposta verificata prima della review: un solo overlay esistente in memoria e JAR identico estratto dall archivio conservato; nessun valore privato stampato.',flush=True)
    print('Dopo consenso:7SQL tecniche READ ONLY,storia36 e intero stato operativo invariati, stesso FarmacieFAILED/tentativi5. Zero migrazioni,grant,budget/resume,upload/job/fonte/acquisizione.',flush=True)
    print('Backup PostgreSQL con Onboarding fermo, massimo256MiB; dump e parsing offline verificati senza restore/repair/rollback.',flush=True)
    print('Breve indisponibilita del SOLO Onboarding: vecchio fermato,scollegato,rinominato e trattenuto. SeSTOP puo restare indisponibile fino a riconciliazione; nessun rollback automatico.',flush=True)
    print('Tre firme con le due chiavi installazione esistenti solo dopo consenso,massimo15aperture. Normale bootstrap OAuth dell owner possibile; nessuna richiesta OAuth/IAM del controller.',flush=True)
    print('Esecuzione900s,startup180s;ulteriori30s solo per disabilitare restart e fermare il proprio candidato non committed. Watchdog effimero solo negativo;esito ambiguoCLAIMED,nessun rilancio/reset.',flush=True)
    print('Massimi: '+json.dumps(c.LIMITS,sort_keys=True),flush=True)
    print('Manutenzione e readiness non sono E2E applicativo. Budget3/900 e resume dello stesso job sono decisioni HUMAN future e separate sulla THS, esclusiva dell utente.',flush=True)
    print('Scadenza review: '+datetime.fromtimestamp(wall,ZoneInfo('Europe/Rome')).isoformat(),flush=True)
    print('Inserisci ESCLUSIVAMENTE la riga seguente e premi Invio; errori correggibili entro la stessa scadenza900s:',flush=True)
    print('APPROVO '+reviewed,flush=True)
    def guard():
        require(time.monotonic()<deadline and time.time()<wall,'FINITE_CONTROL_HUMAN_WINDOW_EXPIRED');ctx.check_sources()
    ctx.terminal.read_exact(reviewed,guard,emit=lambda s:print(s,flush=True),progress=lambda state:ctx.evidence('tty-progress',state))
    ctx.read(ctx.root/'review.json',reviewed)
    return {'schema':'ouf.ths-owner-request-terminal-decision.v1','reviewHash':reviewed,'decision':c.DECISION,'approvedAt':int(time.time())}
def execute_approved(ctx,value,decision):
    c=ctx.core;ctx.current();ctx.refresh_authority();ctx.issueStarted=True
    gate=c.issue(value,ctx.root,ctx.profile,decision,ctx.write,ctx.read);ctx.gate=gate;ctx.review=value
    print(c.encoded({'schema':'ouf.ths-owner-request-update-issued.v1','reviewHash':c.digest(value),'authorityHash':c.sha(gate.raw),
                     'runtimeAuthorityIssued':True,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False}).decode(),flush=True)
    ports=ctx.ports_module.NativePorts(ctx,value,gate);ctx.ports=ports
    execution=c.Execution(gate,ctx.journal_module.Journal(ctx.root),ports);execution.initialize();ctx.execution=execution
    try:
        ctx.watch.launch(ctx,value,gate,execution.journal);return execution.run()
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
        require(os.geteuid()==os.getegid()==0 and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid) and len(sys.argv)==1 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ONE_ISOLATED_ROOT_CONTROL_UPDATE_REQUIRED')
        require(os.isatty(0)and os.isatty(1),'DIRECT_INTERACTIVE_SUDO_NO_PIPE_REQUIRED')
        tty=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
        try:require(os.tcgetpgrp(tty)==os.getpgrp(),'FOREGROUND_CONTROL_REVIEW_TERMINAL_REQUIRED')
        finally:os.close(tty)
        parts,auth,sign,journal,closure,runtime=components();log=Path(__file__).resolve().parent/'operator.log';sys.stdout=Logger(log)
        def cancelled(*_):raise RuntimeError('CONTROL_CONTROLLER_INTERRUPTED_RECONCILE_ONLY')
        for sig in(signal.SIGHUP,signal.SIGINT,signal.SIGTERM):signal.signal(sig,cancelled)
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_THS_PREFLIGHT_WINDOW_EXPIRED'));signal.alarm(300)
        ctx=parts['context'].Context(parts,auth,sign,journal,closure,runtime=runtime);value=review(ctx);signal.alarm(0);decision=terminal(ctx,value);result=execute_approved(ctx,value,decision)
    except Exception as e:
        reason=str(e)if re.fullmatch('[A-Z0-9_]{1,120}',str(e))else'THS_REQUEST_UPDATE_UNPROVEN'
        result={'schema':'ouf.ths-owner-request-update-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,'contextPath':str(ctx.root)if ctx else None,'runtimeEffectsMayBePartial':bool(ctx and ctx.issueStarted),'automaticReplayAllowed':False,'automaticRollbackPerformed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    finally:signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True);return 0 if result.get('complete')else 2
if __name__=='__main__':raise SystemExit(main())
