"""One-use retirement of a retained lease worker under NEW Executor authority.

No activation replay, service restart, retry-budget edit, direct nft write or
shared lock. Root entrypoint must seal this module, custody/projector sources,
selected intake/scope and current HUMAN/signature/native checkpoints. This is
an owner phase implementation, not a standalone operator authorization.
"""
import copy,hashlib,json,math,os,re,subprocess
from pathlib import Path
from transition_journal import digest,hash_value,require
from native_evidence_store import NativeEvidenceStore

PHASE='STOP_REVOKE_OLD_LEASE'
HISTORY_FIXED=('schema','contextRef','generationRef','policyHash','timeAccountingProfile','startedWall','startedMonotonic')
HISTORY_MUTABLE={'state','attempts','lastWall','lastMonotonic','nextWall','nextMonotonic','reason','healthyWallSeconds','healthyMonotonicSeconds','publicationCount','resultRef'}

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def parse(raw):
    def unique(pairs):
        value={}
        for k,v in pairs:require(k not in value,'DUPLICATE_RETIREMENT_INPUT_KEY');value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('NONFINITE_RETIREMENT_INPUT')))
def history_progress(previous,current):
    """Preserve accounting identity and cumulative recovery cost, including outage time."""
    require(type(previous) is dict and type(current) is dict,'RETAINED_RECOVERY_HISTORY_REQUIRED')
    for row in (previous,current):
        require(row.get('schema')=='ouf.bounded-recovery.v1' and row.get('timeAccountingProfile')=='ouf.lease-cumulative-recovery-time.v1'
                and all(hash_value(row.get(k)) for k in ('contextRef','generationRef','policyHash')),'EXACT_RETAINED_RECOVERY_ACCOUNTING_REQUIRED')
        for key in ('attempts','publicationCount'):
            require(type(row.get(key)) is int and row[key]>=0,'CUMULATIVE_RECOVERY_COUNTER_REQUIRED')
        for key in ('startedWall','startedMonotonic','lastWall','lastMonotonic','healthyWallSeconds','healthyMonotonicSeconds'):
            require(type(row.get(key)) in (int,float) and math.isfinite(row[key]) and row[key]>=0,'FINITE_RECOVERY_TIME_REQUIRED')
        for suffix in ('Wall','Monotonic'):
            require(row['last'+suffix]>=row['started'+suffix] and row['healthy'+suffix+'Seconds']<=row['last'+suffix]-row['started'+suffix]+0.001,'RETAINED_RECOVERY_TIME_UNPROVEN')
    require(all(previous.get(k)==current.get(k) for k in HISTORY_FIXED)
            and {k:v for k,v in previous.items() if k not in HISTORY_MUTABLE}=={k:v for k,v in current.items() if k not in HISTORY_MUTABLE},'RETAINED_RECOVERY_IDENTITY_OR_POLICY_CHANGED')
    for key in ('attempts','publicationCount','lastWall','lastMonotonic','healthyWallSeconds','healthyMonotonicSeconds'):
        require(current[key]>=previous[key],'CUMULATIVE_RECOVERY_HISTORY_REGRESSED')
    for suffix in ('Wall','Monotonic'):
        before=previous['last'+suffix]-previous['started'+suffix]-previous['healthy'+suffix+'Seconds']
        after=current['last'+suffix]-current['started'+suffix]-current['healthy'+suffix+'Seconds']
        require(after+0.001>=before,'CUMULATIVE_RECOVERY_COST_RESET')

class R12RetirementChannel:
    """Exact root-custodied files plus bounded systemctl/nft metadata commands.

    Scope comes from selected capture + reviewed installation, sealed in the new
    authority. Historical input is a lower bound, never readiness/live authority.
    lease_projection is the existing source-sealed READ-ONLY native projector.
    No worker/installation program or input configuration is executed.
    """
    def __init__(self,scope,custody,lease_projection):
        require(os.geteuid()==0,'ROOT_RETIREMENT_CHANNEL_REQUIRED')
        self.scope=copy.deepcopy(scope);self.scope_hash=digest(scope)
        require(set(scope)=={'intakeBinding','authorizationBinding','coordinatorBinding','executionBinding','r12Root','activationClaimPath','ownerSourceRoot','programHashes','unit','workerPid','hostBootId'},'EXACT_RETIREMENT_CHANNEL_SCOPE_REQUIRED')
        require(re.fullmatch('ouf[A-Za-z0-9_.@-]{1,120}\\.service',scope['unit']) is not None
                and type(scope['workerPid']) is int and scope['workerPid']>1
                and type(scope['programHashes']) is dict and len(scope['programHashes'])==15,'EXACT_RETAINED_WORKER_SCOPE_REQUIRED')
        require(all(re.fullmatch('[A-Za-z0-9_]+\\.(py|json)',name) and hash_value(h) for name,h in scope['programHashes'].items()),'EXACT_RETAINED_PROGRAM_CLOSURE_REQUIRED')
        self.custody,self.project=custody,lease_projection;self.root=Path(scope['r12Root'])
        require(scope['authorizationBinding']['path']==str(self.root/'authorization.json'),'EXACT_RETAINED_AUTHORIZATION_PATH_REQUIRED')
        self.capture=self.selected()
        self.capture_history_hash=parse(self.bound(scope['intakeBinding']))['fileHashes']['r12-recovery-history.json']
    def read(self,path,expected=None):return self.custody.file_bytes(path,0,{0o600},expected=expected)
    def bound(self,binding):
        require(type(binding) is dict and set(binding)=={'path','sha256'} and hash_value(binding['sha256']),'EXACT_RETIREMENT_FILE_BINDING_REQUIRED')
        return self.read(binding['path'],binding['sha256'])
    def selected(self):
        s=self.scope;raw=self.bound(s['intakeBinding']);manifest=parse(raw)
        require(manifest.get('schema')=='ouf.native-v11-atomic-review-intake.v1'
                and manifest.get('collectionKind')=='EXISTING_COORDINATOR_AND_CUMULATIVE_HISTORY_INPUTS'
                and manifest.get('observationsAreHistorical') is True
                and all(manifest.get(k) is False for k in ('runtimeAuthorityIssued','applicationCutoverAuthorized','productionApplyReady')),'EXACT_HISTORICAL_COORDINATION_INTAKE_REQUIRED')
        root=Path(s['intakeBinding']['path']).parent;files=manifest.get('fileHashes',{})
        require(set(files)=={'native-review-intake.json','existing-authority-profile.json','existing-coordinator.json','retained-human-binding.json','retained-execution-configuration.json','r12-authorization.json','r12-activation-claim.json','r12-worker-invocation.json','r12-worker-status.json','r12-recovery-history.json'},'COMPLETE_SELECTED_COORDINATION_INTAKE_REQUIRED')
        values={name:parse(self.read(root/name,h)) for name,h in files.items()}
        for name,key in [('r12-authorization.json','authorizationBinding'),('existing-coordinator.json','coordinatorBinding'),('retained-execution-configuration.json','executionBinding')]:
            require(files[name]==s[key]['sha256'],'SELECTED_AND_CURRENT_RETIREMENT_BINDING_DRIFT')
        require(values['r12-worker-status.json']['workerPid']==s['workerPid'],'SELECTED_RETAINED_WORKER_PID_DRIFT')
        return values
    def command(self,binding,args,timeout=10):
        require(hash_value(binding.get('sha256')),'SEALED_RETIREMENT_COMMAND_REQUIRED')
        before=self.custody.file_bytes(binding['path'],0,{0o755,0o750,0o700},limit=33554432,expected=binding['sha256'])
        result=subprocess.run([binding['path'],*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        require(result.returncode==0 and len(result.stdout)<=2000000 and len(result.stderr)<=131072,'RETIREMENT_NATIVE_COMMAND_UNPROVEN')
        require(before==self.custody.file_bytes(binding['path'],0,{0o755,0o750,0o700},limit=33554432,expected=binding['sha256']),'RETIREMENT_NATIVE_COMMAND_CUSTODY_CHANGED')
        return result.stdout
    def service(self,cfg,auth):
        names='LoadState,ActiveState,SubState,MainPID,Restart,NRestarts,ExecStart'
        raw=self.command(cfg['commandBindings']['systemctl'],['show',self.scope['unit'],'--property='+names])
        props={}
        for line in raw.decode().splitlines():
            k,v=line.split('=',1);require(k in names.split(',') and k not in props,'EXACT_RETAINED_SERVICE_METADATA_REQUIRED');props[k]=v
        if props.get('LoadState')=='not-found':
            require(props.get('ActiveState')=='inactive' and props.get('SubState')=='dead'
                    and all(k not in props or props[k]==v for k,v in {'MainPID':'0','Restart':'no','NRestarts':'0','ExecStart':''}.items()),'EXACT_RETIRED_TRANSIENT_UNIT_ABSENCE_REQUIRED')
            # Missing properties remain unknown; never manufacture Restart=no
            # or PID0 for an unloaded unit. Private baseline + absent old process
            # + final history/native lease are required by reconciliation.
            return {k:props.get(k) for k in names.split(',') if k!='ExecStart'}|{'ExecStartHash':sha(props['ExecStart'].encode()) if 'ExecStart' in props else None}
        require(set(props)==set(names.split(',')) and props['LoadState']=='loaded'
                and props['Restart']=='no' and props['NRestarts']=='0','RETAINED_SERVICE_RESTART_OR_CUSTODY_DRIFT')
        python=cfg['pythonBinding'];expected=' '.join([python['path'],'-I','-B',str(self.root/'activate.py'),'--supervise',str(self.root/'authorization.json'),self.scope['authorizationBinding']['sha256']])
        commands=re.findall(r'argv\[\]=(.*?) ;',props['ExecStart'])
        require(commands==[expected] and auth['nativeBindings']['python']==python,'EXACT_RETAINED_SERVICE_EXECUTION_REQUIRED')
        props['ExecStartHash']=sha(props.pop('ExecStart').encode());return props
    def current(self):
        s=self.scope;require(digest(s)==self.scope_hash,'IMMUTABLE_RETIREMENT_CHANNEL_SCOPE_REQUIRED')
        require(self.selected()==self.capture,'SELECTED_RETIREMENT_INTAKE_CHANGED')
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==s['hostBootId'],'RETAINED_HOST_BOOT_CHANGED')
        auth=parse(self.bound(s['authorizationBinding']));cfg=parse(self.bound(s['executionBinding']));owner=parse(self.bound(s['coordinatorBinding']))
        require(auth.get('schema')=='ouf.provider-resilient-r12-authorization.v1' and auth.get('serviceUnit')==s['unit']
                and auth.get('hostBootId')==s['hostBootId'] and auth.get('automaticRestart') is False and auth.get('enableAtBoot') is False
                and auth.get('programHashes')==s['programHashes'] and auth.get('ownerConfigurationHash')==s['coordinatorBinding']['sha256']
                and digest({k:v for k,v in auth.items() if k!='contextRef'})==auth.get('contextRef'),'EXACT_RETAINED_R12_AUTHORIZATION_REQUIRED')
        require(parse(self.read(s['activationClaimPath']))==auth['activationClaim'] and auth['activationClaim']['startAuthorized'] is False,'CONSUMED_ACTIVATION_CLAIM_DRIFT')
        invocation=parse(self.read(self.root/'worker-invocation-claim.json'))
        require(invocation=={'contextRef':auth['contextRef'],'pid':s['workerPid'],'hostBootId':s['hostBootId']},'RETAINED_WORKER_INVOCATION_CHANGED')
        for name,h in s['programHashes'].items():self.read(self.root/name,h)
        for name,h in owner['sourceHashes'].items():
            path=Path(name);require(not path.is_absolute() and '..' not in path.parts,'EXACT_OWNER_SOURCE_PATH_REQUIRED');self.read(Path(s['ownerSourceRoot'])/path,h)
        history_raw=self.read(self.root/'retry/recovery.json');worker_raw=self.read(self.root/'worker-status.json');history=parse(history_raw);worker=parse(worker_raw)
        history_progress(self.capture['r12-recovery-history.json'],history)
        require(history['contextRef']==auth['contextRef'] and history['generationRef']==auth['generationRef']
                and worker.get('schema')=='ouf.provider-resilient-worker-status.v1' and worker.get('workerPid')==s['workerPid']
                and worker.get('incidentRef')==auth['incidentRef'] and worker.get('doNotRerunApply') is True
                and worker.get('startAuthorized') is False,'CURRENT_RETAINED_WORKER_HISTORY_REQUIRED')
        service=self.service(cfg,auth)
        process=self.process(cfg,service)
        require(service['MainPID'] in ('0',str(s['workerPid'])) or service['MainPID'] is None and service['LoadState']=='not-found','RETAINED_SERVICE_PID_CHANGED')
        lease_raw=self.read(owner['journalFile']);tables={f:parse(self.command(cfg['commandBindings']['nft'],['-j','list','table',f,owner['kernel']['tableName']])) for f in ('inet','bridge')}
        require(cfg['commandBindings']['nft']=={'path':owner['nftPath'],'sha256':owner['nftSha256']},'RETAINED_NFT_COMMAND_DRIFT')
        lease=self.project(owner,parse(lease_raw),tables)
        require(self.read(owner['journalFile'])==lease_raw and self.read(self.root/'retry/recovery.json')==history_raw
                and self.read(self.root/'worker-status.json')==worker_raw and self.service(cfg,auth)==service and self.process(cfg,service)==process,'RETAINED_WORKER_OR_LEASE_CHANGED_DURING_READ')
        for key in ('authorizationBinding','executionBinding','coordinatorBinding'):self.bound(s[key])
        for name,h in s['programHashes'].items():self.read(self.root/name,h)
        return {'authorizationHash':s['authorizationBinding']['sha256'],'history':history,'worker':worker,'service':service,'processGeneration':process,'lease':lease}
    def process(self,cfg,service):
        pid=self.scope['workerPid'];root=Path('/proc')/str(pid)
        if service['MainPID'] in ('0',None):
            require(not root.exists(),'RETAINED_WORKER_PROCESS_STILL_PRESENT_OR_PID_REUSED');return None
        expected=[cfg['pythonBinding']['path'],'-I','-B',str(self.root/'activate.py'),'--supervise',str(self.root/'authorization.json'),self.scope['authorizationBinding']['sha256']]
        raw=(root/'cmdline').read_bytes()
        require(raw==b'\0'.join(x.encode() for x in expected)+b'\0','EXACT_RETAINED_PROCESS_COMMAND_REQUIRED')
        stat=(root/'stat').read_text();ticks=int(stat.rsplit(')',1)[1].split()[19])
        require(ticks>0 and (root/'cmdline').read_bytes()==raw,'RETAINED_PROCESS_GENERATION_CHANGED')
        return {'pid':pid,'startTicks':ticks,'hostBootId':self.scope['hostBootId']}
    def marker(self,value,create=False):
        path=self.root/'revoked';raw=encoded(value)
        if os.path.lexists(path):require(self.read(path)==raw,'FOREIGN_OR_PARTIAL_RETIREMENT_MARKER');return True
        if not create:return False
        self.custody.create(path,raw);require(self.read(path)==raw,'RETIREMENT_MARKER_PUBLICATION_UNPROVEN');return True
    def stop(self,seconds):
        cfg=parse(self.bound(self.scope['executionBinding']))
        self.command(cfg['commandBindings']['systemctl'],['stop',self.scope['unit']],timeout=seconds)

class R12RetirementAdapter:
    def __init__(self,channel,transition,intent,before_store,store):
        require(type(channel) is R12RetirementChannel,'TYPED_RETAINED_RETIREMENT_CHANNEL_REQUIRED')
        self.channel,self.transition,self.before_store,self.store=channel,transition,before_store,store
        self.intent=copy.deepcopy(intent);self.intent_hash=digest(intent)
        require(set(intent)=={'scopeHash','stopTimeoutSeconds'} and intent['scopeHash']==channel.scope_hash
                and type(intent['stopTimeoutSeconds']) is int and 1<=intent['stopTimeoutSeconds']<=55,'EXACT_BOUNDED_RETIREMENT_INTENT_REQUIRED')
        require(type(before_store) is NativeEvidenceStore and type(store) is NativeEvidenceStore
                and before_store.root!=store.root,'SEPARATE_DURABLE_RETIREMENT_BASELINE_REQUIRED')
        if 'r12Root' in channel.scope:
            old=Path(channel.scope['r12Root'])
            require(not before_store.root.is_relative_to(old) and not store.root.is_relative_to(old),'RETIREMENT_EVIDENCE_MUST_NOT_REWRITE_OLD_ROOT')
    def exact(self,intent):
        row=self.transition.read()
        require(digest(intent)==self.intent_hash and row['state']=='IN_FLIGHT' and row['nextPhase']==0
                and row['effects'][-1]['phase']==PHASE and row['effects'][-1]['intentHash']==self.intent_hash,'DURABLE_ONE_USE_RETIREMENT_BOUNDARY_REQUIRED')
        require(row['predecessorIncidentRef']==self.channel.capture['r12-authorization.json']['incidentRef'] and row['predecessorHistoryHash']==self.channel.capture_history_hash,'RETIREMENT_PREDECESSOR_HISTORY_OR_INCIDENT_DRIFT')
        return row
    def marker(self):return {'schema':'ouf.semantic-r12-retirement-marker.v1','transitionContextHash':self.transition.context,'intentHash':self.intent_hash,'authorizationHash':self.channel.scope['authorizationBinding']['sha256'],'r12ReplayAuthorized':False,'budgetReset':False}
    def baseline(self):
        value=parse(self.channel.read(self.before_store.path(PHASE)))
        self.before_store.read(PHASE,digest(value))
        require(value.get('transitionContextHash')==self.transition.context and value.get('intentHash')==self.intent_hash
                and value.get('scopeHash')==self.channel.scope_hash,'DURABLE_RETIREMENT_BASELINE_BINDING_DRIFT')
        return value['nativeBefore']
    def apply(self,intent):
        row=self.exact(intent);before=self.channel.current()
        require(before['service']['ActiveState']=='active' and before['service']['SubState']=='running'
                and before['service']['MainPID']==str(self.channel.scope['workerPid']),'EXACT_RETAINED_LIVE_SERVICE_BEFORE_STOP_REQUIRED')
        require(not self.channel.marker(self.marker()),'EXISTING_RETIREMENT_MARKER_RECONCILE_REQUIRED')
        # All historical/current history bytes are retained outside the old root.
        self.before_store.publish(PHASE,{'schema':'ouf.semantic-r12-retirement-before.v1','transitionContextHash':self.transition.context,
             'intentHash':self.intent_hash,'scopeHash':self.channel.scope_hash,'nativeBefore':before})
        # The guard recognizes marker existence. Stop is bounded and submitted
        # once; a marker/stop gap remains ambiguous, never a second stop request.
        self.channel.marker(self.marker(),create=True)
        self.channel.stop(intent['stopTimeoutSeconds'])
    def observe(self,intent):
        self.exact(intent)
        try:before=self.baseline()
        except FileNotFoundError:return 'UNKNOWN',{'retirementBaselineAbsent':True,'stopReplayAllowed':False}
        if not self.channel.marker(self.marker()):return 'UNKNOWN',{'retirementMarkerAbsent':True,'stopReplayAllowed':False}
        after=self.channel.current();history_progress(before['history'],after['history'])
        service,worker,history,lease=(after[k] for k in ('service','worker','history','lease'))
        stopped=(service['ActiveState']=='inactive' and service['SubState']=='dead' and (service['MainPID']=='0' or service['MainPID'] is None and service.get('LoadState')=='not-found')
                 and history['state']=='CANCELLED' and history['reason']=='CANCELLED_BY_OWNER'
                 and worker.get('state')=='CANCELLED' and worker.get('ready') is False and worker.get('live') is False
                 and worker.get('setsRevoked') is True and worker.get('attempts')==history['attempts']
                 and worker.get('refreshCount')==history['publicationCount'])
        revoked=(lease.get('journalState')=='QUIESCED' and lease.get('leaseAuthorized') is False
                 and lease.get('startAuthorized') is False and lease.get('providerSetsEmpty') is True
                 and lease.get('journalAndMembershipConsistent') is True and lease.get('nativeStructureVerified') is True
                 and lease.get('flowCount')==2 and len(lease.get('flows',[]))==2
                 and all(f.get('inetAddressCount')==f.get('bridgeAddressCount')==0 for f in lease['flows']))
        if not(stopped and revoked):return 'UNKNOWN',{'oldWorkerRetirementUnproven':True,'stopReplayAllowed':False,'budgetReset':False,'oldServiceStopped':service['ActiveState']=='inactive' and service['SubState']=='dead','finalCancellationPresent':history['state']=='CANCELLED' and history['reason']=='CANCELLED_BY_OWNER','finalWorkerObservationPresent':worker.get('live') is False and worker.get('ready') is False and worker.get('setsRevoked') is True,'workerCountersMatchFinalHistory':worker.get('attempts')==history['attempts'] and worker.get('refreshCount')==history['publicationCount'],'nativeLeaseRevoked':revoked}
        require(after==self.channel.current(),'RETIRED_WORKER_CHANGED_DURING_READ')
        evidence={'schema':'ouf.semantic-r12-retirement-evidence.v1','transitionContextHash':self.transition.context,'intentHash':self.intent_hash,
                  'scopeHash':self.channel.scope_hash,'beforeEvidenceHash':digest({'schema':'ouf.semantic-r12-retirement-before.v1','transitionContextHash':self.transition.context,'intentHash':self.intent_hash,'scopeHash':self.channel.scope_hash,'nativeBefore':before}),
                  'nativeAfter':after,'r12ReplayAuthorized':False,'budgetReset':False,'newRecoveryAuthorityIssued':False}
        self.store.publish(PHASE,evidence);return 'APPLIED',evidence
