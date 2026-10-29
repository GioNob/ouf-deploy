"""One finite phase may start an already installed, signed lease worker once.

No file installer, manager enable/restart, container lifecycle, signing, journal
initialization or provider admission is hidden here. The sealed parent must
install and attest the reviewed bytes and prove the current provider separately.
Reconciliation observes a queued/lost start; it never resends it.
"""
import copy,hashlib,os,re,subprocess
from pathlib import Path
from .custody_capture import digest,encoded,require
from .parent_authority import DiscoveryParentAuthority
from .lease_installation_template import materialize,parent_scope,recompile,hashed
from .node_owner import DiscoveryNodeOwner
from .lease_service import build_installed
from .installed_lease_guard import boot_id
from . import lease_observation
from .native_generation_probe import DOCKER_FIELDS
from tools.semantic_registry_operational_owner.guard import protected_file,private_json
from tools.semantic_policy_token_owner.producer import protected_directory
from cutover_authority import CutoverAuthority
from transition_journal import Transition,PHASES
from native_evidence_store import NativeEvidenceStore
from recovery_journal import Journal

PHASE='START_DISTINCT_LEASE_WORKER'
MANAGER_FIELDS={'LoadState','ActiveState','SubState','MainPID','FragmentPath','DropInPaths','NeedDaemonReload'}


def start_scope(template,*,unit_name,manager,directory):
    t=recompile(template)
    require(type(unit_name) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@-]{0,100}[.]service',unit_name)
        and type(manager) is dict and set(manager)=={'path','sha256','maximumBytes'}
        and manager['path']=='/usr/bin/systemctl' and hashed(manager['sha256'])
        and type(manager['maximumBytes']) is int and 1<=manager['maximumBytes']<=67108864,
        'EXACT_DISCOVERY_MANAGER_START_SCOPE_REQUIRED')
    root=Path(directory)
    require(root.is_absolute() and str(root)==directory and '..' not in root.parts and len(root.parts)>=4
        and all(root!=Path(p) and not root.is_relative_to(p) and not Path(p).is_relative_to(root)
            for p in (t['installationRoot'],t['configurationTemplate']['ledgerRoot'],t['sandboxRoot'])),
        'SEPARATE_PRIVATE_DISCOVERY_START_JOURNAL_REQUIRED')
    return {'schema':'ouf.discovery-lease-manager-start-scope.v1','installation':parent_scope(t),
        'unitName':unit_name,'manager':copy.deepcopy(manager),'journalDirectory':directory,
        'maximumStartAttempts':1,'managerEnableOrRestartAuthorized':False,
        'containerLifecycleOperationsAuthorized':False,'providerAdmissionIsSeparate':True}


class LeaseStartAdapter:
    def __init__(self,*,parent,authority,authority_raw,transition,store,node_owner,
                 template,proposal,scope,intent):
        require(type(parent) is DiscoveryParentAuthority and type(authority) is CutoverAuthority
            and type(transition) is Transition and transition.execution_profile is None and transition.phases==PHASES
            and type(store) is NativeEvidenceStore and type(node_owner) is DiscoveryNodeOwner
            and node_owner.transition is transition and node_owner.store is store
            and node_owner.authority is authority and node_owner.raw==authority_raw
            and authority.verifier is parent.verifier,'SHARED_TYPED_DISCOVERY_START_OWNERS_REQUIRED')
        self.template=recompile(template);self.proposal=copy.deepcopy(proposal);self.scope=copy.deepcopy(scope)
        require(scope==start_scope(template,unit_name=scope['unitName'],manager=scope['manager'],directory=scope['journalDirectory'])
            and proposal==materialize(template,proposal['nativeObservation'],proposal['configuration']['commonLockIdentity']),
            'EXACT_RECOMPILED_DISCOVERY_START_MATERIAL_REQUIRED')
        expected={'creationRequestHash':digest(node_owner.request),'nodeRecipeHash':digest(node_owner.recipe),
            'leaseInstallationScopeHash':digest(scope),'priorEvidencePhase':'INSTALL_AUTHENTICATED_TRANSPORT'}
        require(intent==expected and template['sourceClosureHash']==authority.expected['sourceClosureHash']
            and proposal['configuration']['installationInputsHash']==parent.scope['installationInputsHash']
            and proposal['configuration']['desiredProfileHash']==parent.scope['desiredProfileHash']
            and proposal['configuration']['verification']['context']=={
                k:parent.context[k] for k in ('installationRef','entityRef','attestorRef')},
            'SAME_PARENT_REVIEW_AND_DISTINCT_WORKER_START_INTENT_REQUIRED')
        self.phase,self.transition,self.store,self.node_owner=PHASE,transition,store,node_owner
        self.parent,self.authority,self.authority_raw=parent,authority,bytes(authority_raw)
        self.intent,self.intent_hash,self.request_hash=copy.deepcopy(intent),digest(intent),expected['creationRequestHash']
        self.authority_hash=hashlib.sha256(authority_raw).hexdigest();self.parent_hash=parent.sha
        self.template_hash,self.proposal_hash,self.scope_hash=digest(template),digest(proposal),digest(scope)
        self.root=Path(scope['journalDirectory']);self.journal=Journal(self.root)
        self.configuration_path=Path(template['installationRoot'])/'configuration.json'
        require(self.root!=store.root and not self.root.is_relative_to(store.root) and not store.root.is_relative_to(self.root),
            'SEPARATE_DISCOVERY_START_EVIDENCE_AND_JOURNAL_REQUIRED')

    def current(self,intent):
        require(digest(intent)==digest(self.intent)==self.intent_hash
            and digest(self.template)==self.template_hash and digest(self.proposal)==self.proposal_hash
            and digest(self.scope)==self.scope_hash and self.parent.sha==self.parent_hash
            and hashlib.sha256(self.authority_raw).hexdigest()==self.authority_hash,
            'DISCOVERY_MANAGER_START_SCOPE_DRIFT')
        self.parent.registry_child(self.authority,self.authority_raw)
        self.parent.guard('operationalLeaseInstallation',self.scope)
        from .custody_capture import decode
        signed=decode(self.authority_raw)
        row=self.transition.read();cursor=PHASES.index(PHASE);effects=row.get('effects',[])
        require(signed['phaseIntentHashes'][PHASE]==self.intent_hash and row['state']=='IN_FLIGHT'
            and row['nextPhase']==cursor and row['creationRequestHash']==self.request_hash
            and row['transitionAuthorityEvidenceHash']==self.authority_hash
            and len(effects)==cursor+1 and [e['phase'] for e in effects]==list(PHASES[:cursor+1])
            and all(e['state']=='APPLIED' for e in effects[:-1]) and effects[-1]['state']=='IN_FLIGHT'
            and all(e['intentHash']==signed['phaseIntentHashes'][e['phase']]
                and e['authorityEvidenceHash']==self.authority_hash for e in effects),
            'EXACT_SIGNED_START_PHASE_AFTER_AUTHENTICATED_TRANSPORT_REQUIRED')
        require(self.proposal==materialize(self.template,self.proposal['nativeObservation'],
            self.proposal['configuration']['commonLockIdentity']),'DISCOVERY_START_MATERIAL_CHANGED')
        proof=self.node_owner.verify_retained()
        registry=self.proposal['nativeObservation']['profiles']['registry'];recipe=self.node_owner.recipe
        require(registry['nodeRecipeHash']==digest(recipe)
            and registry['imageConfigurationHash']==recipe['imageConfigurationHash']
            and registry['rootfsSealHash']==digest(recipe['expectedRootfsSeal'])
            and registry['applicationHash']==self.node_owner.adapter.request['applicationHash'],
            'CURRENT_RETAINED_REGISTRY_ADMISSION_MUST_MATCH_INSTALLED_WORKER')
        actual=self.node_owner.engine.inspect(self.transition);peer=self.proposal['nativeObservation']['peers']['registry']
        require(actual['Id']==peer['containerId'] and actual['Image']==peer['imageId']
            and digest({k:actual[k] for k in DOCKER_FIELDS})==peer['dockerBindingHash']
            and actual['State']['Pid']==peer['pid'] and actual['State']['StartedAt']==peer['startedAt'],
            'SAME_PAUSED_REGISTRY_AND_WORKER_NATIVE_OBSERVATION_REQUIRED')
        require(self.transition.read()==row,'DISCOVERY_START_CHECKPOINT_CHANGED')
        return proof

    def installed(self,*,before_start):
        lease_observation.preload_runtime()
        worker,guard,scope=build_installed(self.configuration_path,
            self.proposal['serviceUnit']['configurationAnchor'])
        require(guard.configuration==self.proposal['configuration']
            and scope==self.proposal['recipe']['scope'],'EXACT_PREINSTALLED_SIGNED_DISCOVERY_BYTES_REQUIRED')
        generation=private_json(guard.configuration['generationReceiptPath']);snapshot=self.proposal['nativeObservation']
        require(generation['nativeObservationHash']==digest(snapshot)
            and generation['nativeProfileHash']==snapshot['nativeProfileHash']
            and generation['generationRef']==snapshot['generationRef']
            and boot_id('/proc/sys/kernel/random/boot_id')==snapshot['bootId'],
            'EXACT_PREINSTALLED_DISCOVERY_GENERATION_REQUIRED')
        if before_start:
            with guard.invocation():guard.current(digest(scope),scope['generationRef'])
            row=worker.r.journal.read()
            require(row['state']=='NEW' and row['attempts']==row['publicationCount']==0
                and row.get('reentryCount',0)==0,'NEW_DISTINCT_DISCOVERY_LEDGER_REQUIRED_NO_RESET_OR_ADOPTION')
        else:
            guard.signature(generation);guard.probe(generation)
        return guard

    def manager(self,args):
        program=self.scope['manager']
        protected_file(program['path'],program['maximumBytes'],expected=program['sha256'],modes=(0o755,))
        result=subprocess.run([program['path'],*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,timeout=10,env={'PATH':'/usr/bin:/usr/sbin:/bin','LC_ALL':'C'})
        require(result.returncode==0 and len(result.stdout)<=16384,'DISCOVERY_MANAGER_OUTCOME_REQUIRES_RECONCILIATION')
        protected_file(program['path'],program['maximumBytes'],expected=program['sha256'],modes=(0o755,))
        return result.stdout

    def inactive(self):
        raw=self.manager(['show',self.scope['unitName'],'--no-pager','--property='+','.join(sorted(MANAGER_FIELDS))])
        pairs=[line.split('=',1) for line in raw.decode('ascii').splitlines()]
        require(all(len(v)==2 for v in pairs) and len(pairs)==len(MANAGER_FIELDS),
            'EXACT_PRESTART_DISCOVERY_MANAGER_READ_REQUIRED');value=dict(pairs)
        require(set(value)==MANAGER_FIELDS and value['LoadState']=='loaded'
            and value['ActiveState']=='inactive' and value['SubState']=='dead' and value['MainPID']=='0'
            and value['DropInPaths']=='' and value['NeedDaemonReload']=='no'
            and Path(value['FragmentPath']).resolve()==Path(self.proposal['configuration']['serviceUnitPath']),
            'EXACT_INACTIVE_PREINSTALLED_DISCOVERY_UNIT_REQUIRED')
        return value

    def claim(self):
        return {'schema':'ouf.discovery-manager-start-claim.v1','transitionContextHash':self.transition.context,
            'intentHash':self.intent_hash,'authorityHash':self.authority_hash,'parentAuthorityHash':self.parent_hash,
            'templateHash':self.template_hash,'proposalHash':self.proposal_hash,'scopeHash':self.scope_hash,
            'configurationHash':digest(self.proposal['configuration']),'startAttempts':1,'automaticReplayAllowed':False}

    def apply(self,intent):
        self.current(intent);self.installed(before_start=True);self.inactive()
        with protected_directory(self.root):
            # Durable consumption precedes dispatch. A queued job, timeout or
            # lost response can only be reconciled by observe(), never resent.
            self.journal.initialize(self.claim())
            with self.journal.invocation():
                self.current(intent);self.installed(before_start=True);self.inactive()
                self.journal.create(self.root/'start-dispatch.json',b'{"attempt":1}');self.journal.sync()
                self.manager(['start','--no-block',self.scope['unitName']])

    def observe(self,intent):
        before=self.current(intent)
        try:claim=self.journal.read()
        except FileNotFoundError:
            return 'UNKNOWN',{'ownedStartClaimPresent':False,'startReplayAllowed':False}
        require(claim==self.claim(),'EXACT_RETAINED_DISCOVERY_MANAGER_START_CLAIM_REQUIRED')
        if not os.path.lexists(self.root/'start-dispatch.json'):
            return 'NO_EFFECT',{'ownedStartDispatchNotAttempted':True,'startReplayAllowed':False}
        require(protected_file(self.root/'start-dispatch.json',128,modes=(0o600,))==b'{"attempt":1}',
            'EXACT_OWNED_DISCOVERY_START_DISPATCH_REQUIRED')
        self.installed(before_start=False)
        try:
            observed=lease_observation.observe(self.configuration_path,self.proposal['serviceUnit']['configurationAnchor'],
                unit_name=self.scope['unitName'],systemctl=self.scope['manager'])
        except (ValueError,OSError,subprocess.SubprocessError):
            return 'UNKNOWN',{'ownedStartClaimHash':digest(claim),'positiveWorkerLeaseNotProven':True,'startReplayAllowed':False}
        after=self.current(intent)
        evidence={'schema':'ouf.discovery-distinct-installed-lease-worker-started.v1',
            'transitionContextHash':self.transition.context,'intentHash':self.intent_hash,
            'creationRequestHash':self.request_hash,'claimHash':digest(claim),'templateHash':self.template_hash,
            'configurationHash':digest(self.proposal['configuration']),'nodeProofBeforeHash':digest(before),
            'nodeProofAfterHash':digest(after),'installedWorkerObservation':copy.deepcopy(observed),
            'managerEnableOrRestartPerformed':False,'containerLifecycleOperationsPerformed':False,
            'startReplayAllowed':False,'applicationStartAuthorized':False,'runtimeAuthorityIssued':False,'releaseAcceptance':False}
        path=self.store.path(PHASE)
        if os.path.lexists(path):
            retained=self.store.read_baseline(PHASE,self.transition.context,self.intent_hash)
            require(all(retained.get(k)==evidence[k] for k in ('schema','creationRequestHash','claimHash','templateHash','configurationHash'))
                and retained['installedWorkerObservation']['scopeHash']==observed['scopeHash']
                and retained['installedWorkerObservation']['generationRef']==observed['generationRef']
                and observed['recoveryAttempts']>=retained['installedWorkerObservation']['recoveryAttempts']
                and observed['publications']>=retained['installedWorkerObservation']['publications'],
                'RETAINED_DISCOVERY_START_EVIDENCE_OR_ACCOUNTING_DRIFT')
            return 'APPLIED',retained
        self.store.publish(PHASE,evidence);return 'APPLIED',evidence
