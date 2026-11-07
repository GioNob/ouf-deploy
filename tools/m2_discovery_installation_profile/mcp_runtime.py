"""Only the selected MCP replacement under the current discovery parent/child.

Reuse the existing replacement planner/native comparisons, without inventing
three other replacements or replaying the historical four-container action.
One-use lifecycle dispatches and the existing durable Recovery protocol retain
ambiguity and bounded readiness. Full current-cohort admission remains separate.
"""
import copy,http.client,ipaddress,math,time
from dataclasses import asdict
from pathlib import Path
from .custody_capture import decode,digest,encoded,require
from .cohort_images import DiscoveryImages,checked_component
from .provider_installation_phase import transient
from tools.chatbot_file_cohort.plan import compile_replacement
from tools.chatbot_file_cohort.containers import CohortContainers,CohortPaused,STAGES
from tools.chatbot_file_cohort.gateway_runtime import retry_after_seconds
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_lease_recovery.bounded_recovery import Recovery,Policy,Temporary,number,fingerprint
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import private_json
from image_custody import runtime_image_id,loaded
from engine_creation import Engine
from transition_journal import PHASES

PLAN='ouf.discovery-mcp-replacement-plan.v1'
POLICY=Policy(max_elapsed=3600,attempt_timeout=15)
READINESS={'profile':'ouf.discovery-mcp-installation-readiness.v1','maximumAttempts':128,
    'maximumElapsedSeconds':3600,'attemptTimeoutSeconds':15,'backoffSeconds':[5,15,60,300,900],
    'maximumJitterPercent':20,'respectRetryAfter':True,'readOnlyOnly':True,
    'finiteProfileReason':'WITHIN_THE_ORIGINAL_FINITE_PARENT_AND_CHILD_INSTALLATION_WINDOW'}


def compile_plan(*,old,selected_image,package,cohort_id,environment_delta,registry_request_hash,cohort_manifest_hash):
    require(selected_image['module']=='mcp' and selected_image['modulePackageHash']==digest(package),
        'SAME_SELECTED_MCP_PACKAGE_REQUIRED')
    require(package.get('schema')=='ouf.unsigned-offline-candidate-package.v1'
        and package.get('module')=='mcp' and package.get('runtimeUser')=='10005:10005'
        and package.get('artifactFormat')=='DOCKER_SAVE_OFFLINE_ARCHIVE_NOT_HOST_OCI_DECLARATION'
        and package.get('imageScanGate')=='PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
        and package.get('notReleaseAcceptance') is True and package.get('signatureIssued') is False
        and package.get('targetApplyAuthorized') is False and package.get('vpsOperations')==0,
        'EXACT_SELECTED_OFFLINE_MCP_PACKAGE_RECORD_REQUIRED')
    audit=selected_image['audit']
    image={'Id':runtime_image_id(audit),'Config':audit['imageConfig'],'archiveAudit':audit}
    # Pure planning projection only: the legacy helper's metadata vocabulary
    # differs from the separately produced current package. Keep the actual raw
    # record hash in the resulting row; no larger cohort/source lock is invented.
    planning={'module':'mcp','sourceCommit':package['sourceCommit'],'imageId':package['imageId'],
        'artifactKind':'DOCKER_SAVE','scanGate':package['imageScanGate']}
    row=compile_replacement('mcp',old,image,planning,cohort_id,environment_delta)
    row['modulePackageHash']=digest(package)
    return {'schema':PLAN,'replacement':row,'selectedImageAuditHash':digest(audit),
        'registryCreationRequestHash':registry_request_hash,'cohortManifestHash':cohort_manifest_hash,
        'readinessPolicy':copy.deepcopy(READINESS),'oldContainerRetained':True,
        'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False,'runtimeAuthorityIssued':False}


def component(plan,journal_directory,readiness_directory):
    require(type(plan) is dict and set(plan)=={'schema','replacement','selectedImageAuditHash',
        'registryCreationRequestHash','cohortManifestHash','readinessPolicy','oldContainerRetained',
        'automaticRollbackAllowed','automaticWriteReplayAllowed','runtimeAuthorityIssued'}
        and plan['schema']==PLAN and plan['readinessPolicy']==READINESS
        and plan['oldContainerRetained'] is True
        and all(plan[k] is False for k in ('automaticRollbackAllowed','automaticWriteReplayAllowed','runtimeAuthorityIssued')),
        'EXACT_SINGLE_MCP_REPLACEMENT_PLAN_REQUIRED')
    row=plan['replacement'];require(row['module']=='mcp' and row['name']=='ouf-mcp'
        and row['creationRequestHash']==digest(row['creationRequest'])
        and row['readinessPath']=='/health/ready' and row['automaticRollbackAllowed'] is False
        and row['databaseRestoreAuthorized'] is False,'EXACT_MCP_REPLACEMENT_ROW_REQUIRED')
    paths=[Path(journal_directory),Path(readiness_directory)]
    require(all(p.is_absolute() and str(p)==str(v) and '..' not in p.parts for p,v in zip(paths,(journal_directory,readiness_directory)))
        and not paths[0].is_relative_to(paths[1]) and not paths[1].is_relative_to(paths[0]),
        'DISTINCT_EXPLICIT_MCP_AND_READINESS_JOURNALS_REQUIRED')
    return {'schema':'ouf.discovery-mcp-replacement-component.v1','planHash':digest(plan),
        'imageId':row['creationRequest']['Image'],'oldContainerId':row['oldRuntimeBinding']['containerId'],
        'journalDirectory':str(paths[0]),'readinessDirectory':str(paths[1]),
        'sameRegistryParentAndChildRequired':True,'historicalRecoveryAdoptionAllowed':False,
        'automaticReplayAllowed':False,'budgetReset':False}


class McpReadiness:
    """Recovery adapter publishes only a local proof, never traffic or authority."""
    def __init__(self,owner):self.owner=owner
    def guard(self):self.owner.guard();self.owner.record()
    def pause(self):pass  # No route, traffic lease or domain producer is published by this adapter.
    def prepare(self,deadline):
        owner=self.owner;self.guard();actual=owner.running(owner.row)
        require(actual is not None,'CURRENT_MCP_PROCESS_REQUIRED_FOR_READINESS')
        owner.retained_generation(owner.row,actual)
        proof=owner.health(owner.row,actual,deadline)
        self.guard();after=owner.running(owner.row)
        require(after is not None and Engine.runtime_binding(after)==Engine.runtime_binding(actual),
            'MCP_GENERATION_CHANGED_DURING_READINESS')
        return {'schema':'ouf.discovery-mcp-initial-readiness.v1','scopeHash':digest(owner.scope),
            'runtimeBinding':Engine.runtime_binding(actual),'health':proof,'notFullCohortAdmission':True}
    def publish(self,proof,deadline):
        self.guard();owner=self.owner
        require(owner.monotonic()<deadline,'MCP_READINESS_ATTEMPT_DEADLINE_EXCEEDED')
        with directory(owner.readiness_journal.root) as fd:new_file(fd,'ready-proof.json',encoded(proof))
        require(private_json(owner.readiness_journal.root/'ready-proof.json')==proof,'MCP_READINESS_PROOF_READBACK_DRIFT')
        return digest(proof)


class DiscoveryMcpRuntime:
    """Single-module protocol with explicit reuse of existing native comparisons."""
    def __init__(self,*,images,plan,journal,readiness_journal,monotonic=time.monotonic,boot=None):
        require(type(images) is DiscoveryImages and type(journal) is type(readiness_journal) is Journal,
            'TYPED_DISCOVERY_IMAGES_AND_MCP_JOURNALS_REQUIRED')
        self.images,self.window,self.parent=images,images.window,images.parent
        self.engine,self.journal,self.readiness_journal=images.engine,journal,readiness_journal
        self.clock,self.monotonic=self.parent.clock,monotonic
        self.boot=boot or Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.plan=copy.deepcopy(plan);self.plan_hash=digest(plan);self.row=self.plan['replacement']
        self.rows={'mcp':self.row};self.steps=['mcp.'+s for s in STAGES]
        self.scope=component(plan,journal.root,readiness_journal.root)
        self.cohort_component=checked_component(self.parent,images.scope)
        require(self.cohort_component['mcp']==self.scope,'EXACT_PARENT_MCP_PLAN_AND_JOURNALS_REQUIRED')
        other_roots=[self.window.root,self.window.store.root,*[j.root for j in images.journals.values()]]
        gateway=self.cohort_component['gatewayRuntime']
        if 'journalDirectory' in gateway:other_roots.append(Path(gateway['journalDirectory']))
        require(all(not own.is_relative_to(other) and not other.is_relative_to(own)
            for own in (journal.root,readiness_journal.root) for other in other_roots),
            'SEPARATE_MCP_INSTALLATION_JOURNALS_REQUIRED')
        child=decode(self.window.raw)
        require(child.get('discoveryMcpInstallation')==self.scope
            and not child.get('applicationRegistryCutover',{}).get('postGrantRecovery'),
            'CURRENT_CHILD_MCP_SCOPE_WITHOUT_HISTORICAL_ADOPTION_REQUIRED')
        self.action=AggregateAction(self.window.child,self.window.raw,self.parent.scope['sourceClosureHash'])
        self.owner_ids=tuple(map(id,(images,self.window,self.parent,self.engine,journal,readiness_journal,self.action)))
        adapter=McpReadiness(self)
        self.recovery=Recovery(readiness_journal,adapter,POLICY,digest(self.scope),digest({'boot':self.boot,'scope':self.scope}),
            lambda:(self.clock(),self.monotonic()),lambda:int(digest({
                'scopeHash':digest(self.scope),'attempt':self.readiness_journal.read()['attempts']})[:8],16)/0xffffffff)
        self.guard()

    def guard(self):
        require(self.owner_ids==tuple(map(id,(self.images,self.window,self.parent,self.engine,self.journal,self.readiness_journal,self.action)))
            and self.images.window is self.window and self.images.parent is self.window.parent is self.parent
            and self.engine is self.window.engine is self.images.engine and self.action.authority is self.window.child
            and self.action.raw==self.window.raw and digest(self.plan)==self.plan_hash
            and self.row is self.plan['replacement'] and self.rows=={'mcp':self.row}
            and self.steps==['mcp.'+s for s in STAGES]
            and type(self.recovery) is Recovery and self.recovery.journal is self.readiness_journal
            and self.recovery.policy is POLICY and type(self.recovery.adapter) is McpReadiness
            and self.recovery.adapter.owner is self
            and component(self.plan,self.journal.root,self.readiness_journal.root)==self.scope
            and self.cohort_component==checked_component(self.parent,self.images.scope),
            'MCP_OWNER_PARENT_CHILD_ENGINE_PLAN_OR_JOURNAL_DRIFT')
        selected=self.images.plan['images'][1];audit=selected['audit']
        require(selected['module']=='mcp' and self.plan['selectedImageAuditHash']==digest(audit)
            and self.row['modulePackageHash']==selected['modulePackageHash']
            and self.row['sourceCommit']==audit['sourceCommit']
            and self.row['creationRequest']['Image']==runtime_image_id(audit)
            and self.plan['registryCreationRequestHash']==self.window.request_hash
            and self.plan['cohortManifestHash']==self.images.plan['cohortManifestHash'],
            'SAME_SELECTED_MCP_IMAGE_PACKAGE_REGISTRY_AND_COHORT_REQUIRED')
        self.images.guard();self.parent.guard('cohortInstallation',self.cohort_component)
        self.action.guard('discoveryMcpInstallation',self.scope)

    def initialize(self):
        self.guard();wall,mono=self.clock(),self.monotonic()
        deadline=min(decode(self.parent.raw)['expiresAt'],decode(self.window.raw)['expiresAt'])
        require(number(wall) and number(mono) and wall<deadline,'ORIGINAL_MCP_INSTALLATION_WINDOW_REQUIRED')
        self.journal.initialize({'schema':'ouf.discovery-mcp-container-journal.v1','scopeHash':digest(self.scope),
            'parentAuthorityHash':self.parent.sha,'childAuthorityHash':self.action.authority_hash,'bootId':self.boot,
            'createdWall':wall,'createdMonotonic':mono,'lastWall':wall,'lastMonotonic':mono,'deadlineWall':deadline,
            'deadlineMonotonic':mono+deadline-wall,'version':0,'nextStep':0,'effects':[],'budgetReset':False})
        self.readiness_journal.initialize(self.recovery.initial())
        self.record()

    def record(self):
        value=self.journal.read();wall,mono=self.clock(),self.monotonic();index=value.get('nextStep')
        require(value.get('schema')=='ouf.discovery-mcp-container-journal.v1'
            and value.get('scopeHash')==digest(self.scope) and value.get('parentAuthorityHash')==self.parent.sha
            and value.get('childAuthorityHash')==self.action.authority_hash and value.get('bootId')==self.boot
            and value.get('budgetReset') is False and type(index) is int and 0<=index<=len(STAGES)
            and value['createdWall']<=value['lastWall']<=wall<value['deadlineWall']
            and value['createdMonotonic']<=value['lastMonotonic']<=mono<value['deadlineMonotonic']
            and value['deadlineWall']==min(decode(self.parent.raw)['expiresAt'],decode(self.window.raw)['expiresAt'])
            and math.isclose(value['deadlineMonotonic']-value['createdMonotonic'],
                value['deadlineWall']-value['createdWall'],rel_tol=0,abs_tol=1e-6),
            'MCP_HISTORY_BOOT_OR_ORIGINAL_DEADLINE_DRIFT')
        effects=value['effects'];pending=len(effects)==index+1
        require(len(effects) in (index,index+1) and value['version']==2*index+int(pending)
            and [e['step'] for e in effects]==self.steps[:len(effects)],'MCP_ORDERED_EFFECT_HISTORY_REQUIRED')
        for n,e in enumerate(effects):
            require(e['state']==('CLAIMED' if n==index else 'APPLIED')
                and e['intentHash']==digest({'modulePlan':self.row,'stage':STAGES[n]})
                and (n==index or type(e.get('evidence')) is dict and e['evidenceHash']==digest(e['evidence'])),
                'MCP_EFFECT_INTENT_OR_PROOF_DRIFT')
        return value

    def save(self,previous,value):
        value.update(version=previous['version']+1,lastWall=self.clock(),lastMonotonic=self.monotonic())
        self.journal.compare_and_save(previous,value)
        require(self.record()==value,'MCP_COMMIT_READBACK_DRIFT');return value

    def prerequisites(self):
        self.guard();self.record();row=self.window.transition.read()
        require(row['nextPhase']==PHASES.index('RELEASE_PRODUCERS') and row['state']=='READY'
            and row['transitionAuthorityEvidenceHash']==self.action.authority_hash
            and row['creationRequestHash']==self.window.request_hash
            and row['predecessorHistoryHash']==self.parent.scope['predecessorHistoryHash']
            and all(e['authorityEvidenceHash']==self.action.authority_hash
                and e['intentHash']==decode(self.window.raw)['phaseIntentHashes'][e['phase']] for e in row['effects']),
            'VERIFIED_REGISTRY_AND_HELD_PRODUCERS_REQUIRED_BEFORE_MCP_REPLACEMENT')
        audit=self.images.plan['images'][1]['audit']
        loaded(audit,self.images.inspect(runtime_image_id(audit)))
        return row

    # Reuse only the frozen native comparisons, not its four-module action,
    # journal, readiness scheduler or authority scope.
    def inspect(self,identity):return CohortContainers.inspect(self,identity)
    def retired(self,row,renamed):return CohortContainers.retired(self,row,renamed)
    def candidate(self,row,restored_policy=False):return CohortContainers.candidate(self,row,restored_policy)
    def running(self,row,restored_policy=False):return CohortContainers.running(self,row,restored_policy)
    def retained_generation(self,row,actual):return CohortContainers.retained_generation(self,row,actual)

    def dispatch(self,stage):
        require(stage in STAGES and stage!='ready','EXACT_MCP_LIFECYCLE_EFFECT_REQUIRED')
        row=self.record();require(row['effects'][-1]['step']=='mcp.'+stage and row['effects'][-1]['state']=='CLAIMED',
            'CONSUMED_MCP_STAGE_REQUIRED_BEFORE_DISPATCH')
        self.prerequisites()
        with directory(self.journal.root) as fd:new_file(fd,stage+'-dispatch.json',encoded({
            'schema':'ouf.discovery-mcp-effect-dispatch.v1','scopeHash':digest(self.scope),'stage':stage,
            'attempt':1,'automaticReplayAllowed':False}))
        require(self.record()==row,'MCP_DISPATCH_INVOKING_RECORD_DRIFT')
        self.prerequisites();return CohortContainers.mutation(self,self.row,stage)

    def health(self,row,actual,deadline):
        address=ipaddress.ip_address(actual['NetworkSettings']['Networks']['ouf-backend']['IPAddress'])
        require(address.version==4 and address.is_private and not address.is_loopback and not address.is_unspecified,
            'EXACT_PRIVATE_MCP_HEALTH_ADDRESS_REQUIRED')
        remaining=deadline-self.monotonic();require(remaining>0,'MCP_HEALTH_DEADLINE_EXPIRED')
        client=http.client.HTTPConnection(str(address),8080,timeout=min(5,remaining))
        try:
            client.request('GET',row['readinessPath'],headers={'Accept':'application/json','Connection':'close'})
            response=client.getresponse();raw=response.read(65537)
            require(len(raw)<=65536,'MCP_READINESS_RESPONSE_BOUND_EXCEEDED')
            if response.status in (429,502,503,504):
                minimum=retry_after_seconds(response.getheader('Retry-After',''),self.clock())
                raise Temporary('SERVICE_UNAVAILABLE',retry_after=minimum)
            require(response.status==204 and not raw,'MCP_READINESS_CONTRACT_MISMATCH')
            return {'httpStatus':204,'responseBytes':0}
        except Exception as error:
            if transient(error):raise Temporary('DEPENDENCY_TIMEOUT') from None
            raise
        finally:client.close()

    def readiness_once(self):
        self.prerequisites();before=self.readiness_journal.read()
        require(before.get('generationRef')==self.recovery.generation and before.get('contextRef')==digest(self.scope)
            and before.get('policyHash')==fingerprint(asdict(POLICY)),
            'ORIGINAL_MCP_READINESS_BOOT_CONTEXT_AND_POLICY_REQUIRED')
        result=self.recovery.step()
        if result['state']!='ACTIVE':raise CohortPaused('MCP_READINESS_'+result['state'],result.get('nextWall'))
        proof=private_json(self.readiness_journal.root/'ready-proof.json')
        require(digest(proof)==result['resultRef'] and proof['scopeHash']==digest(self.scope)
            and proof['runtimeBinding']==Engine.runtime_binding(self.running(self.row)),
            'MCP_READINESS_PROOF_OR_GENERATION_DRIFT')
        return proof

    def apply(self):
        with self.journal.invocation():
            while True:
                self.prerequisites();previous=self.record();index=previous['nextStep']
                if index==len(STAGES):return self.report()
                stage=STAGES[index];fresh=len(previous['effects'])==index
                if fresh:
                    following=copy.deepcopy(previous);following['effects'].append({'step':self.steps[index],
                        'state':'CLAIMED','intentHash':digest({'modulePlan':self.row,'stage':stage})})
                    previous=self.save(previous,following)
                    if stage!='ready':self.dispatch(stage)
                proof=self.readiness_once() if stage=='ready' else CohortContainers.observe(self,self.row,stage)
                if proof is None:raise CohortPaused('MCP_EFFECT_UNPROVEN_RECONCILIATION_ONLY')
                self.prerequisites();require(self.record()==previous,'MCP_INVOKING_RECORD_DRIFT')
                following=copy.deepcopy(previous);following['effects'][-1].update(state='APPLIED',evidenceHash=digest(proof),evidence=proof)
                following['nextStep']+=1;self.save(previous,following)

    def report(self,record=None):
        self.guard();row=self.record();complete=row['nextStep']==len(STAGES)
        binding=None
        if complete:
            actual=self.running(self.row,True);require(actual is not None,'CURRENT_COMPLETED_MCP_GENERATION_REQUIRED')
            self.retired(self.row,True);self.retained_generation(self.row,actual);binding=Engine.runtime_binding(actual)
        return {'schema':'ouf.discovery-mcp-replacement-receipt.v1','scopeHash':digest(self.scope),
            'completedEffects':row['nextStep'],'totalEffects':len(STAGES),'replacementVerified':complete,
            'runtimeBinding':binding,'journalHash':digest(row),'oldContainerRetained':True,
            'fullCohortProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
