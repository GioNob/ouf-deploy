"""Current real database/token/node prerequisites, with no renewal or grants."""
import copy,json
from .core import require,digest
from .database import CurrentDatabase
from .node_owner import RecoveryNodeOwner
from .process_binding import RecoveryProcessBinding
from .token_observer import require_observer,guard_lease

def admission_scope(database,node):
    return {'schema':'ouf.semantic-registry-recovery-admission-scope.v1',
        'planHash':digest(database.lifecycle.plan),'databaseScopeHash':digest(database.scope),
        'nodeScopeHash':digest(node.scope),'tokenOwnerBindingHash':node.token_owner.binding.digest(),
        'tokenAcquisitionAllowed':False,'databaseMutationAllowed':False,'sameFreshGenerationRequired':True}

class CurrentAdmission:
    def __init__(self,database,node):
        require(type(database) is CurrentDatabase and type(node) is RecoveryNodeOwner
            and node.lifecycle is database.lifecycle,'ACTUAL_CURRENT_RECOVERY_ADMISSION_OWNERS_REQUIRED')
        require_observer(node.token_owner,node.lifecycle)
        self.database,self.node,self.lifecycle=database,node,node.lifecycle
        self.scope=admission_scope(database,node);self.guard()

    def guard(self):
        row=self.lifecycle.journal()
        require(admission_scope(self.database,self.node)==self.scope
            and json.loads(self.lifecycle.authority.raw).get('semanticRegistryRecoveryAdmission')==self.scope,
            'CURRENT_SIGNED_REGISTRY_ADMISSION_SCOPE_REQUIRED')
        self.node.guard()
        require(self.database.guard()==row and self.lifecycle.journal()==row,
            'RECOVERY_ADMISSION_HISTORY_CHANGED')
        return row

    def prerequisites(self):
        row=self.guard()
        token=guard_lease(self.node.token_owner,self.node.recipe['renewableToken']['minimumRemainingSeconds'])
        database=self.database.snapshot()
        require(self.guard()==row,'RECOVERY_PREREQUISITES_CHANGED')
        return {'currentDatabase':database,'currentRetainedTokenWindow':token,
            'currentTokenOwnerBindingHash':self.node.token_owner.binding.digest(),
            'newGeneration':copy.deepcopy(row['newGeneration'])}

    def paused(self):
        row=self.guard();require(row['nextStage'] in (6,7),'CURRENT_PAUSED_ADMISSION_CHECKPOINT_REQUIRED')
        node=self.node.verify_retained();proof=self.prerequisites()
        require(self.guard()==row,'PAUSED_RECOVERY_ADMISSION_CHANGED')
        return {**proof,'pausedNodeAcceptance':node}

    def active(self):
        row=self.guard();frame=self.node.active_frame();proof=self.prerequisites()
        require(self.guard()==row,'ACTIVE_RECOVERY_ADMISSION_CHANGED')
        return {**proof,'activeFrame':frame}

    def readiness(self):
        row=self.guard();require(row['nextStage'] in (10,11),'CURRENT_APPLICATION_READINESS_PHASE_REQUIRED')
        binding=RecoveryProcessBinding(self.lifecycle,self.node.profile);before=binding.observe()
        actual=self.lifecycle.inspect();health_scope=self.database.readiness['health']
        require(any(e.get('IPAddress')==health_scope['address'] for e in actual['NetworkSettings']['Networks'].values()),
            'READINESS_ADDRESS_OUTSIDE_REVIEWED_REGISTRY')
        health=self.database.channel.health()
        if health is None:return 'UNKNOWN',{'applicationReadinessProven':False}
        admission=self.active()
        require(binding.observe()==before and self.database.channel.health()==health and self.guard()==row,
            'RECOVERY_APPLICATION_READINESS_CHANGED')
        return 'APPLIED',{'schema':'ouf.semantic-registry-recovery-application-ready.v1',
            'newGeneration':copy.deepcopy(row['newGeneration']),'health':health,'currentAdmission':admission,
            'originalSemanticGetSucceeded':False,'releaseAcceptance':False}
