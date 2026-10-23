"""Current unchanged Gateway route and endpoint checks under a new read scope.

Only the qualified file/namespace GET primitive is reused. No completed
diagnostic run/case, old action, old budget or route write is invoked.
"""
import copy,json
from .core import require,digest
from .lifecycle import Lifecycle
from .read_budget import ReadBudget
from tools.semantic_live_route_diagnostic import reader as transport
from tools.ingestion_readiness_patch_execution import runtime_guard

def gateway_scope(lifecycle,pin,profile,routes,network_id):
    return {'schema':'ouf.semantic-registry-recovery-gateway-scope.v1','planHash':digest(lifecycle.plan),
        'gatewayRuntimeHash':digest(pin),'transportProfileHash':digest(profile),
        'completeRetainedRoutesHash':digest(routes),'networkId':network_id,
        'routeWritesAllowed':False,'method':'GET','operation':transport.OPERATION}

class CurrentGateway:
    def __init__(self,lifecycle,pin,profile,routes,network_id,budget):
        require(type(lifecycle) is Lifecycle and type(budget) is ReadBudget
            and budget.store is lifecycle.store and budget.authority is lifecycle.authority,
            'ACTUAL_RECOVERY_GATEWAY_AND_READ_BUDGET_REQUIRED')
        self.lifecycle,self.budget=lifecycle,budget
        self.pin,self.profile,self.routes=map(copy.deepcopy,(pin,profile,routes));self.network_id=network_id
        require(type(routes) is dict and 0<len(routes)<=256,'COMPLETE_RETAINED_RECOVERY_ROUTES_REQUIRED')
        transport.selected_route(routes)
        self.scope=gateway_scope(lifecycle,pin,profile,routes,network_id);self.guard()
    def guard(self):
        row=self.lifecycle.journal()
        require(gateway_scope(self.lifecycle,self.pin,self.profile,self.routes,self.network_id)==self.scope
            and json.loads(self.lifecycle.authority.raw).get('semanticRegistryRecoveryGateway')==self.scope,
            'CURRENT_SIGNED_RECOVERY_GATEWAY_SCOPE_REQUIRED')
        status,actual=self.lifecycle.engine.request('GET','/v1.44/containers/'+self.pin['binding']['containerId']+'/json')
        require(status==200,'CURRENT_GATEWAY_INSPECTION_REQUIRED');runtime_guard.unchanged(actual,self.pin)
        require(self.lifecycle.journal()==row,'GATEWAY_CHECKPOINT_CHANGED')
        return actual
    def verify(self,*,endpoint_required):
        before=self.lifecycle.journal();gateway=self.guard()
        self.budget.reserve('gatewayAdminGets')
        routes=transport.admin_routes(self.profile,gateway)
        require(routes==self.routes,'UNCHANGED_COMPLETE_RECOVERY_GATEWAY_ROUTES_REQUIRED')
        status,network=self.lifecycle.engine.request('GET','/v1.44/networks/'+self.network_id)
        require(status==200,'REVIEWED_RECOVERY_NETWORK_REQUIRED')
        registry=self.lifecycle.inspect()
        proof=transport.correlate(routes,self.routes,self.lifecycle.request,registry,network,gateway)
        require(proof['currentRouteTargetsReviewedRegistryAddressAndPort'] is True
            and proof['currentRouteEqualsRetainedSemanticRoute'] is True
            and proof['completeCurrentRouteMapMatchesRetained'] is True,
            'CURRENT_RECOVERY_ROUTE_BINDING_REQUIRED')
        if endpoint_required:
            require(proof['currentTargetEndpointIsReviewedRegistry'] is True
                and proof['currentTargetEndpointCount']==1,'CURRENT_SAME_REGISTRY_NETWORK_ENDPOINT_REQUIRED')
        else:
            require(proof['reviewedRegistryStopped'] is True and proof['currentTargetEndpointCount']==0
                and proof['reviewedRegistryHasLiveNetworkEndpoint'] is False,
                'REVIEWED_STOPPED_RECOVERY_ENDPOINT_MUST_BE_UNOCCUPIED')
        self.guard()  # approved binding recheck; health-log churn is not identity
        require(self.lifecycle.journal()==before,'RECOVERY_GATEWAY_CHANGED_DURING_READ')
        return {'schema':'ouf.semantic-registry-recovery-current-route.v1','routeMapHash':digest(routes),
            'registryEndpointVerified':endpoint_required,'sameReviewedRegistryTarget':True,'gatewayWrites':0}
