"""Read current APISIX routes beside the publication checkpoint, without recursion.

Use the existing typed read-only namespace channel and reviewed publication
owner. Do not call the publication guard/transport: they require the same full
checkpoint this observer will serve. Read-only reconciliation admits only the
exact before/after map of an already durably dispatched CLAIMED route; it never
marks it APPLIED, sends PUT or changes authority/history.
"""
import copy, os
from .custody_capture import digest, require
from .node_owner import ObservationBudget
from .publication_owner import DiscoveryGatewayPublication, DiscoveryPublicationWindow, BINDING, binding, marker, claim
from .gateway_runtime import DiscoveryGatewayRuntime, DiscoveryGatewayReadOnlyAdmin
from .selected_runtime import DiscoverySelectedRuntime
from tools.semantic_registry_operational_owner.guard import private_json


class CurrentGatewayRoutes:
    def __init__(self, publication):
        require(type(publication) is DiscoveryGatewayPublication
            and type(publication.window) is DiscoveryPublicationWindow,
            'ACTUAL_DISCOVERY_ROUTE_PUBLICATION_AND_WINDOW_REQUIRED')
        self.publication = publication
        self.window = publication.window
        self.selected = self.window.selected
        self.runtime = self.selected.gateway
        self.ids = tuple(map(id, (publication, self.window, self.selected, self.runtime)))
        self.guard()

    def guard(self):
        p, w, s, r = self.publication, self.window, self.selected, self.runtime
        require(self.ids == tuple(map(id, (p, w, s, r))) and type(p) is DiscoveryGatewayPublication
            and type(w) is DiscoveryPublicationWindow and type(s) is DiscoverySelectedRuntime
            and type(r) is DiscoveryGatewayRuntime and p.window is w and w.selected is s
            and s.gateway is r and r.images is s.images and r.parent is w.parent
            and p.owner_ids == tuple(map(id, (w, p.journal, p.action)))
            and p.plan == w.assembly['gatewayPlan'] and digest(p.plan) == p.plan_hash
            and p.scope == w.component['gateway'] and p.action.authority is w.gate.child
            and p.action.raw == w.gate.raw and p.action.authority_hash == w.child_hash
            and str(p.journal.root) == w.component['journalDirectories']['gateway'],
            'SAME_EXACT_CURRENT_GATEWAY_PUBLICATION_RUNTIME_AND_PARENT_REQUIRED')
        # This validates current parent/component/source and recompiled inputs,
        # but deliberately does not call w.guard()/the checkpoint under review.
        w.lineage(); r.guard(); p.journal.check_directory()
        return s.held()

    def progress(self):
        p = self.publication
        if not os.listdir(p.journal.root):
            return None, [copy.deepcopy(p.plan['previousRoutes'])]
        # A binding-only/partial initializer remains consumed; no adoption.
        require(private_json(p.journal.root/BINDING) == binding(p),
            'CURRENT_GATEWAY_ROUTE_PUBLICATION_BINDING_REQUIRED')
        row = p.record(); n = row['nextStep']
        for effect in row['effects'][:n]:
            path = p.journal.root/marker(effect['routeId'])
            require(private_json(path) == claim(p, effect['routeId']),
                'APPLIED_GATEWAY_ROUTE_REQUIRES_ORIGINAL_DISPATCH_MARKER')
        maps = [p.expected(n)]
        if len(row['effects']) == n + 1:
            name = row['effects'][-1]['routeId']; path = p.journal.root/marker(name)
            if os.path.lexists(path):
                require(private_json(path) == claim(p, name), 'EXACT_PENDING_GATEWAY_ROUTE_DISPATCH_REQUIRED')
                maps.append(p.expected(n + 1))
        return row, maps

    def observe(self):
        budget = ObservationBudget(90); held = self.guard(); p, r = self.publication, self.runtime
        row, allowed = self.progress(); generation = r.generation(); budget.check()
        channel = r.transport()
        require(type(channel) is DiscoveryGatewayReadOnlyAdmin and channel.discovery_owner is r,
            'ACTUAL_SAME_READONLY_GATEWAY_NAMESPACE_CHANNEL_REQUIRED')
        channel.check(); routes = channel.routes(); budget.check()
        require(type(routes) is dict and routes in allowed,
            'CURRENT_GATEWAY_ROUTES_DIFFER_FROM_EXACT_REVIEWED_PUBLICATION_PROGRESS')
        channel.check()
        require(channel.routes() == routes and self.progress() == (row, allowed)
            and r.generation() == generation and self.guard() == held,
            'CURRENT_GATEWAY_ROUTES_GENERATION_OR_PUBLICATION_HISTORY_CHANGED')
        budget.check()
        return {'schema': 'ouf.discovery-current-gateway-route-progress.v1',
            'heldHistoryHash': digest(held), 'parentAuthorityHash': self.window.parent_hash,
            'childAuthorityHash': self.window.child_hash, 'publicationPlanHash': p.plan_hash,
            'publicationProgressHash': digest(row), 'gatewayGenerationHash': digest(generation),
            'routeMapHash': digest(routes), 'routeCount': len(routes), 'routeGets': 2,
            'currentRoutesMatchReviewedPublicationProgress': True,
            'currentGatewayConfigurationAndAdminExecutableObserved': True,
            'pendingDispatchedOutcomeStillRequiresOwnerReconciliation': row is not None and len(allowed) == 2,
            'publicationCheckpointReentered': False, 'journalAdvanced': False, 'routeWrites': 0,
            'allGatewayRuntimeExecutableBytesProven': False, 'completePrivateCustodyProven': False,
            'fullCohortProven': False, 'producerReleaseDispatched': False,
            'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'releaseAcceptance': False}
