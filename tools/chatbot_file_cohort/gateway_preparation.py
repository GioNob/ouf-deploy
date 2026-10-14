"""Offline target-specific route compilation from the pinned Gateway package.

Not loaded by the isolated effect executor. The prepared complete JSON plan is
bound to both the aggregate HUMAN authority and the gateway publication scope.
"""
import copy
import re
from tools.chatbot_file_cohort.gateway import PROFILE, route_map
from tools.chatbot_file_cohort.plan import digest, encoded, require, sha

def materialize_target(runtime, references):
    """Only target projection + named secret references; never CI fixture input.

    Gateway source is imported from the authenticated package closure. Its own
    materializers validate issuer, audience, workload, owner routes and scopes.
    """
    from tools.materialize_object_search import materialize as objects
    from tools.materialize_managed_file_mcp import materialize as managed
    from tools.materialize_managed_upload import materialize as upload
    from tools.materialize_semantic_read import materialize as semantic_read
    from tools.materialize_semantic_proposals import add_to_existing
    from tools.materialize_onboarding_review import materialize as review
    from tools.materialize_semantic_human_runtime import materialize as semantic_human
    from tools.materialize_trusted_human_onboarding_runtime import materialize as onboarding_human
    require(set(references) == {'oidcSecretRef', 'delegationKeyEnv', 'authorizationKeyEnv',
            'udpKeyEnv', 'semanticReadKeyEnv', 'semanticProposalKeyEnv', 'semanticReadRouteIds'},
            'EXACT_TARGET_GATEWAY_REFERENCES_REQUIRED')
    oidc = references['oidcSecretRef']
    names = [references[k] for k in ('delegationKeyEnv', 'authorizationKeyEnv', 'udpKeyEnv',
                                    'semanticReadKeyEnv', 'semanticProposalKeyEnv')]
    require(type(oidc) is str and oidc.startswith(('$ENV://', '$secret://'))
            and len(set(names)) == 5 and all(type(n) is str and re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', n)
                                           for n in names), 'DISTINCT_NAMED_GATEWAY_KEYS_REQUIRED')
    args = (runtime, oidc, names[0], names[1])
    result = objects(*args, names[2])
    result['routes'].extend(r for r in managed(*args)['routes']
        if r.get('labels', {}).get('ouf-mediation') == 'managed-file-delegation-v1')
    result['routes'].append(upload(*args))
    result = semantic_read(result, runtime['x-ouf-installation'], names[0], names[3],
        {'scheme': 'http', 'nodes': {'ouf-semantic-registry:8080': 1}}, references['semanticReadRouteIds'])
    result = add_to_existing(result, runtime, names[0], names[4])
    result = review(result, runtime, names[0], names[1])
    result['routes'].extend(semantic_human(runtime, oidc)['routes'])
    approvals = {'trusted-human-onboarding-approvals-get', 'trusted-human-onboarding-approvals-post'}
    result['routes'].extend(r for r in onboarding_human(runtime, oidc)['routes'] if r['id'] in approvals)
    rows = route_map(result['routes'])
    # Make APISIX schema defaults explicit in the signed request so full GET
    # equality does not mistake server-added default values for foreign drift.
    for row in rows.values():
        row.setdefault('status',1)
        row.setdefault('priority',0)
    require(approvals <= set(rows), 'ONBOARDING_APPROVAL_NAMESPACE_REQUIRED')
    require(rows['trusted-human-onboarding-approvals-post']['upstream']['timeout']['read'] == 55,
            'QUALIFIED_CONTINUATION_ROUTE_TIMEOUT_REQUIRED')
    return rows


def compile_gateway_plan(previous, runtime, references, package, transport_binding):
    require(package.get('module') == 'gateway' and package.get('artifactKind') == 'SOURCE_AND_ROUTE_PACKAGE'
            and re.fullmatch(r'[0-9a-f]{40}', package.get('sourceCommit', ''))
            and sha(package.get('cohortSourceLockSha256')), 'QUALIFIED_GATEWAY_SOURCE_PACKAGE_REQUIRED')
    before = route_map(list(previous.values()))
    desired = materialize_target(runtime, references)
    after = copy.deepcopy(before)
    after.update(desired)
    # No id replacement may silently shadow a different retained endpoint.
    selector = lambda r: encoded([r.get('uri'), r.get('uris'), r.get('methods'), r.get('vars')])
    for rid, row in desired.items():
        require(all(other == rid or selector(old) != selector(row) for other, old in after.items()),
                'RETAINED_ROUTE_SELECTOR_COLLISION_REQUIRES_REVIEW')
    changes = [{'id': rid, 'before': before.get(rid), 'after': desired[rid]}
               for rid in sorted(desired) if before.get(rid) != desired[rid]]
    return {'schema': PROFILE, 'sourceCommit': package['sourceCommit'],
            'gatewayModulePackageHash': digest(package), 'targetRuntimeHash': digest(runtime),
            'targetReferencesHash': digest(references), 'transportBinding': copy.deepcopy(transport_binding),
            'previousRuntimeHash': digest(before), 'proposedRuntimeHash': digest(after),
            'previousRoutes': before, 'proposedRoutes': after, 'changes': changes,
            'automaticRollbackAllowed': False, 'automaticWriteReplayAllowed': False,
            'runtimeAuthorityIssued': False, 'notReleaseAcceptance': True}


