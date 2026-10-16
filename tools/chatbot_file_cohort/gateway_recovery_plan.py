"""Offline phase-5 reprocessing plan; never mutates a retained journal or route.

The compiler alone grants no executable scope. The distinct recovery profile
binds its result to retained history, finite HUMAN authority and a concrete
numeric-compatible APISIX owner before the publisher can accept it.
"""
import copy

from tools.chatbot_file_cohort.plan import digest, require

PROFILE = 'ouf.gateway-schema-governed-reprocessing-plan.v1'
ORIGINAL_SCHEMA = '442d48f31d9c117a440dac709e698aa1e71f5b37c03f4db89d127c77f9296232'
PROJECTED_SCHEMA = '47f15551e639f73b72854cb3e5b58d0dec6aecd6e93ed48a0a7c09d1ebeb47c0'
IDENTIFIER = 'urn:ouf:managed-file-execution-proposal:lexical-csv:v1'
CLAIMED_ROUTE_HASH = '2d1393083865aca308d029bf4a8dbd22311a1085e6cc6904bafe18e51bf82283'


def metadata_projection(route):
    """Only the independently reproduced metadata defect may change."""
    result = copy.deepcopy(route)
    schema = result['plugins']['request-validation']['body_schema']
    require(digest(schema) == ORIGINAL_SCHEMA, 'EXACT_QUALIFIED_ORIGINAL_SCHEMA_REQUIRED')
    def visit(value):
        if isinstance(value, dict):
            require(not {'$ref', '$dynamicRef', '$recursiveRef'} & set(value),
                    'SCHEMA_REFERENCE_PREVENTS_METADATA_PROJECTION')
            for child in value.values(): visit(child)
        elif isinstance(value, list):
            for child in value: visit(child)
    visit(schema)
    proposal = schema['properties']['Arguments']['properties']['executionProposal']
    require(proposal.get('$id') == IDENTIFIER, 'QUALIFIED_NESTED_IDENTIFIER_REQUIRED')
    del proposal['$id']
    require(digest(schema) == PROJECTED_SCHEMA, 'EXACT_QUALIFIED_PROJECTED_SCHEMA_REQUIRED')
    return result


def compile_remaining(old_plan, old_journal, first_read, second_read,
                      proposed_transport, numeric_runtime_plan_hash):
    """Describe 28 remaining changes while preserving the 9+1 historical rows.

    Reads passed here must come from the bound owner transport under an
    independently validated retained checkpoint. Hashes are not authorization.
    """
    import re
    require(type(numeric_runtime_plan_hash) is str and
            re.fullmatch('[0-9a-f]{64}', numeric_runtime_plan_hash),
            'REVIEWED_NUMERIC_RUNTIME_PLAN_HASH_REQUIRED')
    require(old_journal.get('planHash') == digest(old_plan)
            and old_journal.get('budgetReset') is False
            and old_journal.get('nextStep') == 9
            and len(old_journal.get('effects', [])) == 10
            and len(old_plan.get('changes', [])) == 37,
            'EXACT_NINE_APPLIED_ONE_CLAIMED_BOUNDARY_REQUIRED')
    expected = copy.deepcopy(old_plan['previousRoutes'])
    complete = copy.deepcopy(expected)
    require(len({c['id'] for c in old_plan['changes']}) == 37,
            'UNIQUE_PREDECESSOR_ROUTE_CHANGES_REQUIRED')
    for change in old_plan['changes']:
        require(complete.get(change['id']) == change['before'],
                'PREDECESSOR_ROUTE_BEFORE_VALUE_DRIFT')
        complete[change['id']] = copy.deepcopy(change['after'])
    require(complete == old_plan['proposedRoutes']
            and digest(expected) == old_plan['previousRuntimeHash']
            and digest(complete) == old_plan['proposedRuntimeHash'],
            'PREDECESSOR_COMPLETE_ROUTE_PLAN_DRIFT')
    for index, effect in enumerate(old_journal['effects']):
        change = old_plan['changes'][index]
        require(effect.get('routeId') == change['id']
                and effect.get('intentHash') == digest(change)
                and effect.get('state') == ('APPLIED' if index < 9 else 'CLAIMED'),
                'RETAINED_GATEWAY_EFFECT_HISTORY_DRIFT')
        if index < 9:
            expected[change['id']] = copy.deepcopy(change['after'])
            require(effect.get('observedMapHash') == digest(expected),
                    'RETAINED_GATEWAY_PREFIX_EVIDENCE_DRIFT')
    claim = old_plan['changes'][9]
    require(digest(claim['id']) == CLAIMED_ROUTE_HASH
            and claim['before'] is None and claim['id'] not in expected,
            'QUALIFIED_ABSENT_ROUTE_CLAIM_REQUIRED')
    require(first_read == second_read == expected,
            'STABLE_EXACT_BEFORE_CLAIM_MAP_REQUIRED')
    result = copy.deepcopy(old_plan)
    target = copy.deepcopy(old_plan['proposedRoutes'])
    target[claim['id']] = metadata_projection(claim['after'])
    remaining = []
    for change in old_plan['changes'][9:]:
        remaining.append({'id': change['id'], 'before': expected.get(change['id']),
                          'after': target[change['id']]})
    require(digest(remaining[0]) != old_journal['effects'][-1]['intentHash'],
            'CONSUMED_INTENT_MUST_NOT_BE_REPLAYED')
    require(all(target[e['routeId']] == expected[e['routeId']]
                for e in old_journal['effects'][:9]),
            'COMPLETED_GATEWAY_PREFIX_MUST_REMAIN_EXACT')
    result.update(previousRoutes=expected, proposedRoutes=target, changes=remaining,
                  previousRuntimeHash=digest(expected), proposedRuntimeHash=digest(target),
                  transportBinding=copy.deepcopy(proposed_transport))
    result['governedReprocessing'] = {
        'profile': PROFILE, 'predecessorPlanHash': digest(old_plan),
        'predecessorJournalHash': digest(old_journal),
        'historicalAppliedEffects': copy.deepcopy(old_journal['effects'][:9]),
        'historicalUnresolvedClaim': copy.deepcopy(old_journal['effects'][9]),
        'historicalClaimOutcome': 'UNPROVEN_OBSERVED_ABSENT',
        'newIntentHash': digest(remaining[0]),
        'numericRuntimePlanHash': numeric_runtime_plan_hash,
        'replayAllowed': False, 'runtimeAuthorityIssued': False,
        'executionIntegrationQualified': False,
    }
    return result
