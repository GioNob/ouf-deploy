#!/usr/bin/env python3
"""Concrete complete route-package fixture from exact production materializers.
The retained source projection is test-only. This result is never target apply input.
"""
import argparse, json, sys
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    sys.path.insert(0,str(a.source.resolve()))
    from tests.test_file_loop_coherence import retained_installation
    from tools.materialize_semantic_proposals import add_to_existing
    from tools.materialize_onboarding_review import materialize as onboarding_review
    from tools.materialize_semantic_human_runtime import materialize as semantic_human
    runtime, existing=retained_installation()
    result=add_to_existing(existing,runtime,'DELEGATION_KEY','SEMANTIC_PROPOSAL_KEY')
    result=onboarding_review(result,runtime,'DELEGATION_KEY','AUTHORIZATION_OWNER_KEY')
    result['routes'].extend(semantic_human(runtime,'$ENV://OIDC_SECRET')['routes'])
    ids=set();matches=set()
    for route in result['routes']:
        rid=route['id'];match=json.dumps([route.get('uri'),route.get('uris'),route.get('methods'),route.get('vars')],sort_keys=True)
        if rid in ids or match in matches:raise ValueError('ROUTE_COLLISION_REQUIRES_RECONCILIATION')
        ids.add(rid);matches.add(match)
    paths={r.get('uri') for r in result['routes']}
    required={'/mcp','/internal/capabilities/v1/execute/urban.object.search'}
    required|={'/internal/capabilities/v1/execute/managed.file/'+s for s in ['upload','handoff','profile','preview','create','review-prepare','review-read']}
    required|={'/internal/capabilities/v1/execute/semantic/'+s for s in ['search','get','create','validate','review','read']}
    if not required<=paths:raise ValueError('INCOMPLETE_FILE_COHORT_ROUTES')
    result['packageQualification']={'profile':'COMPLETE_FILE_COHORT_OFFLINE_MATERIALIZATION','targetBound':False,
        'projectionSource':'tests/fixtures/installation-projection-lab.json','secretValuesRead':False,
        'requiresRetainedTargetProjectionAndRouteReconciliation':True,'targetApplyAuthorized':False}
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':'COMPLETE_ROUTES_MATERIALIZED_OFFLINE','routeCount':len(ids),'targetBound':False}))

if __name__=='__main__':main()
