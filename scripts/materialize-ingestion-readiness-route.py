#!/usr/bin/env python3
"""Offline qualification only. Live installation projection is mandatory before apply."""
import argparse,json,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
sys.path.insert(0,str(a.source.resolve()))
from tools.compile_config import compile_config
from tools.apply_installation_projection import apply_projection
from tools.materialize_apisix_internal_m2m_routes import materialize
from ops.apisix.deploy_internal_m2m_routes import validate_routes
runtime=apply_projection(compile_config(a.source/'ouf-config'),json.loads((a.source/'tests/fixtures/installation-projection-lab.json').read_text()))
packet=materialize(runtime,['r4a-onboarding-ingestion-configuration-read'],'$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET')
validate_routes(packet['routes'])
assert len(packet['routes'])==1 and packet['routes'][0]['methods']==['GET']
packet['packageQualification']={'targetBound':False,'targetApplyAuthorized':False,'requiresRetainedInstallationProjection':True,'secretValuesRead':False}
a.output.write_text(json.dumps(packet,sort_keys=True,indent=2)+'\n')
