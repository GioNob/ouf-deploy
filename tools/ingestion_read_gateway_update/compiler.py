"""Materialize only the two missing READ routes using authenticated Gateway sources."""
import base64,copy,hashlib,json,os
from pathlib import Path
from tools.source_revision_update.gateway import module,lua_constant
from tools.linked_property_rollout.preparation import root_directory,write_new,read_file
from tools.ingestion_read_gateway_update.owner import require,digest
WANTED=('tools/apply_installation_projection.py','tools/delegation_functions.py','tools/materialize_ingestion_read.py',
 'tools/lua/delegation.lua','tools/lua/execute_operational.lua','schemas/mcp-gateway-status-dispatch-v1.json',
 'catalogue/ingestion-read-compiled-bindings.json')
GATEWAY_SOURCE='2dfa53fcf3792e8ed68df4e14303c3b085cdbd43'
def compile_routes(bundle,projection,before,context):
 require(bundle['schema']=='ouf.ingestion-read-gateway-compiler-sources.v1'and bundle['sourceCommit']==GATEWAY_SOURCE
  and set(bundle['files'])==set(WANTED),'EXACT_GATEWAY_COMPILER_SOURCE_BUNDLE_REQUIRED')
 sources={name:base64.b64decode(bundle['files'][name]['base64'],validate=True)for name in WANTED}
 require(all(0<len(raw)<=262144 and hashlib.sha256(raw).hexdigest()==bundle['files'][name]['sha256']
  and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==bundle['files'][name]['gitBlobSha']for name,raw in sources.items()),
  'AUTHENTICATED_GATEWAY_SOURCE_BYTES_REQUIRED')
 directory=Path(context)/'gateway-compiler';directory.mkdir(mode=0o700)
 for name,raw in sources.items():
  target=directory/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);write_new(target,raw)
  require(read_file(target,hashlib.sha256(raw).hexdigest())==raw,'ROOT_STAGED_GATEWAY_SOURCE_CHANGED')
 projector=module(sources[WANTED[0]],'qualified_ingestion_read_projection',directory/WANTED[0])
 renderer=module(sources[WANTED[1]],'qualified_ingestion_read_renderer',directory/WANTED[1])
 materializer=module(sources[WANTED[2]],'qualified_ingestion_read_materializer',directory/WANTED[2],{'function':renderer.function})
 projected=projector.apply_projection(json.loads(sources[WANTED[-1]]),projection)
 templates=[r for r in before.values()if r.get('uri')=='/internal/capabilities/v1/execute']
 require(len(templates)==1,'EXACT_RETAINED_EXECUTE_TEMPLATE_REQUIRED');template=templates[0]
 for key,field in(('ISSUER','issuerUrl'),('AUDIENCE','gatewayAudience'),('MCP_WORKLOAD','mcpServiceIdentity')):
  expected=projected['x-ouf-installation'][field]
  require(lua_constant(template,key)==(expected.rstrip('/')if key=='ISSUER'else expected),'RETAINED_GATEWAY_IDENTITY_CHANGED')
 key_env=lua_constant(template,'DELEGATION_KEY_ENV')
 result=materializer.materialize({'routes':copy.deepcopy(list(before.values()))},projected,key_env)
 require(result['routes'][:-2]==list(before.values())and len(before)==80,'EXACT80_PRESERVED_ROUTES_REQUIRED')
 additions={r['id'].rsplit('-',1)[1]:r for r in result['routes'][-2:]}
 require(set(additions)=={'status','history'}and len({r['id']for r in additions.values()})==2,'EXACT_TWO_READ_ROUTE_ADDITIONS_REQUIRED')
 after=copy.deepcopy(before)
 for row in additions.values():
  require(row['id']not in after,'EXISTING_ROUTE_ID_COLLISION');after[row['id']]=row
 require(len(after)==82,'EXACT82_PROPOSED_ROUTES_REQUIRED')
 return {'beforeRoutes':copy.deepcopy(before),'afterRoutes':after,'additions':additions,
  'sourceCommit':GATEWAY_SOURCE,'sourceHashes':{n:hashlib.sha256(raw).hexdigest()for n,raw in sources.items()},
  'targetRuntimeHash':digest(projected),'maximumGatewayWrites':2,'existingRoutesPreserved':True}
