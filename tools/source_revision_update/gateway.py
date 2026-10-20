"""Compile two additive routes from authenticated production Gateway sources.

The one removed import is dependency resolution for the exact qualified Lua
renderer; its original function and data files are retained. No authority class
is replaced, no credential is read and no target request is issued here.
"""
import ast
import copy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import types
from tools.source_revision_update.owner import require, digest

WANTED = ('tools/apply_installation_projection.py','tools/delegation_functions.py',
          'tools/materialize_source_revision.py','tools/lua/delegation.lua',
          'tools/lua/execute_source_revision.lua',
          'schemas/mcp-gateway-source-revision-prepare-dispatch-v1.json',
          'schemas/mcp-gateway-source-revision-read-dispatch-v1.json')


def source_members(raw, inventory, wanted=WANTED):
    require(type(raw) is bytes and 0 < len(raw) <= 67108864 and inventory.get('truncated') is False,
            'BOUNDED_AUTHENTICATED_SOURCE_ARCHIVE_REQUIRED')
    entries = {r['path']:r for r in inventory['tree']}
    require(len(entries) == len(inventory['tree']) <= 8192, 'COMPLETE_UNIQUE_SOURCE_INVENTORY_REQUIRED')
    result = {}; seen = set()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for row in archive:
            path = PurePosixPath(row.name); name = str(path)
            require(name == row.name.rstrip('/') and not path.is_absolute() and '..' not in path.parts
                    and name not in seen and len(seen) < 8192 and (row.isfile() or row.isdir()),
                    'SAFE_UNIQUE_SOURCE_ARCHIVE_REQUIRED')
            seen.add(name)
            if name in wanted:
                require(row.isfile() and 0 < row.size <= 1048576 and name in entries
                        and entries[name]['mode'] in ('100644','100755'), 'QUALIFIED_SOURCE_MEMBER_REQUIRED')
                value = archive.extractfile(row).read(1048577)
                require(len(value) == row.size and hashlib.sha1(b'blob '+str(len(value)).encode()+b'\0'+value).hexdigest()
                        == entries[name]['sha'], 'QUALIFIED_SOURCE_BLOB_CHANGED')
                result[name] = value
    require(set(result) == set(wanted), 'QUALIFIED_SOURCE_MEMBER_MISSING')
    return result


def module(raw, name, path, dependencies=None):
    result = types.ModuleType(name); result.__file__ = str(path)
    tree = ast.parse(raw,filename=str(path))
    if dependencies is not None:
        removed = []
        for node in tree.body:
            if isinstance(node,ast.ImportFrom) and node.module == 'tools.delegation_functions':
                require(node.level == 0 and len(node.names) == 1 and node.names[0].name == 'function'
                        and node.names[0].asname is None, 'EXACT_RENDERER_DEPENDENCY_REQUIRED')
                removed.append(node)
        require(len(removed) == 1 and set(dependencies) == {'function'}, 'SINGLE_RENDERER_IMPORT_REQUIRED')
        tree.body = [n for n in tree.body if n not in removed]
        result.__dict__.update(dependencies)
    exec(compile(tree,str(path),'exec'),result.__dict__)
    result.__qualified_source_sha256__ = hashlib.sha256(raw).hexdigest()
    return result


def lua_constant(route, name):
    values = []
    for plugin in ('serverless-pre-function','serverless-post-function'):
        for source in route.get('plugins',{}).get(plugin,{}).get('functions',[]):
            values.extend(json.loads(v) for v in re.findall(r'^local '+re.escape(name)+r' = ("[^\n]*")$',source,re.M))
    require(values and len(set(values)) == 1 and type(values[0]) is str, 'UNIQUE_RETAINED_LUA_CONSTANT_REQUIRED')
    return values[0]


def compile_routes(directory, sources, compiled, projection, before):
    directory = Path(directory)
    require(set(sources) == set(WANTED), 'EXACT_SOURCE_REVISION_COMPILER_FILES_REQUIRED')
    for name,raw in sources.items():
        path = directory/name
        require(path.is_file() and not path.is_symlink() and path.read_bytes() == raw,
                'ROOT_STAGED_GATEWAY_SOURCE_CHANGED')
    projector = module(sources[WANTED[0]],'qualified_revision_projection',directory/WANTED[0])
    renderer = module(sources[WANTED[1]],'qualified_revision_lua',directory/WANTED[1])
    materializer = module(sources[WANTED[2]],'qualified_revision_materializer',directory/WANTED[2],
                          {'function':renderer.function})
    runtime = projector.apply_projection(compiled,projection)
    def selected(uri):
        rows = [r for r in before.values() if r.get('uri') == uri]
        require(len(rows) == 1,'EXACT_RETAINED_ROUTE_REQUIRED')
        return rows[0]
    base = selected('/internal/capabilities/v1/execute')
    old = [selected('/internal/capabilities/v1/execute/managed.file/'+mode) for mode in ('review-prepare','review-read')]
    installation = runtime['x-ouf-installation']
    for route in [base,*old]:
        for constant,field in (('ISSUER','issuerUrl'),('AUDIENCE','gatewayAudience'),('MCP_WORKLOAD','mcpServiceIdentity')):
            expected = installation[field].rstrip('/') if constant == 'ISSUER' else installation[field]
            require(lua_constant(route,constant) == expected,'RETAINED_GATEWAY_IDENTITY_CHANGED')
    delegation = lua_constant(base,'DELEGATION_KEY_ENV'); owner = lua_constant(old[0],'OWNER_KEY_ENV')
    require(all(lua_constant(r,'DELEGATION_KEY_ENV') == delegation and lua_constant(r,'OWNER_KEY_ENV') == owner for r in old)
            and owner != delegation,'RETAINED_ONBOARDING_SIGNING_REFERENCES_CHANGED')
    result = materializer.materialize({'routes':copy.deepcopy(list(before.values()))},runtime,delegation,owner)
    require(result['routes'][:-2] == list(before.values()),'PREEXISTING_ROUTES_CHANGED')
    additions = {}
    for route in result['routes'][-2:]:
        mode = route['uri'].rsplit('/',1)[-1]
        require(mode in ('prepare','read') and mode not in additions,'EXACT_TWO_REVISION_ROUTES_REQUIRED')
        require(not any(route['uri'] in ([r.get('uri')]+list(r.get('uris') or []))
                    and ('POST' in r.get('methods',[]) or not r.get('methods')) for r in before.values()),
                'RETAINED_ROUTE_SELECTOR_COLLISION')
        route.setdefault('status',1); route.setdefault('priority',0)
        additions[mode] = route
    after = copy.deepcopy(before); after.update({r['id']:r for r in additions.values()})
    return {'beforeRoutes':copy.deepcopy(before),'afterRoutes':after,'additions':additions,
            'targetRuntimeHash':digest(runtime),'sourceHashes':{n:hashlib.sha256(v).hexdigest() for n,v in sources.items()},
            'delegationKeyEnvironment':delegation,'ownerKeyEnvironment':owner,'maximumGatewayWrites':2,
            'existingRoutesPreserved':True,'credentialValuesRead':False,'runtimeMutations':0}
