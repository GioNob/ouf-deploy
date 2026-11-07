"""Snapshot the already qualified Discovery route and authorization compilers.

Only the fixed public source bodies below can execute. Materializer file reads
resolve against the verified in-memory snapshot, never a later filesystem read.
No target credential, authority, transport or native owner is constructed.
"""
import builtins,hashlib,types
from pathlib import Path
from .custody_capture import require
DISCOVERY_CATALOGUE='catalogue/m2-semantic-discovery-capabilities.json'

GATEWAY_COMMIT='60788cf965334441be0a33c345f5c0bcd66cbdde'
ONBOARDING_COMMIT='be388e1462778438a208c2e00e166370fee32189'
GATEWAY={
    'tools/materialize_semantic_discovery.py':'757738beed19870e672756eaf7ab174cfb023d6a690da5d2cc88a2cf44a197a5',
    'tools/delegation_functions.py':'a599b195ad0b30ca8d785990697ab0d5533d38f163ed56643a2bbf318b256ce0',
    'tools/lua/delegation.lua':'a2286bd8e92a63ce9493730ee49850ffdecf95b74c3443764e67a194cd474dae',
    'tools/lua/execute_semantic_discovery.lua':'97d08a8220ca005675d051be032048c42dcd6de2b205af90a5eef96dd9cbf061',
    'schemas/mcp-gateway-semantic-discovery-request-dispatch-v1.json':'907bbb9fb9e924338f4b6d4f35b9b263095b6aa051c10e44ae4a29a995fe677b',
    'schemas/mcp-gateway-semantic-discovery-status-dispatch-v1.json':'a055f32ba07ec29825db337540f8c757a4e695bdcdaad317bc48569dde69957b',
    'schemas/mcp-gateway-semantic-discovery-candidates-dispatch-v1.json':'b5b11b8f0d5c9602b1e584d393e8c306063549a9998d5aff13b8b4407fc91f67'}
ONBOARDING={
    'scripts/r4a_authorization_lifecycle.py':'77e1f33d335f7116556cb73765c1323e001f4f99400f7fd504685b8fbfd9b89f',
    'scripts/r4a_keycloak_client_scope_catalogue.py':'4ca8a16e7c6bb3a48e5834c4cea97709f51cf77a1f59711b947b84a29c2b74a8',
    DISCOVERY_CATALOGUE:'20030a0fa24b9af35bb0917ca53aad722bf33a4d28a9c062fb30d1d3b6d91497'}


class _SnapshotPath:
    def __init__(self,rows,name=''):self.rows,self.name=rows,name
    def __truediv__(self,name):return _SnapshotPath(self.rows,self.name+'/'+name if self.name else name)
    def read_text(self):return self.rows[self.name].decode('utf-8')


def _module(name,raw,imports=None):
    module=types.ModuleType(name);module.__file__='/verified-public-source/'+name+'.py'
    if imports is not None:
        def selected(name,globals=None,locals=None,fromlist=(),level=0):
            if name in imports:
                require(level==0 and fromlist==('function',),'CLOSED_DISCOVERY_MATERIALIZER_IMPORT_REQUIRED')
                return imports[name]
            return builtins.__import__(name,globals,locals,fromlist,level)
        module.__dict__['__builtins__']={**vars(builtins),'__import__':selected}
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    module.__qualified_source_sha256__=hashlib.sha256(raw).hexdigest()
    return module


class PublicationPrimitives:
    def __init__(self,gateway_sources,owner_sources):
        from tools.chatbot_file_cohort.authorization import OwnerPrimitives,DISCOVERY_PROFILE
        for rows,pins in ((gateway_sources,GATEWAY),(owner_sources,ONBOARDING)):
            require(type(rows) is dict and set(rows)==set(pins)
                and all(type(v) is bytes and 0<len(v)<=131072
                    and hashlib.sha256(v).hexdigest()==pins[k] for k,v in rows.items()),
                'EXACT_PINNED_DISCOVERY_PUBLICATION_SOURCE_CLOSURE_REQUIRED')
        g=dict(gateway_sources);o=dict(owner_sources)
        functions=_module('qualified_discovery_functions',g['tools/delegation_functions.py'])
        functions.ROOT=_SnapshotPath(g,'tools/lua')
        routes=_module('qualified_discovery_materializer',g['tools/materialize_semantic_discovery.py'],
            {'tools.delegation_functions':functions})
        routes.ROOT=_SnapshotPath(g)
        self.gateway=routes
        lifecycle=_module('qualified_owner_authorization_lifecycle',o['scripts/r4a_authorization_lifecycle.py'])
        scopes=_module('qualified_owner_scope_catalogue',o['scripts/r4a_keycloak_client_scope_catalogue.py'])
        self.owner=OwnerPrimitives.from_qualified_modules(lifecycle,scopes,o[DISCOVERY_CATALOGUE],
            ONBOARDING,profile=DISCOVERY_PROFILE)

    @classmethod
    def from_directories(cls,gateway,onboarding,catalogue):
        return cls({p:(Path(gateway)/p).read_bytes() for p in GATEWAY},
            {p:(Path(catalogue) if p==DISCOVERY_CATALOGUE else Path(onboarding)/p).read_bytes()
                for p in ONBOARDING})
