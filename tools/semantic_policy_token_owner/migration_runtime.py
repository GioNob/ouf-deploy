"""Closed verified-memory imports for governed migration components.

No disk source fallback, installation, signing, login or operation at import.
Source/loader hashes and host bindings are independently reviewed before apply.
"""
import ast
import hashlib
import importlib.abc
import importlib.util
import json
import sys

ENTRY='first_controlled_grant'
MODULES=frozenset({'cutover_authority','iam_audience_transaction','iam_binding_candidate',
    'iam_governance_intake','iam_mapper_enrichment','iam_owner_action',
    *('tools.'+n for n in ('materialize_semantic_shared_faces','materialize_southbound_kernel',
        'semantic_provider_deployment_admission','semantic_provider_deployment_authentication',
        'semantic_provider_deployment_consumption','semantic_provider_deployment_producer',
        'semantic_provider_deployment_protocol','semantic_provider_deployment_signing',
        'semantic_provider_lease_coordination','semantic_provider_lease_nft',
        'semantic_provider_peer_bindings','semantic_provider_preexec','semantic_provider_preexec_native'))})
MODULES=MODULES|frozenset({'accounting_gap_session','legacy_retirement','credential_reestablishment',
    'credential_transaction','first_controlled_grant',
    'tools.semantic_policy_token_owner.producer','tools.semantic_policy_token_owner.iam_admission',
    'tools.semantic_lease_recovery.bounded_recovery','tools.semantic_lease_recovery.recovery_journal'})
PACKAGES=frozenset({'tools','tools.semantic_policy_token_owner','tools.semantic_lease_recovery'})
STDLIB=frozenset({'argparse','ast','base64','contextlib','copy','fcntl','hashlib','importlib','ipaddress','json',
    'math','os','pathlib','re','selectors','signal','socket','stat','subprocess','sys','sysconfig',
    'tempfile','time','types','urllib','uuid'})

STDLIB=STDLIB|frozenset({'abc','dataclasses','http','io','ssl','hmac','resource'})

class RuntimeDenied(RuntimeError):pass
def require(ok,reason):
    if not ok:raise RuntimeDenied(reason)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()

def compile_sources(sources):
    require(type(sources)is dict and set(sources)==MODULES,'EXACT_MIGRATION_ACTION_SOURCE_CLOSURE_REQUIRED')
    require(all(type(b)is bytes and 0<len(b)<=131072 for b in sources.values())
        and sum(map(len,sources.values()))<=1048576,'BOUNDED_MIGRATION_ACTION_SOURCES_REQUIRED')
    compiled={}
    for name,raw in sources.items():
        tree=ast.parse(raw,filename='<sealed-migration:'+name+'>')
        for node in ast.walk(tree):
            refs=[v.name for v in node.names] if isinstance(node,ast.Import) else []
            if isinstance(node,ast.ImportFrom):
                require(node.level==0 and node.module is not None,'RELATIVE_MIGRATION_IMPORT_DENIED');refs=[node.module]
            for ref in refs:require(ref in MODULES or ref in PACKAGES or ref.split('.')[0] in STDLIB,'MIGRATION_DEPENDENCY_OUTSIDE_CLOSURE')
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='__import__':
                require(False,'DYNAMIC_MIGRATION_IMPORT_DENIED')
        compiled[name]=compile(tree,'<sealed-migration:'+name+'>','exec')
    return compiled

def declaration(commit,sources,loader):
    require(type(commit)is str and len(commit)==40 and all(c in '0123456789abcdef' for c in commit),'EXACT_MIGRATION_SOURCE_COMMIT_REQUIRED')
    require(type(loader)is bytes and 0<len(loader)<=65536,'EXACT_MIGRATION_LOADER_REQUIRED')
    compile_sources(sources)
    return {'schema':'ouf.policy-token-migration-component-source-closure.v1','sourceCommit':commit,'entryModule':ENTRY,
        'loaderHash':hashlib.sha256(loader).hexdigest(),'sourceHashes':{n:hashlib.sha256(b).hexdigest() for n,b in sorted(sources.items())},
        'moduleCount':len(MODULES),'requiredPythonFlags':['-I','-B','-S'],'fullOwnerInstallerQualified':False,'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}

class MemoryLoader(importlib.abc.MetaPathFinder,importlib.abc.Loader):
    def __init__(self,compiled):self.compiled=compiled
    def find_spec(self,fullname,path=None,target=None):
        if fullname in self.compiled or fullname in PACKAGES:
            return importlib.util.spec_from_loader(fullname,self,is_package=fullname in PACKAGES)
        if fullname.startswith('tools.') or fullname in MODULES:raise RuntimeDenied('MIGRATION_LOCAL_IMPORT_FALLBACK_DENIED')
        return None
    def create_module(self,spec):return None
    def exec_module(self,module):
        if module.__name__ in PACKAGES:module.__path__=[]
        else:exec(self.compiled[module.__name__],module.__dict__)

def load_entry(commit,sources,loader,expected_declaration_hash):
    manifest=declaration(commit,sources,loader)
    require(digest(manifest)==expected_declaration_hash,'MIGRATION_SOURCE_DECLARATION_DRIFT')
    require(sys.flags.isolated and sys.dont_write_bytecode and sys.flags.no_site,'ISOLATED_NO_SITE_MIGRATION_PROCESS_REQUIRED')
    require(not any(n in MODULES or n in PACKAGES or n.startswith('tools.') for n in sys.modules),'PRELOADED_MIGRATION_MODULE_DENIED')
    finder=MemoryLoader(compile_sources(sources));sys.meta_path.insert(0,finder)
    try:return importlib.import_module(ENTRY),manifest
    except Exception:raise RuntimeDenied('SEALED_MIGRATION_IMPORT_FAILED') from None
