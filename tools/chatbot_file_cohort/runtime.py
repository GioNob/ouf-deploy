"""Closed verified-memory imports for the complete finite chatbot cohort action.

No disk source fallback, installation, signing, login or operation at import.
Source/loader hashes and host bindings are independently reviewed before apply.
"""
import ast
import hashlib
import importlib.abc
import importlib.util
import json
import sys

ENTRY='tools.chatbot_file_cohort.delivery'
MODULES=frozenset(['accounting_gap_session', 'application_verification_adapter', 'atomic_review_intake', 'compile_creation_frame_policy', 'compile_file_only_frame_policy', 'compile_semantic_proposal_frame_policy', 'compile_six_mount_frame_policy', 'configtree_mount_observation', 'core_adapter_factory', 'creation_adapter', 'credential_reestablishment', 'credential_transaction', 'cutover_authority', 'cutover_executor', 'database_channel_scope', 'database_gate', 'endpoint_adapter', 'engine_creation', 'fenced_backup', 'fenced_backup_adapter', 'file_only_application', 'file_only_frame_observation', 'file_only_installation', 'file_only_node_owner', 'file_only_profile', 'first_controlled_grant', 'gated_creation_plan', 'gated_process_observation', 'gated_release_adapter', 'gated_stage_adapter', 'iam_audience_transaction', 'iam_binding_candidate', 'iam_governance_intake', 'iam_mapper_enrichment', 'iam_owner_action', 'image_custody', 'image_import', 'legacy_retirement', 'migration_admission_adapter', 'migration_root_custody', 'native_evidence_store', 'paused_attestation_adapter', 'paused_node_acceptance', 'paused_node_observation', 'paused_workload_binding', 'producer_adapter', 'producer_release_adapter', 'projected_frame_observation', 'qualified_owner_authorization_lifecycle', 'qualified_owner_scope_catalogue', 'r12_retirement_adapter', 'runtime_adapters', 'semantic_proposal_frame_observation', 'six_mount_frame_observation', 'tools.chatbot_file_cohort.acceptance', 'tools.chatbot_file_cohort.action_process', 'tools.chatbot_file_cohort.authorization', 'tools.chatbot_file_cohort.containers', 'tools.chatbot_file_cohort.continued_owner', 'tools.chatbot_file_cohort.databases', 'tools.chatbot_file_cohort.delivery', 'tools.chatbot_file_cohort.gateway', 'tools.chatbot_file_cohort.gateway_runtime', 'tools.chatbot_file_cohort.human_session', 'tools.chatbot_file_cohort.images', 'tools.chatbot_file_cohort.plan', 'tools.chatbot_file_cohort.paused_recovery', 'tools.chatbot_file_cohort.postgrant_recovery', 'tools.chatbot_file_cohort.review', 'tools.materialize_semantic_shared_faces', 'tools.materialize_southbound_kernel', 'tools.semantic_lease_recovery.bounded_recovery', 'tools.semantic_lease_recovery.reader', 'tools.semantic_lease_recovery.recovery_journal', 'tools.semantic_policy_token_owner.iam_admission', 'tools.semantic_policy_token_owner.installed_owner', 'tools.semantic_policy_token_owner.mount_observation', 'tools.semantic_policy_token_owner.owner_installation', 'tools.semantic_policy_token_owner.producer', 'tools.semantic_policy_token_owner.reporter', 'tools.semantic_policy_token_owner.source_stage', 'tools.semantic_policy_token_owner.supervisor', 'tools.semantic_policy_token_owner.worker_entry', 'tools.semantic_provider_deployment_admission', 'tools.semantic_provider_deployment_authentication', 'tools.semantic_provider_deployment_consumption', 'tools.semantic_provider_deployment_producer', 'tools.semantic_provider_deployment_protocol', 'tools.semantic_provider_deployment_signing', 'tools.semantic_provider_installer_approval', 'tools.semantic_provider_lease_coordination', 'tools.semantic_provider_lease_nft', 'tools.semantic_provider_node_observation', 'tools.semantic_provider_peer_bindings', 'tools.semantic_provider_preexec', 'tools.semantic_provider_preexec_native', 'tools.semantic_target_review.prepare_application_runtime_inputs', 'transition_journal'])
PACKAGES=frozenset(['tools', 'tools.chatbot_file_cohort', 'tools.semantic_lease_recovery', 'tools.semantic_policy_token_owner', 'tools.semantic_target_review'])
STDLIB=frozenset(['__future__', 'abc', 'argparse', 'ast', 'base64', 'contextlib', 'copy', 'ctypes', 'dataclasses', 'datetime', 'email', 'errno', 'fcntl', 'gzip', 'hashlib', 'hmac', 'http', 'importlib', 'io', 'ipaddress', 'json', 'math', 'os', 'pathlib', 'pwd', 're', 'resource', 'secrets', 'select', 'selectors', 'shutil', 'signal', 'socket', 'ssl', 'stat', 'subprocess', 'sys', 'sysconfig', 'tarfile', 'tempfile', 'termios', 'threading', 'time', 'traceback', 'types', 'urllib', 'uuid', 'zipfile', 'zlib'])

class RuntimeDenied(RuntimeError):pass
def require(ok,reason):
    if not ok:raise RuntimeDenied(reason)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()

def compile_sources(sources):
    require(type(sources)is dict and set(sources)==MODULES,'EXACT_INSTALLER_ACTION_SOURCE_CLOSURE_REQUIRED')
    require(all(type(b)is bytes and 0<len(b)<=262144 for b in sources.values())
        and sum(map(len,sources.values()))<=4194304,'BOUNDED_INSTALLER_ACTION_SOURCES_REQUIRED')
    compiled={}
    for name,raw in sources.items():
        tree=ast.parse(raw,filename='<sealed-chatbot-file-cohort:'+name+'>')
        for node in ast.walk(tree):
            refs=[v.name for v in node.names] if isinstance(node,ast.Import) else []
            if isinstance(node,ast.ImportFrom):
                require(node.level==0 and node.module is not None,'RELATIVE_INSTALLER_IMPORT_DENIED');refs=[node.module]
            for ref in refs:require(ref in MODULES or ref in PACKAGES or ref.split('.')[0] in STDLIB,'INSTALLER_DEPENDENCY_OUTSIDE_CLOSURE')
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='__import__':
                require(len(node.args)>=1 and isinstance(node.args[0],ast.Constant) and node.args[0].value=='random','DYNAMIC_INSTALLER_IMPORT_DENIED')
        compiled[name]=compile(tree,'<sealed-chatbot-file-cohort:'+name+'>','exec')
    return compiled

def declaration(commit,sources,loader,source_pins):
    require(type(commit)is str and len(commit)==40 and all(c in '0123456789abcdef' for c in commit),'EXACT_INSTALLER_SOURCE_COMMIT_REQUIRED')
    require(type(loader)is bytes and 0<len(loader)<=65536,'EXACT_INSTALLER_LOADER_REQUIRED')
    require(type(source_pins)is dict and set(source_pins)=={'ouf-deploy','ouf-onboarding'}
        and source_pins['ouf-deploy']==commit and all(type(v)is str and len(v)==40 and all(c in '0123456789abcdef' for c in v) for v in source_pins.values()),'EXACT_DEPLOY_AND_OWNER_SOURCE_PINS_REQUIRED')
    compile_sources(sources)
    return {'schema':'ouf.chatbot-file-cohort-full-source-closure.v1','sourceCommit':commit,'sourcePins':dict(source_pins),'entryModule':ENTRY,
        'loaderHash':hashlib.sha256(loader).hexdigest(),'sourceHashes':{n:hashlib.sha256(b).hexdigest() for n,b in sorted(sources.items())},
        'moduleCount':len(MODULES),'requiredPythonFlags':['-I','-B','-S'],'targetInstallationAccepted':False,'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}

class MemoryLoader(importlib.abc.MetaPathFinder,importlib.abc.Loader):
    def __init__(self,compiled,sources):self.compiled,self.sources=compiled,sources
    def find_spec(self,fullname,path=None,target=None):
        if fullname in self.compiled or fullname in PACKAGES:
            return importlib.util.spec_from_loader(fullname,self,is_package=fullname in PACKAGES)
        if fullname.startswith('tools.') or fullname in MODULES:raise RuntimeDenied('INSTALLER_LOCAL_IMPORT_FALLBACK_DENIED')
        return None
    def create_module(self,spec):return None
    def exec_module(self,module):
        if module.__name__ in PACKAGES:module.__path__=[]
        else:
            module.__qualified_source_sha256__=hashlib.sha256(self.sources[module.__name__]).hexdigest()
            exec(self.compiled[module.__name__],module.__dict__)

def load_entry(commit,sources,loader,expected_declaration_hash,source_pins):
    manifest=declaration(commit,sources,loader,source_pins)
    require(digest(manifest)==expected_declaration_hash,'INSTALLER_SOURCE_DECLARATION_DRIFT')
    require(sys.flags.isolated and sys.dont_write_bytecode and sys.flags.no_site,'ISOLATED_NO_SITE_INSTALLER_PROCESS_REQUIRED')
    require(not any(n in MODULES or n in PACKAGES or n.startswith('tools.') for n in sys.modules),'PRELOADED_INSTALLER_MODULE_DENIED')
    finder=MemoryLoader(compile_sources(sources),sources);sys.meta_path.insert(0,finder)
    try:return importlib.import_module(ENTRY),manifest
    except Exception:raise RuntimeDenied('SEALED_INSTALLER_IMPORT_FAILED') from None
