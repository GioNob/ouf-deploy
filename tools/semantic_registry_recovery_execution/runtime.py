"""Closed, statically resolved source loader for the Registry postboot path.

Loading this closure issues no authority and dispatches no runtime action.
The exact declaration must be independently bound by the operator package and
the current private review. No installed source or sys.path fallback is used.
"""
import ast
import hashlib
import importlib.abc
import importlib.util
import json
import re
import sys

ENTRY = 'tools.semantic_registry_recovery_execution.postboot_entry'
MAX_MODULES, MAX_SOURCE_BYTES, MAX_TOTAL_BYTES = 256, 262144, 8388608
ALIASES = {
    "accounting_gap_session": "tools/semantic_policy_token_owner/accounting_gap_session.py",
    "application_verification_adapter": "tools/semantic_application_cutover/application_verification_adapter.py",
    "atomic_review_intake": "tools/semantic_application_cutover/atomic_review_intake.py",
    "compile_creation_frame_policy": "tools/semantic_frame_compiler/compile_creation_frame_policy.py",
    "compile_file_only_frame_policy": "tools/semantic_frame_compiler/compile_file_only_frame_policy.py",
    "compile_semantic_proposal_frame_policy": "tools/semantic_frame_compiler/compile_semantic_proposal_frame_policy.py",
    "compile_six_mount_frame_policy": "tools/semantic_frame_compiler/compile_six_mount_frame_policy.py",
    "configtree_mount_observation": "tools/semantic_application_cutover/configtree_mount_observation.py",
    "credential_reestablishment": "tools/semantic_policy_token_owner/credential_reestablishment.py",
    "credential_transaction": "tools/semantic_policy_token_owner/credential_transaction.py",
    "cutover_authority": "tools/semantic_application_cutover/cutover_authority.py",
    "cutover_executor": "tools/semantic_application_cutover/cutover_executor.py",
    "database_channel_scope": "tools/semantic_application_cutover/database_channel_scope.py",
    "database_gate": "tools/semantic_database_cutover/database_gate.py",
    "engine_creation": "tools/semantic_application_cutover/engine_creation.py",
    "fenced_backup": "tools/semantic_database_cutover/fenced_backup.py",
    "fenced_backup_adapter": "tools/semantic_application_cutover/fenced_backup_adapter.py",
    "file_only_frame_observation": "tools/semantic_application_cutover/file_only_frame_observation.py",
    "file_only_node_owner": "tools/semantic_application_cutover/file_only_node_owner.py",
    "file_only_profile": "tools/semantic_application_cutover/file_only_profile.py",
    "first_controlled_grant": "tools/semantic_policy_token_owner/first_controlled_grant.py",
    "gated_creation_plan": "tools/semantic_application_cutover/gated_creation_plan.py",
    "gated_process_observation": "tools/semantic_application_cutover/gated_process_observation.py",
    "iam_audience_transaction": "tools/semantic_policy_token_owner/iam_audience_transaction.py",
    "iam_binding_candidate": "tools/semantic_policy_token_owner/iam_binding_candidate.py",
    "iam_governance_intake": "tools/semantic_policy_token_owner/iam_governance_intake.py",
    "iam_mapper_enrichment": "tools/semantic_policy_token_owner/iam_mapper_enrichment.py",
    "iam_owner_action": "tools/semantic_policy_token_owner/iam_owner_action.py",
    "image_custody": "tools/semantic_application_cutover/image_custody.py",
    "image_import": "tools/semantic_application_cutover/image_import.py",
    "legacy_retirement": "tools/semantic_policy_token_owner/legacy_retirement.py",
    "migration_root_custody": "tools/semantic_policy_token_owner/migration_root_custody.py",
    "native_evidence_store": "tools/semantic_application_cutover/native_evidence_store.py",
    "paused_attestation_adapter": "tools/semantic_application_cutover/paused_attestation_adapter.py",
    "paused_node_acceptance": "tools/semantic_application_cutover/paused_node_acceptance.py",
    "paused_node_observation": "tools/semantic_application_cutover/paused_node_observation.py",
    "paused_workload_binding": "tools/semantic_application_cutover/paused_workload_binding.py",
    "projected_frame_observation": "tools/semantic_application_cutover/projected_frame_observation.py",
    "semantic_proposal_frame_observation": "tools/semantic_application_cutover/semantic_proposal_frame_observation.py",
    "six_mount_frame_observation": "tools/semantic_application_cutover/six_mount_frame_observation.py",
    "tools.materialize_semantic_shared_faces": "tools/semantic_cohort_admission/cohort-draft/tools/materialize_semantic_shared_faces.py",
    "tools.materialize_southbound_kernel": "tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel.py",
    "tools.semantic_provider_deployment_admission": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_admission.py",
    "tools.semantic_provider_deployment_authentication": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py",
    "tools.semantic_provider_deployment_consumption": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_consumption.py",
    "tools.semantic_provider_deployment_producer": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_producer.py",
    "tools.semantic_provider_deployment_protocol": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_protocol.py",
    "tools.semantic_provider_deployment_signing": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_signing.py",
    "tools.semantic_provider_installer_approval": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_installer_approval.py",
    "tools.semantic_provider_lease_coordination": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_coordination.py",
    "tools.semantic_provider_lease_nft": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_nft.py",
    "tools.semantic_provider_node_observation": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_node_observation.py",
    "tools.semantic_provider_peer_bindings": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_peer_bindings.py",
    "tools.semantic_provider_preexec": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec.py",
    "tools.semantic_provider_preexec_native": "tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec_native.py",
    "transition_journal": "tools/semantic_application_cutover/transition_journal.py"
}
STDLIB = frozenset({
    '__future__', 'abc', 'argparse', 'ast', 'base64', 'contextlib', 'copy', 'ctypes',
    'dataclasses', 'datetime', 'email', 'errno', 'fcntl', 'gzip', 'hashlib', 'hmac',
    'http', 'importlib', 'io', 'ipaddress', 'json', 'math', 'os', 'pathlib', 'pwd',
    'random', 're', 'resource', 'secrets', 'select', 'selectors', 'shutil', 'signal',
    'socket', 'ssl', 'stat', 'subprocess', 'sys', 'sysconfig', 'tarfile', 'tempfile',
    'termios', 'threading', 'time', 'traceback', 'types', 'urllib', 'uuid', 'zipfile',
    'zlib',
})


class RuntimeDenied(RuntimeError):
    pass


def require(ok, reason):
    if not ok:
        raise RuntimeDenied(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def source_path(name):
    require(type(name) is str and re.fullmatch(r'[A-Za-z_]\w*(\.[A-Za-z_]\w*)*', name),
            'EXACT_SOURCE_MODULE_NAME_REQUIRED')
    if name in ALIASES:
        return ALIASES[name]
    require(name.startswith('tools.') and not name.endswith('.__init__'),
            'SOURCE_MODULE_OUTSIDE_CLOSED_NAMESPACE')
    return name.replace('.', '/') + '.py'


def package_names(names):
    packages = set()
    for name in names:
        parts = name.split('.')
        packages.update('.'.join(parts[:i]) for i in range(1, len(parts)))
    require(not packages.intersection(names), 'MODULE_PACKAGE_NAME_COLLISION')
    return frozenset(packages)


def relative(name, module, level):
    if not level:
        require(module is not None, 'ABSOLUTE_IMPORT_MODULE_REQUIRED')
        return module
    package = name.rpartition('.')[0]
    require(package and level <= len(package.split('.')), 'RELATIVE_IMPORT_ESCAPES_PACKAGE')
    try:
        return importlib.util.resolve_name('.' * level + (module or ''), package)
    except (ImportError, ValueError):
        raise RuntimeDenied('RELATIVE_IMPORT_ESCAPES_PACKAGE') from None


def references(name, raw):
    """Return (module, imported members) for every static or literal import."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_SOURCE_BYTES,
            'BOUNDED_SOURCE_MODULE_REQUIRED')
    tree = ast.parse(raw, filename='<sealed-registry-postboot:' + name + '>')
    refs = []
    importlib_aliases = {'importlib'}
    import_functions = {'__import__'}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                refs.append((item.name, ()))
                if item.name == 'importlib':
                    importlib_aliases.add(item.asname or item.name)
        elif isinstance(node, ast.ImportFrom):
            module = relative(name, node.module, node.level)
            require(all(item.name != '*' for item in node.names), 'STAR_IMPORT_NOT_CLOSED')
            refs.append((module, tuple(item.name for item in node.names)))
            if module == 'importlib':
                import_functions.update(item.asname or item.name for item in node.names
                                        if item.name == 'import_module')
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dynamic = (isinstance(node.func, ast.Name) and node.func.id in import_functions) or (
            isinstance(node.func, ast.Attribute) and node.func.attr == 'import_module'
            and isinstance(node.func.value, ast.Name) and node.func.value.id in importlib_aliases)
        if dynamic:
            require(node.args and isinstance(node.args[0], ast.Constant)
                    and type(node.args[0].value) is str and not node.args[0].value.startswith('.'),
                    'UNRESOLVED_DYNAMIC_IMPORT_DENIED')
            module = node.args[0].value
            # Existing runtime sources use only literal stdlib dynamic imports.
            # Runtime-owned module imports must be ordinary static imports.
            require(module.split('.')[0] in STDLIB, 'DYNAMIC_APPLICATION_IMPORT_DENIED')
            refs.append((module, ()))
    return tree, tuple(refs)


def dependencies(name, raw, modules, packages):
    tree, refs = references(name, raw)
    required = set()
    for module, members in refs:
        if module.split('.')[0] in STDLIB:
            continue
        if module in modules:
            required.add(module)
        elif module in packages:
            require(members, 'PACKAGE_ONLY_IMPORT_NOT_CLOSED')
            for member in members:
                child = module + '.' + member
                require(child in modules, 'MISSING_STATIC_PACKAGE_MEMBER')
                required.add(child)
        else:
            require(False, 'DEPENDENCY_OUTSIDE_RUNTIME_CLOSURE')
    return tree, required


def compile_sources(sources):
    require(type(sources) is dict and ENTRY in sources and 1 <= len(sources) <= MAX_MODULES
            and all(type(raw) is bytes and 0 < len(raw) <= MAX_SOURCE_BYTES for raw in sources.values())
            and sum(map(len, sources.values())) <= MAX_TOTAL_BYTES, 'BOUNDED_COMPLETE_RECOVERY_SOURCES_REQUIRED')
    for name in sources:
        source_path(name)
    packages = package_names(sources)
    compiled, graph = {}, {}
    for name, raw in sources.items():
        tree, deps = dependencies(name, raw, sources, packages)
        graph[name] = deps
        compiled[name] = compile(tree, '<sealed-registry-postboot:' + name + '>', 'exec')
    reached, pending = set(), [ENTRY]
    while pending:
        name = pending.pop()
        if name not in reached:
            reached.add(name)
            pending.extend(graph[name] - reached)
    require(reached == set(sources), 'UNREACHABLE_EXTRA_SOURCE_DENIED')
    return compiled, packages


def declaration(commit, sources, loader, source_pins):
    require(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit), 'EXACT_SOURCE_COMMIT_REQUIRED')
    require(type(loader) is bytes and 0 < len(loader) <= 65536, 'EXACT_BOUNDED_LOADER_REQUIRED')
    repositories = {'ouf-deploy', 'ouf-semantic-registry', 'ouf-ingestion-runtime', 'ouf-api-gateway', 'ouf-onboarding'}
    require(type(source_pins) is dict and source_pins.get('ouf-deploy') == commit
            and set(source_pins) <= repositories
            and all(type(value) is str and re.fullmatch('[a-f0-9]{40}', value) for value in source_pins.values()),
            'EXPLICIT_SOURCE_REPOSITORY_PINS_REQUIRED')
    _, packages = compile_sources(sources)
    return {
        'schema': 'ouf.semantic-registry-postboot-source-closure.v1',
        'sourceCommit': commit, 'sourcePins': dict(source_pins), 'entryModule': ENTRY,
        'loaderHash': hashlib.sha256(loader).hexdigest(),
        'sourcePaths': {name: source_path(name) for name in sorted(sources)},
        'sourceHashes': {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(sources.items())},
        'sourceGitBlobs': {name: hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                           for name, raw in sorted(sources.items())},
        'packages': sorted(packages), 'moduleCount': len(sources),
        'requiredPythonFlags': ['-I', '-B', '-S'], 'runtimeAuthorityIssued': False,
        'targetInstallationAccepted': False, 'releaseAcceptance': False,
    }


class MemoryLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, compiled, packages, sources):
        self.compiled, self.packages, self.sources = compiled, packages, sources

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.compiled or fullname in self.packages:
            return importlib.util.spec_from_loader(fullname, self, is_package=fullname in self.packages)
        root = fullname.split('.')[0]
        if fullname in ALIASES or root == 'tools' or root not in sys.stdlib_module_names:
            raise RuntimeDenied('LOCAL_SOURCE_IMPORT_FALLBACK_DENIED')
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        name = module.__name__
        if name in self.packages:
            module.__path__ = []
        else:
            module.__qualified_source_sha256__ = hashlib.sha256(self.sources[name]).hexdigest()
            module.__qualified_source_path__ = source_path(name)
            exec(self.compiled[name], module.__dict__)


def load_entry(commit, sources, loader, expected_declaration_hash, source_pins):
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'ISOLATED_NO_SITE_NO_BYTECODE_RUNTIME_REQUIRED')
    manifest = declaration(commit, sources, loader, source_pins)
    require(digest(manifest) == expected_declaration_hash, 'APPROVED_SOURCE_DECLARATION_CHANGED')
    compiled, packages = compile_sources(sources)
    require(not any(name in sources or name in packages or name in ALIASES or name.startswith('tools.')
                    for name in sys.modules), 'PRELOADED_APPLICATION_MODULE_DENIED')
    finder = MemoryLoader(compiled, packages, sources)
    sys.meta_path.insert(0, finder)
    try:
        entry = importlib.import_module(ENTRY)
        # Materialize the complete fixed closure before any worker thread may
        # start. Runtime source guards then observe an immutable module set.
        for name in sorted(sources):
            importlib.import_module(name)
        return entry, manifest
    except Exception:
        # Keep the rejecting finder in place. A failed import must never turn
        # into a retry from disk within this process.
        raise RuntimeDenied('SEALED_POSTBOOT_IMPORT_FAILED') from None
