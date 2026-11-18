"""Pure R3 composition from public document bytes and repository blobs.

No filesystem, clock, process, network or key access. See the task-40b document
for the input map and the intentionally different repository/installed paths.
"""
import builtins
import copy
import hashlib
import json
from pathlib import PurePosixPath
import types

from tools.semantic_provider_operation import authorization as A
from tools.semantic_provider_admission_v2 import broker_v2 as B, evidence_v2 as E
from tools.semantic_provider_admission_v2.l2_binding import L2_LIVE_MAC, live_interface
from tools.semantic_frame_compiler.compile_creation_frame_policy import compile_policy
from tools.semantic_b1_acceptance import acceptance as ACCEPT

ROLES = A.ROLES
RUNTIME = "tools/semantic_runtime_v52/semantic_provider_docker_runtime_v52.py"
SUPERVISOR = "tools/semantic_provider_operation/lease_supervisor.py"
MANDATES = "tools/semantic_authority_mandates/mandates.py"
OBSERVER = "tools/semantic_frame_compiler/frame-observer.py"
OBSERVER_V2 = "tools/semantic_frame_compiler/frame-observer-v2.py"
RECOVERY = ("activation_core", "bounded_recovery", "recovery_journal", "lease_recovery_budget",
            "resilient_lease_adapter", "adaptive_supervisor", "nft_seconds_backend", "deadline_backend",
            "continuous_supervisor", "dns", "readback_margin_compiler")
SUPERVISOR_SOURCES = {SUPERVISOR, "scripts/semantic-provider-lease-supervisor-v2.py",
    "tools/semantic_provider_admission_v2/locking.py",
    "tools/semantic_provider_operation/authorization.py", "tools/semantic_provider_operation/epochs.py",
    *("tools/semantic_lease_recovery/" + n + ".py" for n in RECOVERY)}
# target relative to sourceRoot -> original repository blob path.
SOURCE_MAP = {p: p for p in B.SOURCES | SUPERVISOR_SOURCES | {RUNTIME, MANDATES, OBSERVER}}
for _name in B.MODULES:
    SOURCE_MAP["tools/" + _name + ".py"] = "tools/semantic_cohort_admission/cohort-draft/tools/" + _name + ".py"
# Preserve repository-relative originals as well as the aliases expected by v2.
SOURCE_MAP.update({p: p for p in list(SOURCE_MAP.values())})
SOURCE_INPUTS = frozenset(SOURCE_MAP.values())
# Keep the historical closure exact: no v2 blob in releases 1--5.
SOURCE_MAP_V6 = {p: v for p, v in SOURCE_MAP.items() if p != OBSERVER}
SOURCE_MAP_V6[OBSERVER_V2] = OBSERVER_V2
SOURCE_INPUTS_V6 = frozenset(SOURCE_MAP_V6.values())
# No replacement bytes enter historical closures, including repository aliases.
REPLACEMENTS_V11 = {
    'tools/semantic_lease_recovery/' + n + '.py': 'tools/semantic_lease_recovery/' + n + '_v2.py'
    for n in ('activation_core', 'resilient_lease_adapter', 'adaptive_supervisor', 'continuous_supervisor', 'dns')}
REPLACEMENTS_V11.update({
    SUPERVISOR: 'tools/semantic_provider_operation/lease_supervisor_v2.py',
    'scripts/semantic-provider-lease-supervisor-v2.py': 'scripts/semantic-provider-lease-supervisor-v3.py',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_owner.py':
        'tools/semantic_lease_recovery/lease_owner_v2.py',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_dns.py':
        'tools/semantic_lease_recovery/dns_v2.py'})
SOURCE_MAP_V11 = {p: REPLACEMENTS_V11.get(v, v) for p, v in SOURCE_MAP_V6.items()}
SOURCE_INPUTS_V11 = frozenset(SOURCE_MAP_V11.values())
KERNEL_V1 = 'tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel.py'
KERNEL_V2 = KERNEL_V1.replace('.py', '_v2.py')
REFRESH_V2 = 'tools/semantic_lease_recovery/materialize_southbound_lease_refresh_v2.py'
REPLACEMENTS_V12 = {KERNEL_V1: KERNEL_V2,
    'tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_lease_refresh.py': REFRESH_V2,
    'tools/semantic_lease_recovery/readback_margin_compiler.py': REFRESH_V2}
SOURCE_MAP_V12 = {p: REPLACEMENTS_V12.get(v, v) for p, v in SOURCE_MAP_V11.items()}
# The compiler alias embeds the frozen validator: it must not import itself.
SOURCE_INPUTS_V12 = frozenset(SOURCE_MAP_V12.values()) | {KERNEL_V1}
IDENTITY_SOURCE = 'tools/semantic_provider_r3/identity_provider_v13.py'
SOURCE_MAP_V13 = {**SOURCE_MAP_V12, IDENTITY_SOURCE: IDENTITY_SOURCE}
SOURCE_INPUTS_V13 = frozenset(SOURCE_MAP_V13.values()) | {KERNEL_V1}
EGRESS_V15 = 'tools/semantic_provider_r3/egress_v15.py'
ROUTES_SOURCE = 'tools/semantic_provider_routes/routes.py'
SOURCE_MAP_V15 = {**SOURCE_MAP_V13, **{p: p for p in (
    EGRESS_V15, ROUTES_SOURCE, 'tools/semantic_provider_routes/custody.py',
    'tools/semantic_provider_r3/read_routes_v15.py')}}
SOURCE_INPUTS_V15 = frozenset(SOURCE_MAP_V15.values()) | {KERNEL_V1}
ADAPTER_V16 = 'tools/semantic_provider_r3/adapter_v16.py'
ADAPTER_CONTRACT = 'tools/semantic_provider_config/contract.py'
SOURCE_MAP_V16 = {**SOURCE_MAP_V15, **{p: p for p in (
    ADAPTER_V16, ADAPTER_CONTRACT, 'tools/semantic_provider_r3/read_adapter_v16.py')}}
SOURCE_INPUTS_V16 = frozenset(SOURCE_MAP_V16.values()) | {KERNEL_V1}
SUPERVISOR_SOURCES_V11 = SUPERVISOR_SOURCES | {
    'tools/semantic_provider_dns.py', 'tools/semantic_provider_lease_owner.py'}

L2_SOURCE = "tools/semantic_provider_admission_v2/l2_binding.py"
DATA_INPUTS = {"settings", "coordinator", "coordinationJournal", "a2Manifest", "successors", "semanticPeer",
               "rootfs", "acceptance"} | {r + "/" + p for r in ROLES for p in
                                            ("historicalTemplate", "template", "launch", "context", "policy")}
DATA_INPUTS_V12 = DATA_INPUTS | {'migrationReceipt', 'migrationPlan', 'generationReceipt', 'bootPointer'}
DATA_INPUTS_V13 = DATA_INPUTS_V12 | {'identityProviderPeer'}
DATA_INPUTS_V15 = DATA_INPUTS_V13 | {'southbound/routesProjection'}
DATA_INPUTS_V16 = DATA_INPUTS_V15 | {'adapter/configProjection', 'installationProfile'}
SETTINGS = {"installRoot", "issuedAt", "installationRef", "entityRef", "issuerRef", "anchorBinding",
            "mandateRoot", "opensslBinding", "coordinatorBinding", "tableNames", "runtimeBinding",
            "runtimeRootParent", "rootfsLimits", "supervisorLimits"}
require, canonical, sha = A.require, A.canonical, A.sha


def input_set(files, sources):
    """Closed input pairs; the authenticated sequence still selects the version."""
    return ((set(files) == DATA_INPUTS and set(sources) in
             (SOURCE_INPUTS, SOURCE_INPUTS_V6, SOURCE_INPUTS_V11)) or
            (set(files) == DATA_INPUTS_V12 and set(sources) == SOURCE_INPUTS_V12) or
            (set(files) == DATA_INPUTS_V13 and set(sources) == SOURCE_INPUTS_V13) or
            (set(files) == DATA_INPUTS_V15 and set(sources) == SOURCE_INPUTS_V15) or
            (set(files) == DATA_INPUTS_V16 and set(sources) == SOURCE_INPUTS_V16))


def migration_bindings(files):
    """Reconcile task-65 artifacts without inventing a migration state/schema."""
    require(DATA_INPUTS_V12 <= set(files), 'R3_LEASE_KERNEL_MIGRATION_REQUIRED')
    d = {k: document(files[k]) for k in DATA_INPUTS_V12 - DATA_INPUTS}
    plan, receipt, generation, pointer = (d[k] for k in
        ('migrationPlan', 'migrationReceipt', 'generationReceipt', 'bootPointer'))
    owner, settings = document(files['coordinator']), document(files['settings'])
    code = 'R3_LEASE_KERNEL_MIGRATION_DRIFT'
    require(plan.get('schema') == receipt.get('schema') == 'ouf.semantic-lease-kernel-migration.v1'
            and plan.get('operation') == 'migrate'
            and plan.get('planSha256') == sha(canonical({k: v for k, v in plan.items() if k != 'planSha256'})), code)
    status = receipt.get('status')
    require(status in ('LEASE_KERNEL_MIGRATED', 'LEASE_KERNEL_FINALIZED'), 'R3_LEASE_KERNEL_MIGRATION_STATE_DENIED')
    require((receipt['planSha256'] if status == 'LEASE_KERNEL_MIGRATED' else receipt['migrationPlanSha256'])
            == plan['planSha256'] and receipt['after']['kernel'] == lease_guard_hash(owner['kernel'])
            and receipt['after']['structure'] == owner['expectedStructureHash']
            and receipt['after']['boot'] == plan['expectedBootFootprint']
            and receipt['before'] == plan['before']
            and receipt.get('startAuthorized') is False and receipt.get('leaseAuthorized') is False, code)
    old = plan['context']['owner']
    kernel = {**old['kernel'], 'generation': 2, 'providerFlowMatch': 'ORIGINAL_TUPLE',
              'tableName': old['kernel']['tableName'] + '_g2'}
    root, claim = plan['paths']['generationDirectory'], plan['paths']['migrationDirectory']
    require(type(old['kernel'].get('generation', 1)) is int and old['kernel'].get('generation', 1) == 1
            and owner['kernel'] == plan['destination'] == kernel
            and all(B.absolute(p) for p in (root, claim))
            and plan['paths']['r3']['install_root'] == settings['installRoot']
            and settings['coordinatorBinding'] == {'path': root + '/coordinated-configuration.json',
                                                  'sha256': sha(files['coordinator'])}
            and owner['journalFile'] == root + '/coordination-journal.json'
            and all(owner[k] == old[k] for k in ('commonLockFile', 'nftPath', 'nftSha256', 'dns',
                                                'readBudgetSeconds', 'pollSeconds'))
            and owner['binding']['transactionId'] == plan['planSha256']
            and owner['binding']['configurationHash'] == sha(canonical({k: v for k, v in owner.items() if k != 'binding'})), code)
    require(generation.get('schema') == 'ouf.semantic-lease-kernel-generation.v1'
            and type(generation.get('generation')) is int and generation['generation'] == 2
            and generation['directory'] == root and generation['migrationPlanSha256'] == plan['planSha256']
            and generation['configurationHash'] == sha(files['coordinator'])
            and generation['closure']['coordinated-configuration.json'] == sha(files['coordinator'])
            and all(generation['closure'].get('source/' + p) == h for p, h in owner['sourceHashes'].items())
            and generation['predecessorTableName'] == old['kernel']['tableName']
            and set(pointer) == {'schema', 'receiptFile', 'receiptHash', 'observerFile', 'observerHash'}
            and pointer['schema'] == 'ouf.semantic-coordinated-boot-pointer.v1'
            and pointer['receiptFile'] == root + '/generation-receipt.json'
            and pointer['receiptHash'] == sha(files['generationReceipt'])
            and pointer['observerFile'] == plan['paths']['dispatcher']
            and pointer['observerHash'] == plan['sourceHashes']['@dispatcher'], code)
    return {k: {'path': p, 'sha256': sha(files[k])} for k, p in {
        'migrationPlan': claim + '/plan.json',
        'migrationReceipt': claim + ('/receipt.json' if status == 'LEASE_KERNEL_MIGRATED' else '/finalize-receipt.json'),
        'generationReceipt': root + '/generation-receipt.json',
        'bootPointer': '/etc/ouf/coordinated-boot-installation.json'}.items()}


def sources_v12(sources):
    """Version-local sealed aliases; historical source blobs remain untouched."""
    out = dict(sources)
    def replace(path, old, new):
        require(out[path].count(old) == 1, 'R3_V12_SOURCE_CONTRACT_DRIFT')
        out[path] = out[path].replace(old, new)
    # A self-contained alias keeps the broker's exact historical module set.
    replace(KERNEL_V2, b'from . import materialize_southbound_kernel as historical',
        b'import types\nhistorical = types.ModuleType("r3_kernel_generation_1")\nexec(compile(' +
        repr(sources[KERNEL_V1]).encode('ascii') + b', "<sealed-generation-1>", "exec"), historical.__dict__)')
    replace(KERNEL_V2, b'fields = historical.fields',
            b'fields, ip, name, port = historical.fields, historical.ip, historical.name, historical.port')
    replace(REFRESH_V2, b'from tools.materialize_southbound_kernel_v2 import',
            b'from tools.materialize_southbound_kernel import')
    core = REPLACEMENTS_V11['tools/semantic_lease_recovery/activation_core.py']
    replace(core, b"'materialize_southbound_kernel', 'semantic_provider_dns', 'materialize_southbound_lease_refresh',",
        b"'materialize_southbound_kernel', 'materialize_southbound_kernel_v2', 'semantic_provider_dns', "
        b"'materialize_southbound_lease_refresh', 'materialize_southbound_lease_refresh_v2',")
    # task-65 merges the historical owner AND boot source hashes into g2.
    # Authenticate the retained boot bytes as well, without executing them.
    replace(core, b"*('tools/' + n + '.py' for n in order)}, 'EXACT_INSTALLED_OWNER_CLOSURE_REQUIRED')",
        b"*('tools/' + n + '.py' for n in order), 'scripts/run_semantic_coordinated_boot_guard.py', "
        b"'tools/semantic_provider_boot_coordination.py'}, 'EXACT_INSTALLED_OWNER_CLOSURE_REQUIRED')")
    replace(core, b"        modules[name] = module", b"""        modules[name] = module
        if name in ('materialize_southbound_kernel_v2', 'materialize_southbound_lease_refresh_v2'):
            alias = name.removesuffix('_v2')
            sys.modules['tools.' + alias] = module
            setattr(package, alias, module)
            modules[alias] = module""")
    sup = REPLACEMENTS_V11[SUPERVISOR]
    # Retain every other reviewed pin and the exact loader source-set contract.
    module = contract_module(sources[sup], 'v12_pins')
    for name, path in (('activation_core', core), ('readback_margin_compiler', REFRESH_V2)):
        replace(sup, module.PINS[name].encode(), sha(out[path]).encode())
    return out


def document(raw, code="INPUT_NOT_CANONICAL_PLUS_LF"):
    """Accept canonical JSON, or exactly that JSON plus one LF; never normalize drift."""
    require(type(raw) is bytes and 0 < len(raw) <= 8388608, "BOUNDED_R3_INPUT_REQUIRED")
    body = raw[:-1] if raw.endswith(b"\n") else raw
    # Use the real duplicate/nonfinite decoder with its per-document size bound.
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, "DUPLICATE_R3_INPUT_FIELD")
            result[k] = v
        return result
    try:
        value = json.loads(body, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        require(type(value) is dict and canonical(value) == body, code)
    except (ValueError, UnicodeError):
        raise A.OperationDenied(code) from None
    return value


def contract_module(raw, name):
    """Run the supplied repository validator with lexical POSIX paths and no native IO.

    The complete unmodified module executes; only native imports unavailable on
    Windows and the historical top-level sibling imports are resolved here.
    No sys.modules mutation and no filesystem-dependent validation is performed.
    """
    def importing(module, globals=None, locals=None, fromlist=(), level=0):
        if module == "fcntl":
            return types.SimpleNamespace()
        if module == "authorization":
            return A
        if module == "epochs":
            return types.SimpleNamespace(current=None, live=None, boot_id=None)
        return builtins.__import__(module, globals, locals, fromlist, level)
    result = types.ModuleType("r3_contract_" + name)
    result.__dict__["__builtins__"] = {**vars(builtins), "__import__": importing}
    exec(compile(raw, "<r3-repository-contract>", "exec"), result.__dict__)
    result.Path = PurePosixPath
    return result



def lease_guard_hash(kernel):
    """Exactly the digest validate_global_guard() compares (historical library).

    The coordinator binding's configurationHash digests the whole owner
    document, not the kernel: using it here can never pass on a real
    coordinator (sprint-01 v8 start, GLOBAL_LEASE_GUARD_SCOPE_DRIFT).
    """
    return hashlib.sha256(json.dumps(kernel, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def check_lease_guard(nic, kernel):
    """Fail at composition, not at start, if the historical guard would deny."""
    guard = nic["leaseGuard"]
    governed = {f["source"] for f in kernel["providerFlows"]}
    governed.update(f[k] for f in kernel["staticFlows"] for k in ("source", "destination"))
    require(guard["tableName"] == kernel["tableName"] and nic["bridge"] in kernel["guardedInterfaces"]
            and nic["bridge"] not in kernel["existingInterfaces"], "R3_LEASE_GUARD_SCOPE_DRIFT")
    require(nic["ipv4"] in governed, "R3_LEASE_GUARD_SOURCE_UNBOUND")


def compose(inputs, version=1, *, sequence=None, supersedes=None):
    """Return documents (bytes), authorization (bytes), hashes and audit metadata.

    inputs = {"files": {logical name: bytes}, "sources": {repository path: bytes}}.
    The caller authenticates custody and expected input hashes before calling.
    """
    require(type(version) is int and version >= 1, "R3_VERSION_REQUIRED")
    if version == 1:
        require(sequence in (None, 1) and supersedes is None, "R3_VERSION_ONE_CHAIN_REQUIRED")
        sequence = 1
    else:
        require(type(sequence) is int and sequence >= 2 and type(supersedes) is str
                and A.HEX64.fullmatch(supersedes), "R3_SUCCESSOR_CHAIN_REQUIRED")
    require(type(inputs) is dict and set(inputs) == {"files", "sources"}, "EXACT_R3_INPUTS_REQUIRED")
    files, sources = inputs["files"], inputs["sources"]
    if version >= 16:
        selected_map, selected_inputs, selected_data = SOURCE_MAP_V16, SOURCE_INPUTS_V16, DATA_INPUTS_V16
    elif version >= 15:
        selected_map, selected_inputs, selected_data = SOURCE_MAP_V15, SOURCE_INPUTS_V15, DATA_INPUTS_V15
    elif version >= 13:
        selected_map, selected_inputs, selected_data = SOURCE_MAP_V13, SOURCE_INPUTS_V13, DATA_INPUTS_V13
    elif version >= 12:
        selected_map, selected_inputs, selected_data = SOURCE_MAP_V12, SOURCE_INPUTS_V12, DATA_INPUTS_V12
    else:
        selected_map = SOURCE_MAP_V11 if version >= 11 else SOURCE_MAP_V6 if version >= 6 else SOURCE_MAP
        selected_inputs, selected_data = frozenset(selected_map.values()), DATA_INPUTS
    require(set(files) == selected_data and (set(sources) == selected_inputs
            or version <= 3 and set(sources) == SOURCE_INPUTS - {L2_SOURCE})
            and all(type(v) is bytes and 0 < len(v) <= 131072 for v in sources.values()),
            "EXACT_R3_INPUT_SET_REQUIRED")
    data = {k: document(v, "RECIPE_POLICY_NOT_CANONICAL_PLUS_LF" if k.endswith("/policy")
                        else "INPUT_NOT_CANONICAL_PLUS_LF") for k, v in files.items()}
    for role in ROLES:
        require(files[role + "/policy"] == canonical(data[role + "/policy"]) + b"\n",
                "RECIPE_POLICY_NOT_CANONICAL_PLUS_LF")
    s = data["settings"]
    require(set(s) == SETTINGS, "EXACT_R3_SETTINGS_REQUIRED")
    root = s["installRoot"]
    require(B.absolute(root) and root != "/", "EXPLICIT_INSTALL_ROOT_REQUIRED")
    version_prefix = "" if version == 1 else "versions/" + str(version) + "/"
    code_root = root + ("/" + version_prefix[:-1] if version_prefix else "")
    for k in ("runtimeBinding", "anchorBinding", "coordinatorBinding"):
        require(B.binding(s[k]), "EXACT_R3_BINDING_REQUIRED")
    require(B.binding(s["opensslBinding"], ("version",)), "EXACT_R3_BINDING_REQUIRED")
    require(set(s["tableNames"]) == set(ROLES)
            and len(set(s["tableNames"].values())) == 2
            and all(type(t) is str and A.TABLE.fullmatch(t) and t not in ("ouf_v2_adapter", "ouf_v2_southbound")
                    for t in s["tableNames"].values()), "FRESH_DISTINCT_TABLE_NAMES_REQUIRED")
    owner, journal = data["coordinator"], data["coordinationJournal"]
    if version >= 15:
        egress = contract_module(sources[EGRESS_V15], 'egress_v15')
        routes = contract_module(sources[ROUTES_SOURCE], 'routes_v15')
        identity = contract_module(sources[IDENTITY_SOURCE], 'identity_provider_v13')
        projection = egress.bind_projection(data, routes)
        # Candidate transport rebinding below changes peer declarations only.
        # Report D-052.2 tuple denials before the general kernel/transport gates.
        oidc_port = egress.check_routes(projection, data['southbound/historicalTemplate']['candidate'],
            data['adapter/historicalTemplate']['candidate'], owner['kernel'], identity, routes)
    if version >= 16:
        require(sha(files['coordinator']) == s['coordinatorBinding']['sha256'], 'SUCCESSOR_COORDINATOR_UNPROVEN')
        adapter = contract_module(sources[ADAPTER_V16], 'adapter_v16')
        adapter.check(data, files, contract_module(sources[ADAPTER_CONTRACT], 'adapter_contract_v16'))
    if version >= 12:
        migration_bindings(files)
    require(sha(files["coordinator"]) == s["coordinatorBinding"]["sha256"]
            and owner["binding"]["leaseStructureHash"] == owner["expectedStructureHash"]
            and all(journal[k] == owner["binding"][k] for k in
                    ("transactionId", "configurationHash", "leaseStructureHash"))
            and journal["state"] == "QUIESCED" and journal["leaseAuthorized"] is False
            and journal["startAuthorized"] is False, "SUCCESSOR_COORDINATOR_UNPROVEN")
    require(set(owner["binding"]) == {"transactionId", "configurationHash", "leaseStructureHash"}
            and all(type(v) is str and A.HEX64.fullmatch(v) for v in owner["binding"].values()),
            "EXACT_COORDINATION_BINDING_REQUIRED")
    require(B.absolute(owner["journalFile"]) and B.absolute(owner["commonLockFile"]),
            "EXPLICIT_COORDINATOR_PATH_REQUIRED")
    manifest = data["a2Manifest"]
    body = manifest["manifest"]
    require(body["schema"] == "ouf.semantic-provider-preparation-a.manifest.v1"
            and body["successors"] == data["successors"] and body["semanticPeer"] == data["semanticPeer"],
            "A2_MANIFEST_DRIFT")
    for name, filename in (("successors", "successors.json"), ("semanticPeer", "semantic-peer.json")):
        expected = [v for v in body["filesCreated"] if v["path"] == body["directory"]["path"] + "/" + filename]
        require(len(expected) == 1 and expected[0]["sha256"] == sha(files[name]), "A2_FILE_BINDING_DRIFT")
    accepted = ACCEPT.decode_manifest(files["acceptance"])
    scope = {k: s[k] for k in ("installationRef", "entityRef", "issuerRef")}
    require(accepted["generation"] >= 3 and all(accepted[k] == s[k] for k in ("installationRef", "entityRef"))
            and accepted["trustPolicy"] == s["anchorBinding"], "ACCEPTANCE_SCOPE_DRIFT")
    for key in ("manifest", "successors", "semanticPeer"):
        require(accepted["preparationA"]["files"][key]["sha256"] == sha(files["a2Manifest" if key == "manifest" else key]),
                "ACCEPTANCE_A2_DRIFT")
    require(accepted["preparationA"]["planSha256"] == manifest["planSha256"], "ACCEPTANCE_A2_DRIFT")
    rootfs = data["rootfs"]
    require(rootfs["aSuccessors"]["sha256"] == sha(files["successors"]), "ROOTFS_A2_DRIFT")
    source_map = {target: original for target, original in selected_map.items() if original in sources}
    broker_sources = B.SOURCES & source_map.keys()
    emitted = sources_v12(sources) if version >= 12 else sources
    if version >= 13:
        from .identity_overlay_v13 import sources_v13
        emitted = sources_v13(emitted, SOURCE_MAP, IDENTITY_SOURCE, driver_check=version < 14)
    if version >= 12:
        contract_module(emitted[KERNEL_V2], 'kernel_g2').materialize(owner['kernel'], empty_provider_sets=True)
    docs = {"source/" + target: emitted[original] for target, original in source_map.items()}
    hashes = {target: sha(emitted[original]) for target, original in source_map.items()}

    def put(path, value):
        docs[path] = canonical(value)
        return {"path": code_root + "/" + path, "sha256": sha(docs[path])}

    def source(path):
        return {"path": code_root + "/source/" + path, "sha256": hashes[path]}

    common = {"authorizationRoot": root + "/authorization", "anchorBinding": s["anchorBinding"],
              "mandateRoot": s["mandateRoot"], "opensslBinding": s["opensslBinding"], "mandatesModule": source(MANDATES)}
    dns_profile = {**owner["dns"], "timeoutSeconds": 10} if version >= 11 else owner["dns"]
    rows, policies, templates = {}, {}, {}
    for role in ROLES:
        recipe = {k: data[role + "/" + k] for k in ACCEPT.RECIPE_PARTS}
        policy = compile_policy(recipe["template"], recipe["launch"], recipe["context"])
        require(policy == recipe["policy"], "RECIPE_RECOMPILATION_DRIFT")
        matches = [row for row in data["successors"]["containers"] if row["containerId"] == recipe["context"]["containerId"]]
        require(len(matches) == 1, "EXACT_A2_ROLE_REQUIRED")
        row = matches[0]
        require(row["status"] == "created" and row["runtime"] == "ouf-semantic-admitted-v2"
                and data["successors"]["transactions"][row["containerId"]] == row["transaction"]
                and accepted["creation"]["roles"][role]["transactionRef"] == row["transaction"]
                and accepted["roles"][role]["containerId"] == rootfs["roles"][role]["containerId"] == row["containerId"]
                and accepted["roles"][role]["imageId"] == rootfs["roles"][role]["imageId"] == row["image"]
                and rootfs["roles"][role]["effectiveSeal"] == accepted["roles"][role]["rootfs"]["effectiveSeal"],
                "A2_ACCEPTANCE_ROLE_DRIFT")
        require(all(accepted["roles"][role]["recipe"][k]["sha256"] == sha(files[role + "/" + k])
                    for k in ACCEPT.RECIPE_PARTS), "ACCEPTED_RECIPE_DRIFT")
        rows[role], policies[role] = row, policy
        templates[role] = copy.deepcopy(data[role + "/historicalTemplate"])
    old_cids = {r: templates[r]["candidate"]["containerId"] for r in ROLES}
    require(len(set(old_cids.values()) | {rows[r]["containerId"] for r in ROLES}) == 4,
            "FRESH_DISTINCT_SUCCESSORS_REQUIRED")
    operation_roles, audit = {}, {}
    peers = contract_module(sources[SOURCE_MAP["tools/semantic_provider_peer_bindings.py"]], "peers")
    for role in ROLES:
        t = templates[role]
        require(set(t) == {"schema", "pythonPath", "pythonHash", "commands", "commandHashes", "candidate", "kernel", "dns",
                          "coordinationBinding", "coordinationJournal", "lockFile", "budgetSeconds", "hostNetworkNamespace"}
                and t["schema"] == "ouf.semantic-admission-preparer-template.v1"
                and set(t["commands"]) == set(t["commandHashes"]) == {"ip", "mount", "nft", "nsenter", "umount", "unshare"}
                and all(B.absolute(v) for v in t["commands"].values())
                and all(A.HEX64.fullmatch(v) for v in t["commandHashes"].values())
                and B.absolute(t["pythonPath"]) and A.HEX64.fullmatch(t["pythonHash"])
                and type(t["budgetSeconds"]) is int and 1 <= t["budgetSeconds"] <= 5
                and type(t["hostNetworkNamespace"]) is int and t["hostNetworkNamespace"] > 0,
                "EXACT_NATIVE_PREPARER_TEMPLATE_REQUIRED")
        t.update(kernel=copy.deepcopy(owner["kernel"]), dns=copy.deepcopy(dns_profile),
                 coordinationBinding=copy.deepcopy(owner["binding"]), coordinationJournal=owner["journalFile"],
                 lockFile=owner["commonLockFile"])
        candidate = t["candidate"]
        require(set(candidate) == {"containerId", "transactionId", "networkBindings", "transport", "tableName", "runtimeBinding"},
                "EXACT_HISTORICAL_CANDIDATE_REQUIRED")
        candidate.update(containerId=rows[role]["containerId"], tableName=s["tableNames"][role],
            runtimeBinding=copy.deepcopy(s["runtimeBinding"]),
            transactionId=sha(canonical({"role": role, "containerId": rows[role]["containerId"],
                                         "coordinator": owner["binding"]})))
        require(candidate["tableName"] != owner["kernel"]["tableName"], "CANDIDATE_TABLE_COLLISION")
        for index, nic in enumerate(candidate["networkBindings"]):
            if version >= 4:
                nic["mac"] = L2_LIVE_MAC
                nic["interface"] = live_interface(index)
            if "leaseGuard" in nic:
                if version >= 12:
                    nic['leaseGuard']['tableName'] = owner['kernel']['tableName']
                nic["leaseGuard"]["configurationHash"] = (lease_guard_hash(owner["kernel"]) if version >= 9
                                                          else owner["binding"]["configurationHash"])
                if version >= 9:
                    check_lease_guard(nic, owner["kernel"])
        other = "southbound" if role == "adapter" else "adapter"
        sibling, ingress = 0, 0
        for flow in candidate["transport"]:
            require(set(flow) == {"purpose", "authorityRef", "source", "destination", "protocol", "port", "peerIngress"},
                    "EXACT_SOURCE_FLOW_REQUIRED")
            peer = flow["peerIngress"]
            if peer["kind"] == "CREATED_CANDIDATE":
                old = peer["declaration"]
                require(old["containerId"] == old_cids[other]
                        and old["networkBindings"] == data[other + "/historicalTemplate"]["candidate"]["networkBindings"],
                        "HISTORICAL_SIBLING_DRIFT")
                peer["declaration"] = {"containerId": rows[other]["containerId"],
                    "applicationHash": sha(canonical(policies[other]["expectedOci"])),
                    "networkBindings": copy.deepcopy(templates[other]["candidate"]["networkBindings"])}
                # Do not depend on role iteration order when rebinding leaseGuard.
                for index, nic in enumerate(peer["declaration"]["networkBindings"]):
                    if version >= 4:
                        nic["mac"] = L2_LIVE_MAC
                        nic["interface"] = live_interface(index)
                    if "leaseGuard" in nic:
                        if version >= 12:
                            nic['leaseGuard']['tableName'] = owner['kernel']['tableName']
                        nic["leaseGuard"]["configurationHash"] = (lease_guard_hash(owner["kernel"]) if version >= 9
                                                                  else owner["binding"]["configurationHash"])
                sibling += 1
            else:
                p = data["semanticPeer"]["proposedIngress"]
                require(role == "southbound" and peer["kind"] == p["kind"] == "BRIDGE_PORT"
                        and (flow["source"], flow["destination"], flow["port"], flow["protocol"]) ==
                        (p["sourceIpv4"], p["destinationIpv4"], p["destinationPort"], p["protocol"])
                        and type(p["ifindex"]) is int and p["ifindex"] > 1
                        and p["ifindex"] == data["semanticPeer"]["binding"]["hostIfindex"], "A2_INGRESS_DRIFT")
                flow["peerIngress"] = {"kind": "BRIDGE_PORT", "ifindex": p["ifindex"]}
                ingress += 1
        require(sibling == 1 and ingress == (role == "southbound"), "EXACT_TRANSPORT_FLOW_COUNT_REQUIRED")
        peers.declaration({"containerId": candidate["containerId"], "networkBindings": candidate["networkBindings"],
                           "applicationHash": sha(canonical(policies[role]["expectedOci"]))})
        require(len(peers.declarations(candidate["transport"], candidate["containerId"])) == 1,
                "EXACT_RECIPROCAL_COHORT_REQUIRED")
        if version >= 13 and role == 'southbound':
            if version < 15:
                identity = contract_module(sources[IDENTITY_SOURCE], 'identity_provider_v13')
            try:
                candidate['transport'].append(identity.identity_flow(data['identityProviderPeer'], candidate,
                                                                     owner['kernel']))
            except identity.Denied as error:
                if version >= 15 and error.args == ('R3_IDENTITY_PROVIDER_ISSUER_DRIFT',):
                    require(False, egress.NETWORK)
                raise
            if version >= 15:
                egress.check_identity_flow(candidate, oidc_port)
        prefix = "documents/" + role + "/"
        frame = put(prefix + "frame-policy.json", policies[role])
        seal = put(prefix + "rootfs-seal.json", rootfs["roles"][role]["effectiveSeal"])
        transport = put(prefix + "transport.json", {k: candidate[k] for k in ("networkBindings", "transport", "tableName")})
        preparer = put(prefix + "preparer-template.json", t)
        cfg = {"schema": B.SCHEMA, "sourceRoot": code_root + "/source", "sourceHashes": {p: hashes[p] for p in broker_sources},
            "authorities": scope, "operation": common, "role": role, "containerId": rows[role]["containerId"],
            "registryRoot": root + "/registry", "framePolicyBinding": frame, "rootfsSealBinding": seal,
            "transportBinding": transport, "preparerTemplate": preparer, "runtimeRootParent": s["runtimeRootParent"],
            "rootfsLimits": s["rootfsLimits"], "creationFrameObserverBinding": {
                "python": {"path": t["pythonPath"], "sha256": t["pythonHash"]},
                "source": source(OBSERVER_V2 if version >= 6 else OBSERVER), "configuration": frame}}
        broker = put("broker/" + role + ".json", cfg)
        # Pure replay may use retained pre-v4 source INPUTS. Native v2 loading
        # always validates its complete current package, without this override.
        B.validate(docs["broker/" + role + ".json"], source_set=broker_sources)
        operation_roles[role] = {"containerId": rows[role]["containerId"], "imageManifestDigest": rows[role]["image"],
            "framePolicySha256": frame["sha256"], "admissionConfigurationSha256": broker["sha256"],
            "rootfsSealSha256": seal["sha256"], "transportSha256": transport["sha256"], "tableName": candidate["tableName"]}
        E.documents(operation_roles[role], {k: docs[prefix + filename] for k, filename in
                    (("framePolicy", "frame-policy.json"), ("rootfsSeal", "rootfs-seal.json"), ("transport", "transport.json"))})
        audit[role] = {"recipePolicySha256": sha(files[role + "/policy"]),
            "historicalTemplateSha256": sha(files[role + "/historicalTemplate"]),
            "rootfsResultSha256": sha(files["rootfs"]), "applicationHash": sha(canonical(policies[role]["expectedOci"])),
            "artifactHash": frame["sha256"],
            "originalSealFragmentSha256": sha(canonical(rootfs["roles"][role]["effectiveSeal"])),
            "originalTransportFragmentSha256": sha(canonical({k: data[role + "/historicalTemplate"]["candidate"][k]
                for k in ("networkBindings", "transport", "tableName")}))}
    dns = put("supervisor/dns-profile.json", dns_profile)
    supervisor = {"schema": "ouf.semantic-provider-lease-supervisor.v1", "sourceRoot": code_root + "/source",
        "sourceHashes": {p: hashes[p] for p in (SUPERVISOR_SOURCES_V11 if version >= 11 else SUPERVISOR_SOURCES)}, **scope, **common,
        "registryRoot": root + "/registry", "coordinator": {"ownerConfiguration": s["coordinatorBinding"],
            "journalPath": owner["journalFile"], "commonLockPath": owner["commonLockFile"], "dnsProfile": dns,
            "nftBinding": {"path": owner["nftPath"], "sha256": owner["nftSha256"]}},
        "recoveryJournalRoot": root + "/supervisor/state/recovery", "statusPath": root + "/supervisor/state/status.json",
        "limits": s["supervisorLimits"]}
    sup = put("supervisor/configuration.json", supervisor)
    contract_module(emitted[selected_map[SUPERVISOR]], "supervisor").validate(docs["supervisor/configuration.json"])
    runtime = {"schema": "ouf.semantic-docker-runtime-adapter.v5.2", "sourceHash": hashes[RUNTIME],
        "runtimePath": s["runtimeBinding"]["path"], "runtimeSha256": s["runtimeBinding"]["sha256"],
        "pythonPath": templates["adapter"]["pythonPath"], "pythonSha256": templates["adapter"]["pythonHash"],
        "registryRoot": root + "/registry", "runtimeStateRoot": s["runtimeRootParent"], "opensslBinding": s["opensslBinding"],
        "candidates": {rows[r]["containerId"]: {"role": r, "bundleParents": [data[r + "/context"]["bundleParent"]]} for r in ROLES},
        "admissionConfigurations": {rows[r]["containerId"]: {"path": code_root + "/broker/" + r + ".json",
            "sha256": operation_roles[r]["admissionConfigurationSha256"]} for r in ROLES},
        "operation": {k: v for k, v in {**common, **scope}.items() if k != "opensslBinding"},
        "leaseQuiesce": {"entrypoint": source("scripts/semantic-provider-lease-supervisor-v2.py"), "configuration": sup},
        "limits": {"maxEpochsPerHour": 6},
        **{k: source("tools/semantic_provider_operation/" + n + ".py") for k, n in
           (("authorizationModule", "authorization"), ("epochsModule", "epochs"))}}
    for prefix, entry in (("admission", B.ENTRYPOINTS[0]), ("driver", B.ENTRYPOINTS[2])):
        runtime.update({prefix + "Path": source(entry)["path"], prefix + "Sha256": hashes[entry]})
    rt = put("runtime-configuration.json", runtime)
    module = contract_module(sources[RUNTIME], "runtime")
    module.read = lambda path: docs["runtime-configuration.json"]
    module.load_configuration(PurePosixPath(rt["path"]))
    payload = canonical({"schema": A.SCHEMA, **scope, "sequence": sequence, "supersedes": supersedes,
        "issuedAt": s["issuedAt"], "decision": "OPERATE", "runtimeConfigurationSha256": rt["sha256"],
        "acceptanceSha256": sha(files["acceptance"]), "roles": operation_roles,
        "lease": {"ownerConfigurationSha256": sha(files["coordinator"]),
                  "leaseStructureHash": owner["binding"]["leaseStructureHash"], "dnsProfileSha256": dns["sha256"]}})
    A.validate(payload)
    docs = {version_prefix + path: raw for path, raw in docs.items()}
    directories = {version_prefix + "source", "registry", "authorization", "supervisor/state", "supervisor/state/recovery"}
    for role in ROLES:
        cid_root = "registry/" + rows[role]["containerId"]
        directories.update({cid_root, cid_root + "/epochs"})
        if version == 1:
            docs[cid_root + "/operation.lock"] = b""
    for path in docs:
        directories.update(str(p) for p in PurePosixPath(path).parents if str(p) != ".")
    return {"documents": docs, "authorization": payload,
        "hashes": {**{p: sha(raw) for p, raw in sorted(docs.items())}, f"authorization/{sequence}.json": sha(payload)},
        "inputHashes": {**{k: sha(v) for k, v in sorted(files.items())},
                        **{"repository/" + k: sha(v) for k, v in sorted(sources.items())}},
        "audit": audit, "layout": {"installRoot": root, "directories0700": sorted(directories),
            "files0600": sorted([*docs, f"authorization/{sequence}.json", f"authorization/{sequence}.signature.json"])}}
