"""Generation33 vendor-image contract, independent of frozen image engines1–3.

This is a structural and byte-binding verifier for a future image enginev4.
It does not authenticate ZIPs, execute Go, scan images, attest a producer or
qualify a release. Those independent verifiers must run before publication.
Original-input h1 values are never assigned to patched vendor bytes.
"""
import hashlib
import json
import re
from pathlib import PurePosixPath

PARENT_MANIFEST_SHA256 = '5289372fe7577936376497adba277fb329bb2a625652eacad47c854735937144'
DEPENDENCY_PATCH = {'path': 'patches/iceberg-go/0.7.0-maintained-yaml-vendor.patch',
                    'sha256': '001459c5254303378cb30dafaceec1777cbb143957fa6afb5e2e7eb8cbb46eef'}
LEGACY_YAML = 'gopkg.in/yaml.v3'
PATCHED_CONFIG = 'github.com/apache/iceberg-go/config/config.go'
ORIGINAL_CONFIG_SHA256 = '30ec8eebf86cd2f5df0c8d6bbf8661c0bf72d10fc8c025d6943c9565ae13a604'
PATCHED_CONFIG_SHA256 = '9983e5e82a9372e9f47db6ccc5a55d9b747fd503caaedb5619e4b37e95c75ab4'
SHA = re.compile('[0-9a-f]{64}')
MATERIAL_NAMES = (
    'vendor-source-profile.json', 'vendor-materializer.json',
    'baseline-vendor-origins.json', 'compiled-module-origins.json',
    'vendor-before-files.json', 'vendor-after-files.json',
    'baseline-vendor-file-origins.json', 'baseline-vendor-module-enumeration.txt',
    'vendor-modules.txt', 'vendor-execution.json',
)


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def digest(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def validate_manifest(manifest, parent_bytes):
    require(sha(parent_bytes) == PARENT_MANIFEST_SHA256, 'EXACT_GENERATION32_MANIFEST_REQUIRED')
    parent = json.loads(parent_bytes)
    require(parent.get('generation') == 32 and len(parent.get('orderedPatches', [])) == 32,
            'GENERATION32_SOURCE_PREFIX_REQUIRED')
    require(manifest.get('schema') == 'ouf.seaweedfs-generation-vendor-build-manifest.v1'
            and manifest.get('generation') == 33
            and manifest.get('status') == 'VENDOR_SOURCE_REVIEWED_BUILD_PINNED_NOT_ADMITTED',
            'EXPLICIT_VENDOR_GENERATION_MANIFEST_REQUIRED')
    require(type(manifest.get('sourcePatchCount')) is int and manifest['sourcePatchCount'] == 32
            and type(manifest.get('dependencyPatchCount')) is int and manifest['dependencyPatchCount'] == 1
            and manifest.get('orderedSourcePatches') == parent['orderedPatches']
            and manifest.get('orderedDependencyPatches') == [DEPENDENCY_PATCH]
            and 'orderedPatches' not in manifest,
            'SOURCE_AND_DEPENDENCY_PATCH_DOMAINS_MUST_REMAIN_DISTINCT')
    require(manifest.get('parentManifestSha256') == PARENT_MANIFEST_SHA256
            and manifest.get('rootSourceGitTree') == parent['build']['patchedSourceTree']
            and manifest.get('rootLockfilesSha256') == parent['build']['rootLockfilesSha256'],
            'FROZEN_ROOT_SOURCE32_REQUIRED')
    vendor = manifest.get('vendor', {})
    require(all(digest(vendor.get(field)) for field in ('beforeTreeSha256', 'afterTreeSha256', 'modulesTxtSha256'))
            and vendor['beforeTreeSha256'] != vendor['afterTreeSha256']
            and type(vendor.get('fileCount')) is int and vendor['fileCount'] > 0,
            'EXACT_SEPARATE_VENDOR_TREE_BINDINGS_REQUIRED')
    materials = manifest.get('materialsSha256', {})
    require(set(materials) == set(MATERIAL_NAMES) and all(digest(value) for value in materials.values()),
            'ALL_VENDOR_MATERIAL_DIGESTS_REQUIRED')
    build = manifest.get('build', {})
    require(build.get('go') == '1.27.3' and build.get('os') == 'linux' and build.get('arch') == 'amd64'
            and build.get('cgo') is False and build.get('tags') == [] and build.get('trimpath') is True
            and build.get('moduleMode') == 'vendor'
            and digest(build.get('binarySha256')) and build['binarySha256'] != parent['build']['binarySha256']
            and digest(build.get('compiledPackagesSha256')) and digest(build.get('binaryModuleRowsSha256'))
            and type(build.get('compiledPackages')) is int and build['compiledPackages'] > 0
            and type(build.get('binaryDependencyModules')) is int and build['binaryDependencyModules'] > 0,
            'ACTUAL_NEW_VENDOR_BUILD_FACTS_REQUIRED')
    require(manifest.get('maintenance') == {'status': 'OPEN', 'technicalOwner': None,
            'reviewCadence': 'EACH_CANDIDATE_AND_WEEKLY_WHILE_PATCH_ACTIVE'}
            and manifest.get('allDependenciesMaintained') is False,
            'NO_DOWNSTREAM_MAINTENANCE_INFERENCE')
    require(manifest.get('releaseAdmitted') is False and manifest.get('runtimeAuthorityIssued') is False
            and manifest.get('targetOperations') == 0, 'NO_TARGET_AUTHORITY_OR_RELEASE_ADMISSION')
    return parent


def parse_module_rows(build_info):
    require(not any(line.startswith('\t=>\t') for line in build_info.splitlines()),
            'MODULE_REPLACEMENT_UNSUPPORTED')
    rows = [line.split('\t')[2:] for line in build_info.splitlines() if line.startswith('\tdep\t')]
    require(rows and all(len(row) == 2 or len(row) == 3 and row[2] == '' for row in rows),
            'VENDOR_BUILD_INFO_MUST_NOT_INVENT_H1')
    require(all(row[0] and row[1].startswith('v') for row in rows)
            and len({row[0] for row in rows}) == len(rows), 'UNIQUE_VERSIONED_BINARY_MODULES_REQUIRED')
    return {(row[0], row[1]) for row in rows}


def parse_vendor_modules(data):
    modules = []
    for line in data.decode().splitlines():
        require('=>' not in line, 'VENDOR_MODULE_REPLACEMENT_UNSUPPORTED')
        if not line.startswith('# '):
            continue
        parts = line.split()
        require(len(parts) == 3 and parts[2].startswith('v'), 'CANONICAL_VENDOR_MODULE_HEADER_REQUIRED')
        modules.append((parts[1], parts[2]))
    require(modules and len(modules) == len(set(modules)) and len({m for m, _ in modules}) == len(modules),
            'UNIQUE_VENDOR_MODULE_IDENTITIES_REQUIRED')
    return set(modules)


def origin_rows(value):
    rows = value.get('modules', [])
    require(isinstance(rows, list) and rows and type(value.get('moduleCount')) is int and value['moduleCount'] == len(rows)
            and value.get('moduleCacheMutated') is False,
            'COMPLETE_ORIGINAL_INPUT_INVENTORY_REQUIRED')
    result = {}
    for row in rows:
        identity = (row.get('module'), row.get('version'))
        require(all(isinstance(x, str) and x for x in identity) and identity not in result,
                'DUPLICATE_OR_INVALID_MODULE_ORIGIN')
        require(row.get('checksumsDescribeOriginalInputsOnly') is True
                and digest(row.get('inputZipSha256')) and digest(row.get('inputGoModSha256'))
                and all(isinstance(row.get(name), str) and re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', row[name])
                        for name in ('inputZipH1', 'inputGoModH1')),
                'ORIGINAL_ARCHIVE_IDENTITIES_REQUIRED')
        result[identity] = row
    require(len({module for module, _ in result}) == len(result), 'DUPLICATE_MODULE_ORIGIN_PATH')
    return result


def verify_origin_coverage(baseline, compiled, vendor_modules, build_info, baseline_enumeration, root_go_sum_sha256):
    """Verify set/binding completeness after separate cryptographic ZIP verification."""
    require(baseline_enumeration.startswith(b'vendor/modules.txt original-input enumeration; NOT binary build-info\n')
            and baseline.get('buildInfoSha256') == sha(baseline_enumeration)
            and compiled.get('buildInfoSha256') == sha(build_info.encode())
            and digest(root_go_sum_sha256)
            and baseline.get('rootGoSumSha256') == compiled.get('rootGoSumSha256') == root_go_sum_sha256,
            'ORIGINS_MUST_BIND_DISTINCT_ENUMERATION_AND_ACTUAL_BUILD')
    require(parse_module_rows(baseline_enumeration.decode()) == parse_vendor_modules(vendor_modules),
            'BASELINE_ENUMERATION_MUST_MATCH_VENDOR_MODULES')
    binary = parse_module_rows(build_info)
    all_rows, binary_rows = origin_rows(baseline), origin_rows(compiled)
    require(set(all_rows) == parse_vendor_modules(vendor_modules), 'ALL_VENDORED_MODULE_ORIGINS_REQUIRED')
    require(set(binary_rows) == binary and binary <= set(all_rows), 'EXACT_COMPILED_ORIGIN_SUBSET_REQUIRED')
    fields = ('inputZipH1', 'inputGoModH1', 'inputZipSha256', 'inputGoModSha256',
              'checksumsDescribeOriginalInputsOnly')
    for identity, row in binary_rows.items():
        require(all(row[name] == all_rows[identity][name] for name in fields),
                'BASELINE_AND_BINARY_ORIGIN_DIVERGENCE')
    return {'allVendorModules': len(all_rows), 'compiledModules': len(binary_rows),
            'originalInputChecksumsAreNotPatchedSourceChecksums': True}


def inventory_tree(rows):
    require(isinstance(rows, dict) and rows, 'NONEMPTY_VENDOR_FILE_INVENTORY_REQUIRED')
    for name, value in rows.items():
        require(isinstance(name, str) and name and str(PurePosixPath(name)) == name
                and not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
                and not any(c in name for c in ('\\', '\n', '\r')) and digest(value),
                'SAFE_HASHED_VENDOR_FILE_PATH_REQUIRED')
    return sha(''.join(rows[name] + '  ' + name + '\n' for name in sorted(rows)).encode())


def verify_vendor_inventories(manifest, before, after, file_origins):
    vendor = manifest['vendor']
    require(set(before) == set(after) and len(before) == vendor['fileCount']
            and inventory_tree(before) == vendor['beforeTreeSha256']
            and inventory_tree(after) == vendor['afterTreeSha256'], 'EXACT_VENDOR_FILE_TREES_REQUIRED')
    require([name for name in before if before[name] != after[name]] == [PATCHED_CONFIG]
            and before[PATCHED_CONFIG] == ORIGINAL_CONFIG_SHA256
            and after[PATCHED_CONFIG] == PATCHED_CONFIG_SHA256,
            'ONLY_REVIEWED_DEPENDENCY_CONFIG_DELTA_ALLOWED')
    require(before.get('modules.txt') == after.get('modules.txt') == vendor['modulesTxtSha256'],
            'VENDOR_MODULE_METADATA_MUST_REMAIN_UNCHANGED')
    require(file_origins.get('filesAuthenticatedAgainstOriginalZip') == len(before) - 1
            and file_origins.get('modulesTxtGeneratedByGo') is True
            and file_origins.get('modulesTxtSha256') == before['modules.txt']
            and file_origins.get('vendorTreeSha256') == vendor['beforeTreeSha256'],
            'EVERY_BASE_VENDOR_FILE_ORIGIN_REQUIRED')
    return {'vendorFilesBound': len(before), 'changedVendorFiles': [PATCHED_CONFIG]}


def verify_execution(record):
    require(record.get('effectiveGOFLAGS') == '' and record.get('effectiveGOWORK') == 'off',
            'EXPLICIT_VENDOR_ENVIRONMENT_REQUIRED')
    commands = record.get('rootCommands', [])
    roles = {'build', 'production-deps', 'regression', 'race', 'excluded-profile'}
    require(isinstance(commands, list) and roles <= {r.get('role') for r in commands},
            'ALL_ROOT_VENDOR_COMMAND_ROLES_REQUIRED')
    expected_command = {'build': 'build', 'production-deps': 'list', 'regression': 'test', 'race': 'test'}
    for row in commands:
        args = row.get('args', [])
        require(isinstance(args, list) and args and all(isinstance(a, str) for a in args)
                and args.count('-mod=vendor') == 1
                and not any(a == '-mod' or a.startswith(('-modfile', '-overlay'))
                            or a.startswith('-mod=') and a != '-mod=vendor' for a in args),
                'ROOT_COMMAND_MUST_USE_BOUND_VENDOR')
        role = row.get('role')
        require(role in roles and (args[0] == expected_command[role] if role in expected_command
                                  else args[0] in ('test', 'build')),
                'ROOT_VENDOR_COMMAND_ROLE_MISMATCH')
        require(role != 'production-deps' or '-deps' in args, 'VENDOR_PRODUCTION_DEPS_REQUIRED')
        require(role != 'race' or '-race' in args, 'VENDOR_RACE_COMMAND_REQUIRED')
    for key in ('goModVerifyBefore', 'goModVerifyAfter', 'baselineVendorFilesMatchOriginalArchives'):
        require(record.get(key) is True, 'AUTHENTIC_BASE_VENDOR_SOURCE_VERIFICATION_REQUIRED')
    return {'vendorCommandModeBound': True}


def excluded(path, previous_policy):
    path = path.removeprefix('vendor/').rsplit('/vendor/', 1)[-1]
    if path == 'go.mongodb.org/mongo-driver/v2' or path.startswith('go.mongodb.org/mongo-driver/v2/'):
        return False
    return any(path == name or path.startswith(name + '/')
               for name in previous_policy['excludedModulePaths'] + [LEGACY_YAML])


def verify_compiled(manifest, parent, packages_bytes, build_info):
    lines = packages_bytes.decode().splitlines()
    require(lines == sorted(set(lines)) and len(lines) == manifest['build']['compiledPackages']
            and sha(packages_bytes) == manifest['build']['compiledPackagesSha256'],
            'EXACT_VENDOR_COMPILED_GRAPH_REQUIRED')
    modules = parse_module_rows(build_info)
    require({('github.com/apache/iceberg-go', 'v0.7.0'), ('go.yaml.in/yaml/v3', 'v3.0.5')} <= modules,
            'EXACT_CANONICAL_DEPENDENCY_VERSIONS_REQUIRED')
    require(not any(excluded(path, parent['compiledDependencyPolicy']) for path in lines)
            and not any(excluded(path, parent['compiledDependencyPolicy']) for path, _ in modules),
            'EXCLUDED_COMPILED_DEPENDENCY_PRESENT')
    require({'github.com/apache/iceberg-go/config', 'github.com/apache/iceberg-go/table', 'go.yaml.in/yaml/v3'} <= set(lines),
            'ICEBERG_FEATURE_AND_MAINTAINED_YAML_REQUIRED')
    rows = [line for line in build_info.splitlines() if line.startswith('\tdep\t')]
    require(len(rows) == manifest['build']['binaryDependencyModules']
            and sha(('\n'.join(rows)+'\n').encode()) == manifest['build']['binaryModuleRowsSha256'],
            'EXACT_VENDOR_BINARY_MODULE_ROWS_REQUIRED')
    return {'legacyYamlCompiled': False, 'inheritedCompiledExclusionsPreserved': True}


def verify_material_digests(manifest, materials):
    require(set(materials) == set(MATERIAL_NAMES), 'EXACT_VENDOR_MATERIAL_SET_REQUIRED')
    for name, raw in materials.items():
        require(isinstance(raw, bytes) and sha(raw) == manifest['materialsSha256'][name],
                'VENDOR_MATERIAL_CHANGED:' + name)
    return {'boundMaterials': len(materials), 'cryptographicOriginVerificationPerformedByThisFunction': False}
