"""Rebind the retained adapter recipe after the D-053 publication."""
import copy
import os

from tools.semantic_provider_config import contract as D, observation as O, publication as Q
from tools.semantic_provider_routes import b1 as B, custody as C, publication as P
from tools.semantic_provider_routes.routes import canonical, decode, require, sha


PREVIOUS = B.OUTPUT / 'result.json'
OUTPUT = P.SNAPSHOTS / 'semantic-provider-b1-recipes-v4'
SCHEMA = 'ouf.semantic-provider-b1-recipes-plan.v4'


def revise(role, previous, publication, compiler):
    docs = {part: decode(raw) for part, raw in previous.items()}
    template, launch, context, policy = (docs[part] for part in B.PARTS)
    require(canonical(compiler.compile_policy(template, launch, context)) == canonical(policy),
            'PREVIOUS_POLICY_MISMATCH')
    if role == 'southbound':
        return previous
    require(role == 'adapter', 'B1_ROLE_INVALID')
    revised = copy.deepcopy(launch)
    source = D.source_entry(revised)
    require(source == D.source_entry(policy) and source['source'] == publication['source']
            and source['sha256'] == publication['oldSha256']
            and D.SHA256.fullmatch(publication['newSha256']) and publication['newSha256'] != source['sha256'],
            'ADAPTER_CONFIG_PREVIOUS_SOURCE_UNPROVEN')
    source['sha256'] = publication['newSha256']
    compiled = compiler.compile_policy(template, revised, context)
    require(canonical(compiled) == canonical(policy | {'sources': revised['sources']}),
            'REVISED_POLICY_ONLY_SOURCES_REQUIRED')
    return previous | {'launch': canonical(revised) + b'\n', 'policy': canonical(compiled) + b'\n'}


def observe(docker, pins, *, seal_rootfs=B.verify_rootfs):
    entry = Q.FILES['adapter.json']
    publication = Q.published(entry, pins.publication_sha256, pins.profile_sha256)
    observed, candidates = O.safety(docker, pins, entry)
    previous = decode(C.read(PREVIOUS, pins.previous_recipes_sha256))
    successors = decode(C.read(B.SUCCESSORS, B.SUCCESSORS_SHA))
    rootfs = decode(C.read(B.ROOTFS, B.ROOTFS_SHA))
    require(previous['schema'] == B.SCHEMA and previous['recipeRevision'] == 3
            and previous['status'] == 'SEMANTIC_PROVIDER_B1_RECIPES_PREPARED'
            and previous['recreation'] == B.RECREATION
            and previous['rootfs'] == P.binding(B.ROOTFS, B.ROOTFS_SHA)
            and previous['preparationA']['files']['successors'] ==
                rootfs['aSuccessors'] == P.binding(B.SUCCESSORS, B.SUCCESSORS_SHA)
            and rootfs['rule'] == 'D-042' and rootfs['status'] == 'SEMANTIC_PROVIDER_B1_ROOTFS_EVIDENCE_PREPARED'
            and set(previous['roles']) == set(rootfs['roles']) == set(B.ROLES), 'B1_V3_D042_REQUIRED')
    route = previous['routePublication']
    require(route['path'] == str(P.CLAIM / 'result.json'), 'B1_ROUTE_PUBLICATION_UNPROVEN')
    route_hash, _ = B.published_routes(route['sha256'])
    require(route_hash == previous['routeSha256'], 'B1_ROUTE_PUBLICATION_UNPROVEN')
    compiler = B.compiler_module()
    artifacts, retained, roles = {}, {}, {}
    for role in B.ROLES:
        cid = P.CIDS[role]
        old_role = previous['roles'][role]
        rows = [row for row in successors['containers'] if row['containerId'] == cid]
        require(len(rows) == 1 and set(old_role['recipe']) == set(B.PARTS), 'B1_V3_RECIPE_UNPROVEN')
        pinned = rows[0]
        rf = rootfs['roles'][role]
        require(old_role['containerId'] == cid and old_role['transaction'] == pinned['transaction']
                and rf['imageId'] == pinned['image'], 'B1_RECIPE_IDENTITY_CHANGED')
        raw = {}
        for part in B.PARTS:
            path = PREVIOUS.parent / role / (part + '.json')
            binding = old_role['recipe'][part]
            require(binding == P.binding(path, binding['sha256']), 'B1_V3_RECIPE_UNPROVEN')
            raw[part] = C.read(path, binding['sha256'])
        launch = decode(raw['launch'])
        row = candidates[cid]
        retained[role] = B.retained_frame(row, pinned) | B.retained_config(row, role, launch)
        retained[role]['rootfsSeal'] = seal_rootfs(role, decode(raw['context']), decode(raw['policy']), rf, rootfs)
        if role == 'southbound':
            sources = [item for item in launch['sources'] if item.get('target') == P.TARGET]
            require(len(sources) == 1 and sources[0]['source'] == str(P.SOURCE)
                    and sources[0]['sha256'] == route_hash, 'B1_ROUTE_SOURCE_UNPROVEN')
        artifacts[role] = revise(role, raw, publication, compiler)
        roles[role] = {'containerId': cid, 'transaction': pinned['transaction'],
                       'recipe': {part: P.binding(OUTPUT / role / (part + '.json'), sha(content))
                                  for part, content in artifacts[role].items()}}
    require(O.safety(docker, pins, entry) == (observed, candidates)
            and Q.published(entry, pins.publication_sha256, pins.profile_sha256) == publication
            and P.route_source(route_hash), 'B1_INPUT_CHANGED_DURING_OBSERVATION')
    proposal = {'schema': SCHEMA, 'output': str(OUTPUT), 'previousRecipes': P.binding(PREVIOUS, pins.previous_recipes_sha256),
                'rootfs': previous['rootfs'], 'installationProfile': publication['declaration'],
                'configPublication': P.binding(entry.claim / 'result.json', pins.publication_sha256),
                'adapterConfigSha256': publication['newSha256'], 'routePublication': route, 'routeSha256': route_hash,
                'preparationA': previous['preparationA'], 'recreation': B.RECREATION, 'roles': roles,
                'softwareHashes': B.SOFTWARE, 'retained': retained, 'observed': observed,
                **P.FLAGS, 'acceptanceGranted': False}
    return proposal, artifacts


def execute(mode, pins, *, docker=None, progress=None):
    docker = C.Docker() if docker is None else docker
    progress = {} if progress is None else progress
    with O.fenced():
        C.directory(OUTPUT.parent)
        require(not os.path.lexists(OUTPUT), 'B1_OUTPUT_ALREADY_EXISTS')
        proposal, artifacts = observe(docker, pins)
        digest = sha(canonical(proposal))
        if mode == 'plan':
            return {'status': 'PLAN_READY', 'planSha256': digest, 'plan': proposal}
        require(mode == 'apply' and digest == pins.plan_sha256, 'PLAN_DIGEST_MISMATCH')
        OUTPUT.mkdir(mode=0o700)
        progress['outputCreated'] = True
        C.sync_dir(OUTPUT.parent)
        for role in B.ROLES:
            directory = OUTPUT / role
            directory.mkdir(mode=0o700)
            C.sync_dir(OUTPUT)
            for part, raw in artifacts[role].items():
                C.write_once(directory / (part + '.json'), raw)
        result = proposal | {'schema': B.SCHEMA, 'recipeRevision': 4, 'planSha256': digest,
                             'status': 'SEMANTIC_PROVIDER_B1_RECIPES_PREPARED'}
        C.write_document(OUTPUT / 'result.json', result)
        return result
