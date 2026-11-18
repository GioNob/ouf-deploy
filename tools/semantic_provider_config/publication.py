"""Publish only configuration files and deltas named in the closed table."""
from dataclasses import dataclass
import os
from pathlib import Path
import secrets
from types import MappingProxyType
from typing import Callable

from tools.semantic_provider_config import contract as D, observation as O
from tools.semantic_provider_routes import custody as C, publication as P
from tools.semantic_provider_routes.routes import canonical, decode, require, sha


@dataclass(frozen=True)
class File:
    role: str
    source: Path
    target: str
    metadata: tuple
    limit: int
    claim: Path
    declaration: Path
    project: Callable
    regenerate: Callable


FILES = MappingProxyType({
    'adapter.json': File('adapter', P.SNAPSHOTS / 'semantic-provider-v2-inputs-XE7IwlGm/adapter.json',
                         D.TARGET, D.METADATA, D.MAX_BYTES,
                         P.SNAPSHOTS / 'semantic-provider-config-d053-adapter',
                         Path(D.PROFILE_PATH), D.project, D.regenerate),
})
SCHEMA = 'ouf.semantic-provider-config-publication.v1'


def source_bytes(entry, digest):
    return C.read(entry.source, digest, metadata=entry.metadata, limit=entry.limit)


def declaration(entry, digest):
    raw = C.read(entry.declaration, digest)
    value = decode(raw)
    require(raw == canonical(value) + b'\n', 'CONFIGURATION_DECLARATION_CANONICAL_LF_REQUIRED')
    return value


def delta(entry, original, profile):
    before = entry.project(str(entry.source), original)
    updated, changes, original_projection, updated_projection = entry.regenerate(str(entry.source), original, profile)
    require(before == original_projection and entry.project(str(entry.source), updated) == updated_projection
            and len(updated) <= entry.limit, 'CONFIGURATION_PROJECTION_CHANGED')
    return updated, changes, before, updated_projection


def plan(entry, pins, docker, original, live):
    profile = declaration(entry, pins.profile_sha256)
    updated, changes, before, after = delta(entry, original, profile)
    observed, _ = O.safety(docker, pins, entry)
    require(source_bytes(entry, sha(live)) == live, 'CONFIGURATION_LIVE_BYTES_CHANGED')
    proposal = {'schema': SCHEMA, 'claim': str(entry.claim), 'containers': P.CIDS, 'role': entry.role,
                'target': entry.target, 'maxBytes': entry.limit,
                'declaration': P.binding(entry.declaration, pins.profile_sha256),
                'metadata': dict(zip(('uid', 'gid', 'mode'), entry.metadata)),
                'before': before, 'after': after, 'diff': changes, 'observed': observed, **P.FLAGS}
    return proposal, updated


def replace(entry, raw, recheck, progress):
    staged = entry.source.parent / ('.config-publish-' + secrets.token_hex(16))
    try:
        C.write_once(staged, raw, entry.metadata)
        recheck()
        os.replace(staged, entry.source)
        progress['sourceReplaced'] = True
        C.sync_dir(entry.source.parent)
        require(source_bytes(entry, sha(raw)) == raw, 'CONFIGURATION_READBACK_MISMATCH')
    finally:
        staged.unlink(missing_ok=True)


def receipt(status, proposal):
    return {'schema': SCHEMA, 'status': status, 'planSha256': sha(canonical(proposal)),
            'source': proposal['before']['source'], 'oldSha256': proposal['before']['sha256'],
            'newSha256': proposal['after']['sha256'], 'declaration': proposal['declaration'],
            'diff': proposal['diff'], 'containers': proposal['containers'], **P.FLAGS}


def execute(mode, filename, pins, *, docker=None, progress=None):
    require(filename in FILES, 'CONFIGURATION_FILE_NOT_ALLOWED')
    entry = FILES[filename]
    docker = C.Docker() if docker is None else docker
    progress = {} if progress is None else progress
    with O.fenced():
        if mode == 'restore':
            return restore(entry, pins, docker, progress)
        require(mode in ('plan', 'apply') and not os.path.lexists(entry.claim), 'CONFIGURATION_CLAIM_UNAVAILABLE')
        original = source_bytes(entry, pins.old_sha256)
        proposal, updated = plan(entry, pins, docker, original, original)
        digest = sha(canonical(proposal))
        if mode == 'plan':
            return {'status': 'PLAN_READY', 'planSha256': digest, 'plan': proposal}
        require(digest == pins.plan_sha256, 'PLAN_DIGEST_MISMATCH')
        C.directory(entry.claim.parent)
        entry.claim.mkdir(mode=0o700)
        progress['claimCreated'] = True
        C.sync_dir(entry.claim.parent)
        C.write_once(entry.claim / 'original', original)
        C.write_document(entry.claim / 'plan.json', proposal)

        def recheck():
            require(plan(entry, pins, docker, original, original) == (proposal, updated),
                    'CONFIGURATION_PREFLIGHT_CHANGED')

        replace(entry, updated, recheck, progress)
        require(plan(entry, pins, docker, original, updated) == (proposal, updated), 'CONFIGURATION_POSTFLIGHT_CHANGED')
        result = receipt('CONFIGURATION_PUBLISHED', proposal)
        C.write_document(entry.claim / 'result.json', result)
        return result


def restore(entry, pins, docker, progress):
    C.directory(entry.claim, private=True)
    require(not os.path.lexists(entry.claim / 'restored.json'), 'CONFIGURATION_ALREADY_RESTORED')
    previous = decode(C.read(entry.claim / 'plan.json'))
    require(sha(canonical(previous)) == pins.plan_sha256 and previous['schema'] == SCHEMA
            and previous['claim'] == str(entry.claim), 'RESTORE_PLAN_MISMATCH')
    original = C.read(entry.claim / 'original', pins.old_sha256, limit=entry.limit)
    live = source_bytes(entry, previous['after']['sha256'])
    current, updated = plan(entry, pins, docker, original, live)
    require(live == updated and {**current, 'observed': previous['observed']} == previous,
            'RESTORE_BYTES_UNPROVEN')

    def recheck():
        require(plan(entry, pins, docker, original, live) == (current, updated), 'RESTORE_PREFLIGHT_CHANGED')

    replace(entry, original, recheck, progress)
    require(plan(entry, pins, docker, original, original) == (current, updated), 'RESTORE_POSTFLIGHT_CHANGED')
    result = receipt('CONFIGURATION_RESTORED', previous) | {'restoredSha256': sha(original)}
    C.write_document(entry.claim / 'restored.json', result)
    return result


def published(entry, receipt_sha, profile_sha):
    C.directory(entry.claim, private=True)
    result = decode(C.read(entry.claim / 'result.json', receipt_sha))
    proposal = decode(C.read(entry.claim / 'plan.json'))
    require(not os.path.lexists(entry.claim / 'restored.json') and proposal['schema'] == SCHEMA
            and proposal['claim'] == str(entry.claim) and proposal['role'] == entry.role
            and proposal['target'] == entry.target and proposal['containers'] == P.CIDS
            and result == receipt('CONFIGURATION_PUBLISHED', proposal)
            and result['declaration'] == P.binding(entry.declaration, profile_sha),
            'CONFIGURATION_PUBLICATION_UNPROVEN')
    original = C.read(entry.claim / 'original', result['oldSha256'], limit=entry.limit)
    updated, changes, before, after = delta(entry, original, declaration(entry, profile_sha))
    require((changes, before, after) == (proposal['diff'], proposal['before'], proposal['after'])
            and source_bytes(entry, result['newSha256']) == updated, 'CONFIGURATION_PUBLICATION_DELTA_UNPROVEN')
    return result
