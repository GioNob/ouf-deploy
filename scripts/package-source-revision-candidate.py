#!/usr/bin/env python3
"""Reuse the qualified packager; add a bounded OFFLINE revision-route fixture, never target input."""
import importlib.util
import json
from pathlib import Path
import sys


def main():
    here = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('candidate', here/'package-resolution-comparison-candidate.py')
    candidate = importlib.util.module_from_spec(spec);spec.loader.exec_module(candidate)
    candidate.LOCK_PATH = here.parent/'releases/source-revision-candidate-20261018.json'
    candidate.LOCK = json.loads(candidate.LOCK_PATH.read_text())
    candidate.SOURCES = {row['module']: (row['repository'], row['commit']) for row in candidate.LOCK['modules']}
    candidate.KINDS = {row['module']: row['kind'] for row in candidate.LOCK['modules']}
    candidate.main()
    if sys.argv[1] == 'build' and sys.argv[sys.argv.index('--module')+1] == 'gateway':
        source = Path(sys.argv[sys.argv.index('--source')+1]).resolve()
        output = Path(sys.argv[sys.argv.index('--output')+1]).resolve()
        sys.path.insert(0, str(source))
        from tests.test_file_loop_coherence import retained_installation
        from tools.materialize_source_revision import materialize
        runtime, _ = retained_installation()
        existing = json.loads((output/'routes.file-loop.json').read_text())
        result = materialize(existing, runtime, 'DELEGATION_KEY', 'AUTHORIZATION_OWNER_KEY')
        assert result['routes'][:-2] == existing['routes']
        assert len(result['routes']) == len(existing['routes'])+2
        result['packageQualification'] = {
            'profile': 'GENERIC_SOURCE_REVISION_OFFLINE_MATERIALIZATION', 'targetBound': False,
            'projectionSource': 'tests/fixtures/installation-projection-lab.json',
            'requiresRetainedTargetProjectionAndRouteReconciliation': True,
            'targetApplyAuthorized': False, 'runtimeAuthorityIssued': False}
        (output/'routes.source-revision.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')


if __name__ == '__main__':
    main()
