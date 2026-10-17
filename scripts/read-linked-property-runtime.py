#!/usr/bin/env python3
"""Bounded read-only container metadata, never configuration or credential values."""
import hashlib
import json
import re
import subprocess

def call(args):
    try:
        result = subprocess.run(args, capture_output=True, timeout=10, check=False)
        return result.stdout if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None

def read(prefix, name):
    raw = call(prefix + ['inspect', '--type', 'container', name])
    if raw is None:
        return None
    try:
        row = json.loads(raw)[0]
        state = row['State']
        config = row['Config']
        label = config.get('Labels', {}).get('org.opencontainers.image.revision')
        return {
            'name': name, 'containerId': row['Id'], 'imageId': row['Image'],
            'running': state['Running'], 'startedAt': state['StartedAt'],
            'sourceCommit': label if isinstance(label, str) and re.fullmatch('[0-9a-f]{40}', label) else None,
            'configurationHash': hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        }
    except (ValueError, KeyError, IndexError, TypeError):
        return None

def main():
    prefix = None
    for candidate in (['docker'], ['sudo', '-n', 'docker']):
        if call(candidate + ['version', '--format', '{{.Server.Version}}']) is not None:
            prefix = candidate
            break
    report = {'schema': 'ouf.linked-property-runtime-read.v1', 'readOnly': True,
              'serviceMutations': 0, 'credentialFilesRead': 0, 'credentialValuesPrinted': False,
              'databaseCalls': 0, 'databaseMigrationStateProven': False,
              'completedTechnicalPhases': 8, 'functionalMilestonesProven': 2}
    if prefix is None:
        report.update(complete=False, reason='RUNNER_DOCKER_READ_ACCESS_UNAVAILABLE')
    else:
        names = ('ouf-udp', 'ouf-onboarding')  # retained-host diagnostic, not installer defaults
        first = [read(prefix, name) for name in names]
        second = [read(prefix, name) for name in names]
        stable = all(first) and first == second
        report.update(complete=stable, generationsStable=stable,
                      reason='READ_COMPLETE' if stable else 'RUNTIME_BINDING_UNPROVEN', components=second)
    print('OUF_LINKED_PROPERTY_RUNTIME_READ=' + json.dumps(report, sort_keys=True))

if __name__ == '__main__':
    main()
