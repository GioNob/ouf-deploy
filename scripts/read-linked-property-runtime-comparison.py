#!/usr/bin/env python3
"""Compare retained Docker CLI and API1.44 projections; print metadata only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

def call(args, api=None):
    env = dict(os.environ)
    if api is not None:
        env['DOCKER_API_VERSION'] = api
    try:
        result = subprocess.run(args, capture_output=True, timeout=10, check=False, env=env)
        return result.stdout if result.returncode == 0 and len(result.stdout) <= 2097152 else None
    except (OSError, subprocess.TimeoutExpired):
        return None

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def inspect(prefix, name, api):
    raw = call(prefix + ['inspect', '--type', 'container', name], api)
    if raw is None:
        raise ValueError('RUNTIME_READ_UNAVAILABLE')
    rows = json.loads(raw)
    if type(rows) is not list or len(rows) != 1:
        raise ValueError('ONE_CONTAINER_REQUIRED')
    row = rows[0]
    return row

def metadata(row):
    return {'containerId':row['Id'], 'imageId':row['Image'], 'startedAt':row['State']['StartedAt'],
            'running':row['State']['Running'], 'paused':row['State']['Paused'],
            'configurationHash':digest(row['Config']),
            'sourceCommit':row['Config'].get('Labels',{}).get('org.opencontainers.image.revision')}

def main():
    root = Path(__file__).resolve().parents[1]
    release = json.loads((root/'releases/linked-property-qualified-20261017.json').read_text())
    selection = json.loads((root/'releases/linked-property-preparation-selection-20261017.json').read_text())
    prefix = next((p for p in (['docker'],['sudo','-n','docker'])
                   if call(p+['version','--format','{{.Server.Version}}']) is not None), None)
    if prefix is None:
        raise ValueError('RUNNER_DOCKER_READ_ACCESS_UNAVAILABLE')
    version = call(prefix+['version','--format','{{.Client.APIVersion}}'], '1.44')
    if version is None or version.strip() != b'1.44':
        raise ValueError('EXACT_API_VERSION_ENVIRONMENT_UNPROVEN')
    result = []
    for module in ('udp','onboarding'):
        expected = release['targetRead'][module]
        default = inspect(prefix, expected['containerId'], None)
        fixed = inspect(prefix, expected['containerId'], '1.44')
        default_after = inspect(prefix, expected['containerId'], None)
        fixed_after = inspect(prefix, expected['containerId'], '1.44')
        same = all(default[k] == fixed[k] for k in ('Id','Image')) and default['State'] == fixed['State']
        stable = default == default_after and fixed == fixed_after
        result.append({'module':module, 'sameRuntime':same, 'stableAcrossReads':stable,
                       'default':metadata(default), 'api144':metadata(fixed),
                       'defaultHashMatchesSelection':digest(default['Config'])==selection['configHashes'][module],
                       'api144HashMatchesSelection':digest(fixed['Config'])==selection['configHashes'][module],
                       'differentConfigFields':sorted(k for k in set(default['Config'])|set(fixed['Config'])
                           if (k in default['Config'],default['Config'].get(k)) != (k in fixed['Config'],fixed['Config'].get(k))),
                       'configurationValuesPrinted':False})
    return result

if __name__ == '__main__':
    report={'schema':'ouf.linked-property-runtime-projection-read.v1','readOnly':True,
            'databaseCalls':0,'serviceMutations':0,'credentialFilesRead':0,'credentialValuesPrinted':False,
            'completedTechnicalPhases':8,'functionalMilestonesProven':2}
    try:
        rows=main()
        report.update(complete=all(r['sameRuntime'] and r['stableAcrossReads'] for r in rows),components=rows)
    except Exception as error:
        report.update(complete=False,reason=str(error) if type(error) is ValueError else type(error).__name__)
    print('OUF_LINKED_PROPERTY_RUNTIME_PROJECTION_READ='+json.dumps(report,sort_keys=True))
