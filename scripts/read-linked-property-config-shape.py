#!/usr/bin/env python3
"""Read retained Docker configuration shape; no credential values or file reads."""
import importlib.util
import json
from pathlib import Path
import re

path = Path(__file__).with_name('read-linked-property-runtime-comparison.py')
spec = importlib.util.spec_from_file_location('runtime_reader', path)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)

def normal(key):
    return re.sub('[^a-z0-9]', '', key.lower())

def shape(actual):
    env = dict(r.split('=', 1) for r in actual['Config'].get('Env', []))
    flat = {}
    def flatten(value, prefix=''):
        for key, child in value.items():
            key = prefix + '.' + key if prefix else key
            if type(child) is dict:
                flatten(child, key)
            else:
                flat[key] = child
    if env.get('SPRING_APPLICATION_JSON'):
        flatten(json.loads(env['SPRING_APPLICATION_JSON']))
    rows = []
    for channel, values in [('ENVIRONMENT', env), ('SPRING_APPLICATION_JSON', flat)]:
        for key, value in values.items():
            n = normal(key)
            if not (n.startswith(('springflyway', 'springdatasource', 'springconfig', 'springprofiles')) or key in ('OUF_UDP_DB_URL', 'OUF_UDP_DB_USER', 'OUF_UDP_DB_PASSWORD')):
                continue
            row = {'channel': channel, 'property': key, 'present': value is not None,
                   'kind': type(value).__name__}
            if n in ('springflywayenabled','springflywaybaselineonmigrate','springflywayvalidatemigrate','springflywaycleanDisabled'.lower()):
                row['booleanValue'] = str(value).lower() if str(value).lower() in ('true','false') else 'UNPARSED'
            if n.endswith(('url','user','username')) and isinstance(value,str):
                row['placeholder'] = '${' in value
                row['matchesUdpDatabase'] = value.startswith('jdbc:postgresql:') and value.split('?',1)[0].endswith('/ouf_udp')
                row['matchesUdpRole'] = value == 'ouf_udp'
            rows.append(row)
    return {'properties': rows, 'overrideChannels': [{'property':k,'nonempty':bool(v),'kind':type(v).__name__} for k,v in env.items() if normal(k).startswith(('spring','loader'))], 'springJsonProperties': [{'property':k,'kind':type(v).__name__,'isNull':v is None}for k,v in flat.items()], 'javaOverrideChannelsPresent': any(env.get(k) for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS','_JAVA_OPTIONS')),
            'argumentOverridePresent': any(a.startswith(('--spring.', '-Dspring.')) for a in (actual['Config'].get('Entrypoint') or []) + (actual['Config'].get('Cmd') or [])),
            'mountedConfigurationCount':len([m for m in actual['Mounts'] if m['Destination'].endswith(('.yaml','.yml','.properties'))]),
            'credentialValuesPrinted': False, 'effectiveFlywayConfigurationProven': False}

def main():
    root = Path(__file__).resolve().parents[1]
    release = json.loads((root/'releases/linked-property-qualified-20261017.json').read_text())
    selection = json.loads((root/'releases/linked-property-preparation-selection-20261017.json').read_text())
    prefix = next((p for p in (['docker'], ['sudo','-n','docker']) if runtime.call(p+['version','--format','{{.Server.Version}}']) is not None), None)
    if prefix is None:
        raise ValueError('RUNNER_DOCKER_READ_ACCESS_UNAVAILABLE')
    if runtime.call(prefix+['version','--format','{{.Client.APIVersion}}'], '1.44').strip() != b'1.44':
        raise ValueError('EXACT_API_VERSION_REQUIRED')
    rows=[]
    for module in ('udp','onboarding'):
        expected = release['targetRead'][module]
        actual = runtime.inspect(prefix,expected['containerId'],'1.44')
        if actual['Image'] != expected['imageId'] or runtime.digest(actual['Config']) != selection['configHashes'][module]:
            raise ValueError('EXACT_APPLICATION_REQUIRED')
        row = {'module': module, **shape(actual)}
        following = runtime.inspect(prefix,expected['containerId'],'1.44')
        if actual != following:
            raise ValueError('APPLICATION_CHANGED_DURING_READ')
        rows.append(row)
    return rows

if __name__ == '__main__':
    report={'schema':'ouf.linked-property-configuration-shape.v1','readOnly':True,'credentialFilesRead':0,
            'databaseCalls':0,'serviceMutations':0,'grantRequests':0,'oauthRequests':0,'credentialValuesPrinted':False}
    try:
        report.update(complete=True, components=main())
    except Exception as error:
        report.update(complete=False, reason=str(error) if type(error) is ValueError else type(error).__name__)
    print('OUF_LINKED_PROPERTY_CONFIGURATION_SHAPE='+json.dumps(report, sort_keys=True))

