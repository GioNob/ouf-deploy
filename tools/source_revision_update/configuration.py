"""Verify the retained native Spring datasource/Flyway channels before login.

Only the packaged configuration and one already-mounted non-Spring owner overlay
are supported. No configuration, role, mount or credential is modified.
"""
import hashlib
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
import zipfile
from tools.chatbot_file_cohort.gateway import private_config
from tools.semantic_mcp_update.native import env, private_file
from tools.source_revision_update.owner import require


def overlay_text(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 1048576, 'BOUNDED_OWNER_OVERLAY_REQUIRED')
    # A deliberately closed YAML surface: aliases, directives, complex/quoted
    # mapping keys and flow documents need separate qualification. Values are
    # never returned, logged or interpolated by this verifier.
    for line in raw.decode('utf-8').splitlines():
        text = line.lstrip()
        if not text or text.startswith('#'):
            continue
        require(not text.startswith(('%','{','[','?','<<:',"'",'"'))
                and not re.search(r'(^|\s)[&*!][A-Za-z_]', text), 'UNREVIEWED_OWNER_OVERLAY_SYNTAX')
        match = re.match(r'(?:-\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*:', text)
        if match:
            key = re.sub('[^a-z0-9]', '', match[1].lower())
            require(not key.startswith(('spring','loader')), 'OWNER_OVERLAY_MIGRATION_OVERRIDE')
    return {'nonSpringOwnerOverlay':True,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'configurationValuesPrinted':False}


def additional_location(value):
    require(type(value) is str and 0 < len(value) <= 4096, 'EXACT_ADDITIONAL_LOCATION_REQUIRED')
    if value.startswith('optional:'):
        value = value[len('optional:'):]
    require(value.startswith('file:'), 'ONLY_RETAINED_FILE_OVERLAY_SUPPORTED')
    path = value[len('file:'):]
    require(path.startswith('/') and str(Path(path)) == path and '..' not in Path(path).parts
            and re.fullmatch(r'/[A-Za-z0-9_./-]+\.(?:yml|yaml)',path), 'EXACT_SINGLE_OWNER_OVERLAY_REQUIRED')
    return path


def verify(actual, candidate, postgres, binding, native_port, yaml_sha256, *, root=None):
    values = env(actual['Config']['Env'])
    require(type(native_port) is int and 1 <= native_port <= 65535, 'APPROVED_POSTGRES_PORT_REQUIRED')
    location = None
    for key,value in values.items():
        normalized = re.sub('[^a-z0-9]','',key.lower())
        if key == 'SPRING_CONFIG_ADDITIONAL_LOCATION' and value:
            location = additional_location(value)
        else:
            require(not (normalized.startswith(('spring','loader'))
                    or key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS','_JAVA_OPTIONS')),
                    'UNREVIEWED_SPRING_OVERRIDE_CHANNEL')
    arguments = (actual['Config'].get('Entrypoint') or []) + (actual['Config'].get('Cmd') or [])
    require(not any(a.startswith(('--','-D','@')) for a in arguments), 'UNREVIEWED_JAVA_ARGUMENT_OVERRIDE')
    require(values.get('OUF_ONB_DB_USER') == binding['user'] and bool(values.get('OUF_ONB_DB_PASSWORD')),
            'EXISTING_ONBOARDING_DATABASE_ROLE_REQUIRED')
    url = values.get('OUF_ONB_DB_URL','')
    require(url.startswith('jdbc:postgresql://'), 'NATIVE_POSTGRES_DATASOURCE_REQUIRED')
    parsed = urlsplit(url[5:])
    aliases = {postgres['Name'].lstrip('/'), postgres['Config']['Hostname']}
    for network in postgres['NetworkSettings']['Networks'].values():
        aliases.update(network.get('Aliases') or []); aliases.add(network.get('IPAddress'))
    require(parsed.hostname in aliases and parsed.path == '/'+binding['database']
            and parsed.port in (None,native_port) and not parsed.username and not parsed.password
            and not parsed.fragment and parsed.query in ('','currentSchema='+binding['schema']),
            'EXACT_ONBOARDING_DATABASE_ENDPOINT_REQUIRED')
    private_file(candidate['jar']['path'],candidate['jar']['sha256'],268435456)
    with zipfile.ZipFile(candidate['jar']['path']) as archive:
        names = [n for n in archive.namelist() if re.fullmatch(r'BOOT-INF/classes/application(?:-[^/]+)?\.(?:yml|yaml|properties)',n)]
        require(names == ['BOOT-INF/classes/application.yml'], 'ONE_QUALIFIED_SPRING_CONFIGURATION_REQUIRED')
        require(hashlib.sha256(archive.read(names[0])).hexdigest() == yaml_sha256, 'QUALIFIED_ONBOARDING_CONFIGURATION_CHANGED')
        require(any(n.startswith('BOOT-INF/lib/flyway-core-') for n in archive.namelist()), 'NATIVE_FLYWAY_LIBRARY_REQUIRED')
    overlays = []
    if location is not None:
        matches = [m for m in actual['Mounts'] if m['Destination'] == location]
        require(len(matches) == 1 and matches[0]['Type'] == 'bind' and matches[0]['RW'] is False,
                'EXACT_RETAINED_READONLY_OWNER_OVERLAY_REQUIRED')
        raw, selected = private_config(matches[0]['Source'])
        overlays.append({'binding':selected,'metadata':overlay_text(raw),'target':location})
    working = actual['Config'].get('WorkingDir') or '/'
    require(working.startswith('/') and '..' not in Path(working).parts, 'EXACT_JAVA_WORKING_DIRECTORY_REQUIRED')
    process_root = Path(root) if root is not None else Path('/proc')/str(actual['State']['Pid'])/'root'
    directories = {working,working.rstrip('/')+'/config'}
    for mount in actual['Mounts']:
        destination = mount['Destination'].rstrip('/')
        default_root = working.rstrip('/')+'/config'
        inside_default = (destination == default_root or destination.startswith(default_root+'/')
                          or re.fullmatch(re.escape(working.rstrip('/'))+r'/application(?:-[^/]+)?\.(?:yml|yaml|properties)',destination))
        require(not inside_default or destination == location,
                'UNREVIEWED_DEFAULT_CONFIGURATION_MOUNT')
    config = process_root/(working.rstrip('/')+'/config').lstrip('/')
    if config.exists():
        require(config.is_dir() and not config.is_symlink(), 'DEFAULT_CONFIG_DIRECTORY_DRIFT')
        directories.update(working.rstrip('/')+'/config/'+child.name for child in config.iterdir() if child.is_dir())
    for directory in directories:
        selected = process_root/directory.lstrip('/')
        if not selected.exists():
            continue
        require(selected.is_dir(), 'DEFAULT_CONFIG_DIRECTORY_REQUIRED')
        for child in selected.iterdir():
            if re.fullmatch(r'application(?:-[^/]+)?\.(?:yml|yaml|properties)',child.name):
                target = directory.rstrip('/')+'/'+child.name
                require(location == target, 'EXTERNAL_SPRING_CONFIG_REQUIRES_REVIEW')
    return {'configurationSha256':yaml_sha256,'nativeFlywayEnabledByDefault':True,
        'sameDatasourceAsApplication':True,'databaseMatches':True,'roleMatches':True,
        'higherPriorityMigrationOverridesAbsent':True,'ownerOverlays':overlays,
        'externalUnreviewedConfigurationAbsent':True,'configurationValuesPrinted':False}
