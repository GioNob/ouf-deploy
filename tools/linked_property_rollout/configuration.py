"""Verify the supported native Spring/Flyway binding without changing properties."""
import hashlib,os,re,zipfile
from pathlib import Path
from urllib.parse import urlsplit
from tools.linked_property_rollout.owner import require
from tools.semantic_mcp_update.native import env,private_file

def verify(actual,candidate,postgres,expected_yaml_hash,root=None):
    values=env(actual['Config']['Env'])
    # Any higher-priority Spring source needs its own reviewed resolver. This
    # installation has none; reject drift instead of guessing precedence.
    for key,value in values.items():
        normalized=re.sub('[^a-z0-9]','',key.lower())
        require(not value or not (normalized.startswith(('spring','loader')) or key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS','_JAVA_OPTIONS')),
                'UNREVIEWED_SPRING_OVERRIDE_CHANNEL')
    args=(actual['Config'].get('Entrypoint')or[])+(actual['Config'].get('Cmd')or[])
    require(not any(a.startswith(('--','-D','@')) for a in args),'UNREVIEWED_JAVA_ARGUMENT_OVERRIDE')
    require(values.get('OUF_UDP_DB_USER')=='ouf_udp' and bool(values.get('OUF_UDP_DB_PASSWORD')),
            'EXISTING_APPLICATION_DATABASE_ROLE_REQUIRED')
    url=values.get('OUF_UDP_DB_URL','')
    require(url.startswith('jdbc:postgresql://'),'NATIVE_POSTGRES_DATASOURCE_REQUIRED')
    parsed=urlsplit(url[5:])
    aliases={postgres['Name'].lstrip('/'),postgres['Config']['Hostname']}
    for net in postgres['NetworkSettings']['Networks'].values():
        aliases.update(net.get('Aliases')or[]);aliases.add(net.get('IPAddress'))
    require(parsed.hostname in aliases and parsed.path=='/ouf_udp' and parsed.port in(None,5432)
            and not parsed.username and not parsed.password and not parsed.fragment and parsed.query in ('','currentSchema=ouf_udp'),
            'EXACT_FLYWAY_DATABASE_ENDPOINT_REQUIRED')
    private_file(candidate['jar']['path'],candidate['jar']['sha256'],268435456)
    with zipfile.ZipFile(candidate['jar']['path'])as archive:
        configs=[n for n in archive.namelist() if re.fullmatch(r'BOOT-INF/classes/application(?:-[^/]+)?\.(?:yml|yaml|properties)',n)]
        require(configs==['BOOT-INF/classes/application.yml'],'ONE_QUALIFIED_SPRING_CONFIGURATION_REQUIRED')
        raw=archive.read(configs[0])
        require(hashlib.sha256(raw).hexdigest()==expected_yaml_hash,'QUALIFIED_APPLICATION_CONFIG_CHANGED')
        require(any(n.startswith('BOOT-INF/lib/flyway-core-') for n in archive.namelist()),'NATIVE_FLYWAY_LIBRARY_REQUIRED')
    working=actual['Config'].get('WorkingDir')or'/'
    require(working.startswith('/')and '..'not in Path(working).parts,'EXACT_JAVA_WORKING_DIRECTORY_REQUIRED')
    # Read-only probes under the current process root cover default external
    # Spring locations. No mounted credentials are opened or values printed.
    root=Path(root) if root is not None else Path('/proc')/str(actual['State']['Pid'])/'root'
    for directory in {working,working.rstrip('/')+'/config'}:
        resolved=root/directory.lstrip('/')
        for ext in('properties','yml','yaml'):
            require(not os.path.lexists(resolved/('application.'+ext)), 'EXTERNAL_SPRING_CONFIG_REQUIRES_REVIEW')
        if directory.endswith('/config')and resolved.exists():
            require(resolved.is_dir()and not resolved.is_symlink(),'DEFAULT_CONFIG_DIRECTORY_DRIFT')
            require(not any(resolved.iterdir()),'EXTERNAL_CONFIG_SUBDIRECTORY_REQUIRES_REVIEW')
    return {'configurationSha256':expected_yaml_hash,'nativeFlywayEnabledByDefault':True,
            'sameDatasourceAsApplication':True,'databaseMatches':True,'roleMatches':True,
            'higherPriorityOverridesAbsent':True,'externalDefaultConfigurationAbsent':True,
            'configurationValuesPrinted':False}
