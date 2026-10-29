"""Verify the supported native Spring/Flyway binding without changing properties."""
import hashlib,json,os,re,zipfile
from pathlib import Path
from urllib.parse import urlsplit
from tools.linked_property_rollout.owner import require
from tools.semantic_mcp_update.native import env,private_file

def application_json_metadata(raw):
    """Accept only the reviewed non-migration application settings, never arbitrary JSON."""
    require(type(raw)is str and 0<len(raw.encode())<=65536,'BOUNDED_SPRING_JSON_REQUIRED')
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'DUPLICATE_SPRING_JSON_KEY')
            result[key]=value
        return result
    try:value=json.loads(raw,object_pairs_hook=unique)
    except (ValueError,TypeError):require(False,'VALID_SPRING_JSON_OBJECT_REQUIRED')
    allowed={'oufudpexecutionenabled':bool,'oufudpexecutiongatewayurl':str,
             'oufudpexecutiontokenfile':str,'oufudplaketenantid':str}
    observed={}
    def flatten(obj,prefix='',depth=0):
        require(type(obj)is dict and obj and depth<=12,'BOUNDED_SPRING_JSON_OBJECT_REQUIRED')
        for key,item in obj.items():
            require(type(key)is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',key),'EXACT_SPRING_JSON_PROPERTY_REQUIRED')
            path=prefix+'.'+key if prefix else key
            if type(item)is dict:flatten(item,path,depth+1)
            else:
                normalized=re.sub('[^a-z0-9]','',path.lower())
                require(normalized in allowed and type(item)is allowed[normalized], 'UNREVIEWED_SPRING_JSON_PROPERTY')
                require(normalized not in observed,'AMBIGUOUS_SPRING_JSON_PROPERTY')
                require(type(item)is bool or 0<len(item)<=8192,'BOUNDED_APPLICATION_SETTING_REQUIRED')
                observed[normalized]=type(item).__name__
    flatten(value)
    return {'reviewedApplicationSettings':len(observed),'migrationOverridePresent':False,'configurationValuesPrinted':False}

def verify(actual,candidate,postgres,expected_yaml_hash,root=None):
    values=env(actual['Config']['Env'])
    # The entire container Config is already pinned by the retained review.
    # Parse the application JSON channel; unrelated settings must not be mistaken
    # for datasource/Flyway overrides. All other Spring channels remain denied.
    json_metadata=None
    for key,value in values.items():
        if key=='SPRING_APPLICATION_JSON' and value:
            json_metadata=application_json_metadata(value)
            continue
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
            'higherPriorityMigrationOverridesAbsent':True,'applicationJson':json_metadata,'externalDefaultConfigurationAbsent':True,
            'configurationValuesPrinted':False}
