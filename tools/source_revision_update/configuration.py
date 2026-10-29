"""Verify the retained native Spring datasource/Flyway channels before login.

Only the packaged configuration, the closed retained owner JSON surface and one
already-mounted owner overlay are supported. No value, role, mount or credential is modified.
"""
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
import zipfile
from tools.chatbot_file_cohort.gateway import private_config
from tools.semantic_mcp_update.native import env, private_file
from tools.source_revision_update.owner import require

def application_json_metadata(raw):
    """Classify only existing owner/THS bindings; never rewrite or emit values.

    Dotted boundaries remain significant and the OAuth registration map key is
    literal. Datasource, migration, loader, profiles and other Spring properties
    stay outside this closed source-owner contract.
    """
    require(type(raw)is str and 0<len(raw.encode())<=65536,'BOUNDED_SPRING_JSON_REQUIRED')
    def unique(rows):
        result={}
        for key,value in rows:
            require(key not in result,'DUPLICATE_SPRING_JSON_KEY');result[key]=value
        return result
    try:value=json.loads(raw,object_pairs_hook=unique,
        parse_constant=lambda _:require(False,'NONFINITE_SPRING_JSON'))
    except (ValueError,TypeError):require(False,'VALID_SPRING_JSON_REQUIRED')
    require(type(value)is dict,'SPRING_JSON_OBJECT_REQUIRED')
    allowed={'ouf.authorization.ths.enabled':bool,'ouf.managedfilepicker.gatewayuploadurl':str,
        'ouf.onboarding.udpidentity.gatewayurl':str,'ouf.onboarding.udpidentity.tokenfile':str,
        'ouf.resolution.ths.gatewaybaseurl':str,'ouf.workflow.ths.gatewaybaseurl':str,
        'spring.security.oauth2.client.registration.ouf-ths.scope':list}
    found={}
    def visit(obj,prefix='',depth=0):
        require(type(obj)is dict and depth<=12 and(depth==0 or bool(obj)),'BOUNDED_NONEMPTY_JSON_BRANCH_REQUIRED')
        for key,item in obj.items():
            require(type(key)is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',key),'SPRING_JSON_KEY_SCHEMA')
            full=prefix+'.'+key if prefix else key
            if type(item)is dict:visit(item,full,depth+1);continue
            parts=full.split('.');canonical=[re.sub('[^a-z0-9]','',part.lower())for part in parts]
            if canonical[:5]==['spring','security','oauth2','client','registration']and len(parts)>5:canonical[5]=parts[5]
            name='.'.join(canonical)
            require(name in allowed and name not in found,'UNREVIEWED_OR_DUPLICATE_OWNER_JSON_PROPERTY')
            require(type(item)is allowed[name]and(type(item)is not list or all(type(v)is str for v in item)),
                'OWNER_JSON_PROPERTY_TYPE_CHANGED')
            found[name]={'property':name,'type':type(item).__name__}
    visit(value)
    return {'emptyObject':not bool(value),'propertyOverrides':len(found),'migrationOverridePresent':False,
        'retainedOwnerBindingsOnly':True,'rawSha256':hashlib.sha256(raw.encode()).hexdigest(),
        'properties':[found[key]for key in sorted(found)],'configurationValuesPrinted':False}


def owner_json_overlay(raw):
    """Closed JSON owner/OAuth configuration; no Spring loading/migration channels."""
    def unique(rows):
        value={}
        for key,item in rows:
            require(key not in value,'DUPLICATE_OWNER_OVERLAY_KEY');value[key]=item
        return value
    try:
        value=json.loads(raw,object_pairs_hook=unique,
            parse_constant=lambda _:require(False,'NONFINITE_OWNER_OVERLAY'))
    except (ValueError,TypeError,RecursionError):require(False,'STRICT_OWNER_JSON_REQUIRED')
    require(type(value)is dict and bool(value),'OWNER_JSON_OBJECT_REQUIRED')
    found=set();nodes=0;session={}
    session_fields={'server.servlet.session.cookie.httponly':bool,'server.servlet.session.cookie.secure':bool,
        'server.servlet.session.cookie.samesite':str,'server.servlet.session.timeout':str}
    def visit(obj,prefix=(),depth=0):
        nonlocal nodes
        require(type(obj)is dict and bool(obj) and depth<=16,'BOUNDED_OWNER_JSON_OBJECT')
        for key,item in obj.items():
            nodes+=1;require(nodes<=512 and type(key)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]{0,127}',key),'OWNER_JSON_KEY_SCHEMA')
            parts=prefix+tuple(key.split('.'))
            require(all(parts),'OWNER_JSON_EMPTY_SEGMENT')
            canonical=tuple(re.sub('[^a-z0-9]','',part.lower()) for part in parts)
            require(all(canonical),'OWNER_JSON_EMPTY_CANONICAL_SEGMENT')
            if type(item)is dict:visit(item,parts,depth+1);continue
            name='.'.join(canonical)
            require(not any(name==old or name.startswith(old+'.') or old.startswith(name+'.') for old in found),'AMBIGUOUS_OWNER_JSON_PROPERTY');found.add(name)
            owner=canonical[:1]==('ouf',) and not ''.join(canonical).startswith('oufonbdb')
            oauth=canonical[:5]==('spring','security','oauth2','client','registration') or canonical[:5]==('spring','security','oauth2','client','provider')
            require(owner or oauth or name in session_fields,'UNREVIEWED_OWNER_JSON_NAMESPACE')
            if name in session_fields:
                require(type(item)is session_fields[name],'SESSION_PROPERTY_TYPE_CHANGED')
                session[name]=item
            if oauth:
                require(len(parts)==7 and (parts[5]=='ouf-ths' if canonical[4]=='registration' else re.fullmatch('[A-Za-z0-9_-]{1,128}',parts[5])),'EXACT_THS_OAUTH_MAP_KEY_REQUIRED')
                fields={'clientid','clientsecret','clientauthenticationmethod','authorizationgranttype','redirecturi','scope','provider'} if canonical[4]=='registration' else {'issueruri','authorizationuri','tokenuri','userinfouri','usernameattribute','jwkseturi'}
                require(canonical[-1] in fields,'UNREVIEWED_THS_OAUTH_PROPERTY')
            require(type(item) in (str,bool,int,list),'OWNER_JSON_SCALAR_TYPE')
            values=item if type(item)is list else [item]
            require(len(values)<=256 and all(type(v)in(str,bool,int) for v in values),'OWNER_JSON_SCALAR_LIST')
            if oauth:
                require(type(item)is str or canonical[-1]=='scope' and type(item)is list and all(type(v)is str for v in item),'THS_OAUTH_PROPERTY_TYPE')
            for v in values:
                require(type(v)is not str or len(v)<=65536 and not any(c in v for c in ('${','#{','\x00')),'LITERAL_OWNER_JSON_VALUES_REQUIRED')
    visit(value)
    if session:
        require(set(session)==set(session_fields),'COMPLETE_RETAINED_SESSION_PROPERTIES_REQUIRED')
        require(session['server.servlet.session.cookie.httponly'] is True and session['server.servlet.session.cookie.secure'] is True,'SECURE_HTTPONLY_SESSION_REQUIRED')
        require(session['server.servlet.session.cookie.samesite'].lower() in ('strict','lax','none'),'EXPLICIT_SESSION_SAMESITE_REQUIRED')
        timeout=session['server.servlet.session.timeout']
        simple=re.fullmatch(r'[1-9][0-9]{0,8}(?i:ns|us|ms|s|m|h|d)?',timeout)
        iso=re.fullmatch(r'P(?:[0-9]{1,8}D)?(?:T(?:[0-9]{1,8}H)?(?:[0-9]{1,8}M)?(?:[0-9]{1,8}(?:\.[0-9]{1,9})?S)?)?',timeout)
        require(simple or iso and not timeout.endswith('T') and any(c in '123456789' for c in timeout),'FINITE_POSITIVE_SESSION_TIMEOUT_REQUIRED')
    return {'format':'STRICT_JSON','ownerThsOAuthAndSessionOnly':True,'retainedSessionSecurityValidated':bool(session),'migrationOverridePresent':False,
            'propertyCount':len(found),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'configurationValuesPrinted':False}


def overlay_text(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 1048576, 'BOUNDED_OWNER_OVERLAY_REQUIRED')
    if raw.lstrip().startswith(b'{'):
        return owner_json_overlay(raw)
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
    location = None; json_metadata = None
    for key,value in values.items():
        normalized = re.sub('[^a-z0-9]','',key.lower())
        if key == 'SPRING_APPLICATION_JSON':
            json_metadata = application_json_metadata(value)
        elif key == 'SPRING_CONFIG_ADDITIONAL_LOCATION' and value:
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
        # This verifier is sealed into native owner-update preflights. A JAR
        # that exposes managed-profile recovery must carry its complete THS
        # request contract before a replacement can be reviewed or started.
        # Do not silently patch here: the exact additive change belongs in the
        # installation profile and its separate execution review.
        recovery = [n for n in archive.namelist() if re.fullmatch(r'BOOT-INF/classes/.+/ManagedProfileRecoveryThs\.class',n)]
        if recovery:
            require(len(recovery)==1 and json_metadata is not None,'RECOVERY_THS_EXPLICIT_REQUEST_CONTRACT_REQUIRED')
            pending=[('',json.loads(values['SPRING_APPLICATION_JSON']))];requested=None
            while pending:
                prefix,obj=pending.pop()
                for key,item in obj.items():
                    full=prefix+'.'+key if prefix else key
                    if type(item)is dict:pending.append((full,item));continue
                    if re.sub('[^a-z0-9]','',full.lower())=='springsecurityoauth2clientregistrationoufthsscope':
                        require(requested is None,'RECOVERY_THS_UNIQUE_REQUEST_SCOPE_REQUIRED');requested=item
            required={'ouf.managed-source.preview','ouf.managed-source.file.profile','ouf.onboarding.quarantine.release'}
            require(type(requested)is list and all(type(s)is str for s in requested)
                    and len(requested)==len(set(requested)) and required<=set(requested),
                    'RECOVERY_THS_REQUEST_SCOPE_CONTRACT_INCOMPLETE')
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
        'higherPriorityMigrationOverridesAbsent':True,'ownerOverlays':overlays,'applicationJson':json_metadata,
        'externalUnreviewedConfigurationAbsent':True,'configurationValuesPrinted':False}
