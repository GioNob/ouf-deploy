"""Read current four-container/database bindings and compile the exact cohort.

No effects, file credential reads or public environment output. The caller has
already authenticated the six-module package and copied it to private custody.
"""
import copy
import hashlib
import json
import re
import tarfile
from pathlib import Path
from urllib.parse import urlsplit, unquote, parse_qsl

from engine_creation import Engine
from tools.chatbot_file_cohort.plan import MODULES, compile_cohort, environment, runtime_pin, digest, require
from tools.chatbot_file_cohort.databases import observe_database, compile_database_plan, java_migrations, identifier
from tools.chatbot_file_cohort.images import private_open, image_import_scope
from tools.chatbot_file_cohort.gateway import private_config

DB_PREFIX = {'udp':'OUF_UDP','onboarding':'OUF_ONB','ingestion':'OUF_ING'}
THS_CONFIG_SOURCE = '/opt/ouf/secrets/onboarding-ths.yaml'
THS_CONFIG_TARGET = '/run/secrets/onboarding-ths.yaml'
THS_ADDITIONAL_LOCATION = 'file:' + THS_CONFIG_TARGET


def validate_json_overlay(raw,prefix):
    """Preserve the existing THS OAuth overlay without accepting a DB override."""
    if not raw:return
    require(type(raw) is str and len(raw.encode())<=262144,'BOUNDED_APPLICATION_JSON_REQUIRED')
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'DUPLICATE_APPLICATION_JSON_PROPERTY')
            value[key]=item
        return value
    try:
        value=json.loads(raw,object_pairs_hook=unique)
    except (ValueError,TypeError,RecursionError):
        require(False,'EXACT_APPLICATION_JSON_OBJECT_REQUIRED')
    require(type(value) is dict,'EXACT_APPLICATION_JSON_OBJECT_REQUIRED')
    protected=('springdatasource','springflyway','springconfig','springprofiles',
               'springapplicationjson',re.sub('[^a-z0-9]','',prefix.lower())+'db')
    pending=[('',value,0)];seen=0
    while pending:
        stem,current,depth=pending.pop()
        require(depth<=16,'BOUNDED_APPLICATION_JSON_DEPTH_REQUIRED')
        for name,item in current.items():
            seen+=1
            require(seen<=2048 and 0<len(name)<=256,'BOUNDED_APPLICATION_JSON_PROPERTIES_REQUIRED')
            full=stem+'.'+name if stem else name
            canonical=re.sub('[^a-z0-9]','',full.lower())
            require(not canonical.startswith(protected),'CUSTOM_DATASOURCE_CONFIGURATION_REQUIRES_REVIEW')
            if type(item) is dict:pending.append((full,item,depth+1))


def database_binding(module, actual, postgres, ths_binding=None):
    values = environment(actual['Config'].get('Env') or [])
    if module == 'mcp':
        raw = values.get('MCP_DATABASE_URL','')
    else:
        prefix = DB_PREFIX[module]
        raw = values.get(prefix+'_DB_URL','')
        require(raw.startswith('jdbc:postgresql://'), 'EXPLICIT_CURRENT_JDBC_DATABASE_REQUIRED')
        validate_json_overlay(values.get('SPRING_APPLICATION_JSON'),prefix)
        require(not values.get('SPRING_CONFIG_LOCATION'),
                'CUSTOM_DATASOURCE_CONFIGURATION_REQUIRES_REVIEW')
        additional = values.get('SPRING_CONFIG_ADDITIONAL_LOCATION')
        if additional:
            require(module == 'onboarding' and additional == THS_ADDITIONAL_LOCATION
                    and type(ths_binding) is dict and ths_binding.get('path') == THS_CONFIG_SOURCE,
                    'UNREVIEWED_ADDITIONAL_CONFIG_LOCATION')
            mounts = [m for m in actual.get('Mounts',[]) if m.get('Destination') == THS_CONFIG_TARGET]
            require(len(mounts) == 1 and mounts[0].get('Type') == 'bind'
                    and mounts[0].get('Source') == THS_CONFIG_SOURCE and mounts[0].get('RW') is False,
                    'EXACT_READ_ONLY_THS_CONFIG_BIND_REQUIRED')
            ths_raw,verified = private_config(THS_CONFIG_SOURCE,ths_binding)
            require(verified == ths_binding and ths_raw.lstrip().startswith(b'{'),
                    'SELECTED_THS_JSON_CONFIGURATION_REQUIRED')
            validate_json_overlay(ths_raw.decode('utf-8'),prefix)
        else:
            require(ths_binding is None or module == 'onboarding',
                    'UNREQUESTED_THS_CONFIGURATION_BINDING')
        for key in ('SPRING_DATASOURCE_URL','SPRING_DATASOURCE_USERNAME'):
            corresponding = raw if key.endswith('_URL') else values.get(prefix+'_DB_USER','')
            require(key not in values or values[key] == corresponding, 'CONFLICTING_DATASOURCE_OVERRIDE')
        args = (actual['Config'].get('Entrypoint') or [])+(actual['Config'].get('Cmd') or [])
        require(not any('spring.datasource' in argument for argument in args)
                and not any('spring.datasource' in values.get(key,'') for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS')),
                'COMMAND_DATASOURCE_OVERRIDE_REQUIRES_REVIEW')
        raw = raw[5:]
    parsed = urlsplit(raw)
    require(parsed.scheme in ('postgres','postgresql') and parsed.hostname
            and parsed.port in (None,5432) and not parsed.fragment
            and re.fullmatch('/[A-Za-z_][A-Za-z_0-9]{0,62}',unquote(parsed.path)),
            'BOUNDED_SELECTED_DATABASE_URL_REQUIRED')
    parameters = parse_qsl(parsed.query,keep_blank_values=True,strict_parsing=True)
    require(len(parameters) <= 32 and not ({key.lower() for key,_ in parameters}
            & {'user','username','password','host','hostaddr','port','dbname','database','service','servicefile'}),
            'DATABASE_URL_IDENTITY_OVERRIDE_REQUIRES_REVIEW')
    peers = {postgres['Name'].lstrip('/'),postgres['Config'].get('Hostname')}
    network = postgres['NetworkSettings'].get('Networks',{}).get('ouf-backend')
    require(type(network) is dict, 'POSTGRES_ON_SELECTED_BACKEND_REQUIRED')
    peers.update(network.get('Aliases') or []); peers.add(network.get('IPAddress'))
    require(parsed.hostname in peers and actual['NetworkSettings']['Networks']['ouf-backend']['NetworkID'] == network['NetworkID'],
            'DATASOURCE_MUST_REFERENCE_EXACT_CURRENT_POSTGRES')
    user = unquote(parsed.username or '') if module == 'mcp' else values.get(DB_PREFIX[module]+'_DB_USER','')
    database = unquote(parsed.path)[1:]
    identifier(user); identifier(database)
    return {'database':database,'user':user}


def packaged_migrations(directory, record):
    module = record['module']
    name = 'source.tar' if module == 'mcp' else 'application.jar'
    with private_open(Path(directory)/module/name, 536870912) as source:
        require(hashlib.file_digest(source,'sha256').hexdigest() == record['files'][name], 'PACKAGED_MIGRATION_BYTES_CHANGED')
        source.seek(0)
        if module != 'mcp':
            return java_migrations(source)
        rows = []
        prefix = 'internal/adapter/postgres/migrations/'
        with tarfile.open(fileobj=source,mode='r:') as archive:
            count = 0
            for entry in archive:
                count += 1
                require(count <= 10000, 'BOUNDED_MCP_SOURCE_ARCHIVE_REQUIRED')
                if entry.isdir() or not entry.name.startswith(prefix):
                    continue
                match = re.fullmatch(re.escape(prefix)+r'([0-9]{3})_[a-z0-9_]+\.sql',entry.name)
                require(match is not None and entry.isfile() and 0 < entry.size <= 1048576,
                        'EXACT_PACKAGED_MCP_MIGRATION_REQUIRED')
                with archive.extractfile(entry) as member:
                    rows.append({'version':int(match[1]),'checksum':hashlib.file_digest(member,'sha256').hexdigest()})
        require(1 <= len(rows) <= 256 and len({r['version'] for r in rows}) == len(rows), 'COMPLETE_MCP_MIGRATIONS_REQUIRED')
        return sorted(rows,key=lambda r:r['version'])


def prepare_cohort(engine, package_directory, manifest, image_import_plan, postgres_observation,
                   gateway_plan_hash, authorization_plan_hash, environment_deltas, acceptance_plan_hash=None,
                   ths_binding=None):
    require(type(engine) is Engine, 'REAL_CURRENT_DOCKER_ENGINE_REQUIRED')
    image_import_scope(image_import_plan)
    require(image_import_plan['cohortManifestHash'] == digest(manifest), 'ONE_AUTHENTICATED_COHORT_REQUIRED')
    records = {row['module']:row for row in manifest['modules']}
    require(len(records) == 6 and set(records) == {'semantic','gateway',*MODULES}, 'EXACT_SIX_MODULE_MANIFEST_REQUIRED')
    packages = {name:{k:v for k,v in row.items() if k != 'files'} for name,row in records.items()}
    audits = {row['module']:row for row in image_import_plan['images']}
    observed, images, bindings, migrations, current = {}, {}, {}, {}, {}
    pgpin = runtime_pin(postgres_observation)
    code, pg = engine.request('GET','/v1.44/containers/'+pgpin['containerId']+'/json')
    require(code == 200 and runtime_pin(pg) == pgpin, 'CURRENT_SELECTED_POSTGRES_DRIFT')
    for module in MODULES:
        code, actual = engine.request('GET','/v1.44/containers/ouf-'+module+'/json')
        require(code == 200 and actual.get('Name') == '/ouf-'+module, 'CURRENT_SELECTED_APPLICATION_UNAVAILABLE')
        runtime_pin(actual)
        require(audits[module]['modulePackageHash'] == digest(packages[module]), 'IMAGE_AUDIT_PACKAGE_DRIFT')
        audit = audits[module]['audit']
        observed[module] = actual
        images[module] = {'Id':audit['imageId'],'Config':copy.deepcopy(audit['imageConfig'])}
        bindings[module] = database_binding(module,actual,pg,ths_binding if module == 'onboarding' else None)
        migrations[module] = packaged_migrations(package_directory,records[module])
        current[module] = observe_database(pgpin['containerId'],bindings[module]['user'],bindings[module]['database'],module)
    database_plan = compile_database_plan(pg,bindings,migrations,current)
    plan = compile_cohort(manifest,observed,images,packages,environment_deltas,
        gateway_plan_hash,digest(database_plan),authorization_plan_hash,acceptance_plan_hash)
    for replacement in plan['replacements']:
        module = replacement['module']
        candidate = {'Config':replacement['creationRequest'],
                     'NetworkSettings':observed[module]['NetworkSettings'],
                     'Mounts':observed[module]['Mounts']}
        require(database_binding(module,candidate,pg,ths_binding if module == 'onboarding' else None) == bindings[module],
                'REPLACEMENT_MUST_PRESERVE_REVIEWED_DATABASE_BINDING')
    for name, actual in observed.items():
        code, fresh = engine.request('GET','/v1.44/containers/'+actual['Id']+'/json')
        require(code == 200 and runtime_pin(fresh) == runtime_pin(actual), 'APPLICATION_CHANGED_DURING_PREPARATION')
    code, fresh = engine.request('GET','/v1.44/containers/'+pgpin['containerId']+'/json')
    require(code == 200 and runtime_pin(fresh) == pgpin, 'POSTGRES_CHANGED_DURING_PREPARATION')
    return {'cohortPlan':plan,'databasePlan':database_plan,'observations':observed,'candidateImages':images}
