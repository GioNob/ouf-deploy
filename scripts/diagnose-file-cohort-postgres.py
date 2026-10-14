#!/usr/bin/python3
"""Bounded, read-only diagnosis of the four selected cohort databases.

One pass, no retries, grants, lifecycle operations, migrations or file secrets.
Only check identities/counts, SQLSTATE and finite classifications reach stdout.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from urllib.parse import urlsplit, unquote


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def ident(value):
    need(type(value) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', value),
         'SELECTED_DATABASE_IDENTIFIER_INVALID')
    return '"'+value+'"'


def literal(value):
    return "'"+value.replace("'", "''")+"'"


def failure(raw, code):
    match = re.search(rb'(?:ERROR|FATAL):\s+([0-9A-Z]{5}):', raw)
    state = match[1].decode() if match else None
    classes = {'42501':'INSUFFICIENT_PRIVILEGE', '42P01':'UNDEFINED_TABLE',
               '42703':'UNDEFINED_COLUMN', '42883':'UNDEFINED_FUNCTION',
               '3D000':'INVALID_DATABASE', '28000':'INVALID_AUTHORIZATION',
               '28P01':'INVALID_PASSWORD', '57014':'QUERY_CANCELLED',
               '55P03':'LOCK_UNAVAILABLE', '53300':'CONNECTION_CAPACITY',
               '57P03':'DATABASE_NOT_READY'}
    return {'status':'BLOCKED', 'sqlstate':state,
            'classification':classes.get(state, 'UNCLASSIFIED_CHANNEL_FAILURE'),
            'exitCode':code, 'automaticRetry':False}


def safe_reply(code, raw, diagnostic, check):
    if code:
        return failure(diagnostic, code)
    try:
        value = json.loads(raw)['value']
        result = {'status':'PASS', 'resultPresent':value is not None}
        if type(value) is list:
            need(len(value) <= 256, 'BOUNDED_MIGRATION_HISTORY_REQUIRED')
            result['migrationCount'] = len(value)
        elif type(value) is dict and check == 'ADMIN_OWNERSHIP':
            allowed = {'serverVersion', 'adminSuperuser', 'applicationRoleExists', 'auditRoleAbsent',
                       'applicationSchemaOwnerAuthority', 'applicationAuditTableOwnerAuthority',
                       'applicationAttemptTableOwnerAuthority', 'applicationIncidentTableOwnerAuthority',
                       'applicationAuditSequenceOwnerAuthority'}
            result['facts'] = {k:v for k,v in value.items() if k in allowed and
                              (type(v) is bool or (k == 'serverVersion' and type(v) is int))}
        return result
    except (ValueError, KeyError, TypeError):
        return {'status':'BLOCKED', 'classification':'INVALID_JSON_REPLY', 'automaticRetry':False}


def main():
    need(os.geteuid() == os.getegid() == 0 and os.sys.flags.isolated,
         'ISOLATED_ROOT_DIAGNOSIS_REQUIRED')
    binary = Path(shutil.which('docker') or '/usr/bin/docker').resolve()
    info = binary.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
         'ROOT_DOCKER_EXECUTABLE_REQUIRED')
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    socket = Path('/var/run/docker.sock').resolve()
    socket_stat = socket.stat()
    need(stat.S_ISSOCK(socket_stat.st_mode) and socket_stat.st_uid == 0,
         'LOCAL_ROOT_ENGINE_REQUIRED')
    socket_pin = (socket_stat.st_dev, socket_stat.st_ino)
    env = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C',
           'DOCKER_HOST':'unix://'+str(socket)}
    with tempfile.TemporaryDirectory(prefix='ouf-pg-read-') as config:
        def run(args, data=None):
            need(hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash and
                 (socket.stat().st_dev, socket.stat().st_ino) == socket_pin,
                 'LOCAL_COMMAND_OR_ENGINE_DRIFT')
            # Regular temporary files bound memory even for unexpected output.
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                try:
                    process = subprocess.run([str(binary), '--config', config, *args],
                        input=data, stdout=out, stderr=err, env=env, timeout=20)
                except subprocess.TimeoutExpired:
                    return 124, b'', b''
                need(out.tell() <= 8*1024**2 and err.tell() <= 262144,
                     'BOUNDED_DIAGNOSIS_REPLY_REQUIRED')
                out.seek(0); err.seek(0)
                return process.returncode, out.read(), err.read()

        def inspect(name):
            code, raw, _ = run(['inspect', '--type=container', name])
            need(code == 0, 'SELECTED_CONTAINER_INSPECTION_FAILED')
            rows = json.loads(raw)
            need(type(rows) is list and len(rows) == 1, 'ONE_SELECTED_CONTAINER_REQUIRED')
            row = rows[0]
            need(row['Name'] == '/'+name and re.fullmatch('[0-9a-f]{64}', row['Id'])
                 and row['State']['Running'] is True, 'EXACT_RUNNING_CONTAINER_REQUIRED')
            return row

        pg = inspect('ouf-postgres')
        pins = [pg]
        def query(module, check, user, database, expression):
            ident(user); ident(database)
            sql = ('\\set VERBOSITY verbose\nBEGIN READ ONLY;\n'
                   "SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s';\n"
                   "SELECT json_build_object('value',("+expression+"));\nROLLBACK;\n").encode()
            code, raw, diagnostic = run(['exec', '-i', pg['Id'], 'env',
                'PGAPPNAME=ouf-cutover-cohort-diagnose', 'psql', '-X', '-q', '-A', '-t',
                '-v', 'ON_ERROR_STOP=1', '-U', user, '-d', database], sql)
            result = {'module':module, 'check':check}
            result.update(safe_reply(code, raw, diagnostic, check))
            print(json.dumps(result, sort_keys=True), flush=True)

        for module, prefix in (('udp','OUF_UDP'), ('onboarding','OUF_ONB'),
                               ('ingestion','OUF_ING'), ('mcp','MCP')):
            app = inspect('ouf-'+module); pins.append(app)
            values = dict(item.split('=', 1) for item in app['Config']['Env'])
            raw_url = values['MCP_DATABASE_URL'] if module == 'mcp' else values[prefix+'_DB_URL']
            if raw_url.startswith('jdbc:'): raw_url = raw_url[5:]
            url = urlsplit(raw_url)
            network = pg['NetworkSettings']['Networks']['ouf-backend']
            peers = {pg['Name'].lstrip('/'), pg['Config']['Hostname'], network['IPAddress'],
                     *(network.get('Aliases') or [])}
            need(url.scheme in ('postgres','postgresql') and url.hostname in peers
                 and url.port in (None,5432) and app['NetworkSettings']['Networks']['ouf-backend']['NetworkID']
                 == network['NetworkID'], 'EXACT_SELECTED_POSTGRES_BINDING_REQUIRED')
            user = unquote(url.username or '') if module == 'mcp' else values[prefix+'_DB_USER']
            database = unquote(url.path)[1:]; ident(user); ident(database)
            schema = ident('ouf_'+module)
            query(module, 'DATABASE_IDENTITY', user, database,
                "SELECT json_build_object('name',current_database(),'oid',oid::bigint,'allowConnections',datallowconn,'prepared',(SELECT count(*) FROM pg_prepared_xacts WHERE database=current_database())) FROM pg_database WHERE datname=current_database()")
            history = ("SELECT COALESCE(json_agg(json_build_object('version',version,'checksum',checksum) ORDER BY version),'[]'::json) FROM "+schema+'.schema_migration' if module == 'mcp' else
                "SELECT COALESCE(json_agg(json_build_object('version',version,'script',script,'type',type,'checksum',checksum,'success',success) ORDER BY installed_rank),'[]'::json) FROM "+schema+'.flyway_schema_history')
            query(module, 'MIGRATION_HISTORY', user, database, history)
            if module == 'mcp':
                role = literal(user)
                fields = ["'serverVersion',current_setting('server_version_num')::int",
                          "'adminSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user)",
                          "'applicationRoleExists',EXISTS(SELECT 1 FROM pg_roles WHERE rolname="+role+")",
                          "'auditRoleAbsent',NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='ouf_mcp_operational_audit_owner')",
                          "'applicationSchemaOwnerAuthority',EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='ouf_mcp' AND pg_has_role((SELECT oid FROM pg_roles WHERE rolname="+role+"),nspowner,'USAGE'))"]
                for key, table in (('AuditTable','audit_event'), ('AttemptTable','tool_attempt'),
                                   ('IncidentTable','security_incident'), ('AuditSequence','audit_event_sequence_id_seq')):
                    fields.append("'application"+key+"OwnerAuthority',EXISTS(SELECT 1 FROM pg_class WHERE oid=to_regclass('ouf_mcp."+table+"') AND pg_has_role((SELECT oid FROM pg_roles WHERE rolname="+role+"),relowner,'USAGE'))")
                query(module, 'ADMIN_OWNERSHIP', 'postgres', database,
                      'SELECT json_build_object('+','.join(fields)+')')
        for previous in pins:
            fresh = inspect(previous['Name'].lstrip('/'))
            need(all(fresh[key] == previous[key] for key in ('Id','Image','Config','HostConfig'))
                 and fresh['State']['StartedAt'] == previous['State']['StartedAt']
                 and fresh['State']['Pid'] == previous['State']['Pid'],
                 'CONTAINER_CHANGED_DURING_DIAGNOSIS')
        print(json.dumps({'schema':'ouf.chatbot-cohort-postgres-diagnosis.v1',
            'status':'READ_PASS_COMPLETED_REVIEW_CHECK_RESULTS', 'readOnly':True,
            'databaseMutations':0, 'serviceMutations':0, 'runtimeAuthorityIssued':False,
            'automaticRetry':False, 'budgetReset':False, 'notReleaseAcceptance':True}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        reason = str(error) if type(error) is ValueError and re.fullmatch('[A-Z][A-Z0-9_]{1,159}', str(error)) else type(error).__name__
        print(json.dumps({'status':'BLOCKED', 'reason':reason, 'readOnly':True,
                          'automaticRetry':False, 'runtimeAuthorityIssued':False}), flush=True)
        raise SystemExit(1)
