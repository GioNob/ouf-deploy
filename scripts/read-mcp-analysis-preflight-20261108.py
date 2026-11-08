#!/usr/bin/env python3
"""Read MCP startup bindings and ordinary migration-14 prerequisites. No effects.

Credential files are stat-only. Reprocessing files are public signed deployment
metadata; only their binding/expiry summaries are emitted, without signature claims.
"""
import base64, hashlib, importlib.util, json, os, re, signal, subprocess, sys, tempfile
from pathlib import Path
from datetime import datetime, timezone

CID = '756f70a813a0a01218b9d9a07d56c01702364b67943181b8cc339be98d96531a'
IMAGE = 'sha256:a52180123104ac97e4979ad1b9b291654b076692da51708bb2a377301fef1220'
FRAME = '976cbfab45ec58589ae2a9b4e8922b93bc16dc840f55c371a036f9ab36c132a3'
HELPER = 'read-discovery-contract-20261108.py'
HELPER_SHA = '468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277'
FILES = ('MCP_OIDC_CLIENT_SECRET_FILE', 'MCP_FINGERPRINT_KEY_FILE',
         'MCP_REPROCESSING_KEY_PROFILE_FILE', 'MCP_REPROCESSING_PERMIT_FILE',
         'MCP_REPROCESSING_EXISTING_POLICY_FILE')
PRESENCE = ('MCP_DATABASE_URL', 'MCP_OIDC_TOKEN_ENDPOINT', 'MCP_OIDC_CLIENT_ID',
            'MCP_WORKLOAD_TOKEN', 'MCP_FINGERPRINT_KEY', 'MCP_AUTHORIZATION_BUNDLE_ENDPOINT',
            'MCP_GATEWAY_ENDPOINT', 'MCP_MANAGED_FILE_PICKER_URL',
            'MCP_REPROCESSING_KEY_PROFILE_SHA256', 'MCP_HOST_FILE_ORIGINS')
QUERY = """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s';
SELECT json_build_object(
 'readOnly',current_setting('transaction_read_only')='on',
 'databaseOid',(SELECT oid FROM pg_database WHERE datname=current_database()),
 'migrations',(SELECT coalesce(json_agg(json_build_object('version',version,'checksum',checksum) ORDER BY version),'[]'::json) FROM ouf_mcp.schema_migration),
 'analysisTablePresent',to_regclass('ouf_mcp.profile_analysis') IS NOT NULL,
 'analysisTaskTablePresent',to_regclass('ouf_mcp.profile_analysis_task') IS NOT NULL,
 'applicationRole',json_build_object(
   'canCreateInSchema',has_schema_privilege(current_user,'ouf_mcp','CREATE'),
   'canUseSchema',has_schema_privilege(current_user,'ouf_mcp','USAGE'),
   'canReadMigrationHistory',has_table_privilege(current_user,'ouf_mcp.schema_migration','SELECT'),
   'canRecordMigration',has_table_privilege(current_user,'ouf_mcp.schema_migration','INSERT'),
   'superuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user)));
ROLLBACK;
"""

def need(ok, code):
    if not ok: raise RuntimeError(code)

def helpers():
    p = Path(__file__).with_name(HELPER); raw = p.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == HELPER_SHA, 'CONTRACT_HELPER_CHANGED')
    spec = importlib.util.spec_from_file_location('contract_reader', p)
    c = importlib.util.module_from_spec(spec); exec(compile(raw, str(p), 'exec'), c.__dict__)
    return c, c.helper()

def database_result(value, checksums):
    need(value.get('readOnly') is True and str(value.get('databaseOid')) == '21560', 'EXACT_READ_ONLY_DATABASE_REQUIRED')
    rows = value.get('migrations', [])
    need(isinstance(rows, list) and len(rows) <= 14, 'BOUNDED_MIGRATION_HISTORY_REQUIRED')
    value['exactPrefix1To13'] = (rows == [{'version': i, 'checksum': checksums[str(i)]} for i in range(1, 14)])
    value['ordinaryMigration14MetadataPrerequisites'] = (
        value['exactPrefix1To13'] and value.get('analysisTablePresent') is False and
        value.get('analysisTaskTablePresent') is False and
        all(value.get('applicationRole', {}).get(k) is True for k in
            ('canCreateInSchema', 'canUseSchema', 'canReadMigrationHistory', 'canRecordMigration')))
    value['sqlMigrationExecuted'] = False
    value['scope'] = 'READ_ONLY_APPLICATION_ROLE_METADATA_NOT_MIGRATION_EXECUTION'
    return value

def permit_summary(profile_raw, permit_raw, expected, now):
    profile_matches = hashlib.sha256(profile_raw).hexdigest() == expected
    envelope = json.loads(permit_raw)
    payload = json.loads(base64.b64decode(envelope['payload'], validate=True))
    need(isinstance(payload, dict) and type(payload.get('expiresAt')) is int and
         type(payload.get('issuedAt')) is int, 'SIGNED_PERMIT_METADATA_SHAPE_UNEXPECTED')
    return {'profileHashMatchesDeclaration': profile_matches,
            'expiredAtRead': payload['expiresAt'] <= now,
            'notYetValidAtRead': payload['issuedAt'] > now,
            'signatureVerifiedByReader': False, 'permitOrBudgetChanged': False,
            'meaning': 'PUBLIC_DEPLOYMENT_METADATA_ONLY_NOT_AUTHORITY'}

def startup(doc, c, h, work, report):
    env = h.environment(doc)
    result = {'scope': 'DECLARED_ENV_AND_FILE_METADATA_NOT_CANDIDATE_STARTUP',
              'declaredNonempty': {k: bool(env.get(k)) for k in PRESENCE},
              'fileBindings': {}, 'credentialContentsRead': False,
              'managedUploadMode': env.get('MCP_MANAGED_UPLOAD_ENABLED') if env.get('MCP_MANAGED_UPLOAD_ENABLED') in ('picker','true','probe','') else 'OTHER_OR_ABSENT',
              'processIsMcpServer': False, 'reprocessing': {'configured': False}}
    pid = doc['State']['Pid']
    args = Path('/proc', str(pid), 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
    result['processIsMcpServer'] = args == [b'/usr/local/bin/ouf-mcp', b'server']
    raw = h.read(Path('/proc', str(pid), 'root/usr/local/bin/ouf-mcp'), 64 * 1024 * 1024)
    result['installedBinarySha256'] = hashlib.sha256(raw).hexdigest()
    result['installedBinaryBytes'] = len(raw)
    for key in FILES:
        if not env.get(key): result['fileBindings'][key] = {'declared': False}; continue
        _, metadata = c.mount_file(doc, env[key], False)
        result['fileBindings'][key] = {'declared': True, **metadata}
    selected = ('MCP_REPROCESSING_KEY_PROFILE_FILE','MCP_REPROCESSING_PERMIT_FILE',
                'MCP_REPROCESSING_EXISTING_POLICY_FILE','MCP_REPROCESSING_KEY_PROFILE_SHA256')
    present = [bool(env.get(k)) for k in selected]
    result['reprocessing'] = {'configured': any(present), 'allFourInputsPresent': all(present),
                              'signatureVerifiedByReader': False, 'permitOrBudgetChanged': False}
    if all(present):
        values = []
        for key in selected[:3]:
            raw, meta = c.mount_file(doc, env[key], True)
            need(raw is not None and meta.get('sameAsHostSource'), 'PUBLIC_DEPLOYMENT_FILE_BINDING_UNPROVEN')
            report['publicReprocessingMetadataFilesRead'] += 1
            c.save_private(work, key + '.private', raw); values.append(raw)
        result['reprocessing'].update(permit_summary(values[0], values[1], env[selected[3]], datetime.now(timezone.utc).timestamp()))
    return result

def run(report):
    need(os.geteuid() == 0 and sys.flags.isolated, 'ISOLATED_ROOT_REQUIRED')
    c, h = helpers()
    raw = h.read(h.PLAN, 1048576); need(hashlib.sha256(raw).hexdigest() == h.PLAN_SHA, 'RETAINED_PLAN_CHANGED')
    roles = h.parse(raw)['roles']; need(roles['mcp']['containerId'] == CID, 'CURRENT_MCP_ID_CHANGED')
    doc = h.inspect(CID); pg = h.inspect(roles['postgres']['containerId'])
    need(doc['Image'] == IMAGE and doc['State']['Running'] and h.digest(h.frame(doc)) == FRAME, 'CURRENT_MCP_FRAME_CHANGED')
    need(pg['Image'] == roles['postgres']['nativeImage'] and pg['State']['Running'], 'POSTGRES_IDENTITY_CHANGED')
    work = Path(tempfile.mkdtemp(prefix='mcp-analysis-preflight-', dir=h.ROOT)); os.chmod(work, 0o700)
    report['privateEvidenceDirectory'] = str(work)
    for name, value in (('mcp.private.json', doc), ('postgres.private.json', pg)):
        c.save_private(work, name, (json.dumps(value, sort_keys=True) + '\n').encode())
    report['startup'] = startup(doc, c, h, work, report)
    user, database = c.db_binding(doc, pg, 'mcp', h)
    command = (*c.DOCKER, 'exec', '-i', '-e', 'PGOPTIONS=-c default_transaction_read_only=on',
               '-e', 'PGAPPNAME=ouf-mcp-analysis-preflight', pg['Id'], 'psql', '-X', '-w', '-q', '-A', '-t',
               '-v', 'ON_ERROR_STOP=1', '-h', '/var/run/postgresql', '-U', user, '-d', database)
    report['readOnlyDatabaseSessionsAttempted'] += 1
    result = subprocess.run(command, input=QUERY.encode(), capture_output=True, timeout=12)
    c.save_private(work, 'database.stderr.private', result.stderr[:65536])
    need(result.returncode == 0 and len(result.stdout) <= 131072, 'DATABASE_METADATA_READ_FAILED')
    value = database_result(h.parse(result.stdout), c.MCP_CHECKSUMS)
    c.save_private(work, 'database.private.json', result.stdout); report['database'] = value
    need(h.frame(h.inspect(CID)) == h.frame(doc) and h.frame(h.inspect(pg['Id'])) == h.frame(pg), 'RUNTIME_CHANGED_DURING_READ')
    report.update(status='MCP_ANALYSIS_PREFLIGHT_READ', runtimeUnchangedDuringRead=True,
                  currentContainerId=CID, currentImageId=IMAGE, currentLegacyMac=h.mac_shape(doc),
                  candidateStartupTested=False, migrationDispatched=False)

def main():
    report = {'schema':'ouf.mcp-analysis-preflight.v1','status':'READ_INCOMPLETE',
              'credentialValuesEmitted':False,'credentialFileContentsRead':0,
              'publicReprocessingMetadataFilesRead':0,'readOnlyDatabaseSessionsAttempted':0,
              'databaseWrites':0,'serviceStops':0,'serviceConfigurationChanged':False,
              'imageImports':0,'gatewayWrites':0,'businessRequestsIssued':0,'s3Requests':0,
              'tokenRequests':0,'migrationDispatched':False,'candidateStartupTested':False}
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(RuntimeError('READ_DEADLINE')))
    signal.alarm(55)
    try: run(report)
    except Exception as e:
        report['reason'] = str(e) if type(e) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(e)) else type(e).__name__
    finally: signal.alarm(0)
    report['observedAt'] = datetime.now(timezone.utc).isoformat(); print(json.dumps(report, sort_keys=True))
if __name__ == '__main__': main()
