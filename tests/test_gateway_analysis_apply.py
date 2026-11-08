import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import test_gateway_analysis_delta as fixture

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('publisher', ROOT/'scripts/apply-gateway-analysis-delta-20261108.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def setup_plan():
    data, _ = fixture.fixture()
    # Structurally valid APISIX admission plugins, solely synthetic credentials.
    for entry in data['list']:
        row = entry['value']; plugins = row['plugins']
        plugins['openid-connect'] = {'client_id': 'fixture', 'client_secret': 'synthetic-ci-secret',
            'discovery': 'https://issuer.example.test/.well-known/openid-configuration',
            'bearer_only': True, 'use_jwks': True, 'ssl_verify': True}
        plugins['limit-count'] = {'count': 60, 'time_window': 60, 'rejected_code': 429}
        plugins['serverless-pre-function'] = {'phase': 'rewrite', 'functions': ['return function(conf, ctx) end']}
        if plugins['serverless-post-function']['functions'] == ['OLD_FUNCTION']:
            plugins['serverless-post-function'] = {'phase': 'access', 'functions': ['return function(conf, ctx) end']}
        row['create_time'] = 1; row['update_time'] = 1
    pins = {r['value']['uri']: fixture.m.digest(r['value']) for r in data['list'] if r['value']['uri'] in fixture.m.BEFORE}
    with patch.object(fixture.m, 'BEFORE', pins):
        plan = fixture.m.compile_plan(data, fixture.A)
    expected = p.route_map(data)
    return plan, expected


def report():
    return {'adminPutAttempts': 0, 'routeWritesVerified': 0, 'runtimeChanged': False}


class MemoryAdmin:
    def __init__(self, rows, work, lose_ack=False):
        self.rows, self.work, self.lose_ack = copy.deepcopy(rows), work, lose_ack
        self.puts = 0

    def routes(self):
        return copy.deepcopy(self.rows)

    def put(self, rid, value):
        if not (self.work/f'{self.puts:02d}-intent.json').exists():
            raise AssertionError('durable intent must precede write')
        self.puts += 1
        self.rows[rid] = copy.deepcopy(value)
        if self.lose_ack:
            raise RuntimeError('ADMIN_RESPONSE_UNPROVEN')
        return {'httpStatus': 200, 'body': {'value': value}}

    def guard(self):
        pass


class PublisherTests(unittest.TestCase):
    def test_exact_plan_and_desired_hashes_required(self):
        plan, expected = setup_plan()
        hashes = [p.digest(c['desired']) for c in plan['changes']]
        with patch.object(p, 'PROPOSAL_SHA', p.digest(plan)), patch.object(p, 'DESIRED', hashes):
            self.assertEqual(p.validate_plan(plan), expected)
            changed = copy.deepcopy(plan); changed['changes'][0]['desired']['plugins']['openid-connect']['ssl_verify'] = False
            with self.assertRaisesRegex(RuntimeError, 'EXACT_PREPARED_PROPOSAL_REQUIRED'):
                p.validate_plan(changed)
        with patch.object(p, 'PROPOSAL_SHA', p.digest(plan)):
            with self.assertRaisesRegex(RuntimeError, 'EXACT_EIGHT_DESIRED_ROUTES_REQUIRED'):
                p.validate_plan(plan)

    def test_eight_writes_preserve_other_routes_and_journal_each_ack(self):
        plan, expected = setup_plan()
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); admin = MemoryAdmin(expected, work); result = report()
            p.publish(plan, expected, admin, work, result)
            self.assertEqual(result['routeWritesVerified'], 8)
            self.assertEqual(len(admin.rows), 87)
            for row in plan['unchangedRoutes']:
                self.assertEqual(admin.rows[str(row['id'])], p.body(row))
            self.assertEqual(len(list(work.glob('*-intent.json'))), 8)
            self.assertEqual(len(list(work.glob('*-ack.private.json'))), 8)
            self.assertEqual(len(list(work.glob('*-verified.json'))), 8)
            self.assertTrue(all(x.stat().st_mode & 0o777 == 0o600 for x in work.iterdir()))

    def test_stale_route_causes_zero_writes(self):
        plan, expected = setup_plan()
        with tempfile.TemporaryDirectory() as temp:
            admin = MemoryAdmin(expected, Path(temp)); admin.rows['retained-0']['status'] = 0
            with self.assertRaisesRegex(RuntimeError, 'CURRENT_ROUTES_DIFFER'):
                p.publish(plan, expected, admin, Path(temp), report())
            self.assertEqual(admin.puts, 0)

    def test_lost_ack_is_not_retried_and_preserves_intent(self):
        plan, expected = setup_plan()
        with tempfile.TemporaryDirectory() as temp:
            admin = MemoryAdmin(expected, Path(temp), True); result = report()
            with self.assertRaisesRegex(RuntimeError, 'ADMIN_RESPONSE_UNPROVEN'):
                p.publish(plan, expected, admin, Path(temp), result)
            self.assertEqual(admin.puts, 1)
            self.assertEqual(result['routeWritesVerified'], 0)
            self.assertIsNone(result['runtimeChanged'])
            self.assertTrue((Path(temp)/'00-intent.json').exists())

    def test_foreign_write_after_ack_stops_without_rollback(self):
        plan, expected = setup_plan()
        with tempfile.TemporaryDirectory() as temp:
            admin = MemoryAdmin(expected, Path(temp)); put = admin.put
            def mutate(rid, value):
                ack = put(rid, value); admin.rows['retained-0']['status'] = 0; return ack
            admin.put = mutate
            with self.assertRaisesRegex(RuntimeError, 'ROUTE_WRITE_READBACK_MISMATCH'):
                p.publish(plan, expected, admin, Path(temp), report())
            self.assertEqual(admin.puts, 1)

    def test_only_apisix_timestamps_are_excluded(self):
        self.assertEqual(p.body({'id':'x','create_time':1,'update_time':2,'maximum':9007199254740991}),
                         {'id':'x','maximum':9007199254740991})
        self.assertNotEqual(p.body({'id':'x','status':1}), p.body({'id':'x','status':0}))


def docker(*args, timeout=90):
    run = subprocess.run(['docker', *args], capture_output=True, timeout=timeout)
    if run.returncode:
        raise AssertionError('Synthetic Docker fixture failed: ' + run.stderr[:2000].decode(errors='replace'))
    return run.stdout.decode().strip()


@unittest.skipUnless(os.environ.get('OUF_NATIVE_GATEWAY_DELTA') == '1', 'disposable Docker CI required')
class NativeTests(unittest.TestCase):
    def test_real_apisix_eight_updates_ack_and_exact_readback(self):
        self.assertEqual(os.geteuid(), 0, 'production namespace transport requires root in isolated CI')
        name = 'ouf-delta-ci-' + str(os.getpid())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o755)
            net = docker('network','create',name)
            self.addCleanup(lambda: docker('network','rm',net))
            etcd = docker('run','-d','--name',name+'-etcd','--network',net,'quay.io/coreos/etcd:v3.5.17',
                          'etcd','--listen-client-urls=http://0.0.0.0:2379','--advertise-client-urls=http://'+name+'-etcd:2379')
            self.addCleanup(lambda: docker('rm','-f',etcd))
            config = {'apisix': {'node_listen':9080, 'extra_lua_path':'/usr/local/apisix/conf/?.lua', 'lua_module_hook':'ouf_json_precision'},
                      'deployment': {'role':'traditional', 'role_traditional':{'config_provider':'etcd'},
                        'admin': {'admin_listen':{'ip':'0.0.0.0','port':9180},'allow_admin':['127.0.0.1/32'],
                                  'admin_key':[{'name':'admin','key':'synthetic-ci-admin-key-1234567890','role':'admin'}]},
                        'etcd': {'host':['http://'+name+'-etcd:2379']}}}
            (root/'config.yaml').write_text(json.dumps(config))
            asset = ROOT/'tools/chatbot_file_cohort/assets/apisix'
            cid = docker('run','-d','--name',name+'-apisix','--network',net,
                         '-v',str(root/'config.yaml')+':/usr/local/apisix/conf/config.yaml:ro',
                         '-v',str(asset/'ouf_json_precision.lua')+':/usr/local/apisix/conf/ouf_json_precision.lua:ro',
                         '-v',str(asset/'jsonschema.lua')+':/usr/local/apisix/deps/share/lua/5.1/jsonschema.lua:ro',
                         'apache/apisix@sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d')
            self.addCleanup(lambda: docker('rm','-f',cid))
            c, h = p.helpers(); doc = h.inspect(cid)
            counters = {'adminCredentialConfigurationsRead':0,'externalAdminKeyFilesRead':0,'adminGetAttempts':0}
            admin = p.Admin(c, h, doc, counters)
            deadline = time.monotonic()+40
            while True:
                try:
                    if admin.request('GET','/apisix/admin/routes')['httpStatus'] == 200: break
                except RuntimeError:
                    pass
                self.assertLess(time.monotonic(),deadline,'APISIX did not start'); time.sleep(1)
            plan, expected = setup_plan()
            for rid, row in expected.items():
                response = admin.put(rid,row)
                self.assertIn(response['httpStatus'],(200,201),json.dumps(response)[:1800])
            self.assertEqual(admin.routes(), expected)
            work = root/'journal'; work.mkdir(mode=0o700); result = report()
            p.publish(plan, expected, admin, work, result)
            self.assertEqual(result['routeWritesVerified'],8)
            self.assertEqual(result['finalRouteCount'],87)
            review = admin.routes()['file-review-prepare']['plugins']['request-validation']['body_schema']
            self.assertEqual(review['properties']['Arguments']['properties']['expectedVersion']['maximum'],9007199254740991)
            with self.assertRaises(FileExistsError): work.mkdir(mode=0o700)

    def test_real_postgres_reads_missing_column_then_present_without_writes(self):
        cid = docker('run','-d','-e','POSTGRES_PASSWORD=synthetic-ci-only','postgres:17')
        self.addCleanup(lambda: docker('rm','-f',cid))
        deadline=time.monotonic()+40
        while subprocess.run(['docker','exec',cid,'pg_isready','-U','postgres'],capture_output=True).returncode:
            self.assertLess(time.monotonic(),deadline);time.sleep(1)
        def sql(query,user='postgres'):
            run=subprocess.run(['docker','exec','-i',cid,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',user,'-d','postgres'],
                               input=query,text=True,capture_output=True,timeout=15)
            return run
        setup=sql("CREATE SCHEMA ouf_sem; CREATE ROLE metadata_reader LOGIN; CREATE TABLE ouf_sem.flyway_schema_history(installed_rank int,version text,checksum int,success bool); INSERT INTO ouf_sem.flyway_schema_history VALUES(11,'11',123,true); CREATE TABLE ouf_sem.discovery_request(state text); INSERT INTO ouf_sem.discovery_request VALUES('PENDING'),('SUCCEEDED'); GRANT USAGE ON SCHEMA ouf_sem TO metadata_reader; GRANT SELECT ON ALL TABLES IN SCHEMA ouf_sem TO metadata_reader;")
        self.assertEqual(setup.returncode,0,setup.stderr)
        first=sql(p.SEMANTIC_QUERY,'metadata_reader');self.assertEqual(first.returncode,0,first.stderr)
        a=json.loads(first.stdout);self.assertFalse(a['recoveryColumnPresent']);self.assertTrue(a['readOnly'])
        self.assertTrue(all(x['recovery_state'] is None for x in a['discoveryStates']))
        setup=sql("ALTER TABLE ouf_sem.discovery_request ADD COLUMN recovery_state text DEFAULT 'ACTIVE'; INSERT INTO ouf_sem.flyway_schema_history VALUES(12,'12',456,true);")
        self.assertEqual(setup.returncode,0,setup.stderr)
        second=sql(p.SEMANTIC_QUERY,'metadata_reader');self.assertEqual(second.returncode,0,second.stderr)
        b=json.loads(second.stdout);self.assertTrue(b['recoveryColumnPresent']);self.assertEqual(b['migrations'][-1]['version'],'12')
        self.assertTrue(all(x['recovery_state']=='ACTIVE' for x in b['discoveryStates']))
        rejected=sql("BEGIN READ ONLY; INSERT INTO ouf_sem.discovery_request VALUES('RUNNING','ACTIVE'); ROLLBACK;",'metadata_reader')
        self.assertNotEqual(rejected.returncode,0)
        self.assertIn('read-only transaction',rejected.stderr)


if __name__ == '__main__':
    unittest.main()
