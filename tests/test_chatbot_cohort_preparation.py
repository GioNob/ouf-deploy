import copy
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

import test_chatbot_cohort_containers as fixture
from tools.chatbot_file_cohort import preparation as q, plan as p


class CohortPreparation(unittest.TestCase):
    def inputs(self,module):
        app,_,_ = fixture.container_fixture(module)
        pg = copy.deepcopy(app); pg['Name'] = '/ouf-postgres'; pg['Config']['Hostname'] = 'fixture-postgres'
        pg['NetworkSettings']['Networks']['ouf-backend'].update(Aliases=['ouf-postgres'],IPAddress='172.20.0.2')
        if module == 'mcp':
            app['Config']['Env'] = ['MCP_DATABASE_URL=postgresql://ouf_mcp:private-value@ouf-postgres:5432/ouf_mcp?sslmode=disable']
        else:
            prefix = q.DB_PREFIX[module]
            app['Config']['Env'] = [prefix+'_DB_URL=jdbc:postgresql://ouf-postgres:5432/ouf_'+module,
                prefix+'_DB_USER=ouf_'+module,prefix+'_DB_PASSWORD=private-value']
        return app,pg

    def test_all_selected_databases_bound_to_exact_postgres_without_returning_passwords(self):
        for module in p.MODULES:
            app,pg = self.inputs(module)
            self.assertEqual(q.database_binding(module,app,pg),{'database':'ouf_'+module,'user':'ouf_'+module})
            app['Config']['Env'][0] = app['Config']['Env'][0].replace('ouf-postgres','another-host')
            with self.assertRaisesRegex(p.PlanDenied,'EXACT_CURRENT_POSTGRES'):q.database_binding(module,app,pg)

    def test_java_command_and_config_overrides_cannot_silently_select_another_database(self):
        app,pg = self.inputs('onboarding')
        for key,value in [('SPRING_DATASOURCE_URL','jdbc:postgresql://other:5432/other'),
            ('JAVA_TOOL_OPTIONS','-Dspring.datasource.url=jdbc:postgresql://other/other'),
            ('SPRING_APPLICATION_JSON','{"spring":{"datasource":{}}}')]:
            with self.subTest(key=key):
                modified = copy.deepcopy(app); modified['Config']['Env'].append(key+'='+value)
                with self.assertRaises(p.PlanDenied):q.database_binding('onboarding',modified,pg)
        app['Config']['Cmd'] = ['--spring.datasource.url=jdbc:postgresql://other/other']
        with self.assertRaisesRegex(p.PlanDenied,'COMMAND_DATASOURCE'):q.database_binding('onboarding',app,pg)

    def test_migrations_use_package_bytes_and_reject_drift(self):
        with tempfile.TemporaryDirectory(dir=fixture.ROOT) as tmp:
            root = Path(tmp); root.chmod(0o700)
            for module in ('onboarding','mcp'):
                directory = root/module; directory.mkdir(mode=0o700)
                if module == 'mcp':
                    path = directory/'source.tar'
                    with tarfile.open(path,'w') as archive:
                        raw = b'SELECT 1;\n'; row = tarfile.TarInfo('internal/adapter/postgres/migrations/001_base.sql')
                        row.size = len(raw); archive.addfile(row,io.BytesIO(raw))
                    expected = [{'version':1,'checksum':hashlib.sha256(raw).hexdigest()}]
                else:
                    path = directory/'application.jar'
                    with zipfile.ZipFile(path,'w') as archive:archive.writestr('BOOT-INF/classes/db/migration/V1__base.sql',b'SELECT 1;')
                    expected = [{'version':'1','script':'V1__base.sql','type':'SQL','checksum':78787420,'success':True}]
                record = {'module':module,'files':{path.name:hashlib.sha256(path.read_bytes()).hexdigest()}}
                self.assertEqual(q.packaged_migrations(root,record),expected)
                path.write_bytes(path.read_bytes()+b'drift')
                with self.assertRaisesRegex(p.PlanDenied,'BYTES_CHANGED'):q.packaged_migrations(root,record)


if __name__ == '__main__':unittest.main()
