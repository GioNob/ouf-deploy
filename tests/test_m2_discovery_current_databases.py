"""Actual parent crypto and protected JAR/SQL sources; SQL/Engine leaves modeled."""
import copy,hashlib,sys,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]+[str(ROOT/'tools'/p) for p in
    ('semantic_application_cutover','semantic_frame_compiler','semantic_database_cutover','semantic_policy_token_owner',
     'semantic_lease_recovery','semantic_transaction_profiles','semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_current_cohort as cohort
from tools.m2_discovery_installation_profile import current_databases as m


def artifacts(root):
    rows=[]
    for index,module in enumerate(m.MODULES,1):
        if module=='mcp':
            base=root/'mcp-source';directory=base/'internal/adapter/postgres/migrations';directory.mkdir(mode=0o700,parents=True)
            path=directory/'001_fixture.sql';path.write_bytes(b'SELECT 1;\n');path.chmod(0o600)
            artifact={'format':'MCP_SQL','root':str(base),'files':[{'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'maximumBytes':1048576}]}
            migrations=m.mcp_migrations(base)
        else:
            path=root/(module+'.jar')
            with zipfile.ZipFile(path,'w') as archive:archive.writestr('BOOT-INF/classes/db/migration/V1__fixture.sql',b'SELECT 1;\n')
            path.chmod(0o600)
            artifact={'format':'JAR','root':str(path),'files':[{'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'maximumBytes':1048576}]}
            migrations=m.java_migrations(path)
        rows.append({'module':module,'database':'fixture_'+module,'user':'fixture_'+module,'databaseOid':index,
            'expectedMigrations':migrations,'artifact':artifact})
    return rows


class DatabaseAdmission(unittest.TestCase):
    setUp=cohort.Cohort.setUp
    native=cohort.Cohort.native
    write=cohort.Cohort.write
    binding=cohort.Cohort.binding
    sign=cohort.Cohort.sign
    authority=cohort.Cohort.authority
    runtime_fixture=cohort.Cohort.owner

    def prepared(self):
        runtime,_,_=self.runtime_fixture();inputs={k:runtime.inputs[k] for k in
            ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')}
        docker=Path('/usr/bin/true').resolve()
        inputs.update(schema=m.SCHEMA,postgresRuntimeBinding=runtime.inputs['peers']['postgres']['runtimeBinding'],
            dockerBinding={'path':str(docker),'sha256':hashlib.sha256(docker.read_bytes()).hexdigest()},modules=artifacts(self.root))
        extended=m.bind_database_inputs(runtime.inputs,inputs)
        review=copy.deepcopy(self.review);review['components']['cohortInstallation']['currentAdmission']=copy.deepcopy(
            review['components']['cohortInstallation']['currentAdmission']['requirements'])
        self.review=cohort.m.bind_runtime_review(review,extended);parent=self.authority(seconds=300)
        runtime.selected.images.parent=parent;runtime.selected.images.component=self.review['components']['cohortInstallation']
        runtime.selected.images.engine.path='/run/fixture.sock'
        runtime.selected.guard=lambda:parent.guard('cohortInstallation',runtime.selected.images.component)
        runtime=cohort.m.CurrentCohortRuntime(runtime.selected,extended)
        p=patch.object(m.shutil,'which',return_value=str(docker));p.start();self.addCleanup(p.stop)
        p=patch.dict(m.os.environ,{'DOCKER_HOST':'unix:///run/fixture.sock'});p.start();self.addCleanup(p.stop)
        return m.CurrentCohortDatabases(runtime,inputs),parent

    def sql(self,owner,*,drift=None):
        rows={r['database']:r for r in owner.inputs['modules']};calls=[]
        class Channel:
            def __init__(channel,cid,user,database,application):
                channel.row=rows[database];channel.first=True
                calls.append(('open',cid,user,database,application))
            def query(channel,expression,statement='',timeout=15):
                calls.append(('query',expression,statement,timeout));row=channel.row
                if channel.first:
                    channel.first=False
                    value={'name':row['database'],'oid':row['databaseOid'],'allowConnections':True,'prepared':0,'readOnly':True}
                    if drift:drift(value)
                    return value
                return copy.deepcopy(row['expectedMigrations'])
            def close(channel):calls.append(('close',))
        return Channel,calls

    def test_parent_binds_database_inputs_and_reviewed_artifact_bytes(self):
        owner,_=self.prepared();proof,pins=owner.sources(m.ObservationBudget(30))
        self.assertEqual(set(proof),set(m.MODULES));self.assertEqual(len(pins),4)
        self.assertEqual(owner.runtime.inputs['additionalInputsHashes']['databases'],owner.input_hash)
        original=copy.deepcopy(owner.inputs);owner.inputs['modules'][0]['databaseOid']+=1
        with self.assertRaises(ValueError):owner.guard()
        self.assertNotEqual(m.validate(original),m.validate(owner.inputs))

    def test_all_four_queries_use_read_only_transactions_and_exact_scoped_principals(self):
        owner,_=self.prepared();Channel,calls=self.sql(owner)
        with patch.object(m,'Psql',Channel):
            for row in owner.inputs['modules']:self.assertEqual(owner.database(row,m.ObservationBudget(30))['migrationCount'],1)
        self.assertEqual(len([c for c in calls if c[0]=='open']),4)
        queries=[c for c in calls if c[0]=='query'];self.assertEqual(len(queries),8)
        self.assertEqual([c[2] for c in queries][::2],["BEGIN READ ONLY; SET LOCAL statement_timeout='5s';"]*4)
        self.assertTrue(all(0<c[3]<=5 for c in queries))
        self.assertTrue(all(c[1].startswith('SELECT ') for c in queries))

    def test_database_identity_prepared_transaction_and_read_only_drift_deny(self):
        owner,_=self.prepared()
        for key,value in [('oid',99),('allowConnections',False),('prepared',1),('prepared',False),('readOnly',False)]:
            Channel,_=self.sql(owner,drift=lambda v,k=key,x=value:v.update({k:x}))
            with self.subTest(key=key,value=value),patch.object(m,'Psql',Channel),self.assertRaisesRegex(ValueError,'PACKAGED_MIGRATIONS_CHANGED'):
                owner.database(owner.inputs['modules'][0],m.ObservationBudget(30))

    def test_artifact_custody_and_expected_history_cannot_be_substituted(self):
        owner,_=self.prepared();path=Path(owner.inputs['modules'][0]['artifact']['root']);original=path.read_bytes();path.write_bytes(b'unreviewed')
        with self.assertRaises(ValueError):owner.sources(m.ObservationBudget(30))
        row=owner.inputs['modules'][-1];extra=Path(row['artifact']['root'])/'internal/adapter/postgres/migrations/002_extra.sql'
        extra.write_bytes(b'SELECT 2;\n');extra.chmod(0o600)
        path.write_bytes(original)
        with self.assertRaisesRegex(ValueError,'EXACT_CURRENT_MCP_MIGRATION_DIRECTORY'):owner.sources(m.ObservationBudget(30))

    def test_missing_module_or_duplicate_database_is_denied_before_sql(self):
        owner,_=self.prepared();bad=copy.deepcopy(owner.inputs);bad['modules'].pop()
        with self.assertRaises(ValueError):m.validate(bad)
        bad=copy.deepcopy(owner.inputs);bad['modules'][1]['database']=bad['modules'][0]['database']
        with self.assertRaises(ValueError):m.validate(bad)

    def test_expired_budget_opens_no_database_session(self):
        owner,_=self.prepared();budget=m.ObservationBudget(1);budget.until=0
        with patch.object(m,'Psql') as channel,self.assertRaises(ValueError):owner.database(owner.inputs['modules'][0],budget)
        channel.assert_not_called()

    def test_unset_host_cannot_select_a_different_default_engine(self):
        owner,_=self.prepared()
        with patch.dict(m.os.environ,{},clear=True),self.assertRaisesRegex(ValueError,'SAME_LOCAL_ENGINE'):
            owner.guard()

if __name__=='__main__':unittest.main()
