"""Fixed target reader; real private files, explicit engine/DB test doubles."""
import contextlib,copy,hashlib,importlib.util,io,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('mcp_backup_reader',ROOT/'scripts/read-chatbot-mcp-backup-preflight-20261016.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class Preflight(unittest.TestCase):
    def facts(self):
        return dict(databaseOid=42,databaseMatched=True,roleMatched=True,superuser=True,readOnly=True,
            applicationMissingTableSelect=1,applicationMissingSequenceSelect=0,applicationIncidentSelect=False)
    def prepared(self):
        return {'databasePlan':{'postgresRuntimeBinding':{'containerId':'a'*64},
            'mcpAuditRoleAdministration':{'admin':'fixture_admin'}},'engine':{'socketPath':'/run/docker.sock'}}
    def invoke_preflight(self,facts=None,selector='fixture_admin'):
        p=self.prepared();binding={'user':'fixture_app','database':'fixture_db','databaseOid':42}
        with patch.object(r,'inspect',return_value={'Id':'a'*64,'Config':{'Env':['POSTGRES_USER='+selector]}}),\
            patch.object(r,'bounded',return_value=(0,r.encoded(self.facts()if facts is None else facts),b'',200))as run:
            result=r.backup_reader_preflight('/docker',p,'/private',binding)
        return result,run
    def test_read_only_admin_selector_and_closed_output(self):
        result,run=self.invoke_preflight();self.assertEqual(result,('fixture_admin',self.facts()))
        argv=run.call_args.args[0]
        self.assertIn('PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000',argv)
        self.assertNotIn('GRANT',argv[-1]);self.assertNotIn('ALTER',argv[-1])
        self.assertNotIn('pg_dump',argv)
    def test_wrong_selector_nonadmin_and_unexpected_payload_are_denied(self):
        with self.assertRaises(r.ReadDenied):self.invoke_preflight(selector='other')
        for key,value in [('superuser',False),('roleMatched',False),('databaseOid',43),('readOnly',False),
                          ('applicationMissingTableSelect','secret'),('extra','secret')]:
            facts=self.facts();facts[key]=value
            with self.assertRaises(r.ReadDenied):self.invoke_preflight(facts)
    def test_metadata_only_emits_allowlisted_values(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            p=Path(d)/'record';p.write_bytes(r.encoded({'state':'CANCELLED','attempts':1,
                'controlledCumulativeGrantAttempts':5,'private':'SECRET'}));p.chmod(0o600)
            out=io.StringIO()
            with contextlib.redirect_stdout(out):r.metadata('WORKER',p)
            value=json.loads(out.getvalue());self.assertEqual(value['controlledCumulativeGrantAttempts'],5)
            self.assertNotIn('SECRET',out.getvalue())
            p.write_bytes(r.encoded({'state':'SECRET WITH SPACE'}))
            with self.assertRaises(r.ReadDenied):r.metadata('WORKER',p)
    def test_fixed_target_checkpoint_and_no_automatic_rerun(self):
        self.assertEqual(r.DATABASE_JOURNAL,'2c55b26774660d1e56d6855b5425c18b2cc26a6ab09da463fe324229b744094c')
        out=io.StringIO()
        with contextlib.redirect_stdout(out):r.emit('TEST')
        value=json.loads(out.getvalue());self.assertFalse(value['automaticRetry']);self.assertFalse(value['budgetReset'])

    def test_recovery_checkpoint_collects_all_hashes_and_native_state_without_secrets(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            root=Path(d)
            def write(path,value):
                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                path.write_bytes(r.encoded(value));path.chmod(0o600)
            paths={k:str(root/k)for k in ('transition','node')}
            write(root/'transition/recovery.json',{'state':'READY','nextPhase':10,'effects':[
                {'phase':'VERIFY_APPLICATION','state':'APPLIED','intentHash':'a'*64,
                 'authorityEvidenceHash':'b'*64,'nativeEvidenceHash':'c'*64}],'private':'SECRET'})
            for name in ('frame-policy.json','paused-acceptance.json','attestation-issuance-claim.json'):
                write(root/'node'/name,{'private':'SECRET'})
            for name in ('recovery.json','owner-session.json','owner-admission.json','owner-first-grant.json'):
                write(root/'owner'/name,{'state':'CANCELLED','controlledCumulativeGrantAttempts':5,'private':'SECRET'})
            directories={k:str(root/k)for k in ('containers','authorization','gateway')}
            for path in directories.values():write(Path(path)/'recovery.json',{'effects':[],'private':'SECRET'})
            review={'scopes':{'policyTokenOwnerInstallation':{'journalPath':str(root/'owner')},
                'finiteActionProcess':{'directoryPlan':directories}}}
            native={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Status':'running','Running':True,'Paused':False,'Pid':123,'StartedAt':'start'},
                'RestartCount':0,'Config':{},'HostConfig':{},'Mounts':[],'NetworkSettings':{}}
            out=io.StringIO()
            with patch.object(r,'inspect',return_value=native),contextlib.redirect_stdout(out):
                r.recovery_checkpoint(review,{'registry':{'directoryPlan':paths},'engine':{}})
            self.assertNotIn('SECRET',out.getvalue());rows=[json.loads(s)for s in out.getvalue().splitlines()]
            self.assertEqual(rows[-1]['check'],'REGISTRY_NATIVE');self.assertTrue(rows[-1]['running'])
            self.assertEqual(next(x for x in rows if x['check']=='WORKER')['controlledCumulativeGrantAttempts'],5)

    def complete(self,wrong_checkpoint=False,drift=False):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            root=Path(d);root.chmod(0o700)
            def write(path,value):
                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                path.write_bytes(r.encoded(value));path.chmod(0o600);return r.digest(value)
            plan=self.prepared()['databasePlan'];plan['modules']=[{'module':m,'database':'db_'+m,'user':'app_'+m,
                'databaseOid':42+i,'maximumArchiveBytes':1048576}for i,m in enumerate(r.MODULES)]
            p={'databasePlan':plan,'cohortPlan':{'databasePlanHash':r.digest(plan)},'engine':{}}
            declaration={'sourceCommit':r.SOURCE};bundle={'prepared':p,'declaration':declaration,'sources':{'unused':'SECRET'}}
            bundle_hash=write(root/'bundle.json',bundle)
            process={'unit':r.UNIT,'authorityDirectory':str(root),'bundle':{'path':str(root/'bundle.json'),'sha256':bundle_hash},
                'directoryPlan':{k:str(root/k)for k in ('databases','backups')}}
            review={'scopes':{'finiteActionProcess':process},'sourceClosure':{'declaration':declaration,
                'executables':{'docker':{},'systemctl':{}}},'privateInputHashes':{'preparedInputs':r.digest(p)}}
            rh=write(root/'review.json',review);ah=write(root/'authority.json',review['scopes'])
            write(root/'delivery-status.json',{'authorityHash':ah,'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'COHORT_DATABASE_DUMP_FAILED'})
            journal={'schema':'ouf.chatbot-cohort-database-journal.v1','planHash':r.digest(plan),'authorityHash':ah,
                'budgetReset':False,'restorePerformed':False,'mcpMigration':None,'mcpAuditRole':None,'backups':{}}
            (root/'backups').mkdir(mode=0o700)
            originals={}
            for row in plan['modules']:
                module=row['module'];path=root/'backups'/(module+'.dump')
                raw=b'' if module=='mcp' else b'PGDMP'+b'x'*200
                path.write_bytes(raw);path.chmod(0o600);originals[path]=raw
                entry={'state':'CLAIMED'if module=='mcp' else'COMPLETE','scopeHash':r.digest(row)}
                if module!='mcp':entry.update(archiveSha256=hashlib.sha256(raw).hexdigest(),archiveBytes=len(raw),payloadParsed=True)
                journal['backups'][module]=entry
            jh=write(root/'databases/recovery.json',journal);out=io.StringIO()
            def probe(*args):
                self.assertEqual(args[-1]['user'],'fixture_admin')
                if drift:(root/'backups/mcp.dump').write_bytes(b'x')
                return {'classification':'DUMP_PROBE_SUCCEEDED','backupAccepted':False}
            with patch.object(r,'CONTEXT',root),patch.object(r,'REVIEW',rh),patch.object(r,'AUTHORITY',ah),\
                patch.object(r,'DATABASE_JOURNAL','0'*64 if wrong_checkpoint else jh),\
                patch.object(r,'stopped'),patch.object(r,'native_guard'),patch.object(r,'recovery_checkpoint')as checkpoint,\
                patch.object(r,'executable',return_value='/docker'),patch.object(r,'dump_probe',side_effect=probe)as dump,\
                patch.object(r,'backup_reader_preflight',return_value=('fixture_admin',self.facts()))as preflight,\
                patch.object(r.sys,'flags',isolated=True),contextlib.redirect_stdout(out):
                if wrong_checkpoint or drift:
                    with self.assertRaises(r.ReadDenied):r.main()
                else:r.main()
            if wrong_checkpoint:dump.assert_not_called();preflight.assert_not_called();checkpoint.assert_not_called()
            else:self.assertEqual(dump.call_count,1);self.assertEqual(checkpoint.call_count,1)
            self.assertEqual(r.read(root/'databases/recovery.json'),journal)
            self.assertNotIn('SECRET',out.getvalue())
            if not drift:
                for path,raw in originals.items():self.assertEqual(path.read_bytes(),raw)
            rows=[json.loads(s)for s in out.getvalue().splitlines()]
            self.assertEqual(rows[-1]['check']=='END',not(wrong_checkpoint or drift))
    def test_complete_entry_selects_admin_without_modifying_old_journal_or_archives(self):self.complete()
    def test_wrong_checkpoint_stops_before_admin_probe(self):self.complete(wrong_checkpoint=True)
    def test_archive_drift_blocks_completion(self):self.complete(drift=True)

if __name__=='__main__':unittest.main()
