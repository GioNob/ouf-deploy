"""Reader qualification; Docker and PostgreSQL are explicit test doubles.

Actual private files and subprocess pipes are exercised. No VPS acceptance.
"""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('backup_reader',ROOT/'scripts/read-chatbot-backup-failure-20261015.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class BackupReadback(unittest.TestCase):
    def plan(self):
        return {'postgresRuntimeBinding':{'containerId':'a'*64},'modules':[
            {'module':m,'database':'db_'+m,'user':'app_'+m,'maximumArchiveBytes':1048576}for m in r.MODULES]}

    def journal(self,plan,index=0):
        return {'schema':'ouf.chatbot-cohort-database-journal.v1','planHash':r.digest(plan),
            'authorityHash':r.AUTHORITY,'budgetReset':False,'restorePerformed':False,
            'mcpMigration':None,'mcpAuditRole':None,'version':2,'backups':{
                row['module']:{'state':'CLAIMED' if i==index else 'COMPLETE','scopeHash':r.digest(row)}
                for i,row in enumerate(plan['modules'][:index+1])}}

    def test_closed_error_classification_never_copies_private_values(self):
        cases=[(b'pg_dump: error: query failed: ERROR: permission denied for table PRIVATE',1,'INSUFFICIENT_PRIVILEGE'),
            (b'query would be affected by row-level security policy for table PRIVATE',1,'ROW_LEVEL_SECURITY'),
            (b'aborting because of server version mismatch',1,'DUMP_VERSION_MISMATCH'),
            (b'PRIVATE=token',1,'UNCLASSIFIED_DUMP_FAILURE'),
            (b'',137,'PROBE_TIME_BOUND_EXHAUSTED'),(b'',0,'DUMP_PROBE_SUCCEEDED')]
        for raw,code,expected in cases:self.assertEqual(r.classify(raw,code),expected)

    def test_prefix_selects_only_the_claimed_database(self):
        plan=self.plan()
        for i in range(4):self.assertEqual(r.failed_binding(plan,self.journal(plan,i)),plan['modules'][i])

    def test_wrong_authority_scope_migration_and_nonprefix_fail_closed(self):
        plan=self.plan();good=self.journal(plan)
        variants=[]
        for key,value in [('authorityHash','b'*64),('planHash','c'*64),('budgetReset',True),
            ('restorePerformed',True),('mcpMigration',{'state':'CLAIMED'}),('mcpAuditRole',{})]:
            row=copy.deepcopy(good);row[key]=value;variants.append(row)
        row=copy.deepcopy(good);row['backups']['udp']['scopeHash']='d'*64;variants.append(row)
        row=copy.deepcopy(good);row['backups']['udp']['state']='COMPLETE';variants.append(row)
        row=copy.deepcopy(good);row['backups']['mcp']={'state':'COMPLETE'};variants.append(row)
        for row in variants:
            with self.assertRaises(r.ReadDenied):r.failed_binding(plan,row)

    def test_dump_command_has_inner_deadline_no_restore_and_discards_output(self):
        plan=self.plan()
        with patch.object(r,'bounded',return_value=(1,b'',b'permission denied for table PRIVATE',0))as run:
            result=r.dump_probe('/usr/bin/docker',{'socketPath':'/run/docker.sock'},'/private/config',plan,plan['modules'][0])
        argv=run.call_args.args[0]
        self.assertEqual(argv[argv.index('timeout'):argv.index('pg_dump')],['timeout','-s','KILL','75'])
        self.assertTrue(run.call_args.kwargs['discard']);self.assertEqual(run.call_args.kwargs['seconds'],85)
        self.assertNotIn('pg_restore',argv);self.assertFalse(result['backupAccepted'])
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_real_subprocess_drains_both_pipes_and_drops_dump_bytes(self):
        code,out,err,count=r.bounded([sys.executable,'-c',
            'import sys;sys.stderr.write("e"*60000);sys.stderr.flush();sys.stdout.write("d"*100000)'],discard=True)
        self.assertEqual((code,out,count),(0,b'',100000));self.assertEqual(len(err),60000)

    def test_real_subprocess_output_error_and_time_bounds(self):
        for script,kw in [('print("x"*1000)',{'maximum':100}),
            ('import sys;sys.stderr.write("x"*100000)',{}),
            ('import time;time.sleep(10)',{'seconds':0.1})]:
            with self.assertRaises(r.ReadDenied):r.bounded([sys.executable,'-c',script],**kw)

    def test_real_archive_preserves_empty_and_rejects_links_and_modes(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            p=Path(d)/'udp.dump';p.touch(mode=0o600)
            self.assertEqual(r.archive(p,1000)['bytes'],0)
            p.write_bytes(b'PGDMP'+b'x'*200);self.assertTrue(r.archive(p,1000)['customFormatHeader'])
            with self.assertRaises(r.ReadDenied):r.archive(p,100)
            p.chmod(0o644)
            with self.assertRaises(r.ReadDenied):r.archive(p,1000)
            p.chmod(0o600);q=Path(d)/'link';q.symlink_to(p)
            with self.assertRaises(r.ReadDenied):r.archive(q,1000)
            q.unlink();os.link(p,q)
            with self.assertRaises(r.ReadDenied):r.archive(p,1000)

    def test_duplicate_json_and_untrusted_modes_denied(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            p=Path(d)/'record';p.write_text('{"a":1,"a":2}');p.chmod(0o600)
            with self.assertRaises(r.ReadDenied):r.read(p)
            p.write_text('{"a":1}');p.chmod(0o644)
            with self.assertRaises(r.ReadDenied):r.read(p)

    def test_pg_generation_and_running_producers_deny_probe(self):
        pg={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Pid':123,'StartedAt':'start','Running':True,'Paused':False},
            'Config':{},'HostConfig':{},'Mounts':[],'NetworkSettings':{}}
        prepared={'databasePlan':{'postgresRuntimeBinding':r.runtime_pin(pg)},'engine':{},'cohortPlan':{'replacements':[]}}
        with patch.object(r,'inspect',return_value=pg):r.native_guard(prepared)
        pg['State']['Pid']=124
        with patch.object(r,'inspect',return_value=pg),self.assertRaises(r.ReadDenied):r.native_guard(prepared)
        pg['State']['Pid']=123
        prepared['cohortPlan']['replacements']=[{'oldRuntimeBinding':r.runtime_pin(pg),'oldHostConfig':{}}]
        with patch.object(r,'inspect',return_value=pg),self.assertRaises(r.ReadDenied):r.native_guard(prepared)

    def test_running_delivery_denies(self):
        with patch.object(r,'executable',return_value='/systemctl'),patch.object(r,'bounded',
            return_value=(0,b'ActiveState=active\nMainPID=12\nJob=\n',b'',0)),self.assertRaises(r.ReadDenied):r.stopped({})

    def complete(self,drift=False,bad_status=False):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            context=Path(d);context.chmod(0o700)
            def write(p,value):
                p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                p.write_bytes(r.encoded(value));p.chmod(0o600);return r.digest(value)
            plan=self.plan();prepared={'databasePlan':plan,'cohortPlan':{'databasePlanHash':r.digest(plan)},'engine':{}}
            declaration={'sourceCommit':r.SOURCE}
            bundle={'prepared':prepared,'declaration':declaration,'sources':{'unused':'PRIVATE_SOURCE_MUST_NOT_EXECUTE'}}
            bundle_path=context/'bundle.json';bundle_hash=write(bundle_path,bundle)
            process={'unit':r.UNIT,'authorityDirectory':str(context),'bundle':{'path':str(bundle_path),'sha256':bundle_hash},
                'directoryPlan':{k:str(context/k)for k in ('databases','backups')}}
            review={'scopes':{'finiteActionProcess':process},'sourceClosure':{'declaration':declaration,
                'executables':{'docker':{},'systemctl':{}}},'privateInputHashes':{'preparedInputs':r.digest(prepared)}}
            review_hash=write(context/'review.json',review);auth_hash=write(context/'authority.json',review['scopes'])
            status={'authorityHash':auth_hash,'phase':'PAUSED_REQUIRES_RECONCILIATION',
                'reason':'OTHER' if bad_status else 'COHORT_DATABASE_DUMP_FAILED'}
            write(context/'delivery-status.json',status)
            journal=self.journal(plan);journal['authorityHash']=auth_hash;write(context/'databases/recovery.json',journal)
            archive=context/'backups/udp.dump';archive.parent.mkdir(mode=0o700);archive.touch(mode=0o600)
            original=archive.read_bytes();out=io.StringIO()
            def probe(*args):
                if drift:archive.write_bytes(b'changed')
                return {'classification':'INSUFFICIENT_PRIVILEGE','backupAccepted':False}
            with patch.object(r,'CONTEXT',context),patch.object(r,'REVIEW',review_hash),patch.object(r,'AUTHORITY',auth_hash),\
                patch.object(r,'stopped')as stopped,patch.object(r,'native_guard')as guard,\
                patch.object(r,'executable',return_value='/docker'),patch.object(r,'dump_probe',side_effect=probe)as dump,\
                patch.object(r.sys,'flags',isolated=True),contextlib.redirect_stdout(out):
                if drift or bad_status:
                    with self.assertRaises(r.ReadDenied):r.main()
                else:r.main()
            if bad_status:dump.assert_not_called();guard.assert_not_called()
            else:self.assertEqual(dump.call_count,1)
            if not drift:self.assertEqual(archive.read_bytes(),original)
            self.assertEqual(r.read(context/'databases/recovery.json'),journal)
            self.assertNotIn('PRIVATE',out.getvalue())
            rows=[json.loads(line)for line in out.getvalue().splitlines()]
            if not(drift or bad_status):
                self.assertEqual(rows[-1]['check'],'END');self.assertFalse(rows[-1]['reconciliationPerformed'])
                self.assertTrue(rows[-1]['retainedBackupsAndJournalUnchanged'])
            else:self.assertNotEqual(rows[-1]['check'],'END')

    def test_complete_main_preserves_checkpoint_and_never_executes_bundle_sources(self):self.complete()
    def test_changed_archive_does_not_report_success(self):self.complete(drift=True)
    def test_wrong_failure_denies_before_probe(self):self.complete(bad_status=True)

if __name__=='__main__':unittest.main()
