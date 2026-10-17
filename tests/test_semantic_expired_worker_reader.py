import copy
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-chatbot-semantic-expired-worker-20261017.py')
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)

class Reader(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/root' if os.environ.get('OUF_NATIVE_UIDS')=='1' else ROOT);self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.journal=self.root/'worker';self.journal.mkdir(mode=0o700)
        self.context=self.root/'context';self.context.mkdir(mode=0o700)
        self.session={'predecessorGrantAttempts':69,'maximumCumulativeGrantAttempts':197,
            'policy':{'max_attempts':128},'fenceBinding':{'value':{'journalPath':str(self.journal)}}}
        self.authority={'semanticTokenOnlyExecution':{'reviewHash':m.REVIEW},
            'policyTokenFiniteWorkerSession':self.session,'expiresAt':1792169238}
        self.records={'owner-session.json':self.session,
            'recovery.json':{'workerSessionHash':m.digest(self.session),'controlledPredecessorGrantAttempts':69,
                'controlledCumulativeGrantAttempts':129,'attempts':60,'publicationCount':60,
                'state':'CANCELLED','reason':'CANCELLED_BY_OWNER','unprojected':'SECRET_DO_NOT_PRINT'},
            'owner-admission.json':{'state':'BLOCKED'},
            'owner-status.json':{'state':'ACTIVE','reason':'RECOVERED','attempts':60,'publications':60,'live':True}}
        for name,value in self.records.items():self.write(self.journal/name,value)
        self.write(self.context/'authority.json',self.authority)
        (self.journal/'invocation.lock').touch(mode=0o600)
        self.rows=[]
        for name,value in [('JOURNAL',self.journal),('CONTEXT',self.context),('AUTHORITY',m.digest(self.authority))]:
            p=patch.object(m,name,value);p.start();self.addCleanup(p.stop)
        p=patch.object(m,'emit',side_effect=lambda check,**kw:self.rows.append(dict(check=check,**kw)));p.start();self.addCleanup(p.stop)
        p=patch.object(m.signal,'alarm');p.start();self.addCleanup(p.stop)
    def write(self,path,value):path.write_bytes(m.encoded(value));path.chmod(0o600)
    def test_real_private_records_preserve_counts_and_distinguish_stale_reporter(self):
        opened=[];original=m.read
        def reader(path,*a,**kw):opened.append(Path(path).name);return original(path,*a,**kw)
        with patch.object(m,'read',side_effect=reader):m.main()
        result=self.rows[-2]
        self.assertEqual(result['controlledCumulativeGrantAttempts'],129)
        self.assertEqual(result['state'],'CANCELLED');self.assertFalse(result['lastReportedStatusMatchesJournal'])
        self.assertFalse(result['liveStateProven']);self.assertTrue(result['authorityExpiredAtRead'])
        self.assertEqual(set(opened),{'authority.json',*m.NAMES})
        self.assertNotIn('SECRET',json.dumps(self.rows))
    def test_changed_counts_session_and_boolean_counters_fail_closed(self):
        for key,value in [('controlledCumulativeGrantAttempts',128),('attempts',True),('workerSessionHash','0'*64)]:
            records=copy.deepcopy(self.records);records['recovery.json'][key]=value
            with self.subTest(key=key),self.assertRaises(m.ReadDenied):m.validate(self.authority,records)
    def test_signed_journal_substitution_is_rejected(self):
        authority=copy.deepcopy(self.authority);authority['policyTokenFiniteWorkerSession']['fenceBinding']['value']['journalPath']='/other'
        with self.assertRaises(m.ReadDenied):m.validate(authority,self.records)
    def test_actual_exclusive_worker_lock_blocks_reader_without_writes(self):
        path=self.journal/'invocation.lock';fd=os.open(path,os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(m.ReadDenied,'WORKER_INVOCATION_STILL_HELD'):m.main()
        finally:os.close(fd)
        self.assertFalse(any(row['check']=='PERSISTED_WORKER'for row in self.rows))
    def test_changed_second_snapshot_is_not_reported_as_stable(self):
        original=m.read;count=0
        def read(path,*a,**kw):
            nonlocal count
            value=original(path,*a,**kw)
            if Path(path).name=='recovery.json':
                count+=1
                if count==2:value['attempts']=61
            return value
        with patch.object(m,'read',side_effect=read),self.assertRaisesRegex(m.ReadDenied,'WORKER_SNAPSHOT_DRIFT'):m.main()
        self.assertFalse(any(row['check']=='PERSISTED_WORKER'for row in self.rows))
    def test_symlink_record_rejected(self):
        p=self.journal/'owner-status.json';p.unlink();p.symlink_to(self.journal/'recovery.json')
        with self.assertRaises(m.ReadDenied):m.main()
    def test_actual_cli_reports_only_fixed_projection(self):
        source=(ROOT/'scripts/read-chatbot-semantic-expired-worker-20261017.py').read_text()
        # Replace only retained constants, never production source or a live file.
        source=source.replace('/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem',str(self.context))
        old=source.split("JOURNAL=Path('",1)[1].split("')",1)[0]
        source=source.replace(old,str(self.journal)).replace('ccac6ea4c195de2c65937fb0df581adee5a610f167cb2c125662733932312eed',m.digest(self.authority))
        path=self.root/'reader.py';path.write_text(source)
        result=subprocess.run([sys.executable,'-I','-B','-S',str(path)],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        rows=[json.loads(line)for line in result.stdout.splitlines()]
        self.assertEqual(rows[-2]['controlledCumulativeGrantAttempts'],129)
        self.assertNotIn(b'SECRET',result.stdout)

if __name__=='__main__':unittest.main()
