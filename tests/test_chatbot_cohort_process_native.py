"""Disposable real systemd unit: retained public failure after detached terminal."""
import json,os,subprocess,time,unittest,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

class PublicChildJournal(unittest.TestCase):
    def test_detached_real_bootstrap_failure_is_in_journal_without_private_exception_body(self):
        self.assertEqual(os.geteuid(),0)
        unit='ouf-public-child-fixture-'+uuid.uuid4().hex+'.service'
        private_context=str(ROOT/('PRIVATE_EXCEPTION_PATH_'+uuid.uuid4().hex))
        argv=['systemd-run','--quiet','--wait','--collect','--unit='+unit,
            '--description=OUF disposable public-journal fixture','--property=Type=exec',
            '--property=Restart=no','--property=RuntimeMaxSec=30',
            '--property=StandardOutput=journal','--property=StandardError=journal',
            '--','/usr/bin/python3','-I','-B','-S',str(ROOT/'tools/chatbot_file_cohort/child_bootstrap.py'),
            private_context+'/missing-bundle.json',private_context]
        try:
            result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=45)
            self.assertNotEqual(result.returncode,0)
            output=b''
            for _ in range(10):
                read=subprocess.run(['journalctl','--unit='+unit,'--no-pager','--output=cat'],
                    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
                output=read.stdout
                if b'ouf.chatbot-file-cohort-child-exit.v1' in output:break
                time.sleep(0.2)
            records=[json.loads(line) for line in output.decode().splitlines() if line.startswith('{')]
            self.assertEqual(len(records),1,output.decode())
            self.assertEqual(records[0]['phase'],'FINITE_CHILD_FAILED')
            self.assertEqual(records[0]['exceptionType'],'FileNotFoundError')
            self.assertFalse(records[0]['privateDiagnosticPrinted'])
            self.assertNotIn(b'PRIVATE_EXCEPTION_PATH_',output);self.assertNotIn(b'Traceback',output)
        finally:
            subprocess.run(['systemctl','stop',unit],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            subprocess.run(['systemctl','reset-failed',unit],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)

if __name__=='__main__':unittest.main()
