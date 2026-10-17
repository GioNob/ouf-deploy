"""Local thread serialization retains the nonblocking cross-process fence."""
import json,subprocess,sys,tempfile,threading,unittest
from pathlib import Path
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.csv_materialization_recovery.journal import synchronize

class ConcurrentJournal(unittest.TestCase):
 def test_observer_waits_for_local_transaction_without_false_authority_failure(self):
  with tempfile.TemporaryDirectory() as directory:
   journal=synchronize(Journal(Path(directory).resolve()));journal.initialize({'state':'NEW','attempts':0})
   started=threading.Event();done=threading.Event();results=[]
   def observe():
    started.set()
    try:results.append(journal.read())
    except Exception as error:results.append(type(error).__name__)
    finally:done.set()
   with journal.transaction():
    thread=threading.Thread(target=observe);thread.start()
    self.assertTrue(started.wait(2));self.assertFalse(done.wait(.1))
   thread.join(2);self.assertFalse(thread.is_alive())
   self.assertEqual(results,[{'state':'NEW','attempts':0}])

 def test_other_process_is_still_denied_without_reset_or_write(self):
  with tempfile.TemporaryDirectory() as directory:
   journal=synchronize(Journal(Path(directory).resolve()));journal.initialize({'state':'NEW','attempts':0})
   before=journal.record.read_bytes()
   script="""from pathlib import Path
import sys
from tools.semantic_lease_recovery.recovery_journal import Journal
try: Journal(Path(sys.argv[1])).read()
except BlockingIOError: print('CROSS_PROCESS_FENCE_PRESERVED')
else: raise AssertionError('SECOND_PROCESS_MUST_NOT_ENTER')
"""
   with journal.transaction():
    result=subprocess.run([sys.executable,'-B','-c',script,directory],capture_output=True,timeout=5)
   self.assertEqual(result.returncode,0,result.stderr.decode())
   self.assertEqual(result.stdout,b'CROSS_PROCESS_FENCE_PRESERVED\n')
   self.assertEqual(journal.record.read_bytes(),before)
