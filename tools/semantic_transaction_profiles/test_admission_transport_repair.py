"""Real child processes, deadline/output limits, and retained private errors."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest

HERE = Path(__file__).resolve().parent
DRAFT = HERE.parent/'semantic_cohort_admission/cohort-draft'
sys.path.insert(0,str(DRAFT))
from tools.semantic_provider_deployment_authentication import VerificationBudget
from tools.semantic_provider_preexec import PreexecDenied
from repair_admission_transport import repair, ORIGINAL, PRODUCER, NODE, APPROVAL, PREPARER, DRIVER


class AdmissionTransportRepairTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(),0)
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TRANSACTION_TEST_ROOT',Path.cwd()))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.original = {name:(DRAFT/name).read_bytes() for name in ORIGINAL}
        self.repaired = repair(self.original)
        module = types.ModuleType('repaired_producer')
        exec(compile(self.repaired[PRODUCER],PRODUCER,'exec'),module.__dict__)
        self.producer_class = module.LocalEvidenceProducer

    def producer(self,code,budget):
        path = self.root/'child.py'; path.write_text(code)
        value = self.producer_class.__new__(self.producer_class)
        value.configured = {'source':{'path':str(path)},'configuration':{'path':str(path)}}
        value.budget = VerificationBudget(budget)
        return value

    def invoke(self,producer):
        return producer.invoke(str(Path(sys.executable).resolve()),b'{}')

    def test_silent_valid_child_can_finish_within_existing_twelve_second_budget(self):
        value = self.producer("import sys,time\nsys.stdin.buffer.read()\ntime.sleep(5.4)\nsys.stdout.buffer.write(b'completed')\n",12)
        self.assertEqual(self.invoke(value),b'completed')
        self.assertGreater(value.budget.remaining(18),0)

    def test_existing_total_deadline_still_kills_child_and_does_not_retry(self):
        marker = self.root/'attempts'
        value = self.producer("import sys,time,pathlib\nsys.stdin.buffer.read()\npathlib.Path("+repr(str(marker))+").write_bytes(b'ONE')\ntime.sleep(5.4)\n",1)
        started = time.monotonic()
        with self.assertRaisesRegex(PreexecDenied,'LOCAL_PRODUCER_DEADLINE_MISSED'):
            self.invoke(value)
        self.assertLess(time.monotonic()-started,3)
        self.assertEqual(marker.read_bytes(),b'ONE')

    def test_output_bound_and_nonzero_child_remain_denied(self):
        with self.assertRaisesRegex(PreexecDenied,'LOCAL_PRODUCER_OUTPUT_UNBOUNDED'):
            self.invoke(self.producer("import sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(b'x'*196609)\n",3))
        with self.assertRaisesRegex(PreexecDenied,'LOCAL_PRODUCER_DENIED'):
            self.invoke(self.producer("import sys\nsys.stdin.buffer.read()\nraise SystemExit(1)\n",3))

    def test_actual_cli_failures_retain_private_diagnostics_without_secret_values(self):
        for name,configuration,phase,extra in (
            (NODE,'attestation-producer.json','attestation',[]),
            (APPROVAL,'approval-producer.json','approval',[]),
            (PREPARER,'preparer.json','prepare',['--container-id','a'*64,'--bundle',str(self.root),'--runtime-root',str(self.root),'--mode','prepare']),
            (DRIVER,'driver.json','start',['--mode','start'])):
            with self.subTest(name=name):
                script = self.root/Path(name).name; script.write_bytes(self.repaired[name]); script.chmod(0o600)
                config = self.root/configuration
                config.write_text('{"private_value":"NEVER_PRINT_THIS_SECRET"}'); config.chmod(0o600)
                result = subprocess.run([sys.executable,'-I','-B',str(script),'--configuration',str(config),*extra],
                    input=b'{}',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
                self.assertEqual(result.returncode,1)
                target = config.with_name(config.stem+'-denial-'+phase+'.json')
                raw = target.read_bytes(); evidence = json.loads(raw)
                self.assertEqual(evidence['phase'],phase)
                self.assertFalse(evidence['secretValuesPrinted'])
                self.assertLessEqual(len(evidence['exceptionPoints']),4)
                self.assertEqual(target.stat().st_mode & 0o777,0o600)
                self.assertNotIn(b'NEVER_PRINT_THIS_SECRET',raw+result.stdout+result.stderr)
                self.assertNotIn(str(self.root).encode(),raw)
                # Existing evidence has one owner; a repeated failure cannot replace it.
                subprocess.run([sys.executable,'-I','-B',str(script),'--configuration',str(config),*extra],
                    input=b'{}',stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
                self.assertEqual(target.read_bytes(),raw)

    def test_repair_is_exact_and_never_reapplies(self):
        with self.assertRaisesRegex(ValueError,'ORIGINAL_ADMISSION_SOURCE_HASH_DRIFT'):
            repair(self.repaired)
        changed = dict(self.original); changed[PRODUCER] += b'\n'
        with self.assertRaisesRegex(ValueError,'ORIGINAL_ADMISSION_SOURCE_HASH_DRIFT'):
            repair(changed)
        self.assertEqual({name:hashlib.sha256(raw).hexdigest() for name,raw in self.original.items()},ORIGINAL)


if __name__ == '__main__': unittest.main()
