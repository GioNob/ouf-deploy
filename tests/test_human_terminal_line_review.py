"""Real canonical PTY: visible editing, bad-paste recovery, exact Enter only."""
import importlib.util
import os
from pathlib import Path
import termios
import threading
import time
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('line_review',ROOT/'tools/human_terminal_line_review.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
HASH='a'*64
LINE=('APPROVO '+HASH).encode()
class LineTests(unittest.TestCase):
    def run_reader(self,parts,expire=.65):
        master,slave=os.openpty();before=termios.tcgetattr(slave)
        out=[];states=[];result=[];deadline=time.monotonic()+expire
        def guard():
            if time.monotonic()>=deadline:raise TimeoutError('CI_EXPIRED')
        def run():
            try:m.read_exact(HASH,guard,emit=out.append,progress=states.append,fd=slave,heartbeat=.1)
            except BaseException as e:result.append(e)
            else:result.append(True)
        t=threading.Thread(target=run);t.start()
        try:
            while not states:time.sleep(.001)
            self.assertTrue(termios.tcgetattr(slave)[3]&termios.ECHO)
            self.assertTrue(termios.tcgetattr(slave)[3]&termios.ICANON)
            for delay,data in parts:time.sleep(delay);os.write(master,data)
            t.join(expire+2);self.assertFalse(t.is_alive());self.assertEqual(termios.tcgetattr(slave),before)
            return result[0],out,states
        finally:os.close(master);os.close(slave)
    def test_phone_endings(self):
        for ending in (b'\n',b'\r',b'\r\n'):
            with self.subTest(ending=ending):self.assertIs(self.run_reader([(0,LINE+ending)])[0],True)
    def test_duplicate_paste_does_not_close_before_enter(self):
        result,_,states=self.run_reader([(0,LINE+LINE),(.05,b'\x15'),(.05,LINE+b'\r')])
        self.assertIs(result,True);self.assertEqual(states[-1]['rejectedLines'],0)
    def test_bad_complete_line_then_correction(self):
        result,out,states=self.run_reader([(0,LINE+LINE+b'\n'),(.05,LINE+b'\n')])
        self.assertIs(result,True);self.assertEqual(states[-1]['rejectedLines'],1)
        self.assertTrue(any('Riga non valida' in x for x in out))
    def test_backspace_native_editing(self):
        self.assertIs(self.run_reader([(0,LINE[:-1]+b'b\x7fa\n')])[0],True)
    def test_fragmented_paste(self):
        self.assertIs(self.run_reader([(0,LINE[:8]),(.03,LINE[8:]),(.03,b'\r')])[0],True)
    def test_only_wrong_hash_never_approves(self):
        result,_,states=self.run_reader([(0,b'APPROVO '+b'b'*64+b'\n')],.25)
        self.assertIsInstance(result,TimeoutError);self.assertEqual(states[-1]['rejectedLines'],1)
    def test_no_enter_is_visible_and_not_approved(self):
        result,out,states=self.run_reader([(0,LINE)],.25)
        self.assertIsInstance(result,TimeoutError);self.assertFalse(any(x['enterReceived'] for x in states))
        self.assertTrue(any('Attendo la riga' in x for x in out))
    def test_repeated_errors_do_not_extend_deadline(self):
        start=time.monotonic();result,_,_=self.run_reader([(0,b'wrong\n'),(.04,b'wrong\n'),(.04,b'wrong\n')],.25)
        self.assertIsInstance(result,TimeoutError);self.assertLess(time.monotonic()-start,.6)
    def test_oversized_line_can_be_cleared_before_enter(self):
        self.assertIs(self.run_reader([(0,b'x'*1000),(.03,b'\x15'+LINE+b'\n')])[0],True)
    def test_suffix_is_not_stripped(self):
        result,_,_=self.run_reader([(0,LINE+b' extra\n')],.25)
        self.assertIsInstance(result,TimeoutError)
    def test_pipe_is_not_a_terminal(self):
        r,w=os.pipe()
        try:
            with self.assertRaises(m.TerminalReviewError):m.read_exact(HASH,lambda:None,emit=lambda _:None,progress=lambda _:None,fd=r)
        finally:os.close(r);os.close(w)
if __name__=='__main__':unittest.main()
