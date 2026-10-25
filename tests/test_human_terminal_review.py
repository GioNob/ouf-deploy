"""Real PTY byte/Enter/restore tests. All approval material is synthetic."""
import importlib.util
import os
from pathlib import Path
import termios
import threading
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('terminal',ROOT/'tools/human_terminal_review.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
HASH='a'*64


class TerminalTests(unittest.TestCase):
    def run_reader(self,parts,*,expire=.8):
        master,slave=os.openpty();before=termios.tcgetattr(slave)
        emitted=[];states=[];result=[];deadline=time.monotonic()+expire
        def guard():
            if time.monotonic()>=deadline:raise TimeoutError('SYNTHETIC_EXPIRED')
        def run():
            try:m.read_exact(HASH,guard,emit=emitted.append,progress=states.append,fd=slave,heartbeat=.15)
            except BaseException as error:result.append(error)
            else:result.append(True)
        thread=threading.Thread(target=run);thread.start()
        try:
            while not states:time.sleep(.001)
            for delay,value in parts:
                time.sleep(delay);os.write(master,value)
            thread.join(timeout=expire+2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(termios.tcgetattr(slave),before)
            return result[0],emitted,states
        finally:os.close(master);os.close(slave)
    def test_lf_enter(self):
        result,_,states=self.run_reader([(0,('APPROVO '+HASH+'\n').encode())])
        self.assertIs(result,True);self.assertTrue(states[-1]['enterReceived'])
    def test_mobile_cr_enter_and_crlf(self):
        for ending in ('\r','\r\n','\n\n'):
            with self.subTest(ending=repr(ending)):
                result,_,_=self.run_reader([(0,('APPROVO '+HASH+ending).encode())])
                self.assertIs(result,True)
    def test_paste_without_enter_is_visible_but_never_approved(self):
        result,out,states=self.run_reader([(0,('APPROVO '+HASH).encode())],expire=.35)
        self.assertIsInstance(result,TimeoutError)
        self.assertTrue(any('Input ricevuto' in s for s in out))
        self.assertTrue(any('Attendo Invio' in s for s in out))
        self.assertFalse(states[-1]['enterReceived'])
        self.assertEqual(states[-1]['receivedBytes'],72)
    def test_fragmented_paste_then_explicit_enter(self):
        result,_,_=self.run_reader([(0,b'APPROVO '),(.05,HASH[:32].encode()),(.05,HASH[32:].encode()),(.05,b'\r')])
        self.assertIs(result,True)
    def test_no_input_heartbeat_and_restore(self):
        result,out,states=self.run_reader([],expire=.35)
        self.assertIsInstance(result,TimeoutError)
        self.assertTrue(any('Attendo la riga' in s for s in out))
        self.assertEqual(states[0]['receivedBytes'],0)
    def test_suffix_wrong_hash_and_second_line_denied(self):
        for value in (('APPROVO '+HASH+' extra\n').encode(),('APPROVO '+'b'*64+'\n').encode(),('APPROVO '+HASH+'\nother\n').encode()):
            with self.subTest(value=value[:12]):
                result,_,_=self.run_reader([(0,value)])
                self.assertIsInstance(result,m.TerminalReviewError)
    def test_backspace_correction(self):
        result,_,_=self.run_reader([(0,('APPROVO '+HASH[:-1]+'b').encode()),(.02,b'\x7f'+HASH[-1:].encode()+b'\n')])
        self.assertIs(result,True)
    def test_pipe_cannot_be_approval_source(self):
        r,w=os.pipe()
        try:
            with self.assertRaises(m.TerminalReviewError):m.read_exact(HASH,lambda:None,emit=lambda _:None,progress=lambda _:None,fd=r)
        finally:os.close(r);os.close(w)


if __name__=='__main__':unittest.main()
