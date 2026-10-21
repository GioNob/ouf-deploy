"""Actual controlling PTY input, exact review binding, no signer/key access."""
import errno,json,os,pty,select,signal,sys,termios,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_file_only_preparation
from tools.chatbot_file_cohort import review


class HumanTerminal(unittest.TestCase):
    def test_phase6_review_explains_completed_gateway_existing_ingestion_and_ninth_grant(self):
        value,_=self.fixture();value['postGrantRecoveryReview']={'profile':'ouf.chatbot-gateway-schema-continuation.v1',
            'retainedNumericGateway':{'synthetic':True},'retainedCreatedIngestion':{'synthetic':True}}
        with patch.object(self,'fixture',return_value=(value,('APPROVO '+review.digest(value)).encode())):
            output,_,_=self.interact([('APPROVO '+review.digest(value)).encode()])
        self.assertIn(b'RESULT_OK=',output);self.assertIn(b'Fase tecnica 6/8',output)
        self.assertIn(b'zero nuove scritture',output);self.assertIn(b'Nessun nuovo rename o create Ingestion',output)
        self.assertIn(b'Nove grant',output);self.assertNotIn(b'28 modifiche restanti',output)
    def test_path_reprocessing_review_explains_new_container_and_ten_preserved_grants(self):
        value,_=self.fixture();value['postGrantRecoveryReview']={'profile':'ouf.chatbot-gateway-schema-continuation.v1',
            'retainedNumericGateway':{'synthetic':True},'retainedCreatedIngestion':{'synthetic':True},
            'retainedFailedIngestion':{'synthetic':True}}
        expected=('APPROVO '+review.digest(value)).encode()
        with patch.object(self,'fixture',return_value=(value,expected)):
            output,_,_=self.interact([expected])
        self.assertIn(b'RESULT_OK=',output);self.assertIn(b'correzione PATH Ingestion',output)
        self.assertIn(b'Dieci grant',output);self.assertIn('undicesimo cumulativo'.encode(),output)
        self.assertIn(b'Nuovo container dalla stessa immagine',output)
        self.assertNotIn(b'Nessun nuovo rename o create Ingestion',output)
        self.assertIn(b'zero nuove scritture',output)

    def fixture(self):
        value={'schema':review.SCHEMA,'sourceClosureHash':'a'*64,
            'scopes':{'gatewayRuntimeInstallation':{}},'maximumElapsedSeconds':3600,
            'finiteWorkerMaximumAttempts':128,'finiteWorkerMaximumSeconds':3600}
        return value,('APPROVO '+review.digest(value)).encode('ascii')

    def interact(self,lines,prequeued=None):
        value,expected=self.fixture();sync_read,sync_write=os.pipe();pid,master=pty.fork()
        if pid==0:
            os.close(sync_write)
            real_open=os.open
            def only_tty(path,*args,**kwargs):
                if path!='/dev/tty':raise AssertionError('UNEXPECTED_FILE_ACCESS')
                return real_open(path,*args,**kwargs)
            try:
                # Echo is a terminal feature, not a program diagnostic. Disable
                # it in the test so leakage assertions cover only program output.
                attrs=termios.tcgetattr(0);attrs[3]&=~termios.ECHO;termios.tcsetattr(0,termios.TCSANOW,attrs)
                if prequeued is not None:
                    os.write(1,b'BEFORE_CURRENT_REVIEW\n');os.read(sync_read,1)
                os.close(sync_read)
                with patch.object(review.os,'open',side_effect=only_tty),\
                     patch.object(review,'ExistingEd25519Signer',side_effect=AssertionError('SIGNER_USED')):
                    result=review.terminal_decision(value,'/fixture/private-review.json')
                os.write(1,b'RESULT_OK='+review.encoded(result)+b'\n')
            except Exception as error:
                os.write(1,b'RESULT_DENIED='+str(error).encode()+b'\n')
            finally:os._exit(0)
        os.close(sync_read)
        output=bytearray();sent=False;queued=False;done=False;deadline=time.monotonic()+8
        try:
            while time.monotonic()<deadline:
                if select.select([master],[],[],0.1)[0]:
                    try:part=os.read(master,65536)
                    except OSError as error:
                        if error.errno!=errno.EIO:raise
                        break
                    if not part:break
                    output.extend(part)
                    if prequeued is not None and not queued and b'BEFORE_CURRENT_REVIEW' in output:
                        os.write(master,prequeued+b'\n');os.write(sync_write,b'x');queued=True
                    if not sent and b'\n> ' in output:
                        os.write(master,b'\n'.join(lines)+b'\n');sent=True
                child,status=os.waitpid(pid,os.WNOHANG)
                if child:done=True;break
            if not done:
                while time.monotonic()<deadline:
                    child,status=os.waitpid(pid,os.WNOHANG)
                    if child:done=True;break
                    time.sleep(0.01)
            self.assertTrue(done,'controlling PTY prompt did not terminate')
            self.assertLess(len(output),32768)
            return bytes(output),value,expected
        finally:
            os.close(master);os.close(sync_write)
            if not done:
                os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)

    def test_exact_human_text_returns_only_current_review_decision(self):
        value,expected=self.fixture();output,_,_=self.interact([expected])
        self.assertIn(b'RESULT_OK=',output)
        result=json.loads(output.split(b'RESULT_OK=',1)[1].splitlines()[0])
        self.assertEqual(result['approvedReviewHash'],review.digest(value))
        self.assertEqual(result['approvedSourceClosureHash'],value['sourceClosureHash'])
        self.assertEqual(result['expiresAt']-result['approvedAt'],3600)

    def test_exact_terminal_paste_envelope_keeps_current_hash_binding(self):
        _,expected=self.fixture()
        for raw in (b'\x1b[200~'+expected+b'\x1b[201~',
                    b'APPROVO \x1b[200~'+expected[len(b'APPROVO '):]+b'\x1b[201~'):
            with self.subTest(length=len(raw)):
                output,_,_=self.interact([raw]);self.assertIn(b'RESULT_OK=',output)

    def test_typo_diagnostic_allows_same_prompt_retry_without_leaking_input(self):
        _,expected=self.fixture();secret=b'DO_NOT_PRINT_PRIVATE_INPUT'
        output,_,_=self.interact([secret,expected])
        self.assertIn(b'NOT_ACCEPTED',output);self.assertIn(b'RESULT_OK=',output)
        self.assertNotIn(secret,output)

    def test_three_wrong_answers_end_without_decision_or_signer(self):
        output,_,_=self.interact([b'APPROVO '+b'f'*64]*3)
        self.assertIn(b'RESULT_DENIED=FULL_ACTION_NOT_APPROVED',output)
        self.assertNotIn(b'RESULT_OK=',output)
        self.assertEqual(output.count(b'"status":"NOT_ACCEPTED"'),3)

    def test_parser_never_normalizes_hash_whitespace_unicode_or_ansi(self):
        _,expected=self.fixture()
        for raw in (b' '+expected,expected+b' ',expected.replace(b' ',b'\xc2\xa0'),
            b'YES',b'APPROVO '+b'F'*64,b'\x1b[31m'+expected+b'\x1b[0m',
            b'\x1b[200~'+expected,b'\x1b[200~APPROVO '+b'f'*64+b'\x1b[201~'):
            with self.subTest(length=len(raw)):
                accepted,detail=review.terminal_answer(raw,expected)
                self.assertFalse(accepted);self.assertNotIn('input',detail)

    def test_oversized_input_is_drained_before_retry(self):
        _,expected=self.fixture();output,_,_=self.interact([b'x'*200,expected])
        self.assertIn(b'INPUT_TOO_LONG',output);self.assertIn(b'RESULT_OK=',output)

    def test_prequeued_input_is_not_a_decision_after_current_review(self):
        _,expected=self.fixture();output,_,_=self.interact([expected],prequeued=b'LEFT_FROM_DEVICE_FLOW')
        self.assertIn(b'RESULT_OK=',output);self.assertNotIn(b'NOT_ACCEPTED',output)

    def test_postgrant_review_explains_consumed_grant_and_new_worker_without_new_create(self):
        value,_=self.fixture();value['postGrantRecoveryReview']={'profile':'ouf.chatbot-postgrant-created-continuation.v1'}
        expected=('APPROVO '+review.digest(value)).encode('ascii')
        with patch.object(self,'fixture',return_value=(value,expected)):
            output,_,_=self.interact([expected])
        self.assertIn(b'RESULT_OK=',output)
        self.assertIn(b'Nessun nuovo primo grant.',output)
        self.assertIn(b'zero replay CREATE',output)
        self.assertNotIn(b'Un primo grant (massimo 300 secondi)',output)


    def test_signed_review_explains_four_grants_new_attestation_and_conservative_database_flag(self):
        value,_=self.fixture();value['postGrantRecoveryReview']={'profile':'ouf.chatbot-signed-paused-admission-reprocessing.v1'}
        expected=('APPROVO '+review.digest(value)).encode('ascii')
        with patch.object(self,'fixture',return_value=(value,expected)):
            output,_,_=self.interact([expected])
        self.assertIn(b'RESULT_OK=',output);self.assertIn(b'Quattro grant',output);self.assertIn(b'quinto cumulativo',output)
        self.assertIn(b'databaseMayHaveChanged resta true',output);self.assertIn(b'nuova attestazione',output)
        self.assertNotIn(b'Tre grant',output);self.assertNotIn(b'Le quattro fasi',output)

    def test_mounted_review_explains_three_prior_grants_and_keeps_old_scope_summary_out(self):
        value,_=self.fixture();value['postGrantRecoveryReview']={'profile':'ouf.chatbot-paused-unsigned-attestation-reprocessing.v2'}
        expected=('APPROVO '+review.digest(value)).encode('ascii')
        with patch.object(self,'fixture',return_value=(value,expected)):
            output,_,_=self.interact([expected])
        self.assertIn(b'RESULT_OK=',output)
        self.assertIn(b'Tre grant',output);self.assertIn(b'quarto cumulativo',output)
        self.assertIn(b'90 secondi',output);self.assertIn(b'due intenti falliti',output)
        self.assertNotIn(b'Due grant',output);self.assertNotIn(b'Le quattro fasi',output)
        self.assertNotIn(b'Un primo grant (massimo 300 secondi)',output)


if __name__=='__main__':unittest.main()
