"""Coordinate this executor's observer with its same-process renewal worker.

The retained Journal, disk format and nonblocking cross-process fence stay
unchanged. Only short transactions on this shared object are serialized.
"""
from contextlib import contextmanager
import threading
from tools.semantic_lease_recovery.recovery_journal import Journal

def synchronize(journal):
    if type(journal) is not Journal or hasattr(journal,'_csv_thread_lock'):
        raise ValueError('ONE_SHARED_NATIVE_JOURNAL_REQUIRED')
    original=journal.transaction
    journal._csv_thread_lock=threading.Lock()
    @contextmanager
    def transaction():
        with journal._csv_thread_lock:
            with original():
                yield
    journal.transaction=transaction
    return journal

def report_guard_errors(worker,emit):
    """Report only exception class and frame names; never arguments or locals."""
    import json
    original=worker.r.adapter.guard
    def guard():
        try:return original()
        except Exception as error:
            frames=[];trace=error.__traceback__
            while trace is not None:
                frames.append({'function':trace.tb_frame.f_code.co_name,'line':trace.tb_lineno})
                trace=trace.tb_next
            try:emit('OUF_CSV_POLICY_GUARD_DIAGNOSTIC='+json.dumps({
                'exceptionType':type(error).__name__,'frames':frames[-8:],
                'exceptionMessagePrinted':False,'credentialValuesPrinted':False},sort_keys=True))
            except Exception:pass
            raise
    worker.r.adapter.guard=guard
