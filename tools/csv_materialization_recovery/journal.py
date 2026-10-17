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
