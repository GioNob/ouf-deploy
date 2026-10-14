"""Bounded owner-local status in the existing journal; no token or alert transport."""
import json
import os
import re
import stat
import uuid
from tools.semantic_policy_token_owner.producer import protected_directory,check,identity
from tools.semantic_lease_recovery.recovery_journal import Journal

class OwnerReporter:
    def __init__(self,journal,emit):
        check(type(journal) is Journal and callable(emit));self.journal,self.emit=journal,emit
        self.last=None
    def project(self,status):
        required={'state','reason','attempts','publications','live','applicationReady','runtimeAuthorityIssued'}
        check(type(status) is dict and set(status)==required
              and status['state'] in ('NEW','ACTIVE','RETRY_WAIT','PAUSED_EXHAUSTED','BLOCKED','RECONCILE_REQUIRED','CANCELLED','ATTEMPTING','PUBLISHING')
              and type(status['reason']) is str and re.fullmatch('[A-Z][A-Z0-9_]{0,120}',status['reason'])
              and type(status['attempts']) is int and status['attempts']>=0
              and type(status['publications']) is int and status['publications']>=0
              and status['live'] is True and status['applicationReady'] is False and status['runtimeAuthorityIssued'] is False)
        return dict(status)
    def report(self,status):
        value=self.project(status);raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        if raw==self.last:return value
        with protected_directory(self.journal.root) as directory:
            self.journal.check_directory();temporary='.owner-status-'+uuid.uuid4().hex
            try:
                before=os.stat('owner-status.json',dir_fd=directory,follow_symlinks=False)
                check(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1)
            except FileNotFoundError:before=None
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            try:
                position=0
                while position<len(raw):
                    n=os.write(fd,raw[position:]);check(n>0);position+=n
                os.fsync(fd)
                if before is not None:check(identity(before)==identity(os.stat('owner-status.json',dir_fd=directory,follow_symlinks=False)))
                os.replace(temporary,'owner-status.json',src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
            finally:
                os.close(fd)
                try:os.unlink(temporary,dir_fd=directory)
                except FileNotFoundError:pass
        self.last=raw;self.emit('OUF_POLICY_TOKEN_OWNER_STATUS='+raw.decode());return value
    def unavailable(self):
        # Persistence failure is never reported as ACTIVE/readiness. Keep the
        # previous durable record; emit only one safe unavailable marker.
        raw='OUF_POLICY_TOKEN_OWNER_STATUS_UNAVAILABLE phase=OWNER_LOOP reason=PERSISTENCE_OR_OBSERVER_UNPROVEN evidence=owner-status.json,recovery-journal'
        if self.last!=raw:
            # Loss of the log sink cannot terminate the parked owner or leak
            # exception text. Durable status remains the primary evidence.
            self.last=raw
            try:self.emit(raw)
            except Exception:pass

