"""Deadline-bound nft input without a procfs-backed /dev/stdin dependency.

The owned transaction is executed once from a private temporary regular file.
No shell, table creation, relative TTL replay or authority is added here.
"""
import os,stat,tempfile
from pathlib import Path
from deadline_backend import DeadlineNftBackend
from .custody_capture import require


class DiscoveryNftBackend(DeadlineNftBackend):
    def apply(self,transaction,deadline):
        require(type(transaction) is str and '\0' not in transaction
            and 0<len(transaction.encode('utf-8'))<=1048576,'BOUNDED_DISCOVERY_NFT_TRANSACTION_REQUIRED')
        require(os.geteuid()==os.getegid()==0,'ROOT_PRIVATE_DISCOVERY_NFT_INPUT_REQUIRED')
        if deadline-self.clock()<=0:raise RuntimeError('NFT_APPLY_DEADLINE_MISSED')
        with tempfile.TemporaryDirectory(prefix='ouf-discovery-nft-',dir='/tmp') as directory:
            root=Path(directory);s=root.lstat()
            require(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,
                'PRIVATE_DISCOVERY_NFT_INPUT_DIRECTORY_REQUIRED')
            path=root/'transaction.nft';raw=transaction.encode('utf-8')
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                os.fchmod(fd,0o600);position=0
                while position<len(raw):
                    count=os.write(fd,raw[position:]);require(count>0,'COMPLETE_DISCOVERY_NFT_INPUT_REQUIRED');position+=count
                os.fsync(fd);info=os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and info.st_nlink==1
                    and stat.S_IMODE(info.st_mode)==0o600 and info.st_size==len(raw),
                    'SEALED_PRIVATE_DISCOVERY_NFT_INPUT_REQUIRED')
            finally:os.close(fd)
            # Recompute after file creation: the absolute DNS/attempt deadline
            # is never restarted or credited with preparation time.
            remaining=deadline-self.clock()
            if remaining<=0:raise RuntimeError('NFT_APPLY_DEADLINE_MISSED')
            self.run(['-f',str(path)],timeout=min(remaining,self.budget))
