"""Credential publisher component; no CLI, authority creation or journal initialization.

The sealed installation must provide an existing IAM/transport owner. Synthetic
test owners are not deployment proof. One Recovery instance is one renewal
operation; a failed incident cannot be replaced by another timer job/operation.
"""
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request
import uuid
from tools.semantic_lease_recovery.bounded_recovery import Permanent, Temporary, fingerprint
from tools.semantic_lease_recovery.bounded_recovery import Recovery
from tools.semantic_lease_recovery.recovery_journal import Journal

def check(ok):
    if not ok: raise Permanent('INTEGRITY_UNPROVEN')

def identity(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,
            s.st_size,s.st_mtime_ns,s.st_ctime_ns)

@contextmanager
def protected_directory(path, uid=0, gid=0, mode=0o700):
    """Hold FD-relative no-follow ancestry; never create or repair a directory."""
    path=Path(path)
    check(os.geteuid()==0 and path.is_absolute() and path!=Path('/')
          and '..' not in path.parts and len(path.parts)<=32)
    fds=[]; entries=[]
    try:
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK
        parent=os.open('/',flags); fds.append(parent)
        for index,part in enumerate(path.parts[1:]):
            s=os.stat(part,dir_fd=parent,follow_symlinks=False)
            check(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022)
            child=os.open(part,flags,dir_fd=parent); fds.append(child)
            check(identity(s)==identity(os.fstat(child)))
            entries.append((parent,part,child,(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)))
            parent=child
        s=os.fstat(parent)
        check((s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(uid,gid,mode))
        yield parent
        for directory,name,child,seal in entries:
            current=os.stat(name,dir_fd=directory,follow_symlinks=False)
            check(seal==(current.st_dev,current.st_ino,current.st_uid,current.st_gid,current.st_mode))
            check(seal==(lambda v:(v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode))(os.fstat(child)))
    finally:
        for fd in reversed(fds): os.close(fd)

class CredentialFile:
    def __init__(self,path):
        self.path=Path(path)
        check(self.path.name not in {'','.', '..'})
    def read(self):
        with protected_directory(self.path.parent) as directory:
            before=os.stat(self.path.name,dir_fd=directory,follow_symlinks=False)
            check(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
                  and stat.S_IMODE(before.st_mode)==0o400 and before.st_nlink==1
                  and 0<before.st_size<=4096)
            fd=os.open(self.path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            try:
                check(identity(before)==identity(os.fstat(fd)))
                raw=os.read(fd,4097)
                check(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))
                      ==identity(os.stat(self.path.name,dir_fd=directory,follow_symlinks=False)))
                secret=raw.decode('utf-8').strip()
                check(0<len(secret)<=4096 and not any(c.isspace() for c in secret))
                return secret
            finally: os.close(fd)

@dataclass(frozen=True)
class Binding:
    endpoint: str
    client_id: str
    scope: str
    output_directory: str
    output_member: str
    output_gid: int
    minimum_remaining: int = 90
    maximum_token_seconds: int = 3600

    def __post_init__(self):
        url=urllib.parse.urlsplit(self.endpoint)
        check(url.scheme=='https' and url.hostname and not url.username and not url.password
              and not url.query and not url.fragment and url.path.startswith('/'))
        check(type(self.client_id) is str and re.fullmatch('[A-Za-z0-9_.:-]{1,128}',self.client_id))
        check(type(self.scope) is str and re.fullmatch('[A-Za-z0-9_:/ .-]{1,512}',self.scope))
        check(type(self.output_member) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',self.output_member)
              and self.output_member not in {'.','..'} and type(self.output_gid) is int and self.output_gid>0)
        check(type(self.minimum_remaining) is int and type(self.maximum_token_seconds) is int
              and 1<=self.minimum_remaining<=self.maximum_token_seconds<=86400)
    def digest(self): return fingerprint(self.__dict__)

class DomainOwner(ABC):
    """Installed owner seam, NEVER a substitute for real IAM/source authority."""
    @abstractmethod
    def guard(self, binding_hash): pass
    @abstractmethod
    def prepare(self, binding_hash, deadline): pass
    @abstractmethod
    def admit(self, token, valid_until_monotonic, binding_hash, deadline): pass
    @abstractmethod
    def pause(self): pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

class HttpsGrant:
    """Exactly one request, no redirect/proxy/retry; ambiguous errors stay ambiguous."""
    def __init__(self,clock,context=None,opener=None):
        self.clock=clock; context=context or ssl.create_default_context()
        check(context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED)
        self.opener=opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context),NoRedirect())
    def request(self,binding,secret,deadline):
        timeout=min(10,deadline-self.clock()[1])
        if timeout<=0: raise Temporary('DEPENDENCY_TIMEOUT',no_effect=True)
        body=urllib.parse.urlencode({'grant_type':'client_credentials','client_id':binding.client_id,
                                    'client_secret':secret,'scope':binding.scope}).encode('ascii')
        request=urllib.request.Request(binding.endpoint,data=body,
            headers={'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},method='POST')
        try:
            with self.opener.open(request,timeout=timeout) as response:
                if response.status!=200: raise Temporary('SERVICE_UNAVAILABLE')
                raw=response.read(65537)
                if len(raw)>65536: raise Temporary('DEPENDENCY_UNAVAILABLE')
            return json.loads(raw)
        except urllib.error.HTTPError as error:
            if error.code in (400,401,403): raise Permanent('PERMANENT_FAILURE') from None
            raise Temporary('SERVICE_UNAVAILABLE') from None
        except (Permanent,Temporary): raise
        except Exception: raise Temporary('DEPENDENCY_TIMEOUT') from None

def token_response(value,binding):
    check(type(value) is dict)
    token=value.get('access_token'); seconds=value.get('expires_in')
    check(type(token) is str and 0<len(token)<=16384 and not any(c.isspace() for c in token)
          and type(value.get('token_type')) is str and value['token_type'].lower()=='bearer'
          and type(seconds) is int and binding.minimum_remaining<=seconds<=binding.maximum_token_seconds)
    return token,seconds

class AtomicTokenFile:
    def __init__(self,binding): self.binding=binding
    def check_custody(self):
        b=self.binding
        with protected_directory(b.output_directory,gid=b.output_gid,mode=0o750) as directory:
            names=os.listdir(directory); check(names in ([],[b.output_member]))
            if names:
                info=os.stat(b.output_member,dir_fd=directory,follow_symlinks=False)
                check(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==b.output_gid
                      and stat.S_IMODE(info.st_mode)==0o440 and info.st_nlink==1
                      and 0<info.st_size<=65536)
    def publish(self,token,guard):
        b=self.binding
        with protected_directory(b.output_directory,gid=b.output_gid,mode=0o750) as directory:
            before=os.fstat(directory); names=os.listdir(directory)
            check(names in ([],[b.output_member]))
            old=None
            if names:
                s=os.stat(b.output_member,dir_fd=directory,follow_symlinks=False)
                check(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==b.output_gid
                      and stat.S_IMODE(s.st_mode)==0o440 and s.st_nlink==1)
                old=identity(s)
            temporary='.token-'+uuid.uuid4().hex
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            try:
                os.fchown(fd,0,b.output_gid); os.fchmod(fd,0o440)
                raw=token.encode('utf-8'); position=0
                while position<len(raw):
                    amount=os.write(fd,raw[position:]); check(amount>0); position+=amount
                os.fsync(fd); guard()
                check(set(os.listdir(directory))==set(names)|{temporary})
                current=None if not names else identity(os.stat(b.output_member,dir_fd=directory,follow_symlinks=False))
                check(current==old)
                os.replace(temporary,b.output_member,src_dir_fd=directory,dst_dir_fd=directory)
                os.fsync(directory)
                final=os.stat(b.output_member,dir_fd=directory,follow_symlinks=False)
                check(identity(final)==identity(os.fstat(fd)))
                return fingerprint({'bindingHash':b.digest(),'directoryDevice':before.st_dev,
                    'directoryInode':before.st_ino,'publishedInode':final.st_ino})
            finally:
                os.close(fd)
                try: os.unlink(temporary,dir_fd=directory)
                except FileNotFoundError: pass

class TokenRenewalAdapter:
    """A complete bounded-recovery effect: grant AND atomic publication.

    Caller holds the Journal's exclusive invocation fence for the WHOLE Recovery
    step. No HTTP request occurs in prepare or inside a journal transaction.
    No initialize/renew-budget/next-cycle API exists here.
    """
    def __init__(self,binding,credential,owner,transport,clock):
        check(type(binding) is Binding and type(credential) is CredentialFile
              and isinstance(owner,DomainOwner) and type(transport) is HttpsGrant)
        self.binding,self.credential,self.owner,self.transport,self.clock=binding,credential,owner,transport,clock
        self.writer=AtomicTokenFile(binding); self.evidence=None; self.publication_window=None
    def guard(self):
        self.owner.guard(self.binding.digest())
    def pause(self):
        self.evidence=None; self.publication_window=None
        self.owner.pause()
    def prepare(self,deadline):
        self.publication_window=None
        self.guard(); self.owner.prepare(self.binding.digest(),deadline)
        self.writer.check_custody()
        secret=self.credential.read(); self.guard()
        self.evidence={'deadline':deadline,'secret':secret,'bindingHash':self.binding.digest()}
        return self.evidence
    def publish(self,evidence,deadline):
        check(evidence is self.evidence and evidence['deadline']==deadline
              and evidence['bindingHash']==self.binding.digest())
        self.guard(); started=self.clock()[1]
        check(math.isfinite(started) and started<deadline)
        # Invalidate the local one-use material BEFORE the remote mutation.
        self.evidence=None
        result=self.transport.request(self.binding,evidence['secret'],deadline)
        try:
            try: token,seconds=token_response(result,self.binding)
            except Exception: raise RuntimeError('GRANT_RESPONSE_UNPROVEN') from None
            valid_until=started+seconds
            def publication_guard():
                self.guard()
                if self.clock()[1]>=deadline or valid_until-self.clock()[1]<self.binding.minimum_remaining:
                    raise Temporary('DEPENDENCY_TIMEOUT')
                check(self.owner.admit(token,valid_until,self.binding.digest(),deadline) is True)
            publication_guard()
            receipt=self.writer.publish(token,publication_guard)
            self.guard()
            wall,mono=self.clock()
            check(math.isfinite(wall) and math.isfinite(mono) and mono>=started
                  and mono<deadline and valid_until-mono>=self.binding.minimum_remaining)
            self.publication_window=(wall,mono,valid_until)
            return receipt
        except Temporary as error:
            # A no-effect proof for an admission probe/publication does NOT
            # establish that the preceding OAuth grant had no remote effect.
            raise Temporary(error.code,retry_after=error.retry_after,no_effect=False) from None

class RenewalOperation:
    def __init__(self,recovery):
        check(type(recovery) is Recovery and type(recovery.journal) is Journal
              and type(recovery.adapter) is TokenRenewalAdapter)
        self.recovery=recovery
    def step(self,*,cancelled=False):
        r=self.recovery
        # Process fence is separate from the short journal CAS lock; no shared
        # lease lock or journal transaction spans requests or waits.
        with protected_directory(r.journal.root),r.journal.invocation():
            row=r.journal.read()
            if cancelled: return r.step(cancelled=True)
            try: r.adapter.guard()
            except Permanent as error: return r.pause(row,'BLOCKED',error.code)
            except Exception: return r.pause(row,'BLOCKED','LOCAL_AUTHORITY_UNPROVEN')
            return r.step()
    def public_status(self,row):
        # ACTIVE means this one operation completed, never application readiness
        # or an issuer/installation authority created by this component.
        return {'state':row['state'],'reason':row['reason'],'attempts':row['attempts'],
                'live':True,'renewalCompleted':row['state']=='ACTIVE',
                'applicationReady':False,'runtimeAuthorityIssued':False}
