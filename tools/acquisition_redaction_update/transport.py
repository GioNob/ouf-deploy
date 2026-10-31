"""Pinned Engine raw receipts and candidate-only readiness transport.

Caller owns signed claim/budget before dispatch and persists raw receipt BEFORE
JSON parsing/status guards. This module itself grants no runtime authority.
"""
import hashlib,http.client,json,os,socket,stat,struct,subprocess,sys
from pathlib import Path
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def frame(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
class Engine:
    def __init__(self,p,binding):self.p,self.binding,self.timeout=p,binding,8
    def connection(self,timeout=None):
        path=Path(self.binding['socketPath']);self.p.ancestry(path.parent)
        require(path.resolve()==path,'CANONICAL_ENGINE_SOCKET_REQUIRED');s=path.lstat()
        require(stat.S_ISSOCK(s.st_mode)and s.st_uid==0 and[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]==self.binding['socketBinding'],'EXACT_PINNED_ENGINE_SOCKET_REQUIRED')
        binding=self.binding;selected=self.timeout if timeout is None else timeout
        class Unix(http.client.HTTPConnection):
            def connect(c):
                c.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.sock.settimeout(selected);c.sock.connect(str(path))
                peer=list(struct.unpack('3i',c.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
                require(peer==binding['peerCredentials']and peer[1]==0,'EXACT_PINNED_ROOT_ENGINE_PEER_REQUIRED')
        return Unix('root-local-engine',timeout=selected)
    def raw(self,method,path,body=None,timeout=None):
        require(method in('GET','POST')and path.startswith('/v1.44/'),'CLOSED_ENGINE_METHOD_PREFIX_REQUIRED')
        data=None if body is None else self.p.encoded(body);require(data is None or len(data)<=1048576,'BOUNDED_ENGINE_REQUEST_REQUIRED')
        c=self.connection(timeout)
        try:
            c.request(method,path,body=data,headers={'Content-Type':'application/json','Connection':'close'});r=c.getresponse();raw=r.read(2097153)
            require(len(raw)<=2097152,'BOUNDED_ENGINE_RESPONSE_REQUIRED');return r.status,raw
        except (OSError,http.client.HTTPException):raise Stop('ENGINE_OUTCOME_UNPROVEN_CLAIM_RETAINED')from None
        finally:c.close()
    def request(self,method,path,body=None):
        self.before(method,path,body)
        status,raw=self.raw(method,path,body,timeout=7 if path.endswith('/stop?t=2')else 15 if '/stop?'in path else None)
        self.retained(method,path,status,raw)
        return status,self.p.decode(raw)if raw else None
    def load_raw(self,archive,remaining):
        path=Path(archive['path']);self.p.ancestry(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW);c=None
        try:
            before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o400 and list(frame(before))==archive['metadata']and before.st_size==archive['bytes'],'SEALED_NATIVE_ARCHIVE_REQUIRED')
            with os.fdopen(os.dup(fd),'rb')as stream:
                h=hashlib.sha256()
                for block in iter(lambda:stream.read(65536),b''):h.update(block)
                require(h.hexdigest()==archive['sha256'],'EXACT_NATIVE_ARCHIVE_BYTES_REQUIRED');stream.seek(0)
                c=self.connection(min(120,max(1,remaining-30)));c.request('POST','/v1.44/images/load?quiet=1',body=stream,headers={'Content-Type':'application/x-tar','Content-Length':str(before.st_size),'Connection':'close'})
                r=c.getresponse();raw=r.read(1048577);require(len(raw)<=1048576,'BOUNDED_IMAGE_RECEIPT_REQUIRED')
                # Caller must first retain raw receipt; this frame check is
                # returned separately so it never erases a successful response.
                unchanged=frame(before)==frame(os.fstat(fd))==frame(path.lstat())
                return r.status,raw,unchanged
        except (OSError,http.client.HTTPException):raise Stop('IMAGE_IMPORT_OUTCOME_UNPROVEN_CLAIM_RETAINED')from None
        finally:
            if c:c.close()
            os.close(fd)
CHILD=r'''import http.client,json,os,signal,sys
signal.alarm(10)
try:
 if len(sys.argv)!=2 or not sys.argv[1].isdigit():raise ValueError()
 fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
 c=http.client.HTTPConnection('127.0.0.1',8080,timeout=4)
 c.request('GET','/actuator/health/readiness',headers={'Connection':'close','Accept':'application/json'})
 r=c.getresponse();raw=r.read(65537)
 if len(raw)>65536:raise ValueError()
 sys.stdout.buffer.write(json.dumps({'status':r.status,'rawBodyHex':raw.hex()},sort_keys=True,separators=(',',':')).encode());sys.stdout.buffer.flush();c.close()
except (OSError,http.client.HTTPException):
 sys.stdout.write('{"status":0,"rawBodyHex":""}');sys.stdout.flush();os._exit(0)
except BaseException:os._exit(2)
os._exit(0)
'''
def health(p,pin):
    require(p.process_pin(pin['pid'])==pin,'EXACT_OWN_CANDIDATE_PROCESS_REQUIRED');fd=os.open('/proc/'+str(pin['pid'])+'/ns/net',os.O_RDONLY)
    try:
        s=os.fstat(fd);require([s.st_dev,s.st_ino]==pin['namespaces']['net'],'EXACT_OWN_CANDIDATE_NAMESPACE_REQUIRED')
        r=subprocess.run([sys.executable,'-I','-S','-B','-c',CHILD,str(fd)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(fd,),timeout=12,cwd='/',env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        require(r.returncode==0 and 0<len(r.stdout)<=262144,'READINESS_TRANSPORT_UNPROVEN');return p.decode(r.stdout)
    finally:os.close(fd)
