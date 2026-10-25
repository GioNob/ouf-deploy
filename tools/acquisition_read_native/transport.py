"""Pinned local Engine and single-namespace HTTP. No shell, redirect or arbitrary endpoint."""
import hashlib,http.client,json,os,re,signal,socket,stat,struct,subprocess,sys
from pathlib import Path
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def frame(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
class Engine:
    def __init__(self,p,binding):self.p,self.binding,self.timeout=p,binding,8
    def connection(self,timeout=None):
        timeout=self.timeout if timeout is None else timeout
        path=Path(self.binding['socketPath']);self.p.ancestry(path.parent);s=path.lstat();require(stat.S_ISSOCK(s.st_mode)and [s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]==self.binding['socketBinding'],'CURRENT_PINNED_ENGINE_SOCKET_REQUIRED');outer=self
        class Unix(http.client.HTTPConnection):
            def connect(c):
                c.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.sock.settimeout(timeout);c.sock.connect(str(path));peer=list(struct.unpack('3i',c.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));require(peer==outer.binding['peerCredentials']and peer[1]==0,'CURRENT_PINNED_ROOT_ENGINE_PEER_REQUIRED')
        return Unix('root-local-engine',timeout=timeout)
    def request(self,method,path,body=None):
        require(method in('GET','POST')and path.startswith('/v1.44/'),'ONLY_LOCAL_ENGINE_GET_POST');raw=None if body is None else self.p.encoded(body);require(raw is None or len(raw)<=1048576,'BOUNDED_ENGINE_COMMAND_REQUIRED');c=self.connection()
        try:
            c.request(method,path,body=raw,headers={'Content-Type':'application/json','Connection':'close'});r=c.getresponse();payload=r.read(2097153);require(len(payload)<=2097152,'BOUNDED_ENGINE_RESPONSE_REQUIRED');return r.status,self.p.decode(payload)if payload else None
        except (OSError,ValueError,http.client.HTTPException):raise Stop('ENGINE_EFFECT_OUTCOME_UNPROVEN_NO_REPLAY')from None
        finally:c.close()
    def load(self,archive,remaining):
        path=Path(archive['path']);self.p.ancestry(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);c=None
        try:
            before=os.fstat(fd);require(list(frame(before))==archive['metadata']and stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o400,'EXACT_SEALED_NATIVE_ARCHIVE_REQUIRED')
            with os.fdopen(os.dup(fd),'rb')as stream:
                h=hashlib.sha256()
                for block in iter(lambda:stream.read(1048576),b''):h.update(block)
                require(h.hexdigest()==archive['sha256']and before.st_size==archive['bytes'],'EXACT_NATIVE_ARCHIVE_BYTES_REQUIRED');stream.seek(0);c=self.connection(min(120,max(1,remaining-30)));c.request('POST','/v1.44/images/load?quiet=1',body=stream,headers={'Content-Type':'application/x-tar','Content-Length':str(before.st_size),'Connection':'close'});r=c.getresponse();raw=r.read(1048577);require(r.status==200 and len(raw)<=1048576,'NATIVE_IMAGE_LOAD_RESPONSE_UNPROVEN')
                rows=[self.p.decode(line)for line in raw.splitlines()if line.strip()];require(rows and all(type(v)is dict and not v.get('error')and not v.get('errorDetail')for v in rows),'NATIVE_IMAGE_LOAD_ERROR')
            require(frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'NATIVE_ARCHIVE_CHANGED_DURING_IMPORT');return {'loadResponseHash':hashlib.sha256(raw).hexdigest()}
        except (OSError,ValueError,http.client.HTTPException):raise Stop('NATIVE_IMAGE_LOAD_OUTCOME_UNPROVEN_NO_REPLAY')from None
        finally:
            if c:c.close()
            os.close(fd)
CHILD=r'''import http.client,json,os,re,signal,sys
signal.alarm(10)
try:
 raw=sys.stdin.buffer.read(1048577)
 if not 0<len(raw)<=1048576:raise ValueError()
 v=json.loads(raw)
 if set(v)!={'kind','method','path','body','key'}:raise ValueError()
 admin=v['kind']=='admin'
 if admin:
  if v['method']=='GET':
   if v['path']!='/apisix/admin/routes'or v['body']is not None:raise ValueError()
  elif v['method']=='PUT':
   if v['path']not in('/apisix/admin/routes/execute-ouf-ingestion-acquisition-read','/apisix/admin/routes/execute-urban-acquisition-read')or not isinstance(v['body'],dict):raise ValueError()
  else:raise ValueError()
  if not isinstance(v['key'],str)or not 16<=len(v['key'])<=4096:raise ValueError()
 elif v['kind']=='health':
  if v['method']!='GET'or v['path']not in('/actuator/health/readiness','/health/ready')or v['body']is not None or v['key']is not None:raise ValueError()
 else:raise ValueError()
 fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
 c=http.client.HTTPConnection('127.0.0.1',9180 if admin else 8080,timeout=4)
 headers={'Accept':'application/json','Connection':'close'}
 if admin:headers['X-API-KEY']=v['key']
 body=None if v['body']is None else json.dumps(v['body'],sort_keys=True,separators=(',',':')).encode()
 if body is not None:headers['Content-Type']='application/json'
 c.request(v['method'],v['path'],body=body,headers=headers);r=c.getresponse();raw=r.read(8388609)
 if len(raw)>8388608:raise ValueError()
 sys.stdout.buffer.write(json.dumps({'status':r.status,'body':raw.decode('utf-8')},sort_keys=True,separators=(',',':')).encode());sys.stdout.buffer.flush();c.close()
except BaseException:
 if 'v'in locals()and v.get('kind')=='health':
  sys.stdout.write('{"status":0,"body":""}');sys.stdout.flush();os._exit(0)
 os._exit(2)
os._exit(0)
'''
def namespace(p,pin,kind,method,path,body=None,key=None):
    require(p.process_pin(pin['pid'])==pin,'EXACT_CURRENT_NAMESPACE_PROCESS_REQUIRED');fd=os.open('/proc/'+str(pin['pid'])+'/ns/net',os.O_RDONLY)
    try:
        v=os.fstat(fd);require([v.st_dev,v.st_ino]==pin['namespaces']['net'],'EXACT_NAMESPACE_FD_REQUIRED');r=subprocess.run([sys.executable,'-I','-S','-B','-c',CHILD,str(fd)],input=p.encoded({'kind':kind,'method':method,'path':path,'body':body,'key':key}),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(fd,),timeout=12,cwd='/',env={'PATH':'/usr/bin:/bin','LC_ALL':'C'});require(r.returncode==0 and 0<len(r.stdout)<=16777216,'NAMESPACE_HTTP_OUTCOME_UNPROVEN_NO_REPLAY');return p.decode(r.stdout)
    finally:os.close(fd)
