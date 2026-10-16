"""Local-only adapters: ownership, boot_id and AF_UNIX are simulated.
TLS, role signatures, file I/O and the composed production code remain real.
Never use this driver as hosted native or target acceptance evidence.
"""
import io,os,socket,socketserver,stat,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_chatbot_semantic_policy_refresh_reader import Tests as Metadata
import test_governed_owner_composed as suite
adapter=Metadata();rmdir=os.rmdir;unlink=os.unlink;native_open=os.open;io_open=io.open
native_socket=socket.socket;native_stat=os.stat;sockets={}
class LoopbackUnixFixture:
 def __init__(self,path,handler):
  Path(path).write_bytes(b'');self.server=socketserver.TCPServer(('127.0.0.1',0),handler)
  sockets[str(path)]=self.server.server_address
 def serve_forever(self):return self.server.serve_forever()
 def shutdown(self):return self.server.shutdown()
 def server_close(self):return self.server.server_close()
class MappedSocket:
 def __init__(self):self.raw=native_socket(socket.AF_INET,socket.SOCK_STREAM)
 def connect(self,path):return self.raw.connect(sockets[str(path)])
 def __getattr__(self,name):return getattr(self.raw,name)
with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1])as d:
 boot=Path(d)/"boot";boot.write_text("11111111-1111-1111-1111-111111111111");boot.chmod(0o600)
 with adapter.ownership_adapter()as owners:
  def remove(fn,path,*a,**k):
   try:s=os.stat(path,follow_symlinks=False,**{x:v for x,v in k.items()if x=="dir_fd"});key=(s.st_dev,s.st_ino)
   except OSError:key=None
   result=fn(path,*a,**k);owners.pop(key,None);return result
  mapped=lambda p:boot if str(p)=="/proc/sys/kernel/random/boot_id" else p
  ownership_stat=os.stat
  def stat_with_unix(path,*a,**k):
   result=ownership_stat(path,*a,**k)
   if str(path)in sockets:
    from types import SimpleNamespace
    values={name:getattr(result,name)for name in dir(result)if name.startswith('st_')}
    values['st_mode']=stat.S_IFSOCK|(result.st_mode&0o777);return SimpleNamespace(**values)
   return result
  with patch.object(os,'stat',side_effect=stat_with_unix),patch.object(socketserver,'UnixStreamServer',LoopbackUnixFixture),patch.object(socket,'socket',side_effect=lambda family=socket.AF_INET,*a,**k:MappedSocket()if family==socket.AF_UNIX else native_socket(family,*a,**k)),patch.object(os,"lstat",side_effect=lambda path,*a,**k:os.stat(path,*a,follow_symlinks=False,**k)),patch.object(os,"rmdir",side_effect=lambda *a,**k:remove(rmdir,*a,**k)),patch.object(os,"unlink",side_effect=lambda *a,**k:remove(unlink,*a,**k)),patch.object(os,"open",side_effect=lambda p,*a,**k:native_open(mapped(p),*a,**k)),patch.object(io,"open",side_effect=lambda p,*a,**k:io_open(mapped(p),*a,**k)):
   result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(suite))
raise SystemExit(not result.wasSuccessful())
