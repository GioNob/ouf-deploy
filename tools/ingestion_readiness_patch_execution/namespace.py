"""Read-only namespace FD bound to the unchanged Gateway CID/PID/start/config."""
import copy
import os
from tools.ingestion_readiness_patch_execution import contract as c,runtime_guard
from tools.ingestion_readiness_patch_execution.replacement import EngineReader
def identity(s):return {'device':s.st_dev,'inode':s.st_ino}
class GatewayNamespacePin:
    def __init__(self,reader,pin):
        c.require(type(reader) is EngineReader,'EXACT_NATIVE_ENGINE_READER_REQUIRED')
        self.reader=reader;self.pin=copy.deepcopy(pin);self.fd=None
        self.path='/proc/'+str(pin['binding']['pid'])+'/ns/net'
        self.check();self.binding=identity(os.stat(self.path))
        try:
            self.fd=os.open(self.path,os.O_RDONLY|os.O_CLOEXEC)
            c.require(identity(os.fstat(self.fd))==self.binding,'GATEWAY_NAMESPACE_FD_CHANGED');self.check()
        except BaseException:self.close();raise
    def check(self):
        runtime_guard.unchanged(self.reader.container(self.pin['binding']['containerId']),self.pin)
        if hasattr(self,'binding'):
            c.require(identity(os.stat(self.path))==self.binding,'UNCHANGED_GATEWAY_NAMESPACE_CHANGED')
        if self.fd is not None:
            c.require(identity(os.fstat(self.fd))==self.binding,'HELD_GATEWAY_NAMESPACE_CHANGED')
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None
