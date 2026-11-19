"""Read-only FD pin for a proven replacement Gateway network namespace.

No setns, HTTP, admin credentials or mutations. The reviewed replacement and
durable first-process identity must already exist. Only that new PID is opened;
the predecessor must be stopped and detached. Namespace inode numbers may be
reallocated after destruction, so inode inequality alone is not a generation.
This is a local Engine adapter, not proof of a distributed installation.
"""
import copy
import os
from tools.ingestion_rollout_execution.contract import require
from tools.ingestion_rollout_execution.replacement import EngineReader,validate

def identity(info):return {'device':info.st_dev,'inode':info.st_ino}

class GatewayNamespacePin:
    def __init__(self,reader,frame,image_config,old_id,created_id,process,namespace_binding,
                 old_namespace_binding,*,resolved_owner_key,restart_restored=False):
        require(type(reader)is EngineReader and frame['module']=='gateway','EXACT_NATIVE_GATEWAY_READER_REQUIRED')
        for binding in (namespace_binding,old_namespace_binding):
            require(type(binding)is dict and set(binding)=={'device','inode'}
                    and all(type(v)is int and v>0 for v in binding.values()),'EXPLICIT_NAMESPACE_IDENTITIES_REQUIRED')
        endpoints=frame['requestTemplate']['NetworkingConfig']['EndpointsConfig']
        mode=frame['requestTemplate']['HostConfig'].get('NetworkMode')
        require(mode in endpoints or mode in{v['NetworkID']for v in endpoints.values()},
                'EXPLICIT_PRIVATE_GATEWAY_NETWORK_MODE_REQUIRED')
        self.reader=reader;self.frame=copy.deepcopy(frame);self.image_config=copy.deepcopy(image_config)
        self.old_id,self.created_id=old_id,created_id;self.process=copy.deepcopy(process)
        self.binding=copy.deepcopy(namespace_binding);self.old_binding=copy.deepcopy(old_namespace_binding)
        self.key=resolved_owner_key;self.restored=restart_restored;self.fd=None
        try:
            self.check()
            self.fd=os.open(self.path,os.O_RDONLY|os.O_CLOEXEC)
            require(identity(os.fstat(self.fd))==self.binding,'NEW_NAMESPACE_FD_IDENTITY_REQUIRED')
            self.check()
        except BaseException:
            self.close();raise
    @property
    def path(self):return '/proc/'+str(self.process['pid'])+'/ns/net'
    def check(self):
        retained=self.reader.container(self.old_id)
        require(retained['State']['Running']is False and retained['State']['Pid']==0
                and not retained['NetworkSettings']['Networks']and retained['Name']!='/'+self.frame['name'],
                'STOPPED_DETACHED_RENAMED_PREDECESSOR_REQUIRED')
        actual=self.reader.container(self.created_id)
        validate(self.frame,actual,self.image_config,self.old_id,created_id=self.created_id,process=self.process,
                 resolved_owner_key=self.key,restart_restored=self.restored)
        require(identity(os.stat(self.path))==self.binding,'GATEWAY_PROCESS_NAMESPACE_CHANGED')
        if self.fd is not None:require(identity(os.fstat(self.fd))==self.binding,'HELD_NAMESPACE_FD_CHANGED')
        return {'containerId':self.created_id,'pid':self.process['pid'],'startedAt':self.process['startedAt'],
                'namespace':copy.deepcopy(self.binding),'oldNamespaceReused':False,
                'matchesPreviousNamespaceInode':self.binding==self.old_binding}
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None
    def __enter__(self):
        require(self.fd is not None,'OPEN_PROVEN_NAMESPACE_FD_REQUIRED');self.check();return self
    def __exit__(self,*unused):self.close()
