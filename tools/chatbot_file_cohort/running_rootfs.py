"""Exact immutable image seal plus a bounded, process-bound JVM runtime delta.

This read-only predicate never grants authority or changes an old seal. It is
only for the already released Registry generation; paused images retain their
original full-seal predicate. Every entry is still scanned by the v1 sealer.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import types
from tools.chatbot_file_cohort.plan import encoded,require

PROFILE='ouf.chatbot-running-registry-rootfs.v1'
PERF_PATH='tmp/hsperfdata_ouf/1'
PERF_SCHEMA_SHA='3667d1fd311aae174a4811b4abf57798f6f590f48e2bef5a742e5ff6cc3542f8'
PERF_CONSTANTS_SHA='f9eab5bd81f1150b6fa1d609f2afee1c516219d0e417b6352544185405ab60fc'
QUALIFICATION={'profile':PROFILE,'reproductionSource':'a599054050de5597e36d513464f182f8e022c2a1',
    'reproductionRunId':38832922101,'artifactId':12018067298,
    'artifactSha256':'0a6f72d894a7d6251a4d6f9d1496e9b60a6cbad52c49e2a9016ffe8bd1ba15c1',
    'originalEntries':9302,'runtimeEntries':8,'runtimeRegularFileBytes':32768,
    'perfSchemaSha256':PERF_SCHEMA_SHA,'perfConstantsSha256':PERF_CONSTANTS_SHA,
    'allOriginalEntriesSealed':True,'kernelMappedFileRequired':True,'genericTmpExclusion':False,
    'sameReleasedGenerationRequired':True,'runtimeAuthorityIssued':False}

def replay(records):
    h=hashlib.sha256(b'OUF-ROOTFS-SEAL\x00V1\x00');total=0
    for item in records.values():
        raw=encoded(item);h.update(len(raw).to_bytes(4,'big'));h.update(raw)
        if item['kind']=='file':total+=item['size']
    return {'schema':'ouf.semantic-rootfs-seal.v1','sha256':h.hexdigest(),'entries':len(records),'bytes':total}

def capture(root,limits,budget):
    from tools.semantic_provider_node_observation import rootfs_seal
    # Clone only the function globals; do not monkey-patch the shared sealer.
    records={};namespace=dict(rootfs_seal.__globals__);original=namespace['encoded']
    def record(item):
        require(item['path']not in records,'RUNNING_ROOTFS_DUPLICATE_ENTRY')
        records[item['path']]=item;return original(item)
    namespace['encoded']=record
    seal=types.FunctionType(rootfs_seal.__code__,namespace)(root,limits,budget)
    require(seal==replay(records),'RUNNING_ROOTFS_CAPTURE_DRIFT')
    return seal,records

def perfdata(raw):
    """Parse bounded HotSpot PerfData v2, retaining schema and values privately."""
    require(type(raw)is bytes and len(raw)==32768 and raw[:8]==bytes.fromhex('cafec0c001020001'),
            'RUNNING_JVM_PERFDATA_HEADER_DRIFT')
    def integer(data,start,size=4):return int.from_bytes(data[start:start+size],'little',signed=True)
    used,overflow=integer(raw,8),integer(raw,12);offset,count=integer(raw,24),integer(raw,28)
    require(32<=used<=32768 and overflow==0 and offset==32 and 1<=count<=512 and integer(raw,16,8)>=0,
            'RUNNING_JVM_PERFDATA_BOUNDS_DRIFT')
    items={};schema={}
    for _ in range(count):
        require(offset%8==0 and offset+20<=used,'RUNNING_JVM_PERFDATA_ENTRY_BOUNDS')
        length,name_offset,vector=[integer(raw,offset+i)for i in(0,4,8)]
        dtype,flags,units,variability=raw[offset+12:offset+16];data_offset=integer(raw,offset+16)
        require(24<=length<=4096 and length%8==0 and offset+length<=used and name_offset==20
                and 20<data_offset<length and 0<=vector<=2048 and flags in(0,1) and units in range(1,7)
                and variability in(1,2,3),'RUNNING_JVM_PERFDATA_ENTRY_SCHEMA')
        names=raw[offset+name_offset:offset+data_offset];end=names.find(b'\0')
        require(0<end<=255 and not any(names[end:]),'RUNNING_JVM_PERFDATA_NAME_PADDING')
        name=names[:end].decode('ascii')
        require(re.fullmatch(r'(?:java|sun|com\.sun)\.[A-Za-z0-9_.]+',name)is not None and name not in items,
                'RUNNING_JVM_PERFDATA_NAME_DRIFT')
        require((dtype==ord('J') and vector==0 and data_offset%8==0)or(dtype==ord('B')and 1<=vector<=2048 and units==5),
                'RUNNING_JVM_PERFDATA_TYPE_DRIFT')
        size=8 if dtype==ord('J')else vector
        require(data_offset+size<=length and not any(raw[offset+data_offset+size:offset+length]),'RUNNING_JVM_PERFDATA_DATA_BOUNDS')
        value=raw[offset+data_offset:offset+data_offset+size]
        if dtype==ord('B'):
            stop=value.find(b'\0');require(stop>=0,'RUNNING_JVM_PERFDATA_STRING_UNTERMINATED')
            value=value[:stop]
        items[name]=value;schema[name]=[chr(dtype),flags,units,variability]
        offset+=length
    require(offset==used and not any(raw[used:]),'RUNNING_JVM_PERFDATA_TRAILING_DATA')
    require(items.get('sun.rt.javaCommand')==b'/app/application.jar','RUNNING_JVM_PERFDATA_APPLICATION_DRIFT')
    return schema,items

def mapped_file(root,relative,pid,budget):
    """Use kernel dev/inode and namespace PID to bind the data to this JVM."""
    budget.check();proc=Path('/proc')/str(pid)
    def bounded(path,limit):
        with path.open('rb')as stream:raw=stream.read(limit+1)
        require(len(raw)<=limit,'RUNNING_JVM_KERNEL_METADATA_UNBOUNDED');return raw
    status=bounded(proc/'status',65536).decode();namespace=[x.split(':',1)[1].split()for x in status.splitlines()if x.startswith('NSpid:')]
    require(len(namespace)==1 and namespace[0]==[str(pid),'1'],'RUNNING_JVM_NAMESPACE_PID_DRIFT')
    path=root/relative
    # Every ancestor under the scanned image is opened without following links.
    directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in Path(relative).parts[:-1]:
            nested=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory);os.close(directory);directory=nested
        fd=os.open(Path(relative).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            before=os.fstat(fd)
            def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode)==0o600 and before.st_uid==before.st_gid==10001
                    and before.st_nlink==1 and before.st_size==32768 and not os.listxattr(fd),'RUNNING_JVM_PERFDATA_CUSTODY_DRIFT')
            maps=bounded(proc/'maps',1048576).decode();matches=[]
            for line in maps.splitlines():
                fields=line.split(None,5)
                if len(fields)!=6:continue
                dev=fields[3].split(':')
                if len(dev)==2 and os.makedev(*[int(x,16)for x in dev])==before.st_dev and int(fields[4])==before.st_ino:
                    begin,end=[int(x,16)for x in fields[0].split('-')]
                    require(fields[1]=='rw-s' and fields[2]=='00000000' and end-begin==32768 and fields[5]=='/'+relative,
                            'RUNNING_JVM_PERFDATA_MAPPING_DRIFT');matches.append(fields)
            require(len(matches)==1,'RUNNING_JVM_PERFDATA_MAPPING_REQUIRED')
            raw=os.read(fd,32769);schema,values=perfdata(raw)
            require(identity(before)==identity(os.fstat(fd))==identity(os.stat(Path(relative).name,dir_fd=directory,follow_symlinks=False))
                    and identity(before)==identity((proc/'root'/relative).stat()),'RUNNING_JVM_PERFDATA_IDENTITY_DRIFT')
            # mmap writers may update mtime/ctime between complete scans.
            # They are not part of the v1 semantic seal or kernel file identity.
            # They remain checked within this single bounded read above.
            return schema,values,identity(before)[:7]
        finally:os.close(fd)
    finally:os.close(directory)

def immutable_projection(records,expected):
    """Remove exactly eight typed runtime entries, then replay the original seal."""
    work=[k for k in records if re.fullmatch(r'tmp/tomcat\.8080\.[0-9]{1,20}',k)]
    doc=[k for k in records if re.fullmatch(r'tmp/tomcat-docbase\.8080\.[0-9]{1,20}',k)]
    require(len(work)==len(doc)==1,'RUNNING_ROOTFS_EXACT_TOMCAT_ROOTS_REQUIRED')
    shape={'tmp/hsperfdata_ouf':(0o755,2),doc[0]:(0o700,2),work[0]:(0o700,3)}
    for suffix,links in [('/work',3),('/work/Tomcat',3),('/work/Tomcat/localhost',3),('/work/Tomcat/localhost/ROOT',2)]:
        shape[work[0]+suffix]=(0o755,links)
    for path,(mode,links)in shape.items():
        require(records.get(path)=={'path':path,'kind':'directory','mode':mode,'uid':10001,'gid':10001,'links':links,'xattrs':{}},
                'RUNNING_ROOTFS_DIRECTORY_SHAPE_DRIFT')
    item=records.get(PERF_PATH,{})
    require(set(item)=={'path','kind','mode','uid','gid','links','xattrs','size','sha256'}
            and {k:v for k,v in item.items()if k!='sha256'}=={'path':PERF_PATH,'kind':'file','mode':0o600,'uid':10001,'gid':10001,'links':1,'xattrs':{},'size':32768}
            and type(item['sha256'])is str and re.fullmatch('[0-9a-f]{64}',item['sha256'])is not None,'RUNNING_ROOTFS_PERFDATA_SHAPE_DRIFT')
    allowed=set(shape)|{PERF_PATH};retained={k:v for k,v in records.items()if k not in allowed}
    require(replay(retained)==expected,'RUNNING_ROOTFS_ORIGINAL_IMAGE_SEAL_DRIFT')
    return {k:{f:v for f,v in records[k].items()if f!='sha256'}for k in sorted(allowed)}

def verify_perf_schema(schema,values):
    require(hashlib.sha256(encoded(schema)).hexdigest()==PERF_SCHEMA_SHA,'RUNNING_JVM_PERFDATA_QUALIFIED_SCHEMA_DRIFT')
    constants={k:v.hex()for k,v in values.items()if schema[k][0]=='B'and schema[k][3]==1}
    require(hashlib.sha256(encoded(constants)).hexdigest()==PERF_CONSTANTS_SHA,'RUNNING_JVM_PERFDATA_QUALIFIED_CONSTANTS_DRIFT')

def observe(root,limits,budget,expected,pid):
    """Two complete scans; only the qualified JVM counter values may change."""
    before=None
    for _ in range(2):
        seal,records=capture(root,limits,budget);shape=immutable_projection(records,expected)
        schema,values,identity=mapped_file(root,PERF_PATH,pid,budget);verify_perf_schema(schema,values)
        binding=(shape,identity)
        require(before is None or binding==before,'RUNNING_ROOTFS_RUNTIME_IDENTITY_CHANGED')
        before=binding
    return {'profile':PROFILE,'originalRootfsSeal':dict(expected),'runtimeEntries':8,
            'kernelMappedPerfData':True,'stableRuntimeIdentity':True,'originalSealUnchanged':True,
            'privateMountContentsRead':False,'runtimeAuthorityIssued':False}
