#!/usr/bin/env python3
"""Bounded fixture snapshots and exact single-volume native vacuum command."""
import hashlib
import os
from pathlib import Path
import re
import struct

CHUNK_BYTES=4194304

def require(value,code):
    if not value:raise ValueError(code)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def command_script(chunk):
    vid=chunk['volumeId']
    require(isinstance(vid,str) and re.fullmatch(r'[1-9][0-9]*',vid) and int(vid)<=0xffffffff,'ONE_EXACT_COMPACTION_VOLUME_REQUIRED')
    require(chunk['datFile']=='ouf-identity-fixture_'+vid+'.dat','EXACT_COMPACTION_COLLECTION_REQUIRED')
    return 'lock\nvolume.vacuum -collection=ouf-identity-fixture -volumeId='+vid+' -garbageThreshold=0.01\nunlock\n'

def snapshot(root,chunk,pid):
    command_script(chunk)
    require(root.is_dir() and not root.is_symlink(),'REGULAR_COMPACTION_ROOT_REQUIRED')
    paths=sorted(root.glob('*.dat'));require(0<len(paths)<=24,'BOUNDED_COMPACTION_VOLUMES_REQUIRED')
    files={};indexes={};prefix=hashlib.shake_256(b'OUF OCI33 interrupted streaming PUT v1').digest(CHUNK_BYTES)
    require(sha(prefix)==chunk['dataSha256'],'EXACT_ORPHAN_PAYLOAD_REQUIRED')
    total=0;matches=[]
    for path in paths:
        require(re.fullmatch(r'ouf-identity-fixture_[1-9][0-9]*\.dat',path.name) and path.is_file() and not path.is_symlink(),'REGULAR_FIXTURE_DAT_REQUIRED')
        st=path.stat();total+=st.st_size
        require(st.st_size<=33*1024*1024 and total<=128*1024*1024,'COMPACTION_DAT_BUDGET')
        raw=path.read_bytes();require(len(raw)==st.st_size and len(raw)>=8 and raw[0] in (2,3),'COMPLETE_COMPACTION_DAT_REQUIRED')
        files[path.name]={'bytes':len(raw),'allocatedBytes':st.st_blocks*512,'sha256':sha(raw)}
        if prefix in raw:matches.append(path.name)
        idx=path.with_suffix('.idx');require(idx.is_file() and not idx.is_symlink() and idx.stat().st_size<=1024,'BOUNDED_FIXTURE_INDEX_REQUIRED')
        iraw=idx.read_bytes();require(len(iraw)%16==0,'COMPLETE_COMPACTION_INDEX_REQUIRED')
        latest={}
        for pos in range(0,len(iraw),16):
            nid,offset,size=struct.unpack('>QIi',iraw[pos:pos+16]);require(nid>0 and (size>0 or size==-1),'KNOWN_COMPACTION_INDEX_ENTRY_REQUIRED')
            latest[nid]={'offset':offset*8,'size':size}
        live={};deleted=[]
        for nid,value in latest.items():
            if value['size']==-1:deleted.append(nid);continue
            off=value['offset'];require(off>=8 and off+20<=len(raw),'LIVE_NEEDLE_HEADER_BOUND')
            cookie,actual,size,data_size=struct.unpack('>IQiI',raw[off:off+20])
            require(actual==nid and size==value['size'] and 0<data_size<=CHUNK_BYTES and off+20+data_size<=len(raw),'LIVE_NEEDLE_INDEX_BINDING_REQUIRED')
            live[str(nid)]={'size':size,'dataBytes':data_size,'dataSha256':sha(raw[off+20:off+20+data_size]),'cookieHex':format(cookie,'08x')}
        indexes[idx.name]={'bytes':len(iraw),'sha256':sha(iraw),'liveNeedles':live,'deletedNeedles':sorted(deleted)}
    require(chunk['datFile'] in files,'ORPHAN_VOLUME_PRESENT_REQUIRED')
    temporary=sorted(p.name for p in root.iterdir() if p.suffix in ('.cpd','.cpx','.cpc','.cpldb'))
    deleted_fds=deleted_handles(pid)
    return {'volumePid':int(pid),'datFiles':files,'indexes':indexes,'datBytes':sum(v['bytes'] for v in files.values()),
            'datAllocatedBytes':sum(v['allocatedBytes'] for v in files.values()),'orphanPayloadFiles':matches,
            'temporaryCompactionFiles':temporary,'openDeletedFixtureFiles':sorted(deleted_fds),'mutatingRequests':0}

def deleted_handles(pid, proc_root=Path('/proc')):
    require(str(pid).isdigit() and int(pid)>0,'EXACT_VOLUME_PID_REQUIRED')
    fds=list((proc_root/str(pid)/'fd').iterdir());require(len(fds)<=256,'BOUNDED_VOLUME_FDS_REQUIRED')
    deleted_fds=[]
    for fd in fds:
        try:link=os.readlink(fd)
        except FileNotFoundError:continue
        if re.search(r'/ouf-identity-fixture_[0-9]+\.(dat|idx|cpd|cpx) \(deleted\)$',link):deleted_fds.append(link)
    return sorted(deleted_fds)


def validate(before,after,chunk):
    target=chunk['datFile'];index=str(Path(target).with_suffix('.idx'));nid=chunk['needleId']
    require(before['volumePid']==after['volumePid'],'SAME_LIVE_VOLUME_DURING_COMPACTION_REQUIRED')
    require(set(before['datFiles'])==set(after['datFiles']) and set(before['indexes'])==set(after['indexes']),'SAME_COMPACTION_VOLUME_SET_REQUIRED')
    require(before['orphanPayloadFiles']==[target] and after['orphanPayloadFiles']==[],'ORPHAN_PAYLOAD_PHYSICALLY_REMOVED_REQUIRED')
    for state in (before,after):
        require(not state['temporaryCompactionFiles'] and not state['openDeletedFixtureFiles'],'NO_COMPACTION_LEFTOVERS_OR_OPEN_DELETED_FILES')
    require(nid in before['indexes'][index]['deletedNeedles'] and nid not in after['indexes'][index]['deletedNeedles']
            and str(nid) not in after['indexes'][index]['liveNeedles'],'ORPHAN_INDEX_ENTRY_REMOVED_REQUIRED')
    for name in before['datFiles']:
        idx=str(Path(name).with_suffix('.idx'))
        require(before['indexes'][idx]['liveNeedles']==after['indexes'][idx]['liveNeedles'],'ALL_LIVE_NEEDLES_PRESERVED_REQUIRED')
        if name!=target:
            require(before['datFiles'][name]==after['datFiles'][name] and before['indexes'][idx]==after['indexes'][idx],'UNSELECTED_VOLUMES_UNCHANGED_REQUIRED')
    logical=before['datBytes']-after['datBytes'];allocated=before['datAllocatedBytes']-after['datAllocatedBytes']
    require(logical>=CHUNK_BYTES and allocated>=CHUNK_BYTES,'REAL_DAT_LENGTH_AND_ALLOCATION_REDUCTION_REQUIRED')
    require(after['datFiles'][target]['bytes']<before['datFiles'][target]['bytes'],'TARGET_VOLUME_SHRINK_REQUIRED')
    return {'volumeId':chunk['volumeId'],'fileId':chunk['fileId'],'datBytesReclaimed':logical,'allocatedDatBytesReclaimed':allocated,
            'allLiveNeedlesPreserved':True,'unselectedVolumesUnchanged':True,'orphanPayloadAbsentFromDat':True,
            'orphanIndexEntryRemoved':True,'noTemporaryOrOpenDeletedFiles':True,'vacuumCommands':1,'mutatingRetries':0,
            'postCompactionRestartQualified':False,'compactionCrashQualified':False,'secureErasureQualified':False}


def validate_restart(before,after):
    """Exact compacted storage and allocation must survive a fresh service generation."""
    require(isinstance(after.get('volumePid'),int) and after['volumePid']>0,'LIVE_RESTART_VOLUME_PID_REQUIRED')
    for state in (before,after):
        require(not state['orphanPayloadFiles'] and not state['temporaryCompactionFiles']
                and not state['openDeletedFixtureFiles'],'NO_POST_COMPACTION_ORPHAN_OR_LEFTOVERS')
    require({k:v for k,v in before.items() if k!='volumePid'}=={k:v for k,v in after.items() if k!='volumePid'},
            'EXACT_COMPACTED_STORAGE_AND_ALLOCATION_MUST_SURVIVE')
    # Container/namespace replacement is verified independently, never inferred from PID reuse.
