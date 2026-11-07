#!/usr/bin/env python3
"""Read-only native chunk identity, index tombstone and direct volume observations."""
import hashlib
import http.client
from pathlib import Path
import re
import struct

CHUNK_BYTES=4194304

def require(value,code):
    if not value:raise ValueError(code)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def identify(root,observation):
    require(root.is_dir() and not root.is_symlink(),'REGULAR_CHUNK_ROOT_REQUIRED')
    matches=observation['matches'];require(observation['persistedPrefixFound'] and len(matches)==1,'ONE_EXACT_NATIVE_CHUNK_REQUIRED')
    match=matches[0];name=match['file'];filename=re.fullmatch(r'ouf-identity-fixture_([1-9][0-9]*)\.dat',name)
    require(filename is not None,'EXACT_FIXTURE_DAT_NAME_REQUIRED')
    offset=match['offset'];require(isinstance(offset,int) and offset>=28 and (offset-20)%8==0,'ALIGNED_NEEDLE_HEADER_REQUIRED')
    path=root/name;require(path.is_file() and not path.is_symlink(),'REGULAR_CHUNK_DAT_REQUIRED')
    require(path.stat().st_size<=33*1024*1024,'CHUNK_DAT_BUDGET')
    with path.open('rb') as f:
        version=f.read(1)[0];f.seek(offset-20);raw=f.read(20+CHUNK_BYTES)
    require(version in (2,3) and len(raw)==20+CHUNK_BYTES,'EXACT_V2_V3_NEEDLE_REQUIRED')
    cookie,needle,size,data_size=struct.unpack('>IQiI',raw[:20])
    require(needle>0 and data_size==CHUNK_BYTES and CHUNK_BYTES+5<=size<=CHUNK_BYTES+65536,'EXACT_CHUNK_NEEDLE_SIZE_REQUIRED')
    require(match['bytes']==CHUNK_BYTES and sha(raw[20:])==match['sha256']==observation['expectedChunkSha256'],'CHUNK_PAYLOAD_BINDING_REQUIRED')
    nid=format(needle,'x');nid=('0'+nid) if len(nid)%2 else nid
    return {'fileId':filename[1]+','+nid+format(cookie,'08x'),'volumeId':filename[1],'needleId':needle,
            'cookieHex':format(cookie,'08x'),'datFile':name,'needleOffset':offset-20,'needleSize':size,
            'dataOffset':offset,'dataBytes':data_size,'dataSha256':match['sha256'],'volumeVersion':version}

def index_state(root,chunk):
    name=chunk['datFile'];require(re.fullmatch(r'ouf-identity-fixture_[1-9][0-9]*\.dat',name),'EXACT_FIXTURE_DAT_NAME_REQUIRED')
    require(root.is_dir() and not root.is_symlink(),'REGULAR_CHUNK_ROOT_REQUIRED')
    path=root/Path(name).with_suffix('.idx')
    require(path.is_file() and not path.is_symlink() and path.stat().st_size<=1024*1024,'BOUNDED_REGULAR_INDEX_REQUIRED')
    raw=path.read_bytes();require(0<len(raw)<=1024*1024 and len(raw)%16==0,'EXACT_16_BYTE_INDEX_RECORDS_REQUIRED')
    entries=[]
    for pos in range(0,len(raw),16):
        nid,offset,size=struct.unpack('>QIi',raw[pos:pos+16])
        if nid==chunk['needleId']:entries.append({'record':pos//16,'offset':offset*8,'size':size})
    require(entries and entries[0]['offset']==chunk['needleOffset'] and entries[0]['size']==chunk['needleSize'],'ORIGINAL_CHUNK_INDEX_BINDING_REQUIRED')
    require(len(entries)<=2 and (len(entries)==1 or entries[-1]['size']==-1),'SINGLE_ORPHAN_TOMBSTONE_REQUIRED')
    return {'fileId':chunk['fileId'],'indexFile':path.name,'indexBytes':len(raw),'indexSha256':sha(raw),
            'matchingEntries':entries,'tombstoned':len(entries)==2 and entries[-1]['size']==-1,'mutatingRequests':0}

def read_chunk(ip,chunk,expected):
    require(expected in ('present','absent'),'KNOWN_CHUNK_READ_EXPECTATION_REQUIRED')
    fid=chunk['fileId'];require(re.fullmatch(r'[1-9][0-9]*,[0-9a-f]{10,24}',fid),'EXACT_CHUNK_FILE_ID_REQUIRED')
    conn=http.client.HTTPConnection(ip,18080,timeout=10)
    try:
        conn.request('GET','/'+fid,headers={'Connection':'close'})
        response=conn.getresponse();raw=response.read(CHUNK_BYTES+1)
        require(len(raw)<=CHUNK_BYTES,'BOUNDED_CHUNK_RESPONSE_REQUIRED')
        if expected=='present':require(response.status==200 and len(raw)==chunk['dataBytes'] and sha(raw)==chunk['dataSha256'],'EXACT_LIVE_CHUNK_REQUIRED')
        else:require(response.status==404,'TOMBSTONED_CHUNK_MUST_BE_404')
        return {'fileId':fid,'expectation':expected,'status':response.status,'responseBytes':len(raw),'responseSha256':sha(raw),'mutatingRequests':0}
    finally:conn.close()
