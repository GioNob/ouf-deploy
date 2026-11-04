#!/usr/bin/env python3
"""Native-only fixture witness, appended past a tombstone and observed through IDX/DAT."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import re
import struct

BYTES=1048593
NEEDLE_ID=(1<<48)+33
COOKIE='33aabbcc'

def require(ok,code):
    if not ok:raise ValueError(code)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def body():return hashlib.shake_256(b'OUF OCI33 live relocation witness v1').digest(BYTES)

def identity(chunk):
    vid=chunk['volumeId']
    require(isinstance(vid,str) and re.fullmatch(r'[1-9][0-9]*',vid) and int(vid)<=0xffffffff,'EXACT_RELOCATION_VOLUME_REQUIRED')
    require(chunk['datFile']=='ouf-identity-fixture_'+vid+'.dat','EXACT_RELOCATION_COLLECTION_REQUIRED')
    return {'volumeId':vid,'datFile':chunk['datFile'],'needleId':NEEDLE_ID,'cookieHex':COOKIE,
            'fileId':vid+',01000000000021'+COOKIE,'dataBytes':BYTES,'dataSha256':sha(body())}

def prepare(snapshot,chunk):
    witness=identity(chunk)
    for idx in snapshot['indexes'].values():
        require(str(NEEDLE_ID) not in idx['liveNeedles'] and NEEDLE_ID not in idx['deletedNeedles'],'RESERVED_WITNESS_ID_MUST_BE_UNUSED')
    index=str(Path(chunk['datFile']).with_suffix('.idx'))
    require(chunk['needleId'] in snapshot['indexes'][index]['deletedNeedles'],'DELETED_RECORD_BEFORE_LIVE_WITNESS_REQUIRED')
    return witness

def upload(ip,witness):
    require(witness==identity(witness),'EXACT_RELOCATION_WITNESS_REQUIRED')
    # Explicit fixture ID, not a master assignment or an additional S3 object.
    conn=http.client.HTTPConnection(ip,18080,timeout=30)
    try:
        conn.request('GET','/'+witness['fileId'],headers={'Connection':'close'})
        response=conn.getresponse();raw=response.read(65537)
        require(response.status==404 and len(raw)<=65536,'NATIVE_WITNESS_ABSENT_BEFORE_WRITE_REQUIRED')
    finally:conn.close()
    data=body();conn=http.client.HTTPConnection(ip,18080,timeout=30)
    try:
        conn.request('POST','/'+witness['fileId'],body=data,headers={'Content-Type':'application/octet-stream',
            'Content-Disposition':'attachment; filename="relocation-witness.bin"','Connection':'close',
            'Content-MD5':base64.b64encode(hashlib.md5(data).digest()).decode()})
        response=conn.getresponse();raw=response.read(65537)
        require(len(raw)<=65536 and response.status==201,'ONE_ACKNOWLEDGED_NATIVE_WITNESS_WRITE_REQUIRED')
        result=json.loads(raw);require(result.get('size')==BYTES and not result.get('error'),'COMPLETE_NATIVE_WITNESS_ACK_REQUIRED')
        return {'fileId':witness['fileId'],'preWriteStatus':404,'writeStatus':201,'dataBytes':BYTES,'dataSha256':sha(data),
                'nativeWriteRequests':1,'masterAssignments':0,'mutatingRetries':0,'filerMetadataLinked':False}
    finally:conn.close()

def observe(root,witness):
    require(witness==identity(witness),'EXACT_RELOCATION_WITNESS_REQUIRED')
    require(root.is_dir() and not root.is_symlink(),'REGULAR_RELOCATION_ROOT_REQUIRED')
    dat=root/witness['datFile'];idx=dat.with_suffix('.idx')
    require(dat.is_file() and not dat.is_symlink() and dat.stat().st_size<=33*1024*1024,'BOUNDED_RELOCATION_DAT_REQUIRED')
    require(idx.is_file() and not idx.is_symlink() and idx.stat().st_size<=1024,'BOUNDED_RELOCATION_INDEX_REQUIRED')
    iraw=idx.read_bytes();require(len(iraw)%16==0,'COMPLETE_RELOCATION_INDEX_REQUIRED')
    matches=[]
    for pos in range(0,len(iraw),16):
        nid,offset,size=struct.unpack('>QIi',iraw[pos:pos+16])
        if nid==NEEDLE_ID:matches.append((offset*8,size,pos))
    require(len(matches)==1 and matches[0][1]>0,'SINGLE_LIVE_WITNESS_INDEX_ENTRY_REQUIRED')
    off,size,index_pos=matches[0];raw=dat.read_bytes()
    require(len(raw)>=8 and raw[0] in (2,3) and off>=8 and off+20+BYTES<=len(raw),'BOUNDED_RELOCATION_NEEDLE_REQUIRED')
    cookie,nid,stored_size,length=struct.unpack('>IQiI',raw[off:off+20])
    require(nid==NEEDLE_ID and format(cookie,'08x')==COOKIE and stored_size==size and length==BYTES
            and sha(raw[off+20:off+20+length])==witness['dataSha256'],'EXACT_NATIVE_WITNESS_BODY_REQUIRED')
    return {**witness,'needleOffset':off,'needleSize':size,'dataOffset':off+20,'datBytes':len(raw),
            'datSha256':sha(raw),'indexBytes':len(iraw),'indexSha256':sha(iraw),'indexRecord':index_pos//16,'indexPrefixSha256':sha(iraw[:index_pos]),'prefixSha256':sha(raw[:off]),'mutatingRequests':0}

def validate_append(before,after,witness,observed):
    target=witness['datFile'];index=str(Path(target).with_suffix('.idx'));key=str(NEEDLE_ID)
    require(set(before['datFiles'])==set(after['datFiles']) and set(before['indexes'])==set(after['indexes']),'SAME_WITNESS_VOLUME_SET_REQUIRED')
    for name in before['datFiles']:
        idx=str(Path(name).with_suffix('.idx'))
        if name!=target:
            require(before['datFiles'][name]==after['datFiles'][name] and before['indexes'][idx]==after['indexes'][idx], 'WITNESS_UNSELECTED_VOLUME_UNCHANGED_REQUIRED')
    old=before['indexes'][index];new=after['indexes'][index]
    require(key not in old['liveNeedles'] and set(new['liveNeedles'])==set(old['liveNeedles'])|{key},'ONE_NEW_NATIVE_WITNESS_REQUIRED')
    require(all(new['liveNeedles'][k]==v for k,v in old['liveNeedles'].items()) and old['deletedNeedles']==new['deletedNeedles'], 'WITNESS_PRESERVES_EXISTING_NEEDLES_REQUIRED')
    require(observed['needleOffset']==before['datFiles'][target]['bytes'] and observed['prefixSha256']==before['datFiles'][target]['sha256'], 'NATIVE_WITNESS_APPENDED_WITH_EXACT_PREFIX_REQUIRED')
    require(observed['indexRecord']*16==old['bytes'] and observed['indexPrefixSha256']==old['sha256']
            and new['bytes']==old['bytes']+16,'NATIVE_WITNESS_APPENDED_INDEX_PREFIX_REQUIRED')
    require(observed['datBytes']==after['datFiles'][target]['bytes'] and observed['datSha256']==after['datFiles'][target]['sha256']
        and observed['indexSha256']==new['sha256'],'WITNESS_SNAPSHOT_BINDING_REQUIRED')
    require(new['liveNeedles'][key]=={'size':observed['needleSize'],'dataBytes':BYTES,'dataSha256':witness['dataSha256'],'cookieHex':COOKIE},'WITNESS_NATIVE_IDENTITY_REQUIRED')

def validate(before,after,chunk,reclaimed):
    expected=identity(chunk)
    require(all(before[k]==after[k]==v for k,v in expected.items()) and before['needleSize']==after['needleSize'],'RELOCATED_IDENTITY_AND_BODY_REQUIRED')
    require(before['needleOffset']>=chunk['needleOffset']+20+chunk['dataBytes'],'LIVE_WITNESS_AFTER_DELETED_RECORD_REQUIRED')
    shift=before['needleOffset']-after['needleOffset']
    require(after['needleOffset']>=8 and before['needleOffset']%8==after['needleOffset']%8==0
        and shift>=4194304 and shift==reclaimed['datBytesReclaimed'],'REAL_RELOCATION_ACROSS_RECLAIMED_BYTES_REQUIRED')
    require(before['dataOffset']==before['needleOffset']+20 and after['dataOffset']==after['needleOffset']+20,'RELOCATED_DATA_OFFSET_REQUIRED')
    require(before['datBytes']-after['datBytes']==shift,'EXACT_RELOCATION_AND_DAT_SHRINK_REQUIRED')
    return {'fileId':expected['fileId'],'dataBytes':BYTES,'dataSha256':expected['dataSha256'],
            'needleOffsetBefore':before['needleOffset'],'needleOffsetAfter':after['needleOffset'],'offsetReduction':shift,
            'sameNeedleCookieAndBody':True,'nativeWitnessWrites':1,'mutatingRetries':0,'filerMetadataLinked':False}
