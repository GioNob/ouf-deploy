"""Fixed-scope metadata reader; no signature verification or target authority.

Read existing v2 DSSE/SBOM and bundle receipts. Never execute report content,
read keys, call providers, scan images, sign, configure or start containers.
Only hash references, public attestation identity URLs and typed facts escape.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

ROOT = Path('/etc/ouf/deploy-snapshots/semantic-image-remediation-20261006-v2')
EXPECTED = {
 'provenance.json':'dd647a14dd704c28a19ccb721880fbdbefc2d34878fcab54280ef5bc269e6f08',
 'adapter-sbom-verification.json':'130be704341f05592ea262b71a717b6517b44f1fec1d794bef784e112c11c965',
 'southbound-sbom-verification.json':'1173e841b3138cebf039db7c9b53df28e841fb563058cd63273eb2f7c7b22101',
 'adapter-sbom.json':'17107dfece92a9736f0be9c5fe1bcaa99882125b00c86195d5aea49d31278431',
 'southbound-sbom.json':'ac01cc4dc4d29880f5fc52c70b4758939c906d9a872e0af7ed1946561b5b195a',
}
TARGET = {
 'adapterManifest':'277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc',
 'adapterConfig':'62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320',
 'southboundManifest':'c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366',
 'southboundConfig':'d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04',
}

def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):
    for parent in path.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise ValueError('REPORT_ANCESTOR_CUSTODY_UNPROVEN')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink!=1 or before.st_size>16*1024*1024:
            raise ValueError('REPORT_FILE_CUSTODY_UNPROVEN')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(16*1024*1024+1)
        def identity(i):return (i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns)
        if len(raw)!=before.st_size or identity(before)!=identity(os.fstat(fd)) or identity(before)!=identity(path.lstat()):
            raise ValueError('REPORT_CHANGED_DURING_READ')
        if path.name in EXPECTED and sha(raw)!=EXPECTED[path.name]:raise ValueError('PREVIOUS_REPORT_HASH_DRIFT')
        return raw
    finally:os.close(fd)

def public_url(value):
    if not isinstance(value,str) or len(value)>400:return None
    try:p=urlsplit(value)
    except ValueError:return None
    if p.scheme!='https' or p.hostname not in {'github.com','api.github.com','token.actions.githubusercontent.com',
            'slsa.dev','in-toto.io','cyclonedx.org','spdx.dev'} or p.username or p.password or p.query or p.fragment:
        return None
    if not re.fullmatch(r'[A-Za-z0-9_./@+-]*',p.path):return None
    return value

def summarize(data):
    refs=[];urls=[];facts=[];decoded=[];nodes=[0]
    def walk(value,path='$',depth=0):
        nodes[0]+=1
        if depth>30 or nodes[0]>300000:raise ValueError('REPORT_STRUCTURE_UNBOUNDED')
        if isinstance(value,dict):
            if 'dsseEnvelope' in value and isinstance(value['dsseEnvelope'],dict):
                payload=value['dsseEnvelope'].get('payload')
                if not isinstance(payload,str) or len(payload)>12*1024*1024:raise ValueError('INVALID_DSSE_PAYLOAD')
                raw=base64.b64decode(payload,validate=True)
                decoded.append({'path':path+'.dsseEnvelope','payloadHash':sha(raw),
                                'signatureCount':len(value['dsseEnvelope'].get('signatures',[]))})
                walk(json.loads(raw),path+'.decodedStatement',depth+1)
            for key,item in value.items():
                if key in ('payload','rawBytes','signatures','canonicalizedBody',
                           'components','packages','files','dependencies','vulnerabilities'):continue
                label=key if isinstance(key,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',key) else '<field>'
                here=path+'.'+label
                if key in ('verified','verificationPassed','acceptanceGranted','completeCreationAccepted','compatible') and type(item) is bool:
                    facts.append({'path':here,'reportedValue':item})
                if key in ('status','state','result') and isinstance(item,str) and item in {'PASS','FAIL','BLOCKED','VERIFIED','SUCCESS','ACCEPTED','REJECTED'}:
                    facts.append({'path':here,'reportedValue':item})
                walk(item,here,depth+1)
        elif isinstance(value,list):
            for i,item in enumerate(value):walk(item,path+'['+str(i)+']',depth+1)
        elif isinstance(value,str):
            hashes=re.findall(r'(?:sha256:|(?<![A-Za-z0-9]))([0-9a-f]{64})(?![A-Za-z0-9])',value)
            for digest in hashes:refs.append({'path':path,'sha256':digest})
            url=public_url(value)
            if url and any(label in path.lower() for label in ('identity','issuer','subjectalternativename','builder','workflow','repository','predicatetype')):
                urls.append({'path':path,'publicUrl':url})
    walk(data)
    refs=list({(r['path'],r['sha256']):r for r in refs}.values())
    if len(refs)>300 or len(urls)>40 or len(facts)>60:raise ValueError('REPORT_METADATA_OUTPUT_UNBOUNDED')
    return {'hashReferences':refs,'publicAttestationUrls':urls,'reportedFacts':facts,'decodedEnvelopes':decoded,
            'currentDigestReferences':{key:any(r['sha256']==digest for r in refs) for key,digest in TARGET.items()}}

def main():
    if os.geteuid()!=0:raise SystemExit('ROOT_READ_REQUIRED')
    paths=[ROOT/'evidence/attestations'/name for name in EXPECTED]
    paths += [ROOT/'receipt.json',ROOT/'evidence/receipt.json',ROOT/'evidence/compatibility.json']
    for path in paths:
        report={'file':str(path.relative_to(ROOT)),'signatureVerifiedByThisReader':False,
                'acceptanceGrantedByThisReader':False,'containerOperations':0,'privateKeysRead':0}
        try:
            raw=read(path);report.update(bytes=len(raw),sha256=sha(raw),**summarize(json.loads(raw)))
        except Exception as error:
            reason=str(error) if type(error) is ValueError and re.fullmatch('[A-Z_]{1,80}',str(error)) else 'EXISTING_REPORT_READ_UNPROVEN'
            report.update(status='BLOCKED',phase='READ_EXISTING_IMAGE_EVIDENCE_METADATA',reason=reason,errorType=type(error).__name__)
        print('OUF_V2_ATTESTATION_METADATA='+json.dumps(report,sort_keys=True,separators=(',',':')))

if __name__=='__main__':main()
