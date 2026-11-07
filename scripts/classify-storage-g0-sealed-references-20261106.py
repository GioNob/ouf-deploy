#!/usr/bin/env python3
"""Classify the existing G0 references locally; no repair, provider I/O or admission.
Only aggregate fixed labels leave the VPS; private references and rows stay local.
"""
import collections,hashlib,json,os,re,stat,sys
from pathlib import Path
SCOPE=Path('/var/lib/ouf-g0-network-preparation-20261106/evidence/seaweedfs-g0-20261106-v2')
RECON_SHA='5c0bc6d7351008da9dd53af5489dcf0167c280fe73e99db52de3e9f8c2e5db6a'
SOURCE_PINS={'onboarding':'d5155899b09dda298494b68cefa7e1f281167652','onboarding-retained':'73498c17596ae155a3ed9ab36acfd6bb69da9846','udp':'0d40da05408a14db31d4d41af2372d6a71480291','ingestion':'4165b9e149be467d5d7c6bed35e4e1af4e249db1'}
def require(ok):
    if not ok: raise ValueError('LOCAL_RECEIPT_MISMATCH')
def identity(s):
    return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read_at(parent,name):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=32*1024*1024)
        chunks=[];remaining=before.st_size
        while remaining:
            chunk=os.read(fd,min(remaining,65536));require(bool(chunk));chunks.append(chunk);remaining-=len(chunk)
        raw=b''.join(chunks)
        require(identity(before)==identity(os.fstat(fd))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)))
        return raw,hashlib.sha256(raw).hexdigest()
    finally: os.close(fd)

def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def fingerprint(v):return hashlib.sha256(canonical(v)).hexdigest()
def read_relative(root,relative):
    parts=Path(relative).parts;require(not Path(relative).is_absolute() and '..' not in parts)
    parent=os.dup(root)
    try:
        for part in parts[:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            os.close(parent);parent=child
            info=os.fstat(parent);require(info.st_uid==0 and not info.st_mode&0o022)
        return read_at(parent,parts[-1])
    finally:os.close(parent)
def export_rows(raw,profile,binding):
    require(hashlib.sha256(raw).hexdigest()==binding['rawSha256'])
    lines=raw.splitlines();require(2<=len(lines)<=400000 and all(len(x)<=256*1024 for x in lines))
    docs=[json.loads(x) for x in lines];h=docs[0]
    require(h['kind']=='header' and h['schema']=='ouf.storage-g0-db-export.v1' and h['profile']==profile and h['sourceSchemaCommit']==binding['sourceSchemaCommit']==SOURCE_PINS[profile])
    require(h['readOnly']=='on' and h['isolation']=='repeatable read' and h['profileSchemaCompatible'] is True and docs[-1]=={'kind':'footer','complete':True})
    rows={};current=None
    for d in docs[1:-1]:
        if d['kind']=='section':
            current=d['table'];require(current not in rows);rows[current]=[]
        else:
            require(d['kind']=='row' and d['table']==current and type(d['value']) is dict and len(rows[current])<10000)
            rows[current].append(d['value'])
    return rows
def classify(rows,joined,collection,inventory):
    def rs(t):return rows.get(t,[])
    def index(t,key):
        out={r[key]:r for r in rs(t)};require(len(out)==len(rs(t)));return out
    assets=index('ouf_onboarding.managed_file_asset','asset_id')
    profiles=index('ouf_onboarding.file_profile','profile_id')
    jobs=index('ouf_onboarding.file_profile_job','job_id')
    lakes=index('ouf_udp.lake_object','lake_object_id')
    runs=index('ouf_ingestion.ing_run','run_id')
    attempts=index('ouf_ingestion.processing_attempt','attempt_id')
    objects=collection['objects'];require(len(objects)==120 and collection['complete'] is True)
    seen=[];owners=collections.Counter();refs=collections.Counter()
    def issue(code,ref):seen.append((code,fingerprint(ref)))
    def kind(ref,row,field,table):
        if not isinstance(ref,str):return 'UNRESOLVED_REFERENCE_TYPE'
        if table=='ouf_onboarding.file_profile' and field=='sample_ref':
            match=re.fullmatch(r'profile://managed-files/([^/]+)/jobs/([^/]+)/redacted-sample',ref)
            if match:
                asset,job=match.groups();j=jobs.get(job)
                if asset==row['asset_id'] and asset in assets and j and j['asset_id']==asset and j['profile_id']==row['profile_id']:
                    return 'PROFILE_DB_SAMPLE_JOB_LINKED_CONTENT_NOT_EXPORTED'
                return 'PROFILE_DB_SAMPLE_LINK_UNRESOLVED'
        if table=='ouf_ingestion.ing_quarantine':
            run=runs.get(row['run_id']);attempt=attempts.get(row['attempt_id'])
            linked=run is not None and attempt is not None and attempt['run_id']==row['run_id']
            if field=='evidence_ref':
                for prefix,label in [('contract-or-mapping:','CONTRACT_MAPPING_DIAGNOSTIC_LABEL'),('schema-surveillance:','SCHEMA_SURVEILLANCE_DIAGNOSTIC_LABEL')]:
                    if ref.startswith(prefix) and re.fullmatch(r'[A-Z][A-Z0-9_]{1,100}',ref[len(prefix):]):
                        return label if linked else 'DIAGNOSTIC_LABEL_OWNER_LINK_UNRESOLVED'
            if field=='payload_ref':
                lake=lakes.get(ref[7:] if ref.startswith('lake://') else ref)
                if lake and linked and lake['tenant_id']==run['tenant_id'] and lake['source_id']==run['source_id'] and lake['tier']=='RAW' and lake['state']!='DELETED':
                    # Classification is catalog linkage only; no guessed physical bucket.
                    return 'RAW_LAKE_CATALOG_LINKED_NO_NEW_BODY_CHECK'
                if lake:return 'LAKE_CATALOG_PRESENT_BINDING_REQUIRES_REVIEW'
        if ref.startswith('object://managed-files/'):return 'MANAGED_OBJECT_REFERENCE_REQUIRES_BINDING_REVIEW'
        if ref.startswith('profile://'):return 'OTHER_PROFILE_REFERENCE_REQUIRES_REVIEW'
        if ref.startswith('lake://'):return 'OTHER_LAKE_REFERENCE_REQUIRES_REVIEW'
        if ref.startswith(('http://','https://')):return 'EXTERNAL_REFERENCE_REQUIRES_REVIEW'
        return 'OTHER_REFERENCE_REQUIRES_REVIEW'
    for asset in assets.values():
        if not asset['tenant_id']:
            issue('ASSET_OWNER_UNRESOLVED',asset['asset_id']);owners['assetsWithUnresolvedTenantField']+=1
            owners['tenantFieldNull' if asset['tenant_id'] is None else 'tenantFieldEmptyOrFalse']+=1
            owners['sourceReferencePresent' if asset['source_id'] else 'sourceReferenceAbsent']+=1
            upload=any(r['asset_id']==asset['asset_id'] and r['tenant_id'] and r['content_hash']==asset['content_hash'] and r['size_bytes']==asset['size_bytes'] for r in rs('ouf_onboarding.managed_file_upload_attempt'))
            receipt=any(r['asset_id']==asset['asset_id'] and r['tenant_id'] and r['content_hash']==asset['content_hash'] and r['size_bytes']==asset['size_bytes'] for r in rs('ouf_onboarding.managed_file_owner_reconciliation'))
            owners['matchingUploadRowPresent' if upload else 'matchingUploadRowAbsent']+=1
            owners['matchingOwnerReceiptRowPresent' if receipt else 'matchingOwnerReceiptRowAbsent']+=1
    tables=['ouf_onboarding.managed_file_upload_attempt','ouf_onboarding.managed_file_onboarding_attempt','ouf_onboarding.managed_file_owner_reconciliation','ouf_onboarding.file_profile_job','ouf_onboarding.file_profile','ouf_onboarding_legacy.managed_file_ingestion']
    for table in tables:
        for row in rs(table):
            for field in ('sample_ref','output_ref'):
                if row.get(field):
                    issue('ADDITIONAL_REFERENCE_REQUIRES_CLASSIFICATION',[table,field,row[field]])
                    refs[(field,kind(row[field],row,field,table))]+=1
    for row in rs('ouf_ingestion.ing_quarantine'):
        for field in ('payload_ref','evidence_ref'):
            if row[field]:
                issue('QUARANTINE_REFERENCE_REQUIRES_CLASSIFICATION',[row['quarantine_id'],field])
                refs[(field,kind(row[field],row,field,'ouf_ingestion.ing_quarantine'))]+=1
    expected=[(x['code'],x['referenceSha256']) for x in joined['observationFindings']]
    require(collections.Counter(seen)==collections.Counter(expected) and len(seen)==18)
    require(sum(map(len,rows.values()))==joined['exportRows']==353)
    access=[];allowed={'PRESENT','ABSENT','UNSUPPORTED','UNKNOWN','ERROR'}
    for bucket in inventory['bucketFeatures']:
        acl=bucket.get('acl') or {};value=acl.get('value') or {};require(type(value) is dict)
        owner=value.get('Owner') or {};grants=value.get('Grants')
        states={k:(bucket.get(k,{}).get('status') if bucket.get(k,{}).get('status') in allowed else 'OTHER_STATUS_REQUIRES_REVIEW') for k in ('acl','policy','publicAccessBlock','versioning','encryption','objectLock','lifecycle','replication','notification','cors')}
        access.append({'featureStates':states,'ownerIdPresent':bool(owner.get('ID')),'grantsListPresent':isinstance(grants,list),'grantCount':len(grants) if isinstance(grants,list) else None})
    require(len(access)==2)
    return {'schema':'ouf.storage-g0-reference-classification.v1','status':'LOCAL_REFERENCE_CLASSIFICATION_REVIEW_REQUIRED',
        'exact18FindingFingerprintsMatched':True,'ownerObservations':dict(sorted(owners.items())),
        'referenceClassifications':[{'field':f,'classification':k,'count':n} for (f,k),n in sorted(refs.items())],
        'accessShapesWithoutBucketIdentity':sorted(access,key=lambda x:json.dumps(x,sort_keys=True)),
        'subjectAndSourceReviewProofsExported':False,'tenantOwnershipProven':False,'runtimeInstalledCommitsProven':False,
        'profileSampleContentExported':False,'effectiveAuthorizationProven':False,
        'originalFindingsModified':False,'filesModified':0,'credentialsRead':0,'providerRequests':0,
        'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'g0Complete':False,'acceptanceCreditAdded':0}
def main():
    parent=None
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        for part in SCOPE.parts[1:]:
            st=os.fstat(parent);require(st.st_uid==0 and not st.st_mode&0o022)
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);os.close(parent);parent=child
        st=os.fstat(parent);require(st.st_uid==0 and not st.st_mode&0o022)
        hashes={}
        def read(name,expected=None):
            raw,digest=read_relative(parent,name)
            if expected:require(digest==expected)
            hashes[name]=digest;return raw
        joined=json.loads(read('reconciliation.json',RECON_SHA));bindings=joined['exportBindings']
        require(set(bindings) in ({'onboarding','udp','ingestion'},{'onboarding-retained','udp','ingestion'}))
        rows={}
        for profile,binding in bindings.items():
            role='onboarding' if profile.startswith('onboarding') else profile
            parsed=export_rows(read(SCOPE.name+'-'+role+'/export.private.jsonl',binding['rawSha256']),profile,binding)
            require(not(set(parsed)&set(rows)));rows.update(parsed)
        raw=read(SCOPE.name+'-s3/collection.private.json');collection=json.loads(raw)
        require(fingerprint(collection)==joined['bodyCollectionSha256'])
        inventory=json.loads(read(SCOPE.name+'-s3/inventory-before.private.json',collection['inventoryBeforeSha256']))
        report=classify(rows,joined,collection,inventory)
        report['localInputSha256']=hashes;report['filesRead']=len(hashes)
        print(json.dumps(report,sort_keys=True));return 0
    except Exception:
        print(json.dumps({'status':'HELD','reason':'LOCAL_REFERENCE_CLASSIFICATION_UNPROVEN','providerRequests':0,'filesModified':0,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False}));return 1
    finally:
        if parent is not None:os.close(parent)
if __name__=='__main__':raise SystemExit(main())
