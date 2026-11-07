#!/usr/bin/env python3
"""Finish local G0 payload/feature/runtime metadata review. No provider I/O or writes.
Preserve tenant NULL, original findings and consumed scopes. No admission.
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

PINS=json.loads("{\"reconciliation.json\":\"5c0bc6d7351008da9dd53af5489dcf0167c280fe73e99db52de3e9f8c2e5db6a\",\"seaweedfs-g0-20261106-v2-ingestion/export.private.jsonl\":\"c7f7dec685b9eab6183861b38ea208f7bb607add566bda8eb770852c176ab982\",\"seaweedfs-g0-20261106-v2-onboarding/export.private.jsonl\":\"e998feb525c5b7d0e7c23a2e8bd09ecab757d66c1bbcd0518fcb5ea036fef79c\",\"seaweedfs-g0-20261106-v2-s3/collection.private.json\":\"927b53fea852522999d8d8ba3f33b43c7462431ef127040e93c75f72586cf419\",\"seaweedfs-g0-20261106-v2-s3/inventory-before.private.json\":\"43571bb43921f74adfa5974a0903acb54ee1eadecbc9d5d0d70539ce5cadba55\",\"seaweedfs-g0-20261106-v2-udp/export.private.jsonl\":\"87459409c0cffc10817e083948e81cb099cbc750d7344282c7784893c3a1920f\"}")
BASE_INPUT=Path('/var/lib/ouf-g0-host192-preparation-20261106/inputs/package-input.review.json')
BASE_SHA='dc0ab6d4bf36c03b8086ecbae1be1c3e2e381c94152be01dd1ff6bfbfcd04f6e'
CLAIM_SHA='cec357cb3f8de0eae92157ce59828b3cf9667274cd93dd55d28c5cad7a1793b2'
ROLES=('apisix','caddy','gateway-owner','ingestion','ingestion-evidence-read','keycloak','mcp','minio','onboarding','postgres','semantic','udp','udp-evidence-read')
def protected_directory(path):
    require(path.is_absolute() and str(path)==os.path.normpath(path))
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in ('',*path.parts[1:]):
            if part:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
            st=os.fstat(fd);require(st.st_uid==0 and not st.st_mode&0o022)
        return fd
    except BaseException:
        os.close(fd);raise
def analyze_payloads(rows,joined,collection,runtime):
    assets=rows['ouf_onboarding.managed_file_asset']
    runs={r['run_id']:r for r in rows['ouf_ingestion.ing_run']}
    attempts={r['attempt_id']:r for r in rows['ouf_ingestion.processing_attempt']}
    snapshots=rows['ouf_ingestion.runtime_configuration_snapshot']
    bucket=runtime['storageBuckets']['onboarding']
    require(isinstance(bucket,str) and bucket)
    objects={(x['bucket'],x['key']):x for x in collection['objects']}
    require(len(objects)==len(collection['objects'])==120)
    payloads=[];matched=[]
    expected={(f['code'],f['referenceSha256']) for f in joined['observationFindings']}
    for q in rows['ouf_ingestion.ing_quarantine']:
        ref=q['payload_ref']
        if not ref:continue
        fp=('QUARANTINE_REFERENCE_REQUIRES_CLASSIFICATION',fingerprint([q['quarantine_id'],'payload_ref']))
        require(fp in expected);matched.append(fp)
        require(isinstance(ref,str) and ref.startswith('object://managed-files/'))
        candidates=[a for a in assets if a['staging_ref']==ref]
        run=runs.get(q['run_id']);attempt=attempts.get(q['attempt_id'])
        asset=candidates[0] if len(candidates)==1 else None
        obj=objects.get((bucket,ref[len('object://'):]))
        related=[s for s in snapshots if s['run_id']==q['run_id']]
        snap_exact=bool(asset) and any(s['asset_id_ref']==asset['asset_id'] and s['staging_ref']==ref for s in related)
        active_snap=[s for s in related if s['asset_id_ref'] or s['staging_ref']]
        snap_conflict=bool(asset) and any((s['asset_id_ref'] and s['asset_id_ref']!=asset['asset_id']) or (s['staging_ref'] and s['staging_ref']!=ref) for s in active_snap)
        checks={
            'uniqueAssetForExactStagingRef':asset is not None,
            'bodyInBoundOnboardingBucket':obj is not None,
            'assetHashMatchesObservedBody':bool(asset and obj and asset['content_hash']=='sha256:'+obj['sha256']),
            'assetSizeMatchesObservedBody':bool(asset and obj and type(asset['size_bytes']) is int and asset['size_bytes']==obj['bytes']),
            'quarantineRunAndAttemptLinked':bool(run and attempt and attempt['run_id']==q['run_id']),
            'runSnapshotHasExactAssetAndStagingRef':bool(snap_exact),
            'runSnapshotHasConflictingManagedBinding':bool(snap_conflict),
            'assetSourceMatchesRun':bool(asset and run and asset['source_id'] and asset['source_id']==run['source_id']),
            'assetTenantFieldNull':bool(asset and asset['tenant_id'] is None),
            'assetExplicitTenantMatchesRun':bool(asset and run and asset['tenant_id'] and asset['tenant_id']==run['tenant_id']),
            'assetExplicitTenantConflictsWithRun':bool(asset and run and asset['tenant_id'] and asset['tenant_id']!=run['tenant_id'])}
        physical=all(checks[k] for k in ('uniqueAssetForExactStagingRef','bodyInBoundOnboardingBucket','assetHashMatchesObservedBody','assetSizeMatchesObservedBody','quarantineRunAndAttemptLinked'))
        classification='MANAGED_PAYLOAD_PHYSICAL_LINK_OBSERVED_OWNER_NOT_PROVEN' if physical else 'MANAGED_PAYLOAD_LINK_UNRESOLVED'
        if snap_conflict or checks['assetExplicitTenantConflictsWithRun']:classification='MANAGED_PAYLOAD_BINDING_CONFLICT_REVIEW'
        payloads.append({'classification':classification,'checks':checks})
    require(len(payloads)==len(set(matched))==2)
    grouped=collections.Counter(json.dumps(p,sort_keys=True) for p in payloads)
    return [dict(json.loads(p),count=n) for p,n in sorted(grouped.items())]
def feature_details(inventory):
    out=[]
    for b in inventory['bucketFeatures']:
        acl=b.get('acl') or {};v=acl.get('value') or {};owner=v.get('Owner') or {}
        grants=v.get('Grants');require(acl['status']=='PRESENT' and isinstance(grants,list) and len(grants)==1)
        safe=[]
        for grant in grants:
            g=grant.get('Grantee') or {};kind=g.get('Type')
            permission=grant.get('Permission');uri=g.get('URI')
            safe.append({'type':kind if kind in ('CanonicalUser','Group','AmazonCustomerByEmail') else 'OTHER',
                'permission':permission if permission in ('FULL_CONTROL','READ','WRITE','READ_ACP','WRITE_ACP') else 'OTHER',
                'granteeIdPresent':bool(g.get('ID')),
                'granteeMatchesOwnerId':bool(g.get('ID')==owner.get('ID')) if g.get('ID') and owner.get('ID') else None,
                'groupAudience':'ALL_USERS' if uri=='http://acs.amazonaws.com/groups/global/AllUsers' else 'AUTHENTICATED_USERS' if uri=='http://acs.amazonaws.com/groups/global/AuthenticatedUsers' else 'OTHER_OR_NONE'})
        version=b.get('versioning',{}).get('value') or {}
        notification=b.get('notification',{}).get('value') or {}
        require(isinstance(version,dict) and isinstance(notification,dict))
        states={}
        for field in ('Status','MFADelete'):
            value=version.get(field)
            states[field]=value if value in ('Enabled','Suspended') else 'NOT_SET' if value in (None,'') else 'OTHER_REQUIRES_REVIEW'
        counts={}
        for field in ('TopicConfigurations','QueueConfigurations','LambdaFunctionConfigurations'):
            values=notification.get(field)
            require(values is None or isinstance(values,list));counts[field]=len(values or [])
        out.append({'ownerIdPresent':bool(owner.get('ID')),'grants':safe,'versioningValues':states,
            'notificationDestinationCounts':counts,'eventBridgeConfigurationPresent':notification.get('EventBridgeConfiguration') is not None,
            'bucketPolicyAbsent':b.get('policy',{}).get('status')=='ABSENT',
            'publicAccessBlockUnsupported':b.get('publicAccessBlock',{}).get('status')=='UNSUPPORTED'})
    require(len(out)==2);return sorted(out,key=lambda x:json.dumps(x,sort_keys=True))
def runtime_summary(host,base):
    require(host['schema']=='ouf.storage-g0-host-observation.v1' and not host['findings'] and set(host['roles'])==set(ROLES) and len(host['containers'])==145)
    roles=host['roles'];bound=set();safe={}
    source_mounts={m['Source'] for m in roles['minio']['mounts'] if m.get('Source')}
    for role in ROLES:
        r=roles[role];b=base['roles'][role]
        require(r['id']==b['containerId'] and r['nativeImage']==b['nativeImage'])
        require(type(r['running']) is bool)
        bound.add(r['id']);rev=r.get('declaredRevision')
        safe[role]={'runningAtCollection':r['running'],'pausedAtCollection':r.get('paused') is True,
            'nativeImage':r['nativeImage'],'declaredRevision':rev if isinstance(rev,str) and re.fullmatch('[0-9a-f]{40}',rev) else None,
            'storageBindingCount':len(r['storageBindings']),
            'rwMounts':sum(m.get('RW') is True for m in r['mounts'])}
    other=[r for r in host['containers'] if r['id'] not in bound]
    return {'roles':safe,'nonRosterContainers':len(other),
        'runningNonRosterContainers':sum(r.get('running') is True for r in other),
        'runningNonRosterWithStorageBindings':sum(r.get('running') is True and bool(r['storageBindings']) for r in other),
        'runningNonRosterSharingMinioMount':sum(r.get('running') is True and any(m.get('Source') in source_mounts for m in r['mounts']) for r in other),
        'writerCensusComplete':False,'externalConsumersProvenAbsent':False,'installedSourceMembershipProven':False,
        'observationIsCurrentLiveProbe':False}
def main():
    root=None
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
        root=protected_directory(SCOPE);hashes={}
        def local(name,pin=None):
            raw,digest=read_relative(root,name)
            if pin:require(pin==digest)
            hashes[name]=digest;return raw
        def absolute(path,pin,label):
            fd=protected_directory(path.parent)
            try:raw,digest=read_at(fd,path.name)
            finally:os.close(fd)
            require(digest==pin);hashes[label]=digest;return json.loads(raw)
        joined=json.loads(local('reconciliation.json',RECON_SHA));claim=json.loads(local('claim.private.json',CLAIM_SHA))
        base=absolute(BASE_INPUT,BASE_SHA,'baseInput')
        require(base['operationId']==SCOPE.name and claim['operationId']==SCOPE.name and claim['collectionDecisionRef']=='OUF-G0-COLLECT-20261106-02')
        runtime=absolute(Path(base['operatorEvidenceFiles']['runtime']),claim['boundInputSha256']['operator:runtime'],'runtimeDeclaration')
        require(runtime['installationRef']==base['installationRef'] and runtime['section']=='RUNTIME')
        rows={}
        for role in ('onboarding','ingestion'):
            profile=next(k for k in joined['exportBindings'] if k.startswith(role))
            binding=joined['exportBindings'][profile];name=SCOPE.name+'-'+role+'/export.private.jsonl'
            require(binding['rawSha256']==PINS[name])
            parsed=export_rows(local(name,PINS[name]),profile,binding)
            require(not(set(parsed)&set(rows)));rows.update(parsed)
        name=SCOPE.name+'-s3/collection.private.json';collection=json.loads(local(name,PINS[name]))
        require(fingerprint(collection)==joined['bodyCollectionSha256'] and collection['complete'] is True)
        name=SCOPE.name+'-s3/inventory-before.private.json';inventory=json.loads(local(name,PINS[name]))
        require(collection['inventoryBeforeSha256']==PINS[name])
        before=json.loads(local('host-before.private.json'));after=json.loads(local('host-after.private.json'));require(before==after)
        report={'schema':'ouf.storage-g0-final-local-review.v1','status':'LOCAL_PAYLOAD_FEATURE_RUNTIME_REVIEW_REQUIRED',
            'managedPayloads':analyze_payloads(rows,joined,collection,runtime),
            'bucketFeatureDetailsWithoutIdentity':feature_details(inventory),
            'runtimeAtCollection':runtime_summary(before,base),'localInputSha256':hashes,'filesRead':len(hashes),
            'tenantOwnershipProven':False,'effectiveAuthorizationProven':False,'writerQuiescenceProven':False,
            'independentBackupVerified':False,'originalFindingsModified':False,
            'filesModified':0,'credentialsRead':0,'providerRequests':0,'runtimeAuthorityIssued':False,
            'automaticReplayAllowed':False,'g0Complete':False,'acceptanceCreditAdded':0}
        print(json.dumps(report,sort_keys=True));return 0
    except Exception:
        print(json.dumps({'status':'HELD','reason':'LOCAL_PAYLOAD_FEATURE_RUNTIME_UNPROVEN','providerRequests':0,'filesModified':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False}));return 1
    finally:
        if root is not None:os.close(root)
if __name__=='__main__':raise SystemExit(main())
